"""Per-session risk context.

Tracks how many records have been returned, which accounts were touched,
the widest time span requested in one call, and client IP addresses with
timestamps for anomaly detection (ZT-5 follow-up). A `RecordCount` is a thin
wrapper that makes the increment/decrement semantics explicit and testable.

This module has no opinion on thresholds — that lives in the engine.

TWO CLOCKS, AND WHY BOTH. Every duration this module measures in process is
taken from ``time.monotonic()``, which cannot step backwards and so cannot
produce a negative age when the wall clock is corrected mid-session. A
monotonic reading is meaningless outside the process that took it, though:
its epoch is arbitrary. So the serialised form carries POSIX wall-clock
instants, converted on the way out by `_to_wall_clock` and back on the way in
by `_from_wall_clock`, and a restored context's age is the real elapsed time
since it was created rather than the time since it was last written.

That conversion is the fix for one defect that made three separate things
inert (audit finding, 2026-09-22). ``to_dict`` used to serialise
``time.time()`` -- "now", at serialisation, not the session's start -- so
``RedisSessionStore``'s TTL arithmetic measured elapsed time against a value
every save rewrote and a session never aged out. ``from_dict`` then assigned
that POSIX timestamp straight into ``_start_time``, which
:attr:`RiskContext.session_age_seconds` subtracts from ``time.monotonic()``:
a restored session reported an age of roughly -1.7e9 seconds, so
`engine.py`'s `RiskEngine` could never emit ``SESSION_AGE_EXCEEDED`` either.
`IpTracker` serialised raw monotonic readings while its own docstring claimed
it converted them, which made ``time_since_last_change()`` -- the input to
`ip_anomaly.py`'s `IpAnomalyDetector` impossible-travel check -- a comparison
between two processes' unrelated clock epochs.
"""

from __future__ import annotations

import json
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from postern_core.domain.verification import VerificationTier
from postern_core.risk.types import RiskSignal, Severity


def _to_wall_clock(monotonic_reading: float) -> float:
    """A monotonic reading as a POSIX timestamp, for storage.

    Both clocks are read here, one line apart, so the offset between them is
    this instant's. It is accurate to whatever the scheduler does between the
    two calls, which is microseconds against budgets measured in minutes.
    """
    return time.time() - (time.monotonic() - monotonic_reading)


def _from_wall_clock(posix_timestamp: float) -> float:
    """The inverse of `_to_wall_clock`, applied in the loading process.

    An instant stored in the future -- a clock that stepped back between the
    two processes, or two hosts that disagree -- would otherwise restore as a
    negative age, which is the shape of the defect this conversion exists to
    fix. It is clamped to "now" instead: a session whose age cannot be
    believed is treated as new, which under-reports age rather than handing
    the engine's session-age check a number it would answer False to forever.
    """
    now = time.monotonic()
    elapsed = time.time() - posix_timestamp
    if elapsed < 0:
        return now
    return now - elapsed


@dataclass(frozen=True)
class RecordCount:
    """Immutable snapshot of how many records a session has returned.

    Immutable so it can be passed through tool handlers without mutation
    surprises; the context holds a mutable counter behind the scenes.
    """

    total: int = 0
    """Cumulative records returned across all tool calls in this session."""


@dataclass(frozen=True)
class IpEntry:
    """One IP address recorded at a point in time.

    Immutable so it can be logged, serialized, or passed through handlers
    without mutation concerns.
    """

    ip_address: str
    """The client IP address, as the risk middleware derived it."""

    recorded_at: float
    """``time.monotonic()`` snapshot at recording time (module docstring)."""


# ---------------------------------------------------------------------------
# The serialised shape, as validated models rather than dicts of `Any`.
# ---------------------------------------------------------------------------
#
# WHY MODELS. Until 2026-09-22 ``from_dict`` read a bare ``dict[str, object]``
# and carried seven ``# type: ignore`` comments, one per field it coerced --
# ``int(data["_records"])``, ``set(data["_accounts"])``, and so on. Each
# ignore marked a place where a value of the wrong shape reached a
# constructor instead of a validator, and the defect that hid among them is
# exactly the module docstring's: ``float(data["_start_time"])`` accepted a
# POSIX timestamp into a field holding a monotonic reading, which is
# type-correct and semantically nonsense. The rest of this repository
# validates at its serialisation boundaries rather than coercing across them
# (`models.py`'s `SessionInfo` and the masked types it carries), and these
# models bring this one into line.
#
# `extra` is left at pydantic's default (ignore) rather than set to "forbid".
# During a rolling deploy two replicas run different versions against one
# store, and "forbid" would make the older replica refuse every context the
# newer one wrote -- which, since a store that cannot answer now denies the
# call (`session.py`'s `SessionStoreUnavailable`), turns a deploy into an
# outage. Unknown fields are dropped instead, and `version` is carried so a
# reader can tell which writer produced the value.


class _StoredSignal(BaseModel):
    """One `RiskSignal` as stored.

    ``severity`` is the enum member's NAME, never its number: `types.py`'s
    `Severity` is an ``auto()`` enum whose values are positional and would
    silently re-map every stored row if a member were ever inserted above
    another.
    """

    model_config = ConfigDict(frozen=True)

    code: str
    severity: str
    description: str
    details: dict[str, Any] = Field(default_factory=dict)


class _StoredIpEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    ip_address: str
    recorded_at: float
    """POSIX timestamp, converted from the monotonic reading on the way out."""


class _StoredIpTracker(BaseModel):
    model_config = ConfigDict(frozen=True)

    entries: list[_StoredIpEntry] = Field(default_factory=list)


class _StoredContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: int = 1
    session_id: str | None = None
    records: int = 0
    accounts: list[str] = Field(default_factory=list)
    max_days: int = 0
    started_at: float
    """POSIX timestamp of when the context was CREATED, not when it was last
    written. That distinction is the whole of the TTL defect the module
    docstring records, so this field has no default: a stored value without it
    cannot be aged and must fail validation rather than restore as new."""
    ip_tracker: _StoredIpTracker = Field(default_factory=_StoredIpTracker)
    risk_signals: list[_StoredSignal] = Field(default_factory=list)
    verification_tier: VerificationTier = VerificationTier.SESSION_ONLY


class IpTracker:
    """Tracks client IP addresses per session for anomaly detection.

    Thread-safe enough for FastMCP's in-process test client (single-threaded
    async). Not safe across processes — that requires a shared store.

    Usage: call ``record_ip()`` from middleware or handler with the client IP;
    the tracker accumulates entries and exposes properties for anomaly detection.

    **Bounded:** oldest entries are dropped when the list exceeds ``max_entries``
    (default 100). This prevents unbounded memory growth from a session that
    touches many distinct IPs (which itself is suspicious, but we must not
    amplify the attack by allocating unbounded memory).

    Audit fix (2026-09-21): previously unbounded — a session cycling through
    thousands of IPs would grow the list without limit.
    """

    __slots__ = ("_entries", "_max_entries")

    def __init__(self, max_entries: int = 100) -> None:
        self._entries: list[IpEntry] = []
        self._max_entries = max_entries

    def record_ip(self, ip_address: str) -> None:
        """Record a client IP address at the current monotonic time.

        If the tracker is full, drops the oldest entry before appending
        (FIFO eviction). This bounds memory at ``max_entries * sizeof(IpEntry)``.
        """
        if len(self._entries) >= self._max_entries:
            self._entries.pop(0)  # Drop oldest entry.
        self._entries.append(IpEntry(ip_address=ip_address, recorded_at=time.monotonic()))

    @property
    def distinct_ips(self) -> int:
        """Number of unique IP addresses seen in this session."""
        return len({e.ip_address for e in self._entries})

    @property
    def last_ip(self) -> str | None:
        """Most recently recorded IP, or ``None`` if none recorded."""
        if not self._entries:
            return None
        return self._entries[-1].ip_address

    @property
    def entries(self) -> list[IpEntry]:
        """All recorded IP entries in chronological order."""
        return list(self._entries)

    def time_since_last_change(self) -> float | None:
        """Seconds since the last IP changed (``None`` if fewer than 2 entries)."""
        if len(self._entries) < 2:
            return None
        last = self._entries[-1]
        prev = self._entries[-2]
        if last.ip_address == prev.ip_address:
            return None  # same IP, no change
        return last.recorded_at - prev.recorded_at

    def snapshot(self) -> dict[str, int | str | None]:
        """Return a serialisable snapshot for logging/alerting."""
        return {
            "distinct_ips": self.distinct_ips,
            "last_ip": self.last_ip,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialise IP entries for storage (Redis, DB, etc.).

        Converts each ``time.monotonic()`` reading to a POSIX timestamp, which
        is what this docstring claimed before 2026-09-22 and what it now does.
        """
        stored = _StoredIpTracker(
            entries=[
                _StoredIpEntry(ip_address=e.ip_address, recorded_at=_to_wall_clock(e.recorded_at))
                for e in self._entries
            ]
        )
        return stored.model_dump()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], max_entries: int = 100) -> IpTracker:
        """Reconstruct an ``IpTracker`` from a serialised dict.

        Keeps only the newest ``max_entries`` entries, so a stored blob longer
        than this process's bound cannot re-inflate the list that bound exists
        to cap. Raises ``pydantic.ValidationError`` on a shape it cannot read;
        the store turns that into a refusal rather than a fresh context.
        """
        stored = _StoredIpTracker.model_validate(dict(data))
        tracker = cls(max_entries=max_entries)
        for entry in stored.entries[-max_entries:]:
            tracker._entries.append(
                IpEntry(
                    ip_address=entry.ip_address,
                    recorded_at=_from_wall_clock(entry.recorded_at),
                )
            )
        return tracker


class RiskContext:
    """Per-session state for ZT-5 anomaly detection.

    Thread-safe enough for FastMCP's in-process test client (single-threaded
    async). Not safe across processes — that requires a shared store.

    One context per (customer, client) identity, created and loaded by
    `session.py`'s `SessionStoreBase` and pushed onto a contextvar by the risk
    middleware so tool handlers can record what they returned.
    """

    __slots__ = (
        "_records",
        "_accounts",
        "_max_days",
        "_start_time",
        "_ip_tracker",
        "_session_id",
        "_risk_signals",
        "_verification_tier",
    )

    def __init__(self, session_id: str | None = None) -> None:
        self._records = 0
        self._accounts: set[str] = set()
        self._max_days: int = 0
        self._start_time: float = time.monotonic()
        self._ip_tracker = IpTracker()
        self._session_id = session_id
        self._risk_signals: list[RiskSignal] = []
        self._verification_tier: VerificationTier = VerificationTier.SESSION_ONLY

    @property
    def record_count(self) -> RecordCount:
        return RecordCount(total=self._records)

    @property
    def distinct_accounts(self) -> int:
        return len(self._accounts)

    @property
    def max_days_requested(self) -> int:
        return self._max_days

    @property
    def session_age_seconds(self) -> float:
        return time.monotonic() - self._start_time

    @property
    def started_at(self) -> float:
        """When this context was created, as a POSIX timestamp.

        The store reads this to age a context out. It is derived from the
        monotonic start time rather than stored separately, so there is one
        creation instant and not two that can drift apart.
        """
        return _to_wall_clock(self._start_time)

    @property
    def ip_tracker(self) -> IpTracker:
        """Access the per-session IP tracker for anomaly detection."""
        return self._ip_tracker

    @property
    def session_id(self) -> str | None:
        """Opaque session identifier, set at creation time."""
        return self._session_id

    @property
    def risk_signals(self) -> list[RiskSignal]:
        """Signals emitted by the last evaluation of this call.

        Populated by the risk middleware after each tool call; replaced
        wholesale before the next evaluation so it only carries signals for
        the most recent call.
        """
        return self._risk_signals

    @property
    def verification_tier(self) -> VerificationTier:
        """Current verification tier for this session.

        Starts at ``SESSION_ONLY`` and escalates via
        :meth:`escalate_tier` when the risk engine emits MEDIUM signals.
        """
        return self._verification_tier

    def escalate_tier(self) -> None:
        """Escalate the verification tier by one level.

        Moves ``SESSION_ONLY`` → ``APP_APPROVAL`` →
        ``APP_IDENTITY_VERIFICATION``.  Once at the maximum tier, this is
        a no-op (the session cannot escalate further).

        Called by the risk middleware when the risk engine emits MEDIUM
        signals, so that subsequent tool calls require stronger verification.
        """
        if self._verification_tier < VerificationTier.APP_IDENTITY_VERIFICATION:
            object.__setattr__(
                self, "_verification_tier", VerificationTier(self._verification_tier + 1)
            )

    def record_records(self, count: int) -> None:
        """Add `count` records to the session total."""
        self._records += count

    def record_account(self, account_ref: str) -> None:
        """Track that this account was touched in the session."""
        self._accounts.add(account_ref)

    def record_days(self, days: int) -> None:
        """Track the widest time window requested in one call."""
        if days > self._max_days:
            self._max_days = days

    def record_signals(self, signals: list[RiskSignal]) -> None:
        """Replace this call's signals, for the audit row to read.

        Public because the middleware is in another package and was reaching
        into ``_risk_signals`` directly. Replaces rather than appends: the
        list describes the most recent evaluation, not the session's history,
        which is what `audit.py`'s completion row writes into
        ``audit_log.risk_signals``.
        """
        self._risk_signals = list(signals)

    def snapshot(self) -> dict[str, int | float | str | None]:
        """Return a serialisable snapshot for logging/alerting."""
        snap: dict[str, int | float | str | None] = {
            "records": self._records,
            "distinct_accounts": self.distinct_accounts,
            "max_days_requested": self._max_days,
            "session_age_seconds": round(self.session_age_seconds, 1),
            "session_id": self._session_id,
            "verification_tier": str(self._verification_tier),
        }
        snap.update(self._ip_tracker.snapshot())
        return snap

    def to_dict(self) -> dict[str, Any]:
        """Serialise the full context for storage (Redis, DB, etc.).

        ``started_at`` is the context's CREATION instant in POSIX time, not
        the instant of this call: see the module docstring for what the
        second reading cost.
        """
        stored = _StoredContext(
            session_id=self._session_id,
            records=self._records,
            accounts=sorted(self._accounts),
            max_days=self._max_days,
            started_at=self.started_at,
            ip_tracker=_StoredIpTracker.model_validate(self._ip_tracker.to_dict()),
            risk_signals=[
                _StoredSignal(
                    code=s.code,
                    severity=s.severity.name,
                    description=s.description,
                    details=s.details,
                )
                for s in self._risk_signals
            ],
            verification_tier=self._verification_tier,
        )
        return stored.model_dump()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RiskContext:
        """Reconstruct a ``RiskContext`` from a serialised dict.

        Raises ``pydantic.ValidationError`` for a shape this version cannot
        read, and ``KeyError`` for a severity name it does not know. Both
        reach `session.py`'s `RedisSessionStore`, which turns them into a
        refusal: a context that cannot be read is not the same event as an
        identity that has none, and silently substituting a fresh context
        would hand an attacker who can corrupt one stored value a way to zero
        the budgets it holds.
        """
        stored = _StoredContext.model_validate(dict(data))
        ctx = cls(session_id=stored.session_id)
        ctx._records = stored.records
        ctx._accounts = set(stored.accounts)
        ctx._max_days = stored.max_days
        ctx._start_time = _from_wall_clock(stored.started_at)
        ctx._ip_tracker = IpTracker.from_dict(stored.ip_tracker.model_dump())
        ctx._risk_signals = [
            RiskSignal(
                code=s.code,
                severity=Severity[s.severity],
                description=s.description,
                details=dict(s.details),
            )
            for s in stored.risk_signals
        ]
        ctx._verification_tier = stored.verification_tier
        return ctx

    def to_json(self) -> str:
        """Serialise the context as a JSON string for Redis storage."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, data: str) -> RiskContext:
        """Reconstruct a ``RiskContext`` from a JSON string."""
        return cls.from_dict(json.loads(data))

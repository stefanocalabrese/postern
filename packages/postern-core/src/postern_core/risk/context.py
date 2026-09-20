"""Per-session risk context.

Tracks how many records have been returned, which accounts were touched,
the widest time span requested in one call, and client IP addresses with
timestamps for anomaly detection (ZT-5 follow-up). A `RecordCount` is a thin
wrapper that makes the increment/decrement semantics explicit and testable.

This module has no opinion on thresholds — that lives in the engine.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


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
    """The client IP address (from ``X-Forwarded-For`` or ``remote_addr``)."""

    recorded_at: float
    """``time.monotonic()`` snapshot at recording time."""


class IpTracker:
    """Tracks client IP addresses per session for anomaly detection.

    Thread-safe enough for FastMCP's in-process test client (single-threaded
    async). Not safe across processes — that requires a shared store.

    Usage: call ``record_ip()`` from middleware or handler with the client IP;
    the tracker accumulates entries and exposes properties for anomaly detection.
    """

    __slots__ = ("_entries",)

    def __init__(self) -> None:
        self._entries: list[IpEntry] = []

    def record_ip(self, ip_address: str) -> None:
        """Record a client IP address at the current monotonic time."""
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


class RiskContext:
    """Per-session state for ZT-5 anomaly detection.

    Thread-safe enough for FastMCP's in-process test client (single-threaded
    async). Not safe across processes — that requires a shared store, which
    is ZT-1's refresh evaluation domain.

    Usage: create one per session (on `start_session`), pass it through tool
    handlers, evaluate at the end of each call.
    """

    __slots__ = (
        "_records",
        "_accounts",
        "_max_days",
        "_start_time",
        "_ip_tracker",
    )

    def __init__(self) -> None:
        self._records = 0
        self._accounts: set[str] = set()
        self._max_days: int = 0
        self._start_time: float = time.monotonic()
        self._ip_tracker = IpTracker()

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
    def ip_tracker(self) -> IpTracker:
        """Access the per-session IP tracker for anomaly detection."""
        return self._ip_tracker

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

    def snapshot(self) -> dict[str, int | float]:
        """Return a serialisable snapshot for logging/alerting."""
        snap = {
            "records": self._records,
            "distinct_accounts": self.distinct_accounts,
            "max_days_requested": self._max_days,
            "session_age_seconds": round(self.session_age_seconds, 1),
        }
        snap.update(self._ip_tracker.snapshot())
        return snap

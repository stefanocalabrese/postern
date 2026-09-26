"""RFC 8628 Device Authorization Grant — device codes and storage.

Provides the ``DeviceCode`` model and a pluggable ``DeviceCodeStore`` backed
by either an in-memory dict (dev / test) or Redis (production — compatible
with AWS ElastiCache, Google Memorystore, Azure Cache for Redis, or any
Redis-compatible service).

The device authorization flow (§7.3 of the handoff):

1. Browser calls ``/device_authorization`` → gets a device code and a
   user-visible pairing code (6 chars).
2. A QR code encodes the verification URI + pairing code.
3. User scans with mobile app → bank app shows pairing code + context.
4. User confirms pairing code matches → proceeds to identity verification.
5. After approval, the browser polls ``/token`` with
   ``grant_type=device_code`` to receive access tokens.

The pairing code (``user_code``) carries the anti-phishing control for
A2 (QR relay), and it is worth being precise about which half lives where,
because the two halves are not interchangeable:

- The HUMAN half is the control against a relayed QR. The user compares the
  code their own trusted screen shows against the code the app shows, and
  refuses if they differ. That comparison happens on the operator's app
  pairing screen, which is not in this repository and is still an open
  question (handoff §10.10). Nothing here can perform it or verify that it
  happened.
- The SERVER half, ``services/confirm/device_auth.py::approve_callback``,
  makes the approving app PROVE it holds the ``user_code`` before an approval
  is accepted. That turns a stolen or leaked ``device_code`` on its own into
  an insufficient credential, and it bounds guessing through
  ``user_code_attempts`` below (RFC 8628 §5.2 asks for exactly that). It does
  NOT detect a relay, because a relaying attacker who obtained the QR holds
  both codes.

Usage::

    from postern_core.auth.device_codes import InMemoryDeviceStore

    store = InMemoryDeviceCodeStore()
    code = await store.create_device_code(
        client_id="my-client",
        scopes="accounts:read transactions:read",
    )
    # code.device_code, code.user_code, code.verification_uri ...

    # Later: check if approved
    existing = await store.get_device_code(code.device_code)
    if existing and existing.approved:
        # Browser can exchange for tokens
        pass

Production deployments set ``POSTERN_REDIS_URL`` to enable the Redis
backend; without it, the in-memory store is used.
"""

from __future__ import annotations

import dataclasses
import heapq
import json as _json
import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from datetime import UTC as _UTC
from typing import Any

from postern_core.config import int_arg_or_env

logger = __import__("logging").getLogger(__name__)

#: How many device codes a store will hold before it refuses to create more.
#:
#: WHY A CAP EXISTS AT ALL. ``POST /device_authorization`` is public by RFC
#: 8628's own premise -- the browser starting a pairing holds no credential --
#: and every call stores a row. Measured against ``create_confirm_app`` over
#: raw ASGI on 2026-09-24, before this cap: 2,000 unauthenticated calls, each
#: with a body under the 64 KiB limit `services/confirm/body_limit.py`
#: enforces, left 2,000 device codes costing 128,990,755 bytes, an RSS delta
#: of 131,252,224 bytes, and 64,495 bytes per code. Extrapolated to a million
#: calls that is 64.5 GB. A rate limit bounds the ARRIVAL RATE and does not
#: bound that; this bounds the STANDING COST. Neither substitutes for the
#: other, and `services/confirm/rate_limit.py` holds the other half.
#:
#: WHY 10,000. The number is derived from what a code costs once
#: `services/confirm/device_auth.py` bounds the two caller-supplied fields:
#: a realistic code measures 1,633 bytes and one with both fields at their
#: new ceilings measures 2,336, so 10,000 codes is 16 to 23 MB. Against
#: legitimate demand it is generous: a code lives 900 seconds, so 10,000
#: concurrent codes is a deployment starting a device pairing every 90
#: milliseconds, sustained, across every replica sharing one Redis.
DEFAULT_MAX_DEVICE_CODES = 10_000

#: The shortest device-code lifetime either configuration path accepts.
#:
#: Read by ``POSTERN_REDIS_DEVICE_CODE_TTL`` below and by
#: `services/confirm/settings.py`'s ``POSTERN_DEVICE_CODE_TTL_SECONDS``,
#: which imports this name rather than carrying a second 30.
#:
#: WHY A FLOOR EXISTS AT ALL (bug B1). `RedisDeviceCodeStore` below writes
#: its key with
#: ``max(0, int((expires_at - now).total_seconds()))``, and ``int``
#: TRUNCATES. A code asked for one second has roughly 0.9999 of one left by
#: the time that line runs, so it floors to zero and the ``if ttl_seconds >
#: 0`` guard skips BOTH the ``SETEX`` and the ``ZADD``. Measured on
#: 2026-09-25 against redis:7-alpine::
#:
#:     expires_in=   1  raw=0.999982  int()=0  stored=NO -- nothing written
#:     expires_in=   2  raw=1.999990  int()=1  stored=YES
#:     expires_in= 900  raw=899.999992  int()=899  stored=YES
#:
#: ``create_device_code`` returns a code in all three rows, so the first one
#: hands a browser a device code the store never wrote; its next ``/token``
#: poll is answered ``invalid_grant``, which tells a legitimate customer
#: their code was never real. `InMemoryDeviceCodeStore` stores that same
#: code, so dev and production disagree on the same call.
#:
#: THERE WERE TWO OPERATOR PATHS TO IT, NOT ONE, and this comment said
#: otherwise until 2026-09-25. ``POSTERN_DEVICE_CODE_TTL_SECONDS`` was
#: floored first; ``POSTERN_REDIS_DEVICE_CODE_TTL``, which feeds
#: ``_default_ttl`` and from there ``create_device_code``'s ``expires_in``,
#: was still a bare ``int()``. Measured at ``POSTERN_REDIS_DEVICE_CODE_TTL=1``
#: against redis:7-alpine, through ``create_device_code_store()`` and a
#: ``create_device_code`` call that passes no ``expires_in``::
#:
#:     expires_at - now = 0.999991  int() = 0
#:     get_device_code  -> None
#:     redis EXISTS key -> 0   redis ZSCORE index -> None
#:
#: Both variables now refuse below this number, which is the point of there
#: being one number.
#:
#: WHY 30, DERIVED. Three bounds sit under it, and
#: tests/test_device_grant.py::TestTheFloorIsDerivedAndNotPicked re-derives
#: each one so that this working fails rather than rots:
#:
#: - 2 IS WHERE THE ARITHMETIC BITES. Below it the Redis backend stores
#:   nothing at all; tests/test_redis_backed_stores.py::SHORTEST_STORED_TTL
#:   is that number and carries the same measurement. 30 is 15x it, which is
#:   far enough that no rounding anywhere can reach the cliff.
#: - 5 IS THE BROWSER'S FIRST POLL, `services/confirm/settings.py`'s
#:   ``device_poll_interval_seconds``.
#:   `services/confirm/device_auth.py`'s ``token_endpoint`` answers
#:   ``slow_down`` to anything sooner, so a TTL at or under the interval
#:   expires before the browser is permitted to ask even once. 30 is 6x it,
#:   so a code at the floor survives several polls rather than exactly one.
#: - 15 IS THE LONGEST MEASURED SERVER-SIDE LEG of the approval: CLAUDE.md
#:   prices identity verification, which step 4 of the flow in this
#:   module's docstring reaches, at 5 to 15 seconds. 30 is 2x its worst
#:   case.
#:
#: WHAT THIS DELIBERATELY DOES NOT CLAIM, because a floor that reads as a
#: recommendation is worse than none:
#:
#: - NOT that 30 is usable. It is not. 900 is the default and the only
#:   lifetime in this tree derived for real use, and an operator who sets 30
#:   will strand customers who take longer than half a minute to pick up a
#:   phone. This bounds what is REPRESENTABLE, not what is SUFFICIENT.
#: - NOT that a human can scan a QR, compare a pairing code and approve
#:   within 30 seconds. Nothing here measures a human, and the number is
#:   built only out of legs this repository has measured.
#: - NOT that the truncation is fixed. It is not; ``_set_code`` below
#:   records what still reaches it. This closes the CONFIGURATION paths
#:   and no other.
MIN_DEVICE_CODE_TTL_SECONDS = 30


class DeviceCodeStoreFull(RuntimeError):
    """Raised by ``create_device_code`` when the store is at its cap.

    REFUSING IS THE DECISION, and the alternative was evicting the oldest
    code. `services/confirm/device_auth.py::approve_callback` already faced
    the same trade and recorded the answer: it accepted leaking "this code is
    approved" rather than let a caller "burn the attempt budget ... and
    REVOKE it, denying the legitimate user the token they are already waiting
    on", because "only one of them destroys a session in flight".

    Eviction is that same destruction, aimed by age. It preferentially kills
    the OLDEST pending pairing, which is the customer who has already
    completed identity verification on their phone and is waiting for the
    browser's next poll. They would see the browser hang and fail with no
    explanation, and would have to repeat the verification. Refusal instead
    falls on whoever tries to START a pairing while the store is full, is
    loud, is symmetric between attacker and customer, leaves every in-flight
    pairing untouched, and heals by itself as codes age out.

    So the cost of this choice, stated plainly: a caller who can fill the
    store can stop new pairings. That is a denial of service, and it is the
    bounded-memory one that this cap trades the unbounded-memory one for.
    """

    def __init__(self, held: int, cap: int) -> None:
        super().__init__(f"device code store holds {held} codes, at its cap of {cap}")
        self.held = held
        self.cap = cap


# ---------------------------------------------------------------------------
# DeviceCode — the core model.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DeviceCode:
    """An RFC 8628 device authorization session.

    All fields come from the spec or are extensions needed by Postern's
    QR pairing flow.

    Attributes:
        device_code: Opaque 40+ char code the browser exchanges at /token.
        user_code: Human-readable pairing code (6 chars, shown as XXX-XXX).
        verification_uri: URI the user visits on mobile (e.g. auth page).
        expires_at: When this device code expires (UTC).
        interval: Seconds between token polls (default 5).
        client_id: OAuth client identifier, as supplied at
            ``/device_authorization``. Caller-controlled and never an
            identity: it stays what the request said it was for the whole
            life of the code.
        scopes: Space-separated scope list from the request.
        approved: Whether mobile app has approved this session.
        approved_at: When approval happened (None until approved).
        customer_ref: The customer this code was approved FOR, taken from the
            verified ``sub`` of the banking app's assertion at approval time
            and from nowhere else. Empty until approved.
        user_code_attempts: Failed ``user_code`` comparisons at ``/approve``.
        exchanged_at: When this code was spent at ``POST /token``, or ``None``
            while it is still redeemable. Written only by
            ``consume_device_code`` below, which is the atomic claim the mint
            sits behind, and never cleared.

    ``exchanged_at`` IS WHY A SPENT CODE IS STILL HERE. The alternative was
    revoking the code on a successful exchange, which is one fewer field and
    frees a slot against the cap; it was rejected because the store row is
    what a replay is recorded AGAINST. Delete the row and a second exchange is
    answered by ``token_endpoint``'s unknown-code branch, which runs before
    any identity is read, so the attempt that most deserves an ``audit_log``
    row is the one that cannot have one.
    ``dev-docs/decisions/0012-device-code-single-use.md`` carries the
    reasoning, and ``services/confirm/audit.py``'s ``_arguments`` carries the
    other half: a device code handle "joins to" the code "while it lives".

    ``customer_ref`` used to be ``client_id``, reused for two purposes: the
    OAuth client id before approval and the customer reference after it. That
    overload was the enabling half of audit finding C-01. It meant the value
    ``/token`` minted a token from was a field a caller had populated at
    ``/device_authorization``, so a caller who sent ``client_id=cust_victim``
    and then reached any state where approval had been recorded but the
    identity had not yet been overwritten got a token for ``cust_victim``.
    Separate fields close that: ``/token`` reads ``customer_ref``, which no
    request body can reach and which only a verified approval ever sets, and
    a half-written approval therefore mints nothing at all.
    """

    device_code: str
    user_code: str
    verification_uri: str
    expires_at: datetime
    interval: int = 5
    client_id: str = ""
    scopes: str = ""
    approved: bool = False
    approved_at: datetime | None = None
    customer_ref: str = ""
    user_code_attempts: int = 0
    exchanged_at: datetime | None = None

    @property
    def user_code_display(self) -> str:
        """Return the pairing code as XXX-XXX for display."""
        if len(self.user_code) >= 6:
            return f"{self.user_code[:3]}-{self.user_code[3:6]}"
        return self.user_code

    @property
    def is_expired(self) -> bool:
        """Whether this device code has passed its expiry."""
        return datetime.now(UTC) >= self.expires_at

    @property
    def verification_uri_complete(self) -> str:
        """Verification URI with user_code as query parameter for deep-linking."""
        separator = "&" if "?" in self.verification_uri else "?"
        return f"{self.verification_uri}{separator}user_code={self.user_code}"

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return _json.dumps(_device_code_to_dict(self))

    @classmethod
    def from_json(cls, data: str) -> DeviceCode:
        """Deserialize from JSON string."""
        return _device_code_from_dict(_json.loads(data))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict."""
        return _device_code_to_dict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceCode:
        """Deserialize from a plain dict."""
        return _device_code_from_dict(data)


# ---------------------------------------------------------------------------
# Abstract base class — the interface all backends must implement.
# ---------------------------------------------------------------------------


class DeviceCodeStoreBase(ABC):
    """Abstract base class for device code stores.

    All backends (in-memory, Redis) must implement these methods.
    The factory ``create_device_code_store()`` returns the appropriate
    implementation based on environment configuration.

    All methods are async — even the in-memory store uses ``async def`` so
    callers can uniformly ``await store.xxx()`` regardless of backend.
    """

    @abstractmethod
    async def create_device_code(
        self,
        *,
        client_id: str,
        scopes: str,
        verification_uri: str,
        expires_in: int = 900,
        interval: int = 5,
    ) -> DeviceCode:
        """Create a new device code session and return it.

        Every backend must first drop what has expired and then refuse with
        `DeviceCodeStoreFull` if it still holds ``max_codes``. Sweeping first
        is not an optimisation: an expired code is one no caller can use, so
        refusing a pairing while holding a store full of them would be a
        denial of service performed on this service's behalf by its own
        bookkeeping.
        """

    @abstractmethod
    async def get_device_code(self, device_code: str) -> DeviceCode | None:
        """Look up a device code by its opaque value, or ``None``."""

    @abstractmethod
    async def approve_device_code(self, device_code: str) -> bool:
        """Mark a device code as approved. Returns True if found and updated."""

    @abstractmethod
    async def consume_device_code(self, device_code: str) -> bool:
        """Claim a device code for one token exchange. ``True`` to one caller only.

        Sets ``exchanged_at`` on a code that has none and answers ``True``;
        answers ``False`` for a code this store does not hold and for one
        already spent. The code is MARKED, never removed -- see
        ``DeviceCode.exchanged_at`` for why the row has to survive.

        MUST BE ATOMIC, and this line is the whole contract rather than a
        preference. The caller is `services/confirm/device_auth.py`'s
        ``token_endpoint``, which mints a read token only for the caller that
        wins here. A backend that read the code, awaited anything, and then
        wrote would answer ``True`` to every request in a concurrent burst,
        which is the defect this method exists to close in a form that needs
        two sockets instead of two minutes. Both implementations below say how
        they hold it, and they hold it differently: one never yields, the other
        makes the server settle it.

        A LOST CLAIM IS NOT ROLLED BACK ANYWHERE. Whatever fails after a
        successful claim -- the signing key, the audit store -- leaves the code
        spent and the customer re-pairing from a fresh QR. That is the
        direction ``services/confirm/device_auth.py``'s ``_withdraw_pairing``
        already chose for the endpoint before this one.
        """

    @abstractmethod
    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code (e.g. on explicit cancellation)."""

    @abstractmethod
    async def update_device_code(self, device_code: str, code: DeviceCode) -> None:
        """Replace a device code with an updated version.

        Used by the approval callback to attach the customer identity
        (``customer_ref``, from the verified assertion) after the user
        approves on mobile, and to record a failed ``user_code`` comparison.
        """


# ---------------------------------------------------------------------------
# In-memory backend (default for dev / test).
# ---------------------------------------------------------------------------


def _generate_device_code() -> str:
    """Generate a cryptographically random device code (40+ chars)."""
    return secrets.token_urlsafe(32)  # 43 chars


def _generate_user_code() -> str:
    """Generate a 6-char alphanumeric user code (pairing code)."""
    # RFC 8628 §3.1: user codes are case-insensitive, 6+ chars,
    # all upper-case letters and digits only.
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # no ambiguous chars
    return "".join(secrets.choice(alphabet) for _ in range(6))


class InMemoryDeviceCodeStore(DeviceCodeStoreBase):
    """In-memory store mapping ``device_code`` → ``DeviceCode``.

    Thread-safe enough for FastMCP's in-process test client (single-threaded
    async). Not safe across processes — use ``RedisDeviceCodeStore`` for that.

    Methods are ``async def`` so callers can uniformly ``await store.xxx()``
    regardless of which backend the factory returned.

    UNTIL 2026-09-24 THIS STORE NEVER DROPPED ANYTHING. It has no TTL of its
    own -- the 900-second lifetime described everywhere else in this module is
    ``SETEX`` on the Redis backend, and was never a property of this one. The
    only removals were `revoke_device_code`, reached when a ``POST /token``
    poll happens to find a code expired, or after three wrong pairing codes at
    ``POST /approve``. So a caller who created codes and never polled leaked
    them for the life of the process, not for fifteen minutes. Measured: a
    code created with ``expires_in=1`` still sat in ``_codes`` after it
    reported ``is_expired`` true.

    ``_expiry`` is the reaper that closes it: a heap of
    ``(expiry timestamp, device_code)`` swept on create. Lazy deletion, so a
    code that was revoked or re-indexed leaves a stale heap entry that is
    discarded when it surfaces -- which is why `_drop_expired` re-reads the
    dict rather than trusting the heap. The heap is therefore bounded by the
    codes created in one TTL window rather than by the codes alive now, and
    that bound is what the rate limit and the cap together make finite.
    """

    def __init__(self, max_codes: int = DEFAULT_MAX_DEVICE_CODES) -> None:
        self._codes: dict[str, DeviceCode] = {}
        #: Min-heap of ``(expiry timestamp, device_code)``. See `_drop_expired`.
        self._expiry: list[tuple[float, str]] = []
        self._max_codes = max_codes

    def _drop_expired(self) -> int:
        """Remove every code whose expiry has passed, and say how many.

        Pops the heap while its head is due. Three cases per entry, and the
        dict is the authority in all three: the code is gone already (a stale
        entry from a revocation, discarded), the code carries a LATER expiry
        than this entry claims (a stale entry from a re-index, discarded), or
        it is genuinely due (deleted). Stopping at the first entry that is not
        yet due is what keeps the common case O(1) instead of O(n) per
        creation -- an O(n) sweep on a public endpoint would be its own
        amplification, ~10,000 comparisons per request at the cap.
        """
        now = datetime.now(UTC).timestamp()
        dropped = 0
        while self._expiry and self._expiry[0][0] <= now:
            expires_ts, device_code = heapq.heappop(self._expiry)
            existing = self._codes.get(device_code)
            if existing is None or existing.expires_at.timestamp() > expires_ts:
                continue
            del self._codes[device_code]
            dropped += 1
        if dropped:
            logger.info("device code store: swept %d expired codes", dropped)
        return dropped

    async def create_device_code(
        self,
        *,
        client_id: str,
        scopes: str,
        verification_uri: str,
        expires_in: int = 900,
        interval: int = 5,
    ) -> DeviceCode:
        """Create a new device code session and return it.

        Raises:
            DeviceCodeStoreFull: if the store still holds ``max_codes`` after
                expired codes have been swept.
        """
        self._drop_expired()
        if len(self._codes) >= self._max_codes:
            raise DeviceCodeStoreFull(len(self._codes), self._max_codes)
        device_code = _generate_device_code()
        user_code = _generate_user_code()
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        code = DeviceCode(
            device_code=device_code,
            user_code=user_code,
            verification_uri=verification_uri,
            expires_at=expires_at,
            interval=interval,
            client_id=client_id,
            scopes=scopes,
        )
        self._codes[device_code] = code
        heapq.heappush(self._expiry, (expires_at.timestamp(), device_code))
        return code

    async def get_device_code(self, device_code: str) -> DeviceCode | None:
        """Look up a device code by its opaque value, or ``None``.

        Deliberately NOT expiry-filtered, because the callers depend on
        getting an expired code back: `services/confirm/device_auth.py`'s
        ``token_endpoint`` reads ``is_expired`` to answer RFC 8628 §3.5's
        ``expired_token``, and returning ``None`` here would turn that into
        ``invalid_grant``, which tells a legitimate browser its code was never
        real rather than that it timed out. The reaper is a bound on memory,
        not a second authority on what is valid.
        """
        return self._codes.get(device_code)

    async def approve_device_code(self, device_code: str) -> bool:
        """Mark a device code as approved. Returns True if found and updated."""
        existing = self._codes.get(device_code)
        if existing is None or existing.approved:
            return False
        # Dataclass is frozen, so we replace with a new instance.
        self._codes[device_code] = existing.__class__(
            **{**asdict_frozen(existing), "approved": True, "approved_at": datetime.now(UTC)}
        )
        return True

    async def consume_device_code(self, device_code: str) -> bool:
        """Claim this code for one exchange. ``True`` to one caller only.

        ATOMIC BY NOT YIELDING, which is the whole implementation and is worth
        naming because it is invisible. There is no ``await`` between the read
        and the write, so no other task can run between them: a coroutine only
        suspends at a point that actually yields to the loop, and a dict
        lookup, a comparison and a dict assignment are none. Put an ``await``
        of any kind inside this method and two concurrent polls both see an
        unspent code and both mint.
        """
        existing = self._codes.get(device_code)
        if existing is None or existing.exchanged_at is not None:
            return False
        self._codes[device_code] = existing.__class__(
            **{**asdict_frozen(existing), "exchanged_at": datetime.now(UTC)}
        )
        return True

    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code."""
        self._codes.pop(device_code, None)

    async def update_device_code(self, device_code: str, code: DeviceCode) -> None:
        """Replace a device code with an updated version."""
        self._codes[device_code] = code


def asdict_frozen(obj: Any) -> dict[str, Any]:
    """Convert a frozen dataclass to a mutable dict."""

    if not dataclasses.is_dataclass(obj):
        raise TypeError(f"Expected a dataclass, got {type(obj).__name__}")
    return {f.name: getattr(obj, f.name) for f in dataclasses.fields(obj)}


# ---------------------------------------------------------------------------
# Redis backend — compatible with AWS ElastiCache, Google Memorystore, etc.
# ---------------------------------------------------------------------------

#: How many times ``RedisDeviceCodeStore.consume_device_code`` re-reads a key
#: another writer moved under its ``WATCH`` before it gives up and refuses.
#:
#: WHY IT IS BOUNDED AT ALL. An unbounded retry on a contended key is a spin
#: loop against the one Redis both replicas share, driven by whoever is
#: replaying the code. Three is generous against the only contention that
#: exists at exchange time, which is other consumers: a competing claim that
#: wins writes ``exchanged_at``, so the next read answers ``False`` and
#: returns rather than retrying. Reaching this bound means three writers each
#: beat this one, and the approval that also writes this key has already
#: happened by the time any of them arrives.
#:
#: EXHAUSTION REFUSES, and that is the fail-closed direction: a claim this
#: store could not establish must not mint a token. What the caller is told is
#: `services/confirm/device_auth.py`'s ``invalid_grant``, which is true of a
#: code some other request has by then almost certainly spent.
_CLAIM_ATTEMPTS = 3


class RedisDeviceCodeStore(DeviceCodeStoreBase):
    """Redis-backed device code store.

    Compatible with any Redis-compatible service: AWS ElastiCache for
    Redis, Google Memorystore for Redis, Azure Cache for Redis, or a
    self-hosted Redis instance.

    Device codes are stored as JSON with a TTL matching the code's expiry.
    The ``expires_at`` field is a POSIX timestamp, so codes survive process
    restarts.

    Configuration via environment variables:

    ``POSTERN_REDIS_URL``
        Redis connection string, e.g. ``redis://localhost:6379/0`` or
        ``rediss://user:pass@host:port/0`` (TLS).

    ``POSTERN_REDIS_DEVICE_CODE_TTL``
        Default TTL in seconds for new device codes (default 900 = 15 min).
        Read only when the ``default_ttl`` argument is ``None``, and refused
        below `MIN_DEVICE_CODE_TTL_SECONDS` -- the same floor
        `services/confirm/settings.py` puts under
        ``POSTERN_DEVICE_CODE_TTL_SECONDS``, because the two variables set
        the lifetime of the same object.

    ``POSTERN_REDIS_KEY_PREFIX``
        Key prefix for multi-tenant deployments (default ``"postern:"``).

    Usage::

        store = RedisDeviceCodeStore()
        code = await store.create_device_code(
            client_id="my-client", scopes="accounts:read"
        )
        existing = await store.get_device_code(code.device_code)  # DeviceCode | None
    """

    def __init__(
        self,
        url: str | None = None,
        default_ttl: int | None = None,
        key_prefix: str | None = None,
        max_codes: int = DEFAULT_MAX_DEVICE_CODES,
    ) -> None:
        import redis.asyncio as redis

        self._url = url or os.environ.get("POSTERN_REDIS_URL", "redis://localhost:6379/0")
        # ``default_ttl or int(os.environ.get(...))`` until 2026-09-25. It
        # crashed on ``POSTERN_REDIS_DEVICE_CODE_TTL=`` with a message naming
        # neither the variable nor this class, took zero and negatives without
        # comment -- and at 1 walked straight into B1, because this value
        # becomes ``create_device_code``'s ``expires_in`` and ``_set_code``
        # truncates it to nothing. `MIN_DEVICE_CODE_TTL_SECONDS` above carries
        # the measurement. It also discarded an explicitly passed ``0`` in
        # favour of the environment; `postern_core.config`'s `int_arg_or_env`
        # refuses it instead and says why.
        self._default_ttl = int_arg_or_env(
            default_ttl,
            parameter="default_ttl",
            name="POSTERN_REDIS_DEVICE_CODE_TTL",
            # 900, unchanged: the same literal the bare `int()` defaulted to
            # and the same lifetime `InMemoryDeviceCodeStore.create_device_code`
            # carries in its signature.
            default=900,
            minimum=MIN_DEVICE_CODE_TTL_SECONDS,
            because=(
                "It is the lifetime a device code gets when create_device_code is called "
                "without an expires_in, and a shorter one cannot outlive the browser's "
                "poll interval or the user's approval on their phone; at 1 second the "
                "store's truncation discards the code without storing it at all."
            ),
        )
        self._prefix = key_prefix or os.environ.get("POSTERN_REDIS_KEY_PREFIX", "postern:")
        self._max_codes = max_codes
        self._redis: Any = redis.from_url(  # type: ignore[no-untyped-call]
            self._url,
            decode_responses=True,
        )

    def _key(self, device_code: str) -> str:
        """Build the Redis key for a device code."""
        return f"{self._prefix}device:{device_code}"

    def _index_key(self) -> str:
        """The sorted set indexing live device codes by expiry.

        WHY AN INDEX AND NOT A COUNTER. A counter cannot cap a keyspace whose
        members expire on their own: ``SETEX`` removes the value without
        decrementing anything, so the counter would drift up and eventually
        refuse every pairing with an empty store behind it. A sorted set
        scored by expiry is the standard shape and answers both questions
        this cap needs -- ``ZREMRANGEBYSCORE`` drops what is due and
        ``ZCARD`` counts what is left -- which is also why this backend gets
        a reaper for free rather than leaving expired members to
        ``maxmemory`` eviction choosing victims at random.

        WHY NOT ``DBSIZE`` OR ``SCAN``. Both count a whole database this
        service may share with `postern_core.risk.session` and
        `postern_core.auth.revocation`, which use the same
        ``POSTERN_REDIS_URL`` by design, so either would cap device codes
        against other subsystems' keys. ``SCAN`` is also O(keyspace) on a
        public endpoint.
        """
        return f"{self._prefix}device:index"

    async def create_device_code(
        self,
        *,
        client_id: str,
        scopes: str,
        verification_uri: str,
        expires_in: int | None = None,
        interval: int = 5,
    ) -> DeviceCode:
        """Create a new device code session and return it.

        Raises:
            DeviceCodeStoreFull: if the index still holds ``max_codes`` after
                due members have been dropped.

        THE CHECK IS NOT ATOMIC WITH THE WRITE, and that is accepted rather
        than overlooked. Two replicas can both read a count under the cap and
        both add, so the store can exceed it by roughly the number of
        concurrent creations. A cap is a bound on standing memory, not an
        invariant on a ledger, and paying for exactness here would mean a Lua
        script or a ``WATCH`` retry loop on the one endpoint in this service
        that an unauthenticated caller can reach at will. Over-admitting a
        handful of 2 KB rows is cheaper than either.
        """
        now = datetime.now(UTC).timestamp()
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(self._index_key(), "-inf", now)
        pipe.zcard(self._index_key())
        dropped, held = await pipe.execute()
        if dropped:
            logger.info("device code store: swept %d expired codes", dropped)
        if held >= self._max_codes:
            raise DeviceCodeStoreFull(int(held), self._max_codes)

        device_code = _generate_device_code()
        user_code = _generate_user_code()
        expires_in = expires_in or self._default_ttl
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        code = DeviceCode(
            device_code=device_code,
            user_code=user_code,
            verification_uri=verification_uri,
            expires_at=expires_at,
            interval=interval,
            client_id=client_id,
            scopes=scopes,
        )
        await self._set_code(device_code, code)
        return code

    async def get_device_code(self, device_code: str) -> DeviceCode | None:
        """Look up a device code by its opaque value, or ``None``."""
        data = await self._redis.get(self._key(device_code))
        if data is None:
            return None
        try:
            return DeviceCode.from_json(data)
        except (KeyError, ValueError, TypeError) as exc:  # pragma: no cover
            logger.warning("Failed to deserialize device code %s: %s", device_code, exc)
            return None

    async def approve_device_code(self, device_code: str) -> bool:
        """Mark a device code as approved. Returns True if found and updated."""
        existing = await self.get_device_code(device_code)
        if existing is None or existing.approved:
            return False
        updated = DeviceCode(
            **{**asdict_frozen(existing), "approved": True, "approved_at": datetime.now(UTC)}
        )
        await self._set_code(device_code, updated)
        return True

    async def consume_device_code(self, device_code: str) -> bool:
        """Claim this code for one exchange. ``True`` to one caller only.

        ATOMIC BY MAKING THE SERVER SETTLE IT, which is the only place that can
        settle it: two replicas share one Redis by design, so no lock either
        process holds is a bound on the other. ``WATCH`` the key, read it,
        queue the write in a ``MULTI``, and ``EXEC`` fails if anything touched
        the key in between -- including its own expiry, which Redis counts as a
        modification. The loser retries, reads the ``exchanged_at`` the winner
        wrote, and answers ``False``.

        NOT ``_set_code``, and the difference is two defects rather than a
        style. That helper recomputes the TTL as ``int((expires_at - now))``
        and truncates, so routing the claim through it would shorten every
        code it marked by up to a second (bug B1's arithmetic, one call site
        further on); and it re-``ZADD``s an index score that has not changed.
        ``KEEPTTL`` keeps the server's own remaining time and leaves the index
        alone, which is correct because spending a code does not move its
        expiry.

        A CORRUPT STORED VALUE ANSWERS ``False``, matching
        ``get_device_code``'s choice one method up: a code this store cannot
        deserialize is a code ``token_endpoint`` must not mint against, and
        refusing the claim is how that is said here.
        """
        from redis.exceptions import WatchError

        key = self._key(device_code)
        for _ in range(_CLAIM_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        return False
                    try:
                        code = DeviceCode.from_json(raw)
                    except (KeyError, ValueError, TypeError):
                        logger.warning(
                            "refusing to claim device code %s: its stored value will not "
                            "deserialize",
                            device_code,
                        )
                        return False
                    if code.exchanged_at is not None:
                        return False
                    spent = DeviceCode(**{**asdict_frozen(code), "exchanged_at": datetime.now(UTC)})
                    pipe.multi()
                    pipe.set(key, spent.to_json(), keepttl=True)
                    await pipe.execute()
                    return True
                except WatchError:
                    continue
        logger.warning(
            "refusing to claim device code %s: %d attempts were each beaten by another "
            "writer on the same key",
            device_code,
            _CLAIM_ATTEMPTS,
        )
        return False

    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code, and its index member with it.

        Both, or the cap counts codes that no longer exist and a service that
        revokes normally would refuse pairings it has room for.
        """
        pipe = self._redis.pipeline()
        pipe.delete(self._key(device_code))
        pipe.zrem(self._index_key(), device_code)
        await pipe.execute()

    async def update_device_code(self, device_code: str, code: DeviceCode) -> None:
        """Replace a device code with an updated version."""
        await self._set_code(device_code, code)

    async def _set_code(self, device_code: str, code: DeviceCode) -> None:
        """Store a device code with TTL, and index it by the same expiry.

        ``ZADD`` on every write and not only on creation, so an update
        re-scores rather than leaving the index holding an older expiry than
        the value it points at. Both are skipped when the TTL has already
        passed, which is the existing behaviour for the value and keeps the
        index from gaining a member that is due the moment it lands.

        THE ``int`` BELOW TRUNCATES, AND THAT IS STILL TRUE (bug B1). It
        loses up to one whole second, so a code asked for one second has
        roughly 0.9999 left by the time the line runs, floors to zero, and
        the guard skips BOTH writes. ``create_device_code`` then returns a
        `DeviceCode` this store never wrote, ``get_device_code`` answers
        ``None`` for it immediately, and `InMemoryDeviceCodeStore` stores
        that same code -- so the two backends disagree at the boundary.
        Measured 2026-09-25 against redis:7-alpine: ``expires_in=1`` stores
        nothing, ``expires_in=2`` stores a TTL of 1, ``expires_in=900``
        stores 899.

        WHAT WAS FIXED IS THE CONFIGURATION PATHS ONLY, and there were two
        of them rather than the one this paragraph claimed until 2026-09-25.
        `MIN_DEVICE_CODE_TTL_SECONDS` above refuses both, and
        `services/confirm/settings.py`'s `MIN_DEVICE_CODE_TTL_SECONDS`
        imports it rather than carrying a second 30. The two paths are a
        ``POSTERN_DEVICE_CODE_TTL_SECONDS`` below 30, which arrives here as
        the ``expires_in`` `services/confirm/device_auth.py` passes, and a
        ``POSTERN_REDIS_DEVICE_CODE_TTL`` below 30, which arrives at the same
        argument through ``_default_ttl`` whenever a caller passes none.
        What still reaches the truncation is any direct caller of
        ``create_device_code`` passing a small enough ``expires_in``, which
        in this tree means this repository's own tests --
        tests/test_redis_backed_stores.py::SHORTEST_STORED_TTL exists
        precisely because of it.

        NO GUARD IS RAISED HERE, deliberately. This method has three callers
        and a zero TTL means a different thing in each: from
        ``create_device_code`` it is a caller asking for a lifetime that
        cannot be represented, but from ``approve_device_code`` and
        ``update_device_code`` it is an ordinary race -- a customer who was
        slow, whose code expired while they approved -- and turning that into
        an exception would fail an approval on the write path for being
        late. Nothing available here tells the two apart. Raising in
        ``create_device_code`` instead, where they CAN be told apart, would
        make this backend refuse a lifetime `InMemoryDeviceCodeStore`
        accepts, which does not end the disagreement between them, it only
        moves it from the outcome to the control flow and puts it in
        `DeviceCodeStoreBase`'s contract, where no in-memory test can reach
        it. Ending it properly means changing the arithmetic in BOTH
        backends, which changes the expiry of every device code, and that is
        a separate decision from putting a floor under a setting.
        """
        ttl_seconds = max(0, int((code.expires_at - datetime.now(UTC)).total_seconds()))
        if ttl_seconds > 0:
            pipe = self._redis.pipeline()
            pipe.setex(self._key(device_code), ttl_seconds, code.to_json())
            pipe.zadd(self._index_key(), {device_code: code.expires_at.timestamp()})
            await pipe.execute()

    async def close(self) -> None:
        """Close the Redis connection pool."""
        await self._redis.aclose()


# ---------------------------------------------------------------------------
# Serialization helpers — add to DeviceCode dataclass.
# ---------------------------------------------------------------------------


def _device_code_to_dict(dc: DeviceCode) -> dict[str, Any]:
    """Serialize a DeviceCode to a plain dict."""
    return {
        "device_code": dc.device_code,
        "user_code": dc.user_code,
        "verification_uri": dc.verification_uri,
        "expires_at": dc.expires_at.timestamp(),
        "interval": dc.interval,
        "client_id": dc.client_id,
        "scopes": dc.scopes,
        "approved": dc.approved,
        "approved_at": dc.approved_at.timestamp() if dc.approved_at else None,
        "customer_ref": dc.customer_ref,
        "user_code_attempts": dc.user_code_attempts,
        "exchanged_at": dc.exchanged_at.timestamp() if dc.exchanged_at else None,
    }


def _device_code_from_dict(data: dict[str, Any]) -> DeviceCode:
    """Deserialize a DeviceCode from a plain dict."""
    approved_at = None
    if data.get("approved_at") is not None:
        approved_at = datetime.fromtimestamp(data["approved_at"], tz=_UTC)
    exchanged_at = None
    if data.get("exchanged_at") is not None:
        exchanged_at = datetime.fromtimestamp(data["exchanged_at"], tz=_UTC)
    return DeviceCode(
        device_code=data["device_code"],
        user_code=data["user_code"],
        verification_uri=data["verification_uri"],
        expires_at=datetime.fromtimestamp(data["expires_at"], tz=_UTC),
        interval=data.get("interval", 5),
        client_id=data.get("client_id", ""),
        scopes=data.get("scopes", ""),
        approved=bool(data.get("approved", False)),
        approved_at=approved_at,
        # `.get` with a default, not `data[...]`: a Redis-backed store can be
        # holding codes serialized by the previous release when this one rolls
        # out, and a `KeyError` there would fail every in-flight device grant.
        # Defaulting `customer_ref` to "" is the fail-closed direction -- an
        # old code deserializes with no identity, so `/token` refuses it
        # rather than minting from a stale `client_id`.
        customer_ref=str(data.get("customer_ref", "")),
        user_code_attempts=int(data.get("user_code_attempts", 0)),
        # ``None`` when the key is absent, and here that default is the TRUE
        # reading rather than the fail-closed one: a record written by the
        # previous release came from a build that could not spend a code, so
        # it had not. The two directions differ on purpose -- ``customer_ref``
        # above defaults to empty so an old record mints nothing, while an old
        # record here stays redeemable for the rest of its 900-second life.
        exchanged_at=exchanged_at,
    )


# ---------------------------------------------------------------------------
# Factory — picks the right backend based on environment.
# ---------------------------------------------------------------------------


def create_device_code_store(
    max_codes: int = DEFAULT_MAX_DEVICE_CODES,
) -> DeviceCodeStoreBase:
    """Create a device code store backed by the configured backend.

    Reads ``POSTERN_REDIS_URL``: if set, returns a
    ``RedisDeviceCodeStore``; otherwise returns an ``InMemoryDeviceCodeStore``.

    ``max_codes`` is passed to whichever backend is chosen, so the cap holds
    in both. It is an argument rather than another environment variable read
    in here because `services/confirm/settings.py` owns this service's
    configuration and a caller reading the same value from two places is how
    the two drift.

    This is the recommended entry point for production code:

    .. code-block:: python

        store = create_device_code_store()  # auto-selects backend
    """
    redis_url = os.environ.get("POSTERN_REDIS_URL")
    if redis_url:
        logger.info("Using Redis device code store (url=%s)", redis_url)
        return RedisDeviceCodeStore(url=redis_url, max_codes=max_codes)
    logger.info("Using in-memory device code store (set POSTERN_REDIS_URL for Redis)")
    return InMemoryDeviceCodeStore(max_codes=max_codes)


# ---------------------------------------------------------------------------
# Backwards-compatible alias.
# ---------------------------------------------------------------------------

#: Alias for ``InMemoryDeviceCodeStore`` — kept so existing imports work.
#: New code should use :func:`create_device_code_store` instead.
DeviceCodeStore = InMemoryDeviceCodeStore

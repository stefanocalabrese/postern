"""RFC 8628 Device Authorization Grant — device codes and storage.

Provides the ``DeviceCode`` model and a pluggable ``DeviceCodeStore`` backed
by either an in-memory dict (dev / test) or Redis (production — compatible
with AWS ElastiCache, Google Memorystore, Azure Cache for Redis, or any
Redis-compatible service).

The device authorization flow (§7.3 of the handoff):

1. Browser calls ``/device_authorization`` and gets a device code, a
   user-visible pairing code (6 chars) and ``verification_uri_complete``,
   the pairing page keyed by the code's display handle.
2. The page shows the pairing code and a QR that encodes the operator's app
   link with the ``user_code`` and a rotation token; ``device_code`` is in
   neither.
3. The bank app scans it and calls ``POST /scan``, which records the first
   scanning customer by compare-and-set (``claim_scan``).
4. The user compares the pairing codes and completes identity verification;
   the app calls ``POST /approve`` with the ``user_code``, which approves by
   compare-and-set only for the customer who scanned (``approve_scanned``).
5. After approval, the browser polls ``/token`` with
   ``grant_type=device_code`` to receive a layer-1 session, and the code is
   spent with the session's family id (``consume_device_code``).

The pairing code (``user_code``) carries the anti-phishing control for
A2 (QR relay), and it is worth being precise about which half lives where,
because the two halves are not interchangeable:

- The HUMAN half is the control against a relayed QR. The user compares the
  code their own trusted screen shows against the code the app shows, and
  refuses if they differ. That comparison happens on the operator's app
  pairing screen, which is not in this repository and is still an open
  question (handoff §10.10). Nothing here can perform it or verify that it
  happened.
- The SERVER half is the scan. A code can be approved only by the customer
  whose app scanned it with a genuine, current rotation token, and a second
  customer's scan of an unexchanged code ends the pairing. Guessing a
  ``user_code`` at ``POST /approve`` therefore approves nothing the same
  customer did not scan first. It does NOT detect a relay, because a
  relaying attacker who shows the victim the attacker's own page holds a
  genuine QR; ``dev-docs/qr-page-spec.md`` says so in "What this does not
  fix".

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

import base64
import dataclasses
import enum
import heapq
import json as _json
import os
import secrets
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from datetime import UTC as _UTC
from typing import Any

from postern_core.config import int_arg_or_env, redis_url_from_env

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
    code. Eviction would let an unauthenticated caller end another customer's
    pairing in flight simply by filling the store, and nothing else on this
    path lets a party without an assertion do that.

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


class DeviceCodeStoreContended(RuntimeError):
    """A store operation that could not settle after a bounded number of tries.

    Two sources, both of which refuse rather than loop. A secondary key --
    the ``user_code`` or the display handle -- whose freshly generated value
    was already taken on every one of ``_SECONDARY_KEY_ATTEMPTS`` tries, which
    at 32**6 pairing codes against a 10,000-code cap means something is wrong
    with the generator rather than unlucky. And a compare-and-set whose
    ``WATCH`` was beaten on every one of ``_CLAIM_ATTEMPTS`` tries.

    RAISED RATHER THAN ANSWERED ``False``, where ``consume_device_code``
    answers ``False``. Its caller maps ``False`` onto a response that is true
    whichever way the race went; ``claim_scan`` and ``approve_scanned`` have
    callers that would have to invent a reason, and the handlers record an
    exception's type name in ``audit_log.detail`` already, which is the true
    statement: the store could not decide.
    """


#: How many freshly generated values a secondary key gets before
#: `DeviceCodeStoreContended`. Five is generous: a collision needs a live
#: pairing already holding the same six-character code or 128-bit handle.
_SECONDARY_KEY_ATTEMPTS = 5


class ScanClaim(enum.Enum):
    """What ``claim_scan`` found and did, in one transaction.

    Exactly one per call. ``POST /scan`` maps each onto a response and an
    ``audit_log.detail``; the mapping lives there, and this type says only
    what happened to the row.
    """

    #: ``scanned_by`` was empty and the code unexpired and unapproved. It now
    #: names this customer, with ``scanned_at`` set.
    CLAIMED = "claimed"
    #: This customer already holds the scan and the code is unapproved.
    #: Nothing written. A retried ``POST /scan`` inside the token window.
    ALREADY_MINE = "already_mine"
    #: This customer holds the scan and has approved. Nothing written.
    APPROVED_MINE = "approved_mine"
    #: Another customer holds the scan and the code was never exchanged. The
    #: pairing is revoked in the same transaction: the session-swap defence.
    CONFLICT_REVOKED = "conflict_revoked"
    #: Another customer holds the scan and the code was already exchanged.
    #: Nothing written here, because revoking a spent code recalls nothing:
    #: ``POST /scan`` recalls the session the exchange issued instead, through
    #: the ``session_id`` the exchange wrote on the row.
    CONFLICT_EXCHANGED = "conflict_exchanged"
    #: The row is missing or expired.
    GONE = "gone"


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
        exchanged_at: When this code was spent at ``POST /token``, or ``None``
            while it is still redeemable. Written only by
            ``consume_device_code`` below, which is the atomic claim the mint
            sits behind, and never cleared.
        display_handle: 128 random bits, base64url. Keys the browser's
            pairing page, its QR image and its state endpoint, and is useless
            at ``POST /token``. Empty on a record written before it existed,
            which no page can then find.
        qr_secret: 32 random bytes, the per-pairing HMAC key for the QR's
            rotation token (``services/confirm/qr_token.py``). Never leaves
            the store and never appears in ``repr``. Empty on an older
            record, which is therefore unscannable -- the safe direction.
        creator_ip: The address ``POST /device_authorization`` came from.
            Read by ``POST /scan``, which compares it with the scanning
            request's address and records only the relation on its audit
            row. Lives here and nowhere else, so it is gone when the row is.
        scanned_by: The customer whose app scanned first, from a verified
            assertion ``sub`` at ``POST /scan``. Empty until scanned.
        scanned_at: When that scan was claimed.
        scanner_ip: The address of the ``POST /scan`` request that claimed
            the pairing, written in the same compare-and-set as
            ``scanned_by`` and ``scanned_at`` and never after. ``None`` until
            scanned, and on a record the previous release wrote, which
            recorded no scanner address. Recorded only; nothing reads it back.
        session_id: The refresh family ``POST /token`` created for this code,
            written by ``consume_device_code`` in the same compare-and-set as
            ``exchanged_at``. ``POST /scan`` reads it to recall a family a
            session swap produced. Empty until exchanged, and on a record an
            earlier release wrote.

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
    exchanged_at: datetime | None = None
    display_handle: str = ""
    qr_secret: bytes = field(default=b"", repr=False)
    creator_ip: str | None = None
    scanned_by: str = ""
    scanned_at: datetime | None = None
    scanner_ip: str | None = None
    session_id: str = ""

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
        """The pairing page's URI: ``verification_uri`` plus ``d=<display_handle>``.

        RFC 8628 section 3.3.1 lets the complete URI carry the ``user_code``
        "or other information with the same function"; the display handle is
        that other information. It is not the ``user_code`` because a URL
        keyed by a 30-bit code on a public endpoint is an enumeration oracle,
        and it is never the ``device_code``, the one credential ``POST
        /token`` asks for.
        """
        separator = "&" if "?" in self.verification_uri else "?"
        return f"{self.verification_uri}{separator}d={self.display_handle}"

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
        creator_ip: str | None = None,
    ) -> DeviceCode:
        """Create a new device code session and return it.

        The code carries a fresh ``display_handle`` and ``qr_secret`` and the
        ``creator_ip`` it was given, and is unscanned.

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
    async def get_by_display_handle(self, display_handle: str) -> DeviceCode | None:
        """The live code this display handle keys, or ``None``.

        UNLIKE ``get_device_code``, EXPIRY-FILTERED: the page and the state
        endpoint answer an expired pairing exactly as an unknown one, and
        ``POST /scan`` answers both ``invalid_grant``. The lookup re-reads the
        primary and re-checks that its handle matches and that it has not
        expired, because on Redis the secondary key's TTL can outlive the
        primary's by up to a second under the truncation ``_set_code``
        records.
        """

    @abstractmethod
    async def get_by_user_code(self, user_code: str) -> DeviceCode | None:
        """The live code this stored-form pairing code keys, or ``None``.

        ``user_code`` is the six-character stored form; callers normalise
        first. Expiry-filtered and re-checked for the same reasons as
        ``get_by_display_handle``.
        """

    @abstractmethod
    async def consume_device_code(self, device_code: str, *, session_id: str) -> bool:
        """Claim a device code for one token exchange. ``True`` to one caller only.

        Sets ``exchanged_at`` and ``session_id`` on a code that has none, in
        one write, and answers ``True``;
        answers ``False`` for a code this store does not hold and for one
        already spent. The code is MARKED, never removed -- see
        ``DeviceCode.exchanged_at`` for why the row has to survive.

        MUST BE ATOMIC, and this line is the whole contract rather than a
        preference. The caller is `services/confirm/device_auth.py`'s
        ``token_endpoint``, which issues a session only to the caller that
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

        ``session_id`` IS REQUIRED, for the reason ``claim_scan`` gives for
        ``scanner_ip``: it is the refresh family ``POST /token`` created for
        this exchange, and ``POST /scan`` finds that family through it to
        recall a session swap. Written in the same write as ``exchanged_at``,
        so once a scan sees the code exchanged it sees the family too.
        """

    @abstractmethod
    async def claim_scan(
        self, device_code: str, customer_ref: str, *, scanner_ip: str | None
    ) -> ScanClaim:
        """Record the first scan of a code, or say why this one is not it.

        A COMPARE-AND-SET, modelled on ``consume_device_code``: one
        transaction reads the row, decides with ``_scan_verdict``, and writes
        only for ``CLAIMED`` (``scanned_by``, ``scanned_at``, ``scanner_ip``) and
        ``CONFLICT_REVOKED`` (the whole pairing, secondaries included). Every
        other result writes nothing. The same atomicity contract as
        ``consume_device_code`` holds, for the same reason: two phones
        scanning one QR on two replicas must not both win.

        ``scanner_ip`` IS REQUIRED AND NULLABLE, for the reason
        ``postern_core.store.audit.append`` gives for its ``client_id``: a
        default would let a future caller record "no address" for a scan that
        had one. First scan wins: ``ALREADY_MINE`` writes nothing, so a retry
        from another network does not move the address the claim was made from.

        Raises:
            DeviceCodeStoreContended: if the transaction could not settle.
        """

    @abstractmethod
    async def approve_scanned(self, device_code: str, customer_ref: str) -> bool:
        """Approve a code for the customer who scanned it. ``True`` to one caller.

        Sets ``approved``, ``approved_at`` and ``customer_ref`` only when the
        code is unexpired, unapproved and ``scanned_by == customer_ref``,
        in one compare-and-set; answers ``False`` otherwise and writes
        nothing. It replaces the read-check-write that let two replicas both
        approve and the last writer's ``customer_ref`` win.

        Raises:
            DeviceCodeStoreContended: if the transaction could not settle.
        """

    @abstractmethod
    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code and both of its secondary lookups.

        The only operation that deletes the secondaries early. Consuming a
        code leaves them, so ``POST /scan`` can still find an exchanged row
        and answer ``conflict_exchanged``; otherwise they expire with the
        primary.
        """

    # NO WHOLE-SNAPSHOT WRITE, deliberately, since 2026-09-30. This class
    # offered ``update_device_code`` and ``approve_device_code``, and each
    # wrote a whole row back: a snapshot read before a concurrent
    # ``claim_scan`` or ``approve_scanned`` and written after it silently
    # undoes that compare-and-set, and neither touched the two secondary
    # keys. Every write to an existing code now goes through one of the three
    # compare-and-set methods above or through ``revoke_device_code``.


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


#: Random bytes behind a display handle: 128 bits, 22 base64url characters.
DISPLAY_HANDLE_BYTES = 16

#: Random bytes in a pairing's QR secret, the HMAC-SHA256 key of its rotation
#: token. 32 is SHA-256's output size; RFC 2104 section 3 discourages a key
#: shorter than that.
QR_SECRET_BYTES = 32


def _generate_display_handle() -> str:
    """Generate the value that keys the browser's pairing page."""
    return secrets.token_urlsafe(DISPLAY_HANDLE_BYTES)


def _generate_qr_secret() -> bytes:
    """Generate a pairing's rotation-token key."""
    return secrets.token_bytes(QR_SECRET_BYTES)


def _live_match(code: DeviceCode | None, attribute: str, presented: str) -> DeviceCode | None:
    """``code`` if it is live and its ``attribute`` is exactly ``presented``.

    The re-check both backends run on a secondary lookup. A secondary entry is
    a pointer, and the primary row is the authority: an empty value, an
    expired row, or a row whose own field no longer names what the pointer was
    looked up by all answer ``None``.
    """
    if code is None or not presented or code.is_expired:
        return None
    if getattr(code, attribute) != presented:
        return None
    return code


def _unused(generate: Callable[[], str], taken: dict[str, str], what: str) -> str:
    """A freshly generated value ``taken`` does not hold, or refuse.

    ``generate`` is passed at each call rather than bound at import, so a test
    can replace ``_generate_user_code`` or ``_generate_display_handle`` on the
    module and force a collision.
    """
    for _ in range(_SECONDARY_KEY_ATTEMPTS):
        value = generate()
        if value not in taken:
            return value
    raise DeviceCodeStoreContended(
        f"{_SECONDARY_KEY_ATTEMPTS} generated {what} values were all already in use"
    )


def _scan_verdict(code: DeviceCode, customer_ref: str) -> ScanClaim:
    """Which ``ScanClaim`` a stored code earns, decided from the row alone.

    One pure function both backends call inside their read-then-write, so the
    two cannot disagree about the table in ``dev-docs/qr-page-spec.md``
    section 1. A code can only be approved by the customer in ``scanned_by``
    (``_may_approve``), so "scanned or approved by someone else" is the one
    test ``scanned_by != customer_ref``.

    AN UNSCANNED CODE THAT IS ALREADY APPROVED IS ``GONE``. Nothing this
    release writes produces one; only a record the previous release approved
    does, and that record has no ``qr_secret`` either, so ``POST /scan``
    refuses it earlier. Answering ``GONE`` keeps this function total without
    inventing a seventh result.
    """
    if code.is_expired:
        return ScanClaim.GONE
    if not code.scanned_by:
        return ScanClaim.GONE if code.approved else ScanClaim.CLAIMED
    if code.scanned_by == customer_ref:
        return ScanClaim.APPROVED_MINE if code.approved else ScanClaim.ALREADY_MINE
    if code.exchanged_at is None:
        return ScanClaim.CONFLICT_REVOKED
    return ScanClaim.CONFLICT_EXCHANGED


def _may_approve(code: DeviceCode, customer_ref: str) -> bool:
    """Whether ``approve_scanned`` may approve this code for this customer."""
    return (
        bool(customer_ref)
        and not code.is_expired
        and not code.approved
        and code.scanned_by == customer_ref
    )


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
        #: Display handle to device code, and stored-form pairing code to
        #: device code. Cleared by `_forget` wherever a code leaves `_codes`.
        self._by_handle: dict[str, str] = {}
        self._by_user_code: dict[str, str] = {}

    def _forget(self, device_code: str) -> DeviceCode | None:
        """Remove a code and its two secondary entries, without yielding.

        Synchronous on purpose: `claim_scan` calls it inside its read-then-write
        and must not suspend there. Each secondary entry is removed only if it
        still points at this code, so a value a later code reused is left
        alone.
        """
        code = self._codes.pop(device_code, None)
        if code is None:
            return None
        if self._by_handle.get(code.display_handle) == device_code:
            del self._by_handle[code.display_handle]
        if self._by_user_code.get(code.user_code) == device_code:
            del self._by_user_code[code.user_code]
        return code

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
            self._forget(device_code)
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
        creator_ip: str | None = None,
    ) -> DeviceCode:
        """Create a new device code session and return it.

        Raises:
            DeviceCodeStoreFull: if the store still holds ``max_codes`` after
                expired codes have been swept.
            DeviceCodeStoreContended: if every generated pairing code or
                display handle collided with a live one.
        """
        self._drop_expired()
        if len(self._codes) >= self._max_codes:
            raise DeviceCodeStoreFull(len(self._codes), self._max_codes)
        device_code = _generate_device_code()
        user_code = _unused(_generate_user_code, self._by_user_code, "user_code")
        display_handle = _unused(_generate_display_handle, self._by_handle, "display handle")
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        code = DeviceCode(
            device_code=device_code,
            user_code=user_code,
            verification_uri=verification_uri,
            expires_at=expires_at,
            interval=interval,
            client_id=client_id,
            scopes=scopes,
            display_handle=display_handle,
            qr_secret=_generate_qr_secret(),
            creator_ip=creator_ip,
        )
        self._codes[device_code] = code
        self._by_user_code[user_code] = device_code
        self._by_handle[display_handle] = device_code
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

    async def get_by_display_handle(self, display_handle: str) -> DeviceCode | None:
        """The live code this display handle keys, or ``None``."""
        device_code = self._by_handle.get(display_handle)
        code = self._codes.get(device_code) if device_code is not None else None
        return _live_match(code, "display_handle", display_handle)

    async def get_by_user_code(self, user_code: str) -> DeviceCode | None:
        """The live code this stored-form pairing code keys, or ``None``."""
        device_code = self._by_user_code.get(user_code)
        code = self._codes.get(device_code) if device_code is not None else None
        return _live_match(code, "user_code", user_code)

    async def consume_device_code(self, device_code: str, *, session_id: str) -> bool:
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
            **{
                **asdict_frozen(existing),
                "exchanged_at": datetime.now(UTC),
                "session_id": session_id,
            }
        )
        return True

    async def claim_scan(
        self, device_code: str, customer_ref: str, *, scanner_ip: str | None
    ) -> ScanClaim:
        """Record the first scan, or say why this one is not it.

        ATOMIC BY NOT YIELDING, for the reason ``consume_device_code`` gives:
        no ``await`` between the read, ``_scan_verdict`` and the write, and
        ``_forget`` is synchronous for exactly this caller.
        """
        existing = self._codes.get(device_code)
        if existing is None:
            return ScanClaim.GONE
        claim = _scan_verdict(existing, customer_ref)
        if claim is ScanClaim.CLAIMED:
            self._codes[device_code] = dataclasses.replace(
                existing,
                scanned_by=customer_ref,
                scanned_at=datetime.now(UTC),
                scanner_ip=scanner_ip,
            )
        elif claim is ScanClaim.CONFLICT_REVOKED:
            self._forget(device_code)
        return claim

    async def approve_scanned(self, device_code: str, customer_ref: str) -> bool:
        """Approve for the scanner, atomically by not yielding."""
        existing = self._codes.get(device_code)
        if existing is None or not _may_approve(existing, customer_ref):
            return False
        self._codes[device_code] = dataclasses.replace(
            existing, approved=True, approved_at=datetime.now(UTC), customer_ref=customer_ref
        )
        return True

    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code and both of its secondary entries."""
        self._forget(device_code)


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

#: Delete ``KEYS[1]`` only while it still holds ``ARGV[1]``, the device code
#: that claimed it. A secondary key can expire on its own and be claimed by
#: another live code's ``SET NX EX`` before this code's revoke runs; an
#: unconditional ``DEL`` would then drop the new pairing's pointer and leave
#: it unfindable by that value. One script, so the compare and the delete are
#: one server-side step, and it queues inside a ``MULTI`` like any command,
#: which keeps ``claim_scan``'s conflict revoke a single transaction.
#: `InMemoryDeviceCodeStore._forget` applies the same rule.
_DELETE_IF_OWNED = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)


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

        self._url = url or redis_url_from_env() or "redis://localhost:6379/0"
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

    def _handle_key(self, display_handle: str) -> str:
        """The secondary key a display handle is looked up by.

        A device code is ``secrets.token_urlsafe`` output and never contains
        a colon, so ``device:handle:...`` and ``device:user_code:...`` cannot
        collide with ``_key``'s ``device:<device_code>``.
        """
        return f"{self._prefix}device:handle:{display_handle}"

    def _user_code_key(self, user_code: str) -> str:
        """The secondary key a stored-form pairing code is looked up by."""
        return f"{self._prefix}device:user_code:{user_code}"

    def _secondary_keys(self, code: DeviceCode) -> list[str]:
        """Both secondary keys a stored code owns. A record written before
        display handles existed owns only the second."""
        keys = [self._user_code_key(code.user_code)]
        if code.display_handle:
            keys.append(self._handle_key(code.display_handle))
        return keys

    def _queue_secondary_deletes(self, pipe: Any, code: DeviceCode) -> None:
        """Queue a compare-and-delete of each secondary key `code` owns.

        Each key goes only while it still names ``code.device_code``; one that
        another code has since claimed is left to that code.
        """
        for key in self._secondary_keys(code):
            pipe.eval(_DELETE_IF_OWNED, 1, key, code.device_code)

    async def _claim_secondary(
        self,
        key_for: Callable[[str], str],
        generate: Callable[[], str],
        device_code: str,
        ttl_seconds: int,
        what: str,
    ) -> str:
        """Claim a fresh secondary key with ``SET NX EX``, or refuse.

        ``NX`` IS THE UNIQUENESS CHECK, and there is no other. Reading the key
        and then setting it would let two replicas both find it free and both
        write, and the second writer's pointer would silently re-home the
        first pairing's ``user_code``. ``EX`` in the same command means a key
        without a TTL cannot exist even if the connection drops mid-create.
        """
        for _ in range(_SECONDARY_KEY_ATTEMPTS):
            value = generate()
            if await self._redis.set(key_for(value), device_code, nx=True, ex=ttl_seconds):
                return value
        raise DeviceCodeStoreContended(
            f"{_SECONDARY_KEY_ATTEMPTS} generated {what} values were all already in use"
        )

    async def create_device_code(
        self,
        *,
        client_id: str,
        scopes: str,
        verification_uri: str,
        expires_in: int | None = None,
        interval: int = 5,
        creator_ip: str | None = None,
    ) -> DeviceCode:
        """Create a new device code session and return it.

        Raises:
            DeviceCodeStoreFull: if the index still holds ``max_codes`` after
                due members have been dropped.
            DeviceCodeStoreContended: if every generated pairing code or
                display handle was already a live secondary key.

        THE SECONDARY KEYS ARE CLAIMED BEFORE THE PRIMARY IS WRITTEN, so a
        collision is resolved by regenerating the value rather than by
        rewriting a stored row. Their TTL is the requested lifetime in whole
        seconds; the primary's is recomputed and truncated by ``_set_code``,
        so the two can differ by up to a second, which is why both lookups
        re-check the primary.

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
        expires_in = expires_in or self._default_ttl
        secondary_ttl = max(1, int(expires_in))
        user_code = await self._claim_secondary(
            self._user_code_key, _generate_user_code, device_code, secondary_ttl, "user_code"
        )
        display_handle = await self._claim_secondary(
            self._handle_key, _generate_display_handle, device_code, secondary_ttl, "display handle"
        )
        expires_at = datetime.now(UTC) + timedelta(seconds=expires_in)
        code = DeviceCode(
            device_code=device_code,
            user_code=user_code,
            verification_uri=verification_uri,
            expires_at=expires_at,
            interval=interval,
            client_id=client_id,
            scopes=scopes,
            display_handle=display_handle,
            qr_secret=_generate_qr_secret(),
            creator_ip=creator_ip,
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

    async def get_by_display_handle(self, display_handle: str) -> DeviceCode | None:
        """The live code this display handle keys, or ``None``."""
        if not display_handle:
            return None
        device_code = await self._redis.get(self._handle_key(display_handle))
        if device_code is None:
            return None
        return _live_match(
            await self.get_device_code(device_code), "display_handle", display_handle
        )

    async def get_by_user_code(self, user_code: str) -> DeviceCode | None:
        """The live code this stored-form pairing code keys, or ``None``."""
        if not user_code:
            return None
        device_code = await self._redis.get(self._user_code_key(user_code))
        if device_code is None:
            return None
        return _live_match(await self.get_device_code(device_code), "user_code", user_code)

    async def consume_device_code(self, device_code: str, *, session_id: str) -> bool:
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
                    spent = DeviceCode(
                        **{
                            **asdict_frozen(code),
                            "exchanged_at": datetime.now(UTC),
                            "session_id": session_id,
                        }
                    )
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

    async def claim_scan(
        self, device_code: str, customer_ref: str, *, scanner_ip: str | None
    ) -> ScanClaim:
        """Record the first scan, or say why this one is not it.

        ``WATCH``/``MULTI`` on the primary, the shape ``consume_device_code``
        uses and for its reasons, with ``KEEPTTL`` on the claim so the scan
        does not move the expiry. ``CONFLICT_REVOKED`` deletes the primary,
        its index member and both secondary keys inside the same ``MULTI``
        (each secondary only while it still names this code), so no replica
        can observe the pairing half-revoked. A value that will not
        deserialize is ``GONE``: a row this store cannot read is not one
        a scan may claim.
        """
        from redis.exceptions import WatchError

        key = self._key(device_code)
        for _ in range(_CLAIM_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    raw = await pipe.get(key)
                    if raw is None:
                        return ScanClaim.GONE
                    try:
                        code = DeviceCode.from_json(raw)
                    except (KeyError, ValueError, TypeError):
                        logger.warning(
                            "refusing a scan of device code %s: its stored value will not "
                            "deserialize",
                            device_code,
                        )
                        return ScanClaim.GONE
                    claim = _scan_verdict(code, customer_ref)
                    if claim is ScanClaim.CLAIMED:
                        scanned = dataclasses.replace(
                            code,
                            scanned_by=customer_ref,
                            scanned_at=datetime.now(UTC),
                            scanner_ip=scanner_ip,
                        )
                        pipe.multi()
                        pipe.set(key, scanned.to_json(), keepttl=True)
                        await pipe.execute()
                    elif claim is ScanClaim.CONFLICT_REVOKED:
                        pipe.multi()
                        pipe.delete(key)
                        pipe.zrem(self._index_key(), device_code)
                        self._queue_secondary_deletes(pipe, code)
                        await pipe.execute()
                    return claim
                except WatchError:
                    continue
        raise DeviceCodeStoreContended(
            f"a scan claim was beaten by another writer {_CLAIM_ATTEMPTS} times"
        )

    async def approve_scanned(self, device_code: str, customer_ref: str) -> bool:
        """Approve for the scanner, with the server settling the race.

        The same ``WATCH``/``MULTI``/``KEEPTTL`` shape as ``claim_scan``. The
        loser of two concurrent approvals retries, reads ``approved`` the
        winner wrote, and answers ``False``.
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
                            "refusing to approve device code %s: its stored value will not "
                            "deserialize",
                            device_code,
                        )
                        return False
                    if not _may_approve(code, customer_ref):
                        return False
                    approved = dataclasses.replace(
                        code,
                        approved=True,
                        approved_at=datetime.now(UTC),
                        customer_ref=customer_ref,
                    )
                    pipe.multi()
                    pipe.set(key, approved.to_json(), keepttl=True)
                    await pipe.execute()
                    return True
                except WatchError:
                    continue
        raise DeviceCodeStoreContended(
            f"an approval was beaten by another writer {_CLAIM_ATTEMPTS} times"
        )

    async def revoke_device_code(self, device_code: str) -> None:
        """Remove a device code, its index member and its two secondary keys.

        The index member, or the cap counts codes that no longer exist and a
        service that revokes normally would refuse pairings it has room for.
        The secondary keys, or a revoked pairing's ``user_code`` would still
        resolve until its TTL ran out -- to nothing, since the lookup re-reads
        the primary, but at the cost of holding the value out of reuse.

        The row is read first to learn the secondary names. A row that is
        already gone leaves its secondary keys to their own TTL, which is
        what they would have done anyway. A secondary key that expired after
        the read and was claimed by another code is left alone, because each
        delete is conditional on the key still naming this code.
        """
        stored = await self.get_device_code(device_code)
        pipe = self._redis.pipeline()
        pipe.delete(self._key(device_code))
        pipe.zrem(self._index_key(), device_code)
        if stored is not None:
            self._queue_secondary_deletes(pipe, stored)
        await pipe.execute()

    async def _set_code(self, device_code: str, code: DeviceCode) -> None:
        """Store a device code with TTL, and index it by the same expiry.

        Called by ``create_device_code`` only. Every later write to a code --
        the scan claim, the approval, the exchange -- is a ``WATCH``/``MULTI``
        transaction with ``KEEPTTL``, because none of them moves the expiry
        and none may be undone by a stale snapshot. Both writes here are
        skipped when the TTL has already passed, which keeps the index from
        gaining a member that is due the moment it lands.

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

        NO GUARD IS RAISED HERE, deliberately. Until 2026-09-30 this method
        had two more callers, the whole-snapshot writers the compare-and-set
        methods replaced, and for them a zero TTL was an ordinary race rather
        than a caller asking for a lifetime that cannot be represented. With
        ``create_device_code`` the only caller, raising here would be raising
        there, and it would make this backend refuse a lifetime
        `InMemoryDeviceCodeStore` accepts, which does not end the
        disagreement between them, it only
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
        "exchanged_at": dc.exchanged_at.timestamp() if dc.exchanged_at else None,
        "display_handle": dc.display_handle,
        # Standard base64 so the JSON stays text. ``None`` rather than ``""``
        # for an absent secret, so a reader of the stored value can tell "no
        # secret" from a secret that happens to encode short.
        "qr_secret": base64.b64encode(dc.qr_secret).decode("ascii") if dc.qr_secret else None,
        "creator_ip": dc.creator_ip,
        "scanned_by": dc.scanned_by,
        "scanned_at": dc.scanned_at.timestamp() if dc.scanned_at else None,
        "scanner_ip": dc.scanner_ip,
        "session_id": dc.session_id,
    }


def _device_code_from_dict(data: dict[str, Any]) -> DeviceCode:
    """Deserialize a DeviceCode from a plain dict."""
    approved_at = None
    if data.get("approved_at") is not None:
        approved_at = datetime.fromtimestamp(data["approved_at"], tz=_UTC)
    exchanged_at = None
    if data.get("exchanged_at") is not None:
        exchanged_at = datetime.fromtimestamp(data["exchanged_at"], tz=_UTC)
    scanned_at = None
    if data.get("scanned_at") is not None:
        scanned_at = datetime.fromtimestamp(data["scanned_at"], tz=_UTC)
    # ``validate=True`` so a stored value that is not base64 raises
    # ``binascii.Error``, a ``ValueError``, which every caller already treats
    # as a corrupt record, rather than decoding to a different key.
    raw_secret = data.get("qr_secret")
    qr_secret = base64.b64decode(raw_secret, validate=True) if raw_secret else b""
    raw_creator_ip = data.get("creator_ip")
    raw_scanner_ip = data.get("scanner_ip")
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
        # A ``user_code_attempts`` key on a record the previous release wrote
        # is ignored: the per-code attempt budget it counted was removed when
        # the pairing code became the lookup key, where it means nothing.
        # ``None`` when the key is absent, and here that default is the TRUE
        # reading rather than the fail-closed one: a record written by the
        # previous release came from a build that could not spend a code, so
        # it had not. The two directions differ on purpose -- ``customer_ref``
        # above defaults to empty so an old record mints nothing, while an old
        # record here stays redeemable for the rest of its 900-second life.
        exchanged_at=exchanged_at,
        # ALL FIVE DEFAULT TO ABSENT, and for the pairing that is the
        # fail-closed direction: a record the previous release wrote has no
        # handle, so no page finds it, and no secret, so no rotation token
        # verifies against it. It cannot be scanned and so cannot be approved;
        # with a 900-second lifetime none outlives a deploy by long.
        display_handle=str(data.get("display_handle", "")),
        qr_secret=qr_secret,
        creator_ip=str(raw_creator_ip) if raw_creator_ip is not None else None,
        scanned_by=str(data.get("scanned_by", "")),
        scanned_at=scanned_at,
        # ABSENT MEANS NONE, and here that is the TRUE reading rather than a
        # fail-closed default: the previous release recorded no scanner
        # address, so there is none.
        scanner_ip=str(raw_scanner_ip) if raw_scanner_ip is not None else None,
        # ABSENT MEANS EMPTY: a record an earlier release wrote was exchanged,
        # if at all, before any family existed, so there is none to recall.
        session_id=str(data.get("session_id", "")),
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
    redis_url = redis_url_from_env()
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

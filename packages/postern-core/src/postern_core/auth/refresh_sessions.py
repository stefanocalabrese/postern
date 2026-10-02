"""Refresh-token families for the layer-1 session token (spec section 4).

A SESSION FAMILY is everything issued from one device-code exchange: one
family id (``sid``), a chain of refresh tokens of which exactly one is
current, and the access tokens minted alongside. It lives at most
`SESSION_ABSOLUTE_LIFETIME` from the exchange, and nothing extends that.

THE REFRESH TOKEN IS ``prt1.<sid>.<secret>``. ``sid`` is 16 random bytes,
unpadded base64url (22 characters), and appears in every access token, so it
is NOT a secret: it only selects a record. ``secret`` is
``secrets.token_urlsafe(32)``, fresh per refresh token. The store keeps the
SHA-256 of the WHOLE token as lowercase hex and never the token, and every
action requires that hash to equal one the record holds. That is RFC 9700
section 4.14.2's integrity note: a known ``sid`` with any other secret matches
nothing, writes nothing and changes nothing.

ROTATION WITH REUSE DETECTION. Each refresh retires the presented token into
``retained_hashes`` and makes a new one current. A retained token presented
again means two parties hold one family, and the family is revoked in the same
transaction that noticed. The server cannot tell which party is the customer,
so both lose it -- RFC 9700's stated cost, which also falls on a client that
retries a refresh whose response it lost.

ONE PURE VERDICT, TWO BACKENDS. `_rotation_verdict` decides from the record
alone, the pattern `postern_core.auth.device_codes`'s ``_scan_verdict`` set, so
the in-memory and Redis stores cannot disagree about what a presentation earns.
The in-memory store is atomic by not yielding between its read and its write;
the Redis store makes the server settle it with ``WATCH``/``MULTI``.

TIMESTAMPS ARE MILLISECONDS. ``created_at`` is compared with
`postern_core.auth.revocation`'s ``customer_revoked_at``, which is integer
milliseconds, so the record keeps the creation instant exactly at that
resolution (`RefreshSession.created_ms`). The store stamps it: Redis ``TIME``
on the Redis backend, the one clock the revocation stamp is written with, and
``time.time_ns()`` in memory.

ACCEPTED RESIDUALS ON REDIS, recorded rather than scripted. The cap is read
and the family written in separate round trips, so N ``create`` calls running
at once can all see room and all land: the store holds at most
``max_sessions + N``. `postern_core.auth.device_codes`'s
``RedisDeviceCodeStore`` accepts the same overshoot for the same reason. A
crash between the ``SET NX`` and the ``ZADD`` leaves a family the index does
not count, bounded only by its key's TTL (one hour). That second shape is this
store's alone: the device-code store writes its primary key and index entry
in one ``MULTI``. A Lua script would close both and was judged not worth it
for a bound on standing memory.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from postern_core.config import redis_url_from_env

logger = logging.getLogger(__name__)

#: How long a family lives from its exchange. Absolute: rotation does not move
#: it. One hour, not the twelve first approved, until the per-family app
#: notification exists (spec, "What this does not fix").
SESSION_ABSOLUTE_LIFETIME = timedelta(hours=1)

#: Rotations one family may make. One hour at one refresh per 10-minute
#: access token is 6; 64 admits a client refreshing about once a minute, and
#: bounds ``retained_hashes`` at 64 hashes of 64 characters, about 4 KiB.
MAX_GENERATIONS = 64

#: The default of ``POSTERN_MAX_REFRESH_SESSIONS``: `postern_core.auth.device_codes`'s
#: ``DEFAULT_MAX_DEVICE_CODES`` times the lifetime ratio (3,600 s / 900 s).
DEFAULT_MAX_REFRESH_SESSIONS = 40_000

#: Random bytes behind a family id: 128 bits, 22 base64url characters.
SID_BYTES = 16

#: The refresh token's version prefix.
REFRESH_TOKEN_PREFIX = "prt1"  # noqa: S105 -- a format tag, not a credential

#: The whole refresh token, anchored. 22 characters of ``sid`` and 43 of
#: secret are what ``secrets.token_urlsafe`` produces for 16 and 32 bytes.
REFRESH_TOKEN_PATTERN = re.compile(r"prt1\.([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})")

#: How many times a Redis compare-and-set re-reads a record another writer
#: moved under its ``WATCH`` before it gives up, as
#: `postern_core.auth.device_codes`'s ``_CLAIM_ATTEMPTS`` does.
_CLAIM_ATTEMPTS = 3

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class RefreshSessionStoreFull(RuntimeError):
    """The store holds ``max_sessions`` live families after sweeping."""

    def __init__(self, held: int, cap: int) -> None:
        super().__init__(f"refresh session store holds {held} families, at its cap of {cap}")
        self.held = held
        self.cap = cap


class RefreshSessionStoreContended(RuntimeError):
    """A compare-and-set was beaten by another writer on every attempt."""


class RefreshSessionCollision(RuntimeError):
    """``create`` was handed a ``sid`` the store already holds: 128 bits collided."""


class Rotation(enum.Enum):
    """What one presentation of a refresh token earned."""

    ROTATED = "rotated"
    REUSED = "reused"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    EXHAUSTED = "exhausted"
    GONE = "gone"


def ms_of(instant: datetime) -> int:
    """``instant`` as integer milliseconds since the Unix epoch, exactly."""
    return (instant - _EPOCH) // timedelta(milliseconds=1)


def from_ms(value: int) -> datetime:
    """Inverse of `ms_of`."""
    return _EPOCH + timedelta(milliseconds=value)


def now_ms() -> int:
    """This process's clock in milliseconds, for the in-memory backends."""
    return time.time_ns() // 1_000_000


def new_sid() -> str:
    """A fresh family id."""
    return secrets.token_urlsafe(SID_BYTES)


def new_refresh_token(sid: str) -> str:
    """A fresh refresh token for family ``sid``."""
    return f"{REFRESH_TOKEN_PREFIX}.{sid}.{secrets.token_urlsafe(32)}"


def hash_refresh_token(token: str) -> str:
    """SHA-256 of the whole presented value, lowercase hex."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def sid_of(presented: str) -> str | None:
    """The family id a well-formed refresh token names, or ``None``."""
    match = REFRESH_TOKEN_PATTERN.fullmatch(presented)
    return match.group(1) if match else None


def canonical_scope(value: str) -> str:
    """Split on ASCII space, drop empties and duplicates, sort by code point, join.

    Spec section 6 step 5. Used for a family's ``scopes``, for every ``scope``
    claim, and for comparing a requested scope with the granted one.
    """
    return " ".join(sorted({part for part in value.split(" ") if part}))


@dataclass(frozen=True)
class RefreshSession:
    """One family, as the store holds it. Never carries a token."""

    sid: str
    customer_ref: str
    client_id: str
    scopes: str
    created_at: datetime
    expires_at: datetime
    generation: int
    # Out of ``repr`` so a logged record carries no hash an attacker could
    # match against a token seen elsewhere.
    current_hash: str = field(repr=False)
    retained_hashes: tuple[str, ...] = field(default=(), repr=False)
    access_tokens: tuple[tuple[str, datetime], ...] = ()
    revoked_at: datetime | None = None
    revoked_reason: str = ""
    device_code_handle: str = ""

    @property
    def created_ms(self) -> int:
        """``created_at`` in integer milliseconds, the resolution revocation compares at."""
        return ms_of(self.created_at)

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def live_jtis(self, now: datetime) -> tuple[str, ...]:
        """The ``jti`` of every access token of this family not yet expired."""
        return tuple(jti for jti, exp in self.access_tokens if exp > now)

    def to_json(self) -> str:
        return json.dumps(
            {
                "sid": self.sid,
                "customer_ref": self.customer_ref,
                "client_id": self.client_id,
                "scopes": self.scopes,
                "created_at_ms": ms_of(self.created_at),
                "expires_at_ms": ms_of(self.expires_at),
                "generation": self.generation,
                "current_hash": self.current_hash,
                "retained_hashes": list(self.retained_hashes),
                "access_tokens": [[jti, ms_of(exp)] for jti, exp in self.access_tokens],
                "revoked_at_ms": ms_of(self.revoked_at) if self.revoked_at else None,
                "revoked_reason": self.revoked_reason,
                "device_code_handle": self.device_code_handle,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_json(cls, raw: str) -> RefreshSession:
        data = json.loads(raw)
        revoked = data.get("revoked_at_ms")
        return cls(
            sid=str(data["sid"]),
            customer_ref=str(data["customer_ref"]),
            client_id=str(data["client_id"]),
            scopes=str(data["scopes"]),
            created_at=from_ms(int(data["created_at_ms"])),
            expires_at=from_ms(int(data["expires_at_ms"])),
            generation=int(data["generation"]),
            current_hash=str(data["current_hash"]),
            retained_hashes=tuple(str(h) for h in data["retained_hashes"]),
            access_tokens=tuple((str(j), from_ms(int(e))) for j, e in data["access_tokens"]),
            revoked_at=from_ms(int(revoked)) if revoked is not None else None,
            revoked_reason=str(data.get("revoked_reason", "")),
            device_code_handle=str(data.get("device_code_handle", "")),
        )


@dataclass(frozen=True)
class RotationOutcome:
    """What `RefreshSessionStoreBase.rotate` decided, and what it saw.

    ``session`` is the record as the transaction left it (``None`` for
    ``GONE`` on a missing or unreadable record), so a caller answering a
    non-``ROTATED`` result can re-run its own classification against exactly
    what the store saw. ``jtis`` are the family's unexpired access-token ids
    for ``REUSED`` and ``REVOKED``, and empty otherwise.
    """

    rotation: Rotation
    session: RefreshSession | None = None
    jtis: tuple[str, ...] = ()


def _stamped(session: RefreshSession, created_ms: int) -> RefreshSession:
    """``session`` with the store's own clock as its creation instant."""
    created = from_ms(created_ms)
    return dataclasses.replace(
        session, created_at=created, expires_at=created + SESSION_ABSOLUTE_LIFETIME
    )


def _pruned(
    tokens: tuple[tuple[str, datetime], ...], now: datetime
) -> tuple[tuple[str, datetime], ...]:
    return tuple((jti, exp) for jti, exp in tokens if exp > now)


def _is_current(session: RefreshSession, presented_hash: str) -> bool:
    return hmac.compare_digest(session.current_hash, presented_hash)


def _rotation_verdict(session: RefreshSession, presented_hash: str, now: datetime) -> Rotation:
    """The one decision both backends make inside their transaction.

    POSSESSION FIRST. A hash this family never issued is ``UNKNOWN`` in every
    state the family can be in, so a caller holding a ``sid`` and a guessed
    secret learns nothing, not even that the family is revoked (RFC 9700
    section 4.14.2). Then revoked, so a revoked family answers the same to
    every token it issued. Then a retained hash, which is reuse. Then the
    two ends of life.
    """
    retained = presented_hash in session.retained_hashes
    if not retained and not _is_current(session, presented_hash):
        return Rotation.UNKNOWN
    if session.revoked_at is not None:
        return Rotation.REVOKED
    if retained:
        return Rotation.REUSED
    if session.generation >= MAX_GENERATIONS:
        return Rotation.EXHAUSTED
    if session.is_expired(now):
        return Rotation.GONE
    return Rotation.ROTATED


def _revoked(session: RefreshSession, reason: str, now: datetime) -> RefreshSession:
    """``session`` revoked, keeping the first reason, pruned."""
    if session.revoked_at is not None:
        return dataclasses.replace(session, access_tokens=_pruned(session.access_tokens, now))
    return dataclasses.replace(
        session,
        revoked_at=now,
        revoked_reason=reason,
        access_tokens=_pruned(session.access_tokens, now),
    )


def _rotated(
    session: RefreshSession,
    new_hash: str,
    access_jti: str,
    access_expires_at: datetime,
    now: datetime,
) -> RefreshSession:
    return dataclasses.replace(
        session,
        generation=session.generation + 1,
        retained_hashes=(*session.retained_hashes, session.current_hash),
        current_hash=new_hash,
        access_tokens=(*_pruned(session.access_tokens, now), (access_jti, access_expires_at)),
    )


def _decide(
    session: RefreshSession,
    *,
    presented_hash: str,
    new_hash: str,
    access_jti: str,
    access_expires_at: datetime,
    now: datetime,
) -> tuple[RotationOutcome, RefreshSession | None]:
    """The verdict and the record to write, or ``None`` when nothing is written."""
    verdict = _rotation_verdict(session, presented_hash, now)
    if verdict is Rotation.ROTATED:
        written = _rotated(session, new_hash, access_jti, access_expires_at, now)
        return RotationOutcome(verdict, written), written
    if verdict is Rotation.REUSED:
        written = _revoked(session, "reuse", now)
        return RotationOutcome(verdict, written, written.live_jtis(now)), written
    if verdict is Rotation.REVOKED:
        return RotationOutcome(verdict, session, session.live_jtis(now)), None
    return RotationOutcome(verdict, session), None


class RefreshSessionStoreBase(ABC):
    """The family store, in whichever backend. Async throughout."""

    @abstractmethod
    async def create(self, session: RefreshSession) -> RefreshSession:
        """Store a new family and return it as stored.

        The store STAMPS ``created_at`` from its own clock and sets
        ``expires_at`` to that plus `SESSION_ABSOLUTE_LIFETIME`; the values on
        ``session`` are replaced. Sweeps expired families first, then raises
        `RefreshSessionStoreFull` at the cap. An existing ``sid`` raises
        `RefreshSessionCollision`.
        """

    @abstractmethod
    async def get(self, sid: str) -> RefreshSession | None:
        """The live family, or ``None`` for missing, expired or undeserializable."""

    @abstractmethod
    async def discard(self, sid: str) -> None:
        """Delete a family nobody holds a token for (spec section 5 step 3, and step 0 when
        the revocation check refuses or fails after the family was created)."""

    @abstractmethod
    async def rotate(
        self,
        sid: str,
        *,
        presented_hash: str,
        new_hash: str,
        access_jti: str,
        access_expires_at: datetime,
    ) -> RotationOutcome:
        """One compare-and-set deciding with `_rotation_verdict`.

        ``ROTATED`` retains the presented hash, makes ``new_hash`` current,
        increments ``generation`` and records the new access ``jti``.
        ``REUSED`` revokes the family with reason ``reuse`` in the same
        transaction. Every other result writes nothing.
        """

    @abstractmethod
    async def revoke(self, sid: str, *, reason: str) -> tuple[str, ...] | None:
        """Revoke a family, keeping the first reason; its unexpired jtis, or ``None``."""

    async def close(self) -> None:  # noqa: B027 - concrete and empty on purpose
        """Release any connection this store holds. A no-op by default."""
        return None


class InMemoryRefreshSessionStore(RefreshSessionStoreBase):
    """Per process. ``create_confirm_app`` refuses it without the dev flag.

    Atomic by not yielding: no method below awaits between its read and its
    write, which is the whole implementation of its compare-and-set.
    """

    def __init__(self, max_sessions: int = DEFAULT_MAX_REFRESH_SESSIONS) -> None:
        self._sessions: dict[str, RefreshSession] = {}
        self._max_sessions = max_sessions

    def _sweep(self, now: datetime) -> None:
        for sid in [sid for sid, s in self._sessions.items() if s.is_expired(now)]:
            del self._sessions[sid]

    async def create(self, session: RefreshSession) -> RefreshSession:
        stamped = _stamped(session, now_ms())
        self._sweep(datetime.now(UTC))
        if len(self._sessions) >= self._max_sessions:
            raise RefreshSessionStoreFull(len(self._sessions), self._max_sessions)
        if session.sid in self._sessions:
            raise RefreshSessionCollision(f"family {session.sid} already exists")
        self._sessions[session.sid] = stamped
        return stamped

    async def get(self, sid: str) -> RefreshSession | None:
        session = self._sessions.get(sid)
        if session is None or session.is_expired(datetime.now(UTC)):
            return None
        return session

    async def discard(self, sid: str) -> None:
        self._sessions.pop(sid, None)

    async def rotate(
        self,
        sid: str,
        *,
        presented_hash: str,
        new_hash: str,
        access_jti: str,
        access_expires_at: datetime,
    ) -> RotationOutcome:
        session = self._sessions.get(sid)
        if session is None:
            return RotationOutcome(Rotation.GONE)
        outcome, written = _decide(
            session,
            presented_hash=presented_hash,
            new_hash=new_hash,
            access_jti=access_jti,
            access_expires_at=access_expires_at,
            now=datetime.now(UTC),
        )
        if written is not None:
            self._sessions[sid] = written
        return outcome

    async def revoke(self, sid: str, *, reason: str) -> tuple[str, ...] | None:
        session = self._sessions.get(sid)
        if session is None:
            return None
        now = datetime.now(UTC)
        written = _revoked(session, reason, now)
        self._sessions[sid] = written
        return written.live_jtis(now)


def _ttl_seconds(expires_at: datetime, now: datetime) -> int:
    """Seconds until ``expires_at``, rounded UP.

    Truncation shortened device codes by up to a second (bug B1, in
    `postern_core.auth.device_codes`'s ``MIN_DEVICE_CODE_TTL_SECONDS``
    commentary); a family must not lose its last second the same way. Every
    read re-checks ``expires_at`` anyway, so the key outliving the record by
    under a second is harmless.
    """
    return max(1, math.ceil((expires_at - now).total_seconds()))


class RedisRefreshSessionStore(RefreshSessionStoreBase):
    """Families in Redis, shared by every replica.

    ``{prefix}refresh:session:<sid>`` holds the JSON record with a TTL set by
    ``create`` (``SET NX EX``) and kept by every later write (``KEEPTTL``).
    ``{prefix}refresh:index`` is a sorted set of ``sid`` scored by expiry,
    swept on ``create`` and counted for the cap, the shape
    `postern_core.auth.device_codes`'s ``RedisDeviceCodeStore`` uses and for
    its reasons.
    """

    def __init__(
        self,
        url: str | None = None,
        key_prefix: str | None = None,
        max_sessions: int = DEFAULT_MAX_REFRESH_SESSIONS,
    ) -> None:
        import redis.asyncio as redis

        self._url = url or redis_url_from_env() or "redis://localhost:6379/0"
        self._prefix = key_prefix or os.environ.get("POSTERN_REDIS_KEY_PREFIX", "postern:")
        self._max_sessions = max_sessions
        self._redis: Any = redis.from_url(  # type: ignore[no-untyped-call]
            self._url, decode_responses=True
        )

    def _key(self, sid: str) -> str:
        return f"{self._prefix}refresh:session:{sid}"

    @property
    def _index_key(self) -> str:
        return f"{self._prefix}refresh:index"

    async def _server_ms(self) -> int:
        """Redis ``TIME`` in milliseconds: the clock the revocation stamp uses."""
        seconds, microseconds = await self._redis.time()
        return int(seconds) * 1000 + int(microseconds) // 1000

    async def create(self, session: RefreshSession) -> RefreshSession:
        created_ms = await self._server_ms()
        stamped = _stamped(session, created_ms)
        now = from_ms(created_ms)
        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(self._index_key, "-inf", created_ms / 1000)
        pipe.zcard(self._index_key)
        dropped, held = await pipe.execute()
        if dropped:
            logger.info("refresh session store: swept %d expired families", dropped)
        if held >= self._max_sessions:
            raise RefreshSessionStoreFull(int(held), self._max_sessions)
        written = await self._redis.set(
            self._key(session.sid),
            stamped.to_json(),
            nx=True,
            ex=_ttl_seconds(stamped.expires_at, now),
        )
        if not written:
            raise RefreshSessionCollision(f"family {session.sid} already exists")
        await self._redis.zadd(self._index_key, {session.sid: ms_of(stamped.expires_at) / 1000})
        return stamped

    def _parse(self, sid: str, raw: str | None) -> RefreshSession | None:
        if raw is None:
            return None
        try:
            return RefreshSession.from_json(raw)
        except (KeyError, ValueError, TypeError):
            logger.warning("refresh session %s will not deserialize; treating it as gone", sid)
            return None

    async def get(self, sid: str) -> RefreshSession | None:
        session = self._parse(sid, await self._redis.get(self._key(sid)))
        if session is None or session.is_expired(datetime.now(UTC)):
            return None
        return session

    async def discard(self, sid: str) -> None:
        pipe = self._redis.pipeline()
        pipe.delete(self._key(sid))
        pipe.zrem(self._index_key, sid)
        await pipe.execute()

    async def rotate(
        self,
        sid: str,
        *,
        presented_hash: str,
        new_hash: str,
        access_jti: str,
        access_expires_at: datetime,
    ) -> RotationOutcome:
        from redis.exceptions import WatchError

        key = self._key(sid)
        for _ in range(_CLAIM_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    session = self._parse(sid, await pipe.get(key))
                    if session is None:
                        return RotationOutcome(Rotation.GONE)
                    outcome, written = _decide(
                        session,
                        presented_hash=presented_hash,
                        new_hash=new_hash,
                        access_jti=access_jti,
                        access_expires_at=access_expires_at,
                        now=datetime.now(UTC),
                    )
                    if written is not None:
                        pipe.multi()
                        pipe.set(key, written.to_json(), keepttl=True)
                        await pipe.execute()
                    return outcome
                except WatchError:
                    continue
        raise RefreshSessionStoreContended(
            f"a refresh of family {sid} was beaten by another writer {_CLAIM_ATTEMPTS} times"
        )

    async def revoke(self, sid: str, *, reason: str) -> tuple[str, ...] | None:
        from redis.exceptions import WatchError

        key = self._key(sid)
        for _ in range(_CLAIM_ATTEMPTS):
            async with self._redis.pipeline(transaction=True) as pipe:
                try:
                    await pipe.watch(key)
                    session = self._parse(sid, await pipe.get(key))
                    if session is None:
                        return None
                    now = datetime.now(UTC)
                    written = _revoked(session, reason, now)
                    pipe.multi()
                    pipe.set(key, written.to_json(), keepttl=True)
                    await pipe.execute()
                    return written.live_jtis(now)
                except WatchError:
                    continue
        raise RefreshSessionStoreContended(
            f"a revocation of family {sid} was beaten by another writer {_CLAIM_ATTEMPTS} times"
        )

    async def close(self) -> None:
        await self._redis.aclose()


def create_refresh_session_store(
    max_sessions: int = DEFAULT_MAX_REFRESH_SESSIONS,
) -> RefreshSessionStoreBase:
    """A Redis store when ``POSTERN_REDIS_URL`` is set, else an in-memory one.

    The same choice `postern_core.auth.device_codes.create_device_code_store`
    makes, on the same variable, so one URL points every store at one Redis.
    """
    redis_url = redis_url_from_env()
    if redis_url:
        logger.info("Using Redis refresh session store")
        return RedisRefreshSessionStore(url=redis_url, max_sessions=max_sessions)
    logger.info("Using in-memory refresh session store (set POSTERN_REDIS_URL for Redis)")
    return InMemoryRefreshSessionStore(max_sessions=max_sessions)

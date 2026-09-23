"""ZT-7 -- Revocation: three scopes, one shared store, and one decision per call.

WHAT WAS WRONG UNTIL THIS COMMIT. `RevocationList` below existed, was correct,
had 24 tests, and had NO WAY TO BE POPULATED. `services/api/main.py`'s
`create_app` constructed one, handed it to `ReadTokenMinter`, and dropped the
reference; `grep -rn "revoke_session|revoke_customer_client|kill_switch"
services stub` returned zero callers. An operator who learned a customer's
session was compromised, or that an AI vendor's client was exfiltrating, had
no mechanism to act. It was also in-process memory, per replica, lost on
restart, so even a populated one would have applied to whichever replica the
operator happened to reach.

Three revocation scopes map to the three acceptance criteria in the zero-trust
plan §4:

1. **Per-session** -- revoke one ``jti`` (one device, one client) without
   affecting the customer's other sessions.
2. **Per-customer + per-client** -- revoke all sessions for a customer-client
   pair (the "connected-app list" cut).
3. **Per-client kill switch** -- revoke every session from one client across
   all customers (the "disable one AI vendor" switch).

WHICH ``jti`` THE SESSION SCOPE MEANS. The ``jti`` of the CUSTOMER's inbound
access token, read by `services/api/middleware/revocation.py`'s
`RevocationMiddleware` from the validated token's claims. Not the internal
token's: `postern_core.auth.internal_jwt.InternalTokenMinter` generates a
fresh ``jti`` on every mint, so revoking one of those would revoke a token
that has already been spent and can never be presented again.

WHY A CLI AND NOT AN ADMIN HTTP ROUTE. `postern_core.auth.revoke_cli` is the
operator surface, and the absence of a route is a decision, not an omission.
This repository has no admin identity to authenticate. `services/confirm`'s
`AppAssertionMiddleware` verifies a CUSTOMER's banking-app assertion, so
pointing it at an admin route would mean either accepting any customer's
assertion to revoke anybody, or inventing an admin issuer, audience and role
claim -- a new authentication scheme, on the internet-facing MCP service, on
the one endpoint whose abuse either un-revokes an attacker or mass-revokes
every customer. `.importlinter`'s `api-not-confirm` contract also forbids
`services.api` from importing that middleware, so "reuse the pattern" would
mean writing a second verifier rather than reusing one. The CLI's
authorization is instead "can reach the configured Redis and run the
command", which is an infrastructure property the operator already owns and
already trusts with the risk session store. This paragraph would have been a
decision record; `dev-docs/` is gitignored and `docs/decisions/` holds stale
copies, so it lives here, in a tracked file, instead.

WHAT REVOKING DOES NOT STOP, STATED PLAINLY. Only `services/api` consults
this store. `services/confirm` has no revocation check at all: neither the
RFC 8628 device-grant token exchange nor
``POST /challenges/{challenge_id}/approve``. **Revoking a session does not
stop a payment approval.** A customer whose session is revoked mid-flow can
still approve a challenge that was already created, and the approval callback
will still reach the backend write endpoint. Closing that is a follow-up, and
it is the write path, so it is worth more than the read path this covers.

WHAT IS ALSO NOT BUILT. The zero-trust plan §4's fourth ZT-7 bullet -- the
customer cutting their own sessions from inside the bank app, and seeing
which client accessed what -- is a customer-initiated action whose home is
`services/confirm`, which already derives a customer from a verified
assertion. It is not built here. The operator's own banking-app backend can
write to this same store, and that is the documented route until a route
exists.

PERSISTENCE AND REPLICA REACH. `create_revocation_store` reads
``POSTERN_REDIS_URL`` and returns `RedisRevocationStore` when it is set,
`InMemoryRevocationStore` otherwise, following the shape
`postern_core.auth.device_codes.create_device_code_store` and
`postern_core.risk.session.create_session_store` already use. A deployment
that does not set it gets a store that is per replica and dies on restart,
which for a revocation list is worse than useless, because an operator would
believe they had acted. `services/api/main.py`'s existing
``POSTERN_REQUIRE_REDIS`` guard is what a production deployment sets to
refuse startup without one.

NO TTL. Revocation keys never expire. A kill switch that silently lapsed
after thirty minutes, the way a risk context does, would be worse than no
kill switch: the operator would have acted once and been un-acted on by a
timer. Every scope has an explicit restore command instead.

FAIL CLOSED. A store that cannot answer raises `RevocationStoreUnavailable`
and the middleware refuses the call. Reporting an outage as "not revoked"
would silently un-revoke every entry at exactly the moment the operator most
believes they have acted. This adds no new outage mode: the risk session
store already refuses every call on the same Redis being unreachable
(`postern_core.risk.session.SessionStoreUnavailable`).

NO CACHE. One Redis round trip per checked request. ZT-7's acceptance bar is
"terminates access within 30 seconds", and any cache TTL spends that budget
for a saving measured against a call that already makes a database write and
an HTTP request to the operator's backend.

ONE DECISION PER CALL. The check runs once, in the middleware, and its answer
is published on a `ContextVar` that `postern_core.auth.read_minter`'s
`ReadTokenMinter` reads synchronously before it signs anything. The minter
cannot do the lookup itself: it is called from
`postern_core.facade.client`'s `get_json` through a synchronous
`TokenMinter` protocol, and a Redis read is a coroutine. The alternative
considered and rejected was a second, in-process `RevocationList` held by the
minter: with Redis configured nothing would ever populate it, so the minter
would have been checking a permanently empty list -- a control that looks
like a control, which is the defect this whole commit exists to remove.

**AN UNSET DECISION REFUSES.** `require_revocation_decision` raises rather
than returning "not revoked". An unset `ContextVar` means the middleware did
not run, which cannot happen in a `create_app`-assembled server, so it is
either a future code path that bypassed the check or a directly constructed
minter. Both must refuse. A directly constructed minter that genuinely has no
revocation to consult passes `unchecked_revocation` explicitly, which is
greppable; a seam that defaulted to permissive is how a control stays inert.

Usage:
    store = create_revocation_store()
    await store.revoke_session(jti="tok-9f2")
    await store.revoke_customer_client(customer_ref="cust_7f3a", client_id="vendor-claude")
    await store.kill_switch(client_id="vendor-claude")

    claims = {"jti": "tok-9f2", "sub": "cust_7f3a", "client_id": "vendor-claude"}
    assert await store.is_revoked(claims)

See ``tests/test_zt7_revocation.py`` for the `RevocationList` matrix and
``tests/test_zt7_revocation_reachable.py`` for the end-to-end path.
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RevocationEntry:
    """One revocation record. Immutable so it can be stored in sets/frozensets."""

    jti: str | None = None
    """Session-level revocation: unique per token (UUID)."""

    customer_ref: str | None = None
    """Customer-level scope: the ``sub`` from the token."""

    client_id: str | None = None
    """Client-level scope: the ``client_id`` from the token (optional)."""

    @property
    def is_kill_switch(self) -> bool:
        """True if this entry revokes all sessions for a client (no customer, no jti)."""
        return self.jti is None and self.customer_ref is None and self.client_id is not None

    @property
    def is_customer_client(self) -> bool:
        """True if this entry revokes all sessions for a customer–client pair."""
        return self.jti is None and self.customer_ref is not None and self.client_id is not None

    @property
    def is_session(self) -> bool:
        """True if this entry revokes exactly one session (has jti)."""
        return self.jti is not None


class RevocationList:
    """In-memory revocation list with three scopes.

    Thread-safe for the common case (single-threaded ASGI app). This is the
    in-memory CORE, not the whole mechanism: `InMemoryRevocationStore` wraps
    one to satisfy `RevocationStoreBase`, and `RedisRevocationStore` is what a
    deployment with more than one replica actually runs.

    Uses O(1) set lookups per scope (audit fix 2026-09-21): three separate
    sets indexed by the lookup key rather than one set requiring iteration.

    The check order matters: session revocation is checked first (most
    specific), then customer+client, then kill switch (least specific).
    This means a killed client's sessions are also caught by the session check.
    """

    def __init__(self) -> None:
        # O(1) lookup by jti — session revocation is the most specific scope.
        self._session_jtis: set[str] = set()
        # O(1) lookup by (customer_ref, client_id) — connected-app list.
        self._customer_client: set[tuple[str, str]] = set()
        # O(1) lookup by client_id — kill switch.
        self._kill_switch: set[str] = set()

    def revoke_session(
        self,
        *,
        jti: str,
        customer_ref: str | None = None,
        client_id: str | None = None,
    ) -> None:
        """Revoke one session by its ``jti`` (ZT-7, per-session scope).

        This is the most specific revocation: only the token with this ``jti``
        is rejected. The customer's other sessions continue to work.

        Args:
            jti: The JWT ID from the token's claims (unique per token).
            customer_ref: Optional, for audit logging. Not used in the check
                (the jti alone is sufficient).
            client_id: Optional, for audit logging. Not used in the check.
        """
        self._session_jtis.add(jti)

    def revoke_customer_client(
        self,
        *,
        customer_ref: str,
        client_id: str,
    ) -> None:
        """Revoke all sessions for a customer–client pair (ZT-7, connected-app scope).

        This is the "connected-app list" cut: the customer opens their bank app,
        sees the AI vendor in their connected-apps list, and revokes it. All
        sessions from that customer–client pair are rejected immediately.

        Args:
            customer_ref: The ``sub`` from the token (opaque customer identifier).
            client_id: The OAuth client ID of the AI vendor.
        """
        self._customer_client.add((customer_ref, client_id))

    def kill_switch(self, *, client_id: str) -> None:
        """Revoke every session from one client across all customers (ZT-7, kill switch).

        This is the "disable one AI vendor" switch. Every token carrying this
        ``client_id`` — regardless of customer or jti — is rejected immediately.

        Args:
            client_id: The OAuth client ID of the AI vendor to disable.
        """
        self._kill_switch.add(client_id)

    def restore_session(self, *, jti: str) -> None:
        """Undo `revoke_session`. Silent when the ``jti`` was never revoked.

        The three restores exist because this list has no TTL: an entry stays
        until something removes it, so something has to be able to. Idempotent
        for the reason `RevocationStoreBase` states -- an operator undoing a
        revocation under time pressure must not have to know whether a
        colleague already did.
        """
        self._session_jtis.discard(jti)

    def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        """Undo `revoke_customer_client`. Silent when the pair was not revoked."""
        self._customer_client.discard((customer_ref, client_id))

    def restore_client(self, *, client_id: str) -> None:
        """Undo `kill_switch`. Silent when the client was not killed."""
        self._kill_switch.discard(client_id)

    def is_revoked(self, claims: Mapping[str, Any]) -> bool:
        """Check whether a token's claims are revoked.

        Returns True if any revocation entry matches the claims. The check
        order is: session (most specific) → customer+client → kill switch
        (least specific). All lookups are O(1) set membership tests.

        Args:
            claims: The JWT claims dict (at minimum ``jti``, ``sub``, and
                optionally ``client_id``).

        Returns:
            True if the token is revoked, False otherwise.
        """
        jti = claims.get("jti")
        customer_ref = claims.get("sub")
        client_id = claims.get("client_id")

        # 1. Session revocation (most specific: jti alone) — O(1).
        if jti is not None and jti in self._session_jtis:
            return True

        # 2. Customer + client revocation (connected-app list) — O(1).
        if customer_ref is not None and client_id is not None:
            if (customer_ref, client_id) in self._customer_client:
                return True

        # 3. Kill switch (least specific: any token with this client_id) — O(1).
        if client_id is not None and client_id in self._kill_switch:
            return True

        return False

    def clear(self) -> None:
        """Remove all revocation entries. Useful for tests."""
        self._session_jtis.clear()
        self._customer_client.clear()
        self._kill_switch.clear()

    @property
    def entry_count(self) -> int:
        """Number of revocation entries (for testing/monitoring)."""
        return len(self._session_jtis) + len(self._customer_client) + len(self._kill_switch)

    def get_entries_by_scope(
        self,
    ) -> dict[str, int]:
        """Count entries by scope type. Useful for testing."""
        return {
            "session": len(self._session_jtis),
            "customer_client": len(self._customer_client),
            "kill_switch": len(self._kill_switch),
        }


class RevokedError(PermissionError):
    """This identity's access is revoked, or no revocation decision exists.

    A `PermissionError` subclass so that the refusal reads the same way as
    `services/api/server.py`'s `token_customer_resolver` refusing a caller it
    cannot name: both are "this request does not get to proceed", and both
    escape the tool dispatch as a top-level JSON-RPC error rather than a
    ``result.isError`` the model can read around.
    """


class RevocationStoreUnavailable(RuntimeError):
    """The store could not answer, so the call must be refused.

    Never collapsed into "not revoked". A backend that reported its own
    outage as an empty revocation list would un-revoke every entry it holds,
    at exactly the moment the operator most believes they have acted.
    """


@dataclass(frozen=True)
class RevocationSnapshot:
    """Everything a store currently revokes, for the CLI's ``list`` command.

    Tuples rather than sets so the CLI prints a stable order, and so a caller
    cannot mutate a store's state through the object it was handed.
    """

    sessions: tuple[str, ...] = ()
    """Revoked ``jti`` values (per-session scope)."""

    customer_clients: tuple[tuple[str, str], ...] = ()
    """Revoked ``(customer_ref, client_id)`` pairs (connected-app scope)."""

    clients: tuple[str, ...] = ()
    """Revoked ``client_id`` values (kill-switch scope)."""

    @property
    def total(self) -> int:
        """How many entries this snapshot carries, across all three scopes."""
        return len(self.sessions) + len(self.customer_clients) + len(self.clients)


class RevocationStoreBase(ABC):
    """The operator-reachable revocation surface, in whichever backend.

    Async throughout, including the in-memory backend, so a caller writes
    ``await store.is_revoked(...)`` without knowing which one it holds -- the
    same reason `postern_core.risk.session.SessionStoreBase` is async on both
    of its backends.

    Every mutator is idempotent: revoking what is already revoked, and
    restoring what is not revoked, both succeed silently. An operator acting
    on a compromised session under time pressure must not have to care
    whether a colleague already ran the same command.
    """

    @abstractmethod
    async def is_revoked(self, claims: Mapping[str, Any]) -> bool:
        """Whether these token claims are revoked under any of the three scopes.

        Raises `RevocationStoreUnavailable` when the store cannot answer.
        """

    @abstractmethod
    async def revoke_session(self, *, jti: str) -> None:
        """Revoke one session by the ``jti`` of the customer's access token."""

    @abstractmethod
    async def restore_session(self, *, jti: str) -> None:
        """Undo `revoke_session` for this ``jti``."""

    @abstractmethod
    async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        """Revoke every session of one customer through one OAuth client."""

    @abstractmethod
    async def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        """Undo `revoke_customer_client` for this pair."""

    @abstractmethod
    async def kill_switch(self, *, client_id: str) -> None:
        """Revoke every session from one OAuth client, across all customers."""

    @abstractmethod
    async def restore_client(self, *, client_id: str) -> None:
        """Undo `kill_switch` for this client."""

    @abstractmethod
    async def entries(self) -> RevocationSnapshot:
        """Everything currently revoked."""

    async def close(self) -> None:  # noqa: B027 - concrete and empty on purpose
        """Release any connection this store holds. A no-op by default.

        Deliberately NOT abstract. Only `RedisRevocationStore` holds anything
        to release, and making every backend implement an empty method is how
        a caller ends up not calling it at all. `postern_core.auth.revoke_cli`
        closes whatever store it built, without asking which one it is.
        """
        return None


class InMemoryRevocationStore(RevocationStoreBase):
    """`RevocationList` behind the async store interface.

    Per process, so under more than one replica an entry written here applies
    to whichever replica the writer reached and to no other, and a restart
    forgets it. That is a deployment property and it is why production sets
    ``POSTERN_REDIS_URL``; `services/api/main.py`'s ``POSTERN_REQUIRE_REDIS``
    guard is how an operator refuses to start without one.

    The three sets beside the list are what `entries` reads. `RevocationList`
    indexes for O(1) lookup and exposes only counts, and the CLI's ``list``
    command needs the values back; keeping them here rather than reaching into
    the lookup structure leaves that structure free to change shape.
    """

    def __init__(self, revocation_list: RevocationList | None = None) -> None:
        self._list = revocation_list or RevocationList()
        self._sessions: set[str] = set()
        self._customer_clients: set[tuple[str, str]] = set()
        self._clients: set[str] = set()

    async def is_revoked(self, claims: Mapping[str, Any]) -> bool:
        return self._list.is_revoked(claims)

    async def revoke_session(self, *, jti: str) -> None:
        self._list.revoke_session(jti=jti)
        self._sessions.add(jti)

    async def restore_session(self, *, jti: str) -> None:
        self._list.restore_session(jti=jti)
        self._sessions.discard(jti)

    async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        self._list.revoke_customer_client(customer_ref=customer_ref, client_id=client_id)
        self._customer_clients.add((customer_ref, client_id))

    async def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        self._list.restore_customer_client(customer_ref=customer_ref, client_id=client_id)
        self._customer_clients.discard((customer_ref, client_id))

    async def kill_switch(self, *, client_id: str) -> None:
        self._list.kill_switch(client_id=client_id)
        self._clients.add(client_id)

    async def restore_client(self, *, client_id: str) -> None:
        self._list.restore_client(client_id=client_id)
        self._clients.discard(client_id)

    async def entries(self) -> RevocationSnapshot:
        return RevocationSnapshot(
            sessions=tuple(sorted(self._sessions)),
            customer_clients=tuple(sorted(self._customer_clients)),
            clients=tuple(sorted(self._clients)),
        )


def _pair_member(customer_ref: str, client_id: str) -> str:
    """The stored form of a customer-client pair.

    JSON rather than ``f"{customer}|{client}"``: `client_id` is not
    trustworthy as a key fragment. fastmcp 4.0.3 fills
    ``AccessToken.client_id`` from ``client_id`` or ``azp`` or ``sub``, so a
    token carrying neither of the first two puts its raw ``sub`` there, and a
    delimiter inside either half would let one pair be written in a form that
    reads back as a different pair. A two-element JSON array cannot be
    confused with another pair whatever the halves contain.
    """
    return json.dumps([customer_ref, client_id], separators=(",", ":"))


def _pair_from_member(member: str) -> tuple[str, str]:
    """Inverse of `_pair_member`, for `RedisRevocationStore.entries`."""
    parsed = json.loads(member)
    return str(parsed[0]), str(parsed[1])


class RedisRevocationStore(RevocationStoreBase):
    """Redis-backed revocation, shared by every replica and surviving restart.

    Compatible with any Redis-compatible service: AWS ElastiCache for Redis,
    Google Memorystore for Redis, Azure Cache for Redis, or a self-hosted
    instance -- the same compatibility `postern_core.risk.session`'s
    `RedisSessionStore` already documents.

    Three SETs, one per scope, so `entries` enumerates what is revoked without
    a key scan and `is_revoked` is at most three ``SISMEMBER`` calls in one
    pipeline, which is one round trip.

    NO TTL is set on any of them. See this module's docstring: a revocation
    that expires on a timer is a revocation the operator was silently un-done
    on.

    Configuration via environment variables:

    ``POSTERN_REDIS_URL``
        Redis connection string, e.g. ``redis://localhost:6379/0`` or
        ``rediss://user:pass@host:port/0`` (TLS).

    ``POSTERN_REDIS_KEY_PREFIX``
        Key prefix for multi-tenant deployments (default ``"postern:"``).
    """

    def __init__(self, url: str | None = None, key_prefix: str | None = None) -> None:
        import redis.asyncio as redis

        self._url = url or os.environ.get("POSTERN_REDIS_URL", "redis://localhost:6379/0")
        self._prefix = key_prefix or os.environ.get("POSTERN_REDIS_KEY_PREFIX", "postern:")
        self._redis: Any = redis.from_url(  # type: ignore[no-untyped-call]
            self._url,
            decode_responses=True,
        )

    @property
    def _sessions_key(self) -> str:
        return f"{self._prefix}revoked:sessions"

    @property
    def _pairs_key(self) -> str:
        return f"{self._prefix}revoked:customer-clients"

    @property
    def _clients_key(self) -> str:
        return f"{self._prefix}revoked:clients"

    async def is_revoked(self, claims: Mapping[str, Any]) -> bool:
        """Check every applicable scope in one round trip.

        Only the scopes these claims could match are queried: a call carrying
        no ``jti`` asks nothing of the session set. Claims that match no scope
        at all return False without touching Redis, because no entry could
        name them.
        """
        jti = claims.get("jti")
        customer_ref = claims.get("sub")
        client_id = claims.get("client_id")

        checks: list[tuple[str, str]] = []
        if isinstance(jti, str):
            checks.append((self._sessions_key, jti))
        if isinstance(customer_ref, str) and isinstance(client_id, str):
            checks.append((self._pairs_key, _pair_member(customer_ref, client_id)))
        if isinstance(client_id, str):
            checks.append((self._clients_key, client_id))
        if not checks:
            return False

        try:
            pipe = self._redis.pipeline(transaction=False)
            for key, member in checks:
                pipe.sismember(key, member)
            results = await pipe.execute()
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation list could not be read: {type(exc).__name__}"
            ) from exc
        return any(bool(result) for result in results)

    async def _add(self, key: str, member: str) -> None:
        try:
            await self._redis.sadd(key, member)
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation entry could not be written: {type(exc).__name__}"
            ) from exc

    async def _remove(self, key: str, member: str) -> None:
        try:
            await self._redis.srem(key, member)
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation entry could not be removed: {type(exc).__name__}"
            ) from exc

    async def revoke_session(self, *, jti: str) -> None:
        await self._add(self._sessions_key, jti)

    async def restore_session(self, *, jti: str) -> None:
        await self._remove(self._sessions_key, jti)

    async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        await self._add(self._pairs_key, _pair_member(customer_ref, client_id))

    async def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        await self._remove(self._pairs_key, _pair_member(customer_ref, client_id))

    async def kill_switch(self, *, client_id: str) -> None:
        await self._add(self._clients_key, client_id)

    async def restore_client(self, *, client_id: str) -> None:
        await self._remove(self._clients_key, client_id)

    async def entries(self) -> RevocationSnapshot:
        try:
            sessions = await self._redis.smembers(self._sessions_key)
            pairs = await self._redis.smembers(self._pairs_key)
            clients = await self._redis.smembers(self._clients_key)
        except Exception as exc:
            raise RevocationStoreUnavailable(
                f"revocation list could not be enumerated: {type(exc).__name__}"
            ) from exc
        return RevocationSnapshot(
            sessions=tuple(sorted(str(value) for value in sessions)),
            customer_clients=tuple(sorted(_pair_from_member(str(value)) for value in pairs)),
            clients=tuple(sorted(str(value) for value in clients)),
        )

    async def close(self) -> None:
        await self._redis.aclose()


def create_revocation_store() -> RevocationStoreBase:
    """Create a revocation store backed by the configured backend.

    Reads ``POSTERN_REDIS_URL``: if set, returns a `RedisRevocationStore`;
    otherwise returns an `InMemoryRevocationStore`. Same contract as
    `postern_core.risk.session.create_session_store` and
    `postern_core.auth.device_codes.create_device_code_store`, so one
    environment variable configures all three and no deployment ends up with
    a shared session store beside a per-replica revocation list.
    """
    redis_url = os.environ.get("POSTERN_REDIS_URL")
    if redis_url:
        logger.info("Using Redis revocation store")
        return RedisRevocationStore(url=redis_url)
    logger.info("Using in-memory revocation store (set POSTERN_REDIS_URL for Redis)")
    return InMemoryRevocationStore()


# ---------------------------------------------------------------------------
# The per-call decision: published by the middleware, read by the minter.
# ---------------------------------------------------------------------------

#: What a `ReadTokenMinter` calls to learn whether this call is revoked.
RevocationDecision = Callable[[], bool]

_decision: ContextVar[bool | None] = ContextVar("postern_revocation_decision", default=None)


def current_decision() -> bool | None:
    """The middleware's answer for this call, or ``None`` if it did not run."""
    return _decision.get()


@contextmanager
def decision_scope(revoked: bool) -> Iterator[None]:
    """Publish a revocation decision for the duration of this block.

    RESET ON EXIT, through the token `ContextVar.set` returns, and that is not
    tidiness. A value set and left set in the task that assembles the app
    would be INHERITED by every request task spawned from that context, so one
    "not revoked" written at startup would become the standing default for
    calls whose middleware never ran -- the exact permissive fallback
    `require_revocation_decision` exists to refuse.
    """
    token = _decision.set(revoked)
    try:
        yield
    finally:
        _decision.reset(token)


def require_revocation_decision() -> bool:
    """The default decision provider: an unset decision is a refusal.

    `services/api/middleware/revocation.py`'s `RevocationMiddleware` publishes
    a decision on every tool call it admits, so in a `create_app`-assembled
    server this never raises. It fires for a code path that reached the minter
    without passing that middleware, and for a `ReadTokenMinter` constructed
    directly. Both must refuse rather than sign.
    """
    decision = _decision.get()
    if decision is None:
        raise RevokedError(
            "no revocation decision for this call: the revocation middleware "
            "did not run, so this token will not be minted"
        )
    return decision


def unchecked_revocation() -> bool:
    """A decision provider that never refuses. TEST AND STARTUP SEAM ONLY.

    Named rather than written as a bare ``lambda: False`` at each site, so
    that ``grep -rn unchecked_revocation`` lists every place the ZT-7 check is
    deliberately absent. Today that is `services/api/main.py`'s startup probe,
    which mints one token for a reference to nobody before any request exists,
    and the unit tests that construct a `ReadTokenMinter` to measure something
    else entirely: the key split, request deadlines, the minter probe.
    """
    return False

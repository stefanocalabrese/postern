"""Per-session risk context store, keyed on the caller's verified identity.

Provides a pluggable store backed by either an in-memory dict (dev / test) or
Redis (production — compatible with AWS ElastiCache, Google Memorystore,
Azure Cache for Redis, or any Redis-compatible service), plus a ``ContextVar``
so tool handlers can reach the current call's context without threading it
through every function.

WHAT THE KEY IS, AND WHY IT IS NOT A HANDLE. Until 2026-09-22 a context was
created by ``start_session``, addressed by an opaque handle, and looked up
from a ``session_handle`` tool argument. Three things were wrong with that at
once. No registered tool declared such an argument, and FastMCP generates
``"additionalProperties": false``, so no client could supply one either --
every budget, threshold and tier check in ZT-5 was unreachable. The handle
was also a bearer string: whoever presented it got the context, which is the
direct-object-reference shape CLAUDE.md forbids for ``user_id``. And an agent
that disliked its own budget could call ``start_session`` again for a fresh
zero-budget context at tier ``SESSION_ONLY``.

The context is now keyed on `SessionKey`: the customer the access token
resolves to, plus the OAuth client that presented it. Nothing the model can
set reaches the key, so there is nothing to forge and nothing to reset; the
pair matches the scope ZT-7 revokes on (`revocation.py`'s
`RevocationList.revoke_customer_client`), so "this customer, through this AI
vendor" means the same thing in both places.

A STORE THAT CANNOT ANSWER REFUSES THE CALL. `load` returns ``None`` only
for "this identity has no context yet", which is the first call of a session
and entirely normal. Anything else -- an unreachable Redis, a value that will
not deserialise -- raises `SessionStoreUnavailable`, and the middleware turns
that into a denied call. The two used to be one answer (log a warning, run
the tool with no risk tracking at all), which under MCP 2026-07-28 is not an
edge case: any request can land on any instance, so with an in-memory store
behind a load balancer the miss is the NORMAL case. Consent and audit in this
repository already fail closed (`0006-audit-write-failure.md`); this now
matches them.

Production deployments set ``POSTERN_REDIS_URL`` to enable the Redis backend;
without it, the in-memory store is used and is per replica.
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
from abc import ABC, abstractmethod
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from postern_core.config import (
    MIN_REPRESENTABLE_TTL_SECONDS,
    int_arg_or_env,
    redis_url_from_env,
)
from postern_core.risk.context import RiskContext

logger = logging.getLogger(__name__)

#: How long a risk context lives, from creation, before the store forgets it.
#: 30 minutes, matching ``POSTERN_REDIS_SESSION_TTL``'s existing default.
#:
#: This is a bound on how long a budget accumulates AND on how long a block
#: lasts: a caller whose context carries a HIGH signal is refused until the
#: context ages out, and can then accumulate a fresh budget. That is inherent
#: to a per-session budget with any lifetime, and the number is the trade --
#: shorter means a bulk-extraction attempt costs the attacker less waiting,
#: longer means a false positive costs a real customer more.
DEFAULT_SESSION_TTL_SECONDS = 1800

#: The shortest ``POSTERN_REDIS_SESSION_TTL`` this store accepts.
#:
#: THERE IS NO DERIVATION HERE BEYOND "IT MUST BE POSITIVE", and saying so is
#: the honest answer rather than inventing a number that reads as advice.
#: `services/confirm/settings.py`'s `MIN_DEVICE_CODE_TTL_SECONDS` could be
#: derived at 30 because three independent legs of the device grant have
#: measured durations to sit above. A risk context has no equivalent: nothing
#: in this repository measures how long a session that deserves a budget
#: lasts, so any figure above one second would be a preference wearing a
#: bound's clothes.
#:
#: WHAT ONE SECOND IS, THEN. It is the boundary between "short" and "off",
#: and it is measured. At ``_ttl = 0``, against redis:7-alpine on 2026-09-25,
#: ``save`` writes the key with a TTL of 1 -- ``_remaining_ttl`` floors there
#: -- and the very next ``load`` computes ``ceil(0 - elapsed) <= 0``, deletes
#: the key and answers ``None``. So every call gets a fresh context with a
#: zeroed budget, the per-session budgets and tier escalation of ZT-5 never
#: accumulate, and bulk extraction (A6) is counted against nothing. Negatives
#: do the same, harder. That is not a short session, it is the control turned
#: off through a variable whose name does not say so.
MIN_SESSION_TTL_SECONDS = MIN_REPRESENTABLE_TTL_SECONDS


class SessionStoreUnavailable(RuntimeError):
    """The store could not answer, so the call must be refused.

    Distinct from ``load`` returning ``None``, which means "no context for
    this identity yet" and is the ordinary first call of a session. This is
    raised for an unreachable backend, a timeout, or a stored value that will
    not deserialise -- every case where continuing would mean running the
    tool with no risk tracking, or with a budget silently reset to zero.
    """


@dataclass(frozen=True)
class SessionKey:
    """The identity a risk context is keyed on: customer plus OAuth client.

    Both halves come from the validated access token and neither is reachable
    from tool arguments. ``client_id`` is separate from the customer because
    two AI vendors acting for one customer are two callers: a budget shared
    across them would let one vendor's traffic block another's, and ZT-7
    already revokes at exactly this granularity.
    """

    customer_ref: str
    """The customer, as `identity.py`'s `CustomerResolver` answered."""

    client_id: str
    """The OAuth client, or ``"-"`` when the call carried no access token."""

    @property
    def value(self) -> str:
        """The storage key: a SHA-256 digest of the pair, never the pair.

        HASHED, for two reasons that are not cosmetic. A Redis key space is a
        different retention surface from ``audit_log``, and a digest keeps
        customer references out of it. And ``client_id`` is not trustworthy
        as a key fragment: fastmcp 4.0.3 fills ``AccessToken.client_id`` with
        ``claims.get("client_id") or claims.get("azp") or claims.get("sub")``,
        so a token carrying neither of the first two puts its raw ``sub``
        there -- which `identity.py` warns can be PAN-, IBAN- or DNI-shaped if
        the issuer is under attacker control. A digest also cannot carry a
        delimiter into a key name.

        The version prefix is what makes a future change of key shape a
        migration rather than a silent collision.
        """
        material = f"postern-risk-v1|{self.customer_ref}|{self.client_id}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    @property
    def log_ref(self) -> str:
        """A short, non-reversing handle for log lines."""
        return self.value[:12]


class SessionStoreBase(ABC):
    """Abstract base class for risk session stores.

    Backends implement `load`, `save` and `remove`; `context_for` is
    concrete and is what the middleware calls, so "create on first use" is
    decided in one place rather than once per backend.

    All methods are async — even the in-memory store uses ``async def`` so
    callers can uniformly ``await store.xxx()`` regardless of backend.
    """

    @abstractmethod
    async def load(self, key: SessionKey) -> RiskContext | None:
        """The stored context for this identity, or ``None`` if there is none.

        Raises `SessionStoreUnavailable` when the store cannot answer. A
        backend must never collapse that into ``None``: the caller creates a
        fresh, empty context for ``None``, so an outage reported that way
        would zero every budget it touched.
        """

    @abstractmethod
    async def save(self, key: SessionKey, ctx: RiskContext) -> None:
        """Persist a context's current state, after the handlers mutated it."""

    @abstractmethod
    async def remove(self, key: SessionKey) -> None:
        """Forget this identity's context."""

    async def context_for(self, key: SessionKey) -> RiskContext:
        """This identity's context, created and stored on first use.

        The created context carries `SessionKey.value` as its
        ``session_id``, so a log line, an audit row and a store key all name
        the same thing.
        """
        ctx = await self.load(key)
        if ctx is not None:
            return ctx
        ctx = RiskContext(session_id=key.value)
        await self.save(key, ctx)
        return ctx


class InMemorySessionStore(SessionStoreBase):
    """In-memory store mapping `SessionKey` → `RiskContext`.

    Per process, so under more than one replica each replica sees only the
    traffic it served and every budget is really a per-replica budget. That
    is a deployment property, not a bug to fix here: production sets
    ``POSTERN_REDIS_URL``.

    Contexts age out on read at ``ttl_seconds`` from CREATION, not from last
    use. Without that, nothing here ever expired: a context that reached a
    HIGH signal blocked its identity for the life of the process, and the
    engine's own ``SESSION_AGE_EXCEEDED`` threshold would have made that the
    normal end state of any long-lived session.
    """

    def __init__(self, ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS) -> None:
        self._contexts: dict[str, RiskContext] = {}
        self._ttl = ttl_seconds

    async def load(self, key: SessionKey) -> RiskContext | None:
        ctx = self._contexts.get(key.value)
        if ctx is None:
            return None
        if ctx.session_age_seconds >= self._ttl:
            del self._contexts[key.value]
            logger.info("risk context %s expired after %ds", key.log_ref, self._ttl)
            return None
        return ctx

    async def save(self, key: SessionKey, ctx: RiskContext) -> None:
        """Store the live object.

        The dict holds the same instance the middleware and the handlers
        mutate, so this is not a serialisation round trip. It is still called
        on every path the Redis backend is called on, because a backend that
        is only exercised by one of two stores is a backend nothing tests.
        """
        self._contexts[key.value] = ctx

    async def remove(self, key: SessionKey) -> None:
        self._contexts.pop(key.value, None)


class RedisSessionStore(SessionStoreBase):
    """Redis-backed session store.

    Compatible with any Redis-compatible service: AWS ElastiCache for Redis,
    Google Memorystore for Redis, Azure Cache for Redis, or a self-hosted
    instance.

    Context data is stored as JSON with a TTL measured from the context's
    creation instant, which `context.py` serialises as a POSIX timestamp.

    Configuration via environment variables:

    ``POSTERN_REDIS_URL``
        Redis connection string, e.g. ``redis://localhost:6379/0`` or
        ``rediss://user:pass@host:port/0`` (TLS).

    ``POSTERN_REDIS_SESSION_TTL``
        Context TTL in seconds (default 1800 = 30 min). Read only when the
        ``ttl`` argument is ``None``, and refused below one second --
        `int_arg_or_env` carries both halves of that rule.

    ``POSTERN_REDIS_KEY_PREFIX``
        Key prefix for multi-tenant deployments (default ``"postern:"``).
    """

    def __init__(
        self,
        url: str | None = None,
        ttl: int | None = None,
        key_prefix: str | None = None,
    ) -> None:
        import redis.asyncio as redis

        self._url = url or redis_url_from_env() or "redis://localhost:6379/0"
        # ``ttl or int(os.environ.get(...))`` until 2026-09-25, which crashed
        # on ``POSTERN_REDIS_SESSION_TTL=`` with a message naming neither the
        # variable nor this class, took zero and negatives without comment,
        # and discarded an explicitly passed ``0`` in favour of the
        # environment. `postern_core.config`'s `int_arg_or_env` closes all
        # three and is the same reader `services/api/settings.py` and
        # `services/confirm/settings.py` read their numbers through.
        self._ttl = int_arg_or_env(
            ttl,
            parameter="ttl",
            name="POSTERN_REDIS_SESSION_TTL",
            default=DEFAULT_SESSION_TTL_SECONDS,
            minimum=MIN_SESSION_TTL_SECONDS,
            because=(
                "It is how long a risk context accumulates its ZT-5 budget before the "
                "store forgets it; at zero every load answers None, so every call starts "
                "from an empty budget and bulk extraction accumulates against nothing."
            ),
        )
        self._prefix = key_prefix or os.environ.get("POSTERN_REDIS_KEY_PREFIX", "postern:")
        self._redis: Any = redis.from_url(  # type: ignore[no-untyped-call]
            self._url,
            decode_responses=True,
        )

    def _key(self, key: SessionKey) -> str:
        return f"{self._prefix}risk:{key.value}"

    async def load(self, key: SessionKey) -> RiskContext | None:
        """Read, age, and refresh this identity's context.

        EVERY failure below is a refusal, not a miss, and the ``except
        Exception`` is that width on purpose: a connection error, a timeout
        and a value that will not deserialise all end the same way, because
        the alternative for each is a fresh context with zeroed budgets. The
        deserialisation case is the one worth naming -- treating a corrupt
        value as absent would hand anyone who can write one key a way to
        clear the budget it holds.
        """
        redis_key = self._key(key)
        try:
            data = await self._redis.get(redis_key)
            if data is None:
                return None
            ctx = RiskContext.from_json(data)
            # One monotonic reading, not two wall-clock ones: `started_at`
            # takes its own wall-clock read after this one, which made a
            # fresh context's age slightly negative and `ceil` round it up.
            elapsed = ctx.session_age_seconds
            # CEIL, not `int`: truncating throws away the fraction of a
            # second every read, so a context re-read often enough would lose
            # a second of its lifetime per read rather than keeping the
            # absolute one it was given.
            remaining = math.ceil(self._ttl - elapsed)
            if remaining <= 0:
                await self._redis.delete(redis_key)
                logger.info(
                    "risk context %s expired (elapsed=%.1fs > ttl=%ds)",
                    key.log_ref,
                    elapsed,
                    self._ttl,
                )
                return None
            # Re-assert the remaining lifetime so a read cannot extend it.
            await self._redis.expire(redis_key, remaining)
        except Exception as exc:
            raise SessionStoreUnavailable(
                f"risk context {key.log_ref} could not be read: {type(exc).__name__}"
            ) from exc
        return ctx

    async def save(self, key: SessionKey, ctx: RiskContext) -> None:
        try:
            await self._redis.setex(self._key(key), self._remaining_ttl(ctx), ctx.to_json())
        except Exception as exc:
            raise SessionStoreUnavailable(
                f"risk context {key.log_ref} could not be written: {type(exc).__name__}"
            ) from exc

    async def remove(self, key: SessionKey) -> None:
        try:
            await self._redis.delete(self._key(key))
        except Exception as exc:
            raise SessionStoreUnavailable(
                f"risk context {key.log_ref} could not be removed: {type(exc).__name__}"
            ) from exc

    def _remaining_ttl(self, ctx: RiskContext) -> int:
        """What is left of this context's lifetime, never less than a second.

        A save that reset the key to the FULL TTL would turn an absolute
        lifetime into an idle one, and a caller that keeps calling would hold
        one context, and one budget window, open indefinitely.
        """
        # One monotonic reading: two wall-clock reads in the wrong order gave a
        # negative age for a fresh context, and `ceil` made it lifetime + 1.
        remaining = math.ceil(self._ttl - ctx.session_age_seconds)
        return max(1, remaining)

    async def close(self) -> None:
        """Close the Redis connection pool."""
        await self._redis.aclose()


def create_session_store() -> SessionStoreBase:
    """Create a session store backed by the configured backend.

    Reads ``POSTERN_REDIS_URL``: if set, returns a `RedisSessionStore`;
    otherwise returns an `InMemorySessionStore`.
    """
    redis_url = redis_url_from_env()
    if redis_url:
        logger.info("Using Redis risk session store")
        return RedisSessionStore(url=redis_url)
    logger.info("Using in-memory risk session store (set POSTERN_REDIS_URL for Redis)")
    return InMemorySessionStore()


# ---------------------------------------------------------------------------
# ContextVar — shared across all backends.
# ---------------------------------------------------------------------------

_current_session: ContextVar[RiskContext | None] = ContextVar("postern_risk_session", default=None)


def get_current_session() -> RiskContext | None:
    """Return the ``RiskContext`` for the current tool call, or ``None``.

    ``None`` means no risk middleware is installed on this server: when one
    is, every call it admits has a context, because a call it cannot build
    one for is refused rather than run.
    """
    return _current_session.get()


def set_current_session(ctx: RiskContext | None) -> None:
    """Push a context onto the current call's contextvar.

    Called by the risk middleware before ``call_next`` and reset after the
    call completes.
    """
    _current_session.set(ctx)


#: Alias for :class:`InMemorySessionStore` — kept so existing imports work.
#: New code should use :func:`create_session_store` instead.
SessionStore = InMemorySessionStore

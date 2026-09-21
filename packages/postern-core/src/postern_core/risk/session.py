"""Per-session risk context store.

Provides a pluggable ``SessionStore`` backed by either an in-memory dict
(dev / test) or Redis (production — compatible with AWS ElastiCache, Google
Memorystore, Azure Cache for Redis, or any Redis-compatible service).

Plus a ``ContextVar`` so tool handlers can reach the current session's
context without threading it through every function.

Usage::

    from postern_core.risk.session import create_session_store, get_current_session

    store = create_session_store()  # reads POSTERN_REDIS_URL
    ctx = store.create_session()
    handle = ctx.session_id

    # later, in a tool handler:
    current = get_current_session()  # reads the ContextVar

The ``RiskMiddleware`` (services/api) installs a contextvar setter so
every tool call automatically pushes the session onto the var.

Production deployments set ``POSTERN_REDIS_URL`` to enable the Redis
backend; without it, the in-memory store is used.
"""

from __future__ import annotations

import logging
import os
import uuid
from abc import ABC, abstractmethod
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any

from postern_core.risk.context import RiskContext

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Abstract base class — the interface all backends must implement.
# ---------------------------------------------------------------------------

class SessionStoreBase(ABC):
    """Abstract base class for risk session stores.

    All backends (in-memory, Redis, database) must implement these three
    methods.  The factory ``create_session_store()`` returns the appropriate
    implementation based on environment configuration.

    All methods are async — even the in-memory store uses ``async def`` so
    callers can uniformly ``await store.xxx()`` regardless of backend.
    """

    @abstractmethod
    async def create_session(self) -> SessionHandle:
        """Create a new session and return its handle."""

    @abstractmethod
    async def get_session(self, session_handle: str) -> RiskContext | None:
        """Look up the context for a session, or ``None`` if not found."""

    @abstractmethod
    async def remove_session(self, session_handle: str) -> None:
        """Remove a session (e.g. on explicit end or timeout)."""

    @abstractmethod
    async def save_session(self, session_handle: str, ctx: RiskContext) -> None:
        """Persist a session's current state (after handler mutations).

        Called by ``RiskMiddleware`` after each tool call completes, so that
        data recorded by the handler (records, accounts, days, IPs) survives
        process restarts when backed by Redis.
        """


# ---------------------------------------------------------------------------
# Session handle — shared across all backends.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SessionHandle:
    """Opaque handle identifying a risk session.

    Returned by ``start_session`` and passed back on every subsequent call
    so the server can look up the correct ``RiskContext``.
    """

    value: str
    """UUID string, unique per session."""


# ---------------------------------------------------------------------------
# In-memory backend (default for dev / test).
# ---------------------------------------------------------------------------

class InMemorySessionStore(SessionStoreBase):
    """In-memory store mapping ``session_handle`` → ``RiskContext``.

    Thread-safe enough for FastMCP's in-process test client (single-threaded
    async). Not safe across processes — use ``RedisSessionStore`` for that.

    Methods are ``async def`` so callers can uniformly ``await store.xxx()``
    regardless of which backend the factory returned.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, RiskContext] = {}

    async def create_session(self) -> SessionHandle:
        """Create a new session and return its handle."""
        handle = SessionHandle(value=str(uuid.uuid4()))
        self._sessions[handle.value] = RiskContext(session_id=handle.value)
        return handle

    async def get_session(self, session_handle: str) -> RiskContext | None:
        """Look up the context for a session, or ``None`` if not found."""
        return self._sessions.get(session_handle)

    async def remove_session(self, session_handle: str) -> None:
        """Remove a session."""
        self._sessions.pop(session_handle, None)

    async def save_session(self, session_handle: str, ctx: RiskContext) -> None:
        """Persist a session's current state.

        No-op for in-memory store — the dict reference is already live,
        so mutations are immediately visible to subsequent ``get_session``
        calls.  This method exists for interface parity with Redis.
        """


# ---------------------------------------------------------------------------
# Redis backend — compatible with AWS ElastiCache, Google Memorystore, etc.
# ---------------------------------------------------------------------------

class RedisSessionStore(SessionStoreBase):
    """Redis-backed session store.

    Compatible with any Redis-compatible service: AWS ElastiCache for
    Redis, Google Memorystore for Redis, Azure Cache for Redis, or a
    self-hosted Redis instance.

    Session data is stored as JSON with a configurable TTL (default 30 min
    idle). The ``_start_time`` field is a POSIX timestamp (not monotonic),
    so sessions survive process restarts.

    Configuration via environment variables:

    ``POSTERN_REDIS_URL``
        Redis connection string, e.g. ``redis://localhost:6379/0`` or
        ``rediss://user:pass@host:port/0`` (TLS).

    ``POSTERN_REDIS_SESSION_TTL``
        Session TTL in seconds (default 1800 = 30 min).

    ``POSTERN_REDIS_KEY_PREFIX``
        Key prefix for multi-tenant deployments (default ``"postern:"``).

    Usage::

        store = RedisSessionStore()
        handle = await store.create_session()
        ctx = await store.get_session(handle.value)  # RiskContext | None
    """

    def __init__(
        self,
        url: str | None = None,
        ttl: int | None = None,
        key_prefix: str | None = None,
    ) -> None:
        import redis.asyncio as redis

        self._url = url or os.environ.get("POSTERN_REDIS_URL", "redis://localhost:6379/0")
        self._ttl = ttl or int(os.environ.get("POSTERN_REDIS_SESSION_TTL", "1800"))
        self._prefix = key_prefix or os.environ.get("POSTERN_REDIS_KEY_PREFIX", "postern:")
        self._redis: Any = redis.from_url(  # type: ignore[no-untyped-call]
            self._url,
            decode_responses=True,
        )

    def _key(self, session_handle: str) -> str:
        """Build the Redis key for a session."""
        return f"{self._prefix}session:{session_handle}"

    async def create_session(self) -> SessionHandle:
        """Create a new session and return its handle."""
        handle = SessionHandle(value=str(uuid.uuid4()))
        ctx = RiskContext(session_id=handle.value)
        await self._set_session(handle.value, ctx)
        return handle

    async def get_session(self, session_handle: str) -> RiskContext | None:
        """Look up the context for a session, or ``None`` if not found."""
        data = await self._redis.get(self._key(session_handle))
        if data is None:
            return None
        try:
            return RiskContext.from_json(data)
        except (KeyError, ValueError, TypeError) as exc:  # pragma: no cover
            logger.warning("Failed to deserialize session %s: %s", session_handle, exc)
            return None

    async def remove_session(self, session_handle: str) -> None:
        """Remove a session."""
        await self._redis.delete(self._key(session_handle))

    async def save_session(self, session_handle: str, ctx: RiskContext) -> None:
        """Persist a session's current state (after handler mutations)."""
        await self._set_session(session_handle, ctx)

    async def _set_session(self, session_handle: str, ctx: RiskContext) -> None:
        """Store a session with TTL."""
        await self._redis.setex(
            self._key(session_handle),
            self._ttl,
            ctx.to_json(),
        )

    async def refresh_ttl(self, session_handle: str) -> None:
        """Refresh the TTL on an existing session (extend lifetime).

        Call this periodically for active sessions to prevent premature
        expiration.  No-op if the session doesn't exist.
        """
        key = self._key(session_handle)
        ttl = await self._redis.ttl(key)
        if ttl > 0:
            await self._redis.expire(key, self._ttl)

    async def close(self) -> None:
        """Close the Redis connection pool."""
        await self._redis.aclose()


# ---------------------------------------------------------------------------
# Factory — picks the right backend based on environment.
# ---------------------------------------------------------------------------

def create_session_store() -> SessionStoreBase:
    """Create a session store backed by the configured backend.

    Reads ``POSTERN_REDIS_URL``: if set, returns a
    ``RedisSessionStore``; otherwise returns an ``InMemorySessionStore``.

    This is the recommended entry point for production code:

    .. code-block:: python

        store = create_session_store()  # auto-selects backend
    """
    redis_url = os.environ.get("POSTERN_REDIS_URL")
    if redis_url:
        logger.info("Using Redis session store (url=%s)", redis_url)
        return RedisSessionStore(url=redis_url)
    logger.info("Using in-memory session store (set POSTERN_REDIS_URL for Redis)")
    return InMemorySessionStore()


# ---------------------------------------------------------------------------
# ContextVar — shared across all backends.
# ---------------------------------------------------------------------------

_current_session: ContextVar[RiskContext | None] = ContextVar(
    "postern_risk_session", default=None
)


def get_current_session() -> RiskContext | None:
    """Return the ``RiskContext`` for the current tool call, or ``None``.

    Returns ``None`` when no session is active (e.g. ``start_session``
    itself, or a call arriving without a session handle).
    """
    return _current_session.get()


def set_current_session(ctx: RiskContext | None) -> None:
    """Push a session context onto the current call's stack.

    Called by ``RiskMiddleware`` before ``call_next``; reset after the
    call completes.
    """
    _current_session.set(ctx)


# ---------------------------------------------------------------------------
# Backwards-compatible alias.
# ---------------------------------------------------------------------------

#: Alias for ``InMemorySessionStore`` — kept so existing imports work.
#: New code should use :func:`create_session_store` instead.
SessionStore = InMemorySessionStore

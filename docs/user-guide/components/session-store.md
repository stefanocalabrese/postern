# Session Store

In-memory and Redis backends for per-session risk context, device codes, and revocation lists.

## Overview

Postern uses a pluggable session store pattern across multiple subsystems: risk context,
device authorization codes, and revocation lists. Each subsystem defines an abstract base
class (`StoreBase`) with in-memory (dev/test) and Redis (production) implementations.

```
packages/postern-core/src/postern_core/risk/session.py      Risk context session store
packages/postern-core/src/postern_core/auth/device_codes.py  Device code store
packages/postern-core/src/postern_core/auth/revocation.py    Revocation list
```

## Session Store Pattern

### Abstract Base Class

All stores implement a common interface:

```python
class SessionStoreBase(ABC):
    @abstractmethod
    async def get_session(self, session_id: str) -> RiskContext | None: ...

    @abstractmethod
    async def set_session(self, session_id: str, context: RiskContext) -> None: ...

    @abstractmethod
    async def delete_session(self, session_id: str) -> None: ...

    @abstractmethod
    async def close(self) -> None: ...  # Cleanup resources (Redis connection pool)
```

All methods are `async def`, even the in-memory store uses async so callers can
uniformly `await store.xxx()` regardless of backend.

### Factory Function

```python
def create_session_store() -> SessionStoreBase:
    """Picks backend based on POSTERN_REDIS_URL environment variable."""
    redis_url = os.environ.get("POSTERN_REDIS_URL")
    if redis_url:
        return RedisSessionStore(url=redis_url)
    return InMemorySessionStore()
```

## In-Memory Backend (`InMemorySessionStore`)

Thread-safe enough for FastMCP's in-process test client (single-threaded async).
Not safe across processes, use Redis for that.

```python
class InMemorySessionStore(SessionStoreBase):
    def __init__(self, default_ttl_seconds: int = 480 * 60):
        self._sessions: dict[str, tuple[RiskContext, float]] = {}  # session_id → (context, expiry)
        self._default_ttl = default_ttl

    async def get_session(self, session_id: str) -> RiskContext | None:
        """Returns None if session doesn't exist or has expired."""
        entry = self._sessions.get(session_id)
        if entry is None:
            return None
        context, expiry = entry
        if time.time() >= expiry:
            del self._sessions[session_id]  # Clean up expired
            return None
        return context

    async def set_session(self, session_id: str, context: RiskContext) -> None:
        expiry = time.time() + self._default_ttl
        self._sessions[session_id] = (context, expiry)

    async def delete_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)

    async def close(self) -> None:
        self._sessions.clear()  # No-op for in-memory, but satisfies ABC
```

### TTL-based expiry

Sessions expire after `default_ttl_seconds` (default 480 minutes = 8 hours, matching
`RiskConfig.max_session_age_minutes`). Expired sessions are lazily cleaned up on access.

## Redis Backend (`RedisSessionStore`)

Compatible with any Redis-compatible service: AWS ElastiCache for Redis, Google
Memorystore for Redis, Azure Cache for Redis, or a self-hosted Redis instance.

Sessions are stored as JSON with a TTL matching the session's expiry. The `_start_time`
field is stored as a POSIX timestamp (not `time.monotonic()`), so sessions survive
process restarts.

```python
class RedisSessionStore(SessionStoreBase):
    def __init__(self, url: str | None = None, default_ttl: int | None = None):
        import redis.asyncio as redis
        self._url = url or os.environ.get("POSTERN_REDIS_URL", "redis://localhost:6379/0")
        self._default_ttl = default_ttl or 480 * 60  # 8 hours
        self._redis = redis.from_url(self._url, decode_responses=True)

    def _key(self, session_id: str) -> str:
        return f"postern:session:{session_id}"

    async def get_session(self, session_id: str) -> RiskContext | None:
        data = await self._redis.get(self._key(session_id))
        if data is None:
            return None
        try:
            return RiskContext.from_json(data)
        except (KeyError, ValueError, TypeError):
            return None  # Corrupted data, treat as absent

    async def set_session(self, session_id: str, context: RiskContext) -> None:
        ttl_seconds = max(0, int(self._default_ttl - (time.time() - context.session_start)))
        if ttl_seconds > 0:
            await self._redis.setex(self._key(session_id), ttl_seconds, context.to_json())

    async def delete_session(self, session_id: str) -> None:
        await self._redis.delete(self._key(session_id))

    async def close(self) -> None:
        await self._redis.aclose()
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POSTERN_REDIS_URL` | `redis://localhost:6379/0` | Redis connection string (use `rediss://` for TLS) |
| `POSTERN_REDIS_KEY_PREFIX` | `postern:` | Key prefix for multi-tenant deployments |

## ContextVar Pattern (Per-Call Access)

Each subsystem uses a `ContextVar` for per-call access to the current session context:

```python
from typing import ContextVar

_current_session: ContextVar[RiskContext | None] = ContextVar(
    "current_risk_context", default=None
)

def get_current_session() -> RiskContext | None:
    """Get the current session context from the active call."""
    return _current_session.get()

def set_current_session(session: RiskContext) -> None:
    """Set the session context for the current call."""
    _current_session.set(session)
```

The middleware sets the ContextVar at call start and clears it on completion. This allows
tool handlers to access session state without threading it through every function signature.

## Serialization

Both backends rely on `RiskContext` serialization methods:

```python
# To dict (for Redis storage)
data = context.to_dict()
# {
#     "_records": 42,
#     "_accounts": ["acc_1", "acc_2"],
#     "_max_days": 90,
#     "_start_time": 1697800000.0,    # wall-clock (not monotonic)
#     "_ip_tracker": {"entries": [...]},
#     "_session_id": "sess_abc123",
#     "_risk_signals": [...],
#     "_verification_tier": 0,
# }

# To JSON (for Redis SETEX)
json_str = context.to_json()

# From dict/JSON (reconstruction)
context = RiskContext.from_dict(data)
context = RiskContext.from_json(json_str)
```

Key detail: `_start_time` is stored as a **wall-clock** POSIX timestamp (not
`time.monotonic()`) so the session survives process restarts. On reconstruction,
the monotonic clock is re-derived from the wall-clock value.

## Revocation List (`packages/postern-core/src/postern_core/auth/revocation.py`)

The revocation list is an in-memory set with O(1) lookups. Three scopes:

```python
class RevocationList:
    _session_jtis: set[str]        # Per-session revocation (ends that session)
    _customer_client: set[tuple]   # Per-customer+client revocation (ends all sessions)
    _kill_switch: set[str]         # Per-client kill switch (ends ALL sessions for client)
```

- **Per-session**: Revokes a single session by its JTI (JWT ID)
- **Per-customer+client**: Revokes all sessions for a customer-client pair
- **Kill switch**: Revokes ALL sessions for a client (nuclear option)

> **Note:** The revocation list has had a Redis backend since 2026-09-23
> (`RedisRevocationStore`), the same `create_revocation_store()` pattern as the session
> store and device code store above. Enabling `POSTERN_REQUIRE_REDIS` refuses startup
> without `POSTERN_REDIS_URL`, so production does not fall back to the in-memory,
> per-replica list.

## Device Code Store (`packages/postern-core/src/postern_core/auth/device_codes.py`)

Device codes use the same pluggable pattern:

```python
class DeviceCodeStoreBase(ABC):
    @abstractmethod
    async def create_device_code(self, *, client_id: str, scopes: str, ...) -> DeviceCode: ...
    @abstractmethod
    async def get_device_code(self, device_code: str) -> DeviceCode | None: ...
    @abstractmethod
    async def get_by_display_handle(self, display_handle: str) -> DeviceCode | None: ...
    @abstractmethod
    async def get_by_user_code(self, user_code: str) -> DeviceCode | None: ...
    @abstractmethod
    async def consume_device_code(self, device_code: str) -> bool: ...
    @abstractmethod
    async def claim_scan(self, device_code: str, customer_ref: str) -> ScanClaim: ...
    @abstractmethod
    async def approve_scanned(self, device_code: str, customer_ref: str) -> bool: ...
    @abstractmethod
    async def revoke_device_code(self, device_code: str) -> None: ...
```

There is no whole-row write. `consume_device_code`, `claim_scan` and
`approve_scanned` are compare-and-set operations -- `WATCH`/`MULTI` on Redis, no
`await` between read and write in memory -- because a snapshot read before one of
them and written back after it would silently undo it. The two lookups are
secondary keys created with `SET NX EX`, deleted on revoke and left in place by
consume.

Factory: `create_device_code_store()` picks the backend based on `POSTERN_REDIS_URL`.

## Source References

| Component | File |
|-----------|------|
| Risk session store | [`packages/postern-core/src/postern_core/risk/session.py`](../../../packages/postern-core/src/postern_core/risk/session.py) |
| Device code store | [`packages/postern-core/src/postern_core/auth/device_codes.py`](../../../packages/postern-core/src/postern_core/auth/device_codes.py) |
| Revocation list | [`packages/postern-core/src/postern_core/auth/revocation.py`](../../../packages/postern-core/src/postern_core/auth/revocation.py) |
| Risk context (serialization) | [`packages/postern-core/src/postern_core/risk/context.py`](../../../packages/postern-core/src/postern_core/risk/context.py) |

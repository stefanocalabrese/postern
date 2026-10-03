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

`POSTERN_REDIS_URL` is shared with the revocation list, the device code store and the
refresh-family store, so the Redis behind it must meet their requirements, not only
this store's: Redis 5.0 or later (7.0 or later recommended) with scripting (`EVAL`)
enabled, and **non-clustered**, a standalone instance or a single-shard primary with
replicas, because several steps write more than one key at once and cluster mode
refuses those with `CROSSSLOT` (`dev-docs/device-grant-session-token-spec.md` §6 step
6; measured, with the operations that fail and those that do not, in
`tests/test_redis_cluster_mode.py` and "Topology and version" below). A managed service (AWS ElastiCache, Google Memorystore, Azure Cache for Redis)
qualifies only in a configuration that meets all three.

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

### Topology and version (1 October 2026)

**The Redis must be non-clustered**: a standalone instance, or a single-shard
primary with replicas. Several steps span more than one key: the customer
revocation script writes the pair set, the per-customer
`revoked:customer-at:` key and the per-pair `revoked:pair-at:` key; the kill-switch
script writes the `revoked:clients` set and the per-client `revoked:client-at:` key; `revoke_device_code` deletes a code's primary key,
its index entry and its secondary keys in one `MULTI`/`EXEC`; the refresh-family
store's `discard` deletes a family's key and its index entry in one
`MULTI`/`EXEC`. Redis in cluster mode refuses any of those whose keys hash to
different slots with `CROSSSLOT`, and none of the key names this code builds
carries a hash tag.

**Measured on 3 October 2026** against `redis:7-alpine` as a single-node cluster
owning all 16384 slots (`tests/test_redis_cluster_mode.py`; a single node enforces
the same-slot rule but never answers `MOVED`, and multi-node resharding and managed
cluster endpoints were not measured):

- **Refused with `CROSSSLOT`, writing nothing:** `revoke_customer_client` (3 keys),
  `kill_switch` (2 keys since 3 October 2026: the `revoked:clients` set, slot 2773,
  and `revoked:client-at:<client_id>`, slot 8708 for `vendor-x`; it was a single-key
  `SADD` before), `revoke_session`, `prune_sessions`, `restore_session` and
  `unindexed_session_count` (2 keys each; for `revoke_session` this means the
  opportunistic prune after it never runs, because the revoke itself raised), the
  refresh-family store's `discard`, the conflict revoke inside `claim_scan`, and
  `revoke_device_code`. This is not slot luck: the keys of the default prefix
  `postern:` have pinned slots (for example 9931, 4183, 11233 and 2420 for the
  session set, its index, the pairs set and a customer stamp), asserted against
  `CLUSTER KEYSLOT` in the test.
- **Refused with `CROSSSLOT`, after writing something:** `create_device_code`
  (primary and index in one `MULTI`). The `user_code` and display-handle keys are
  claimed first with `SET NX EX` and stay until their TTL; no primary and no index
  entry exist afterwards.
- **Work, because each command touches one key:** `restore_client` (one `SREM`),
  `entries`, `is_revoked` (a non-transactional pipeline, including its `GET`s of
  the `client-at` and `pair-at` stamps, measured with a seeded entry and stamp),
  `customer_revoked_at`, `client_revoked_at`, `is_customer_revoked`, the refresh store's `create`, `get`, `rotate` and
  `revoke` (`WATCH`/`MULTI` on one key), the device-code store's lookups,
  `claim_scan` (first scan), `approve_scanned` and `consume_device_code`, the
  risk session store, and the customer rate limiter.
- **Not fail-closed everywhere.** The revocation store wraps the refusal in
  `RevocationStoreUnavailable`. The refresh-family and device-code stores wrap
  nothing, so the raw `redis.exceptions.ResponseError` reaches the caller;
  `services/confirm/device_auth.py` catches only `DeviceCodeStoreFull` and
  `DeviceCodeStoreContended` around `create_device_code` (the HTTP path was not
  driven).
- **The A2 second-scanner defence does not happen.** When a second customer scans
  an already-scanned pairing, `claim_scan` is meant to revoke it in one
  transaction. On a cluster that transaction is refused (measured at the store:
  the pairing survives and stays approvable by the first customer). Reading
  `services/confirm/device_auth.py`, not driving it: `_withdraw_pairing` swallows
  the failure and logs at ERROR, and `scan_callback` records a
  `refused("ResponseError")` audit row and re-raises, so the second scanner gets a
  500 and the pairing is not withdrawn.
- **Refresh-family `discard` fails no request.** Its only production caller,
  `_discard_orphan`, catches the exception, logs a warning and lets the request
  succeed, so the refusal leaves an orphaned family until its TTL (read from the
  code, not driven).
- **The startup preflight passes.** `run_redis_preflight` (`TIME`, `CONFIG GET`)
  takes no key and succeeded on the cluster. Only that function was run, not the
  services' composition roots, so "the service boots" is an inference from it. On
  that inference a cluster deployment starts, serves reads, and fails the first
  revocation write or pairing create. A `POSTERN_REDIS_URL` ending in a database
  other than `/0` fails earlier: `SELECT is not allowed in cluster mode`.
- **A hash tag works.** With a prefix such as `{postern}:` in
  `POSTERN_REDIS_KEY_PREFIX` every key lands in one slot. Driven with a tagged
  prefix: all three revocation scripts (customer-client, session, kill switch),
  `restore_client`, `client_revoked_at`, `prune_sessions`, `restore_session`,
  `unindexed_session_count`, `is_revoked`, the refresh `create` and `discard`, and
  the whole device-code lifecycle (create, first scan, conflict revoke). The
  single-key operations were not re-run tagged; they work by inference, since
  they worked untagged. A tag makes one shard hold all of it, so a cluster buys
  no capacity, only failover. It is measured on one node; it is not a supported
  configuration.

The session revocation set `revoked:sessions` has a companion sorted set,
`revoked:sessions:exp` (member `jti`, score the instant after which the entry
may be removed, in milliseconds). Both are written by one script and pruned by
another, so they must share a slot as well. The set itself has no TTL; entries
older than 930 seconds are removed by the prune that each session revoke runs
(up to 1,000 per call) and by `revoke.py prune-sessions`. A `revoked:sessions`
member written by your own backend with a plain `SADD` has no `:exp` entry and
is never pruned; `prune-sessions` prints a lower bound on how many such
members exist. The 930-second retention assumes `POSTERN_JWKS_URI` names
confirm's `/session/jwks.json`, so every revoked `jti` belongs to a token that
lives 600 seconds. A `jti` revoked with the `session` verb for a longer-lived
token from some other issuer would be pruned after 930 seconds while that
token could still verify. It also assumes confirm's clock is not ahead of the
api's by more than about 330 seconds and that Redis `TIME` does not jump
forward by more than about 330 seconds between a revoke and a prune.

**`revoked:client-at:<client_id>` (3 October 2026).** A kill switch stamps when
it was written, in milliseconds on Redis `TIME`, in the same script as its
`SADD`. `restore-kill-switch` leaves the stamp, and it expires after 3,900
seconds (`CLIENT_REVOKED_AT_TTL_SECONDS`: the 3,600-second refresh-family
lifetime plus a 300-second margin, which also covers the 930 seconds the api's
access-token floor needs). While it exists the api refuses an access token of
that client whose `iat` is not more than 2 seconds past the stamp, and confirm
refuses and permanently revokes a refresh family of that client created at or
before it. While the switch stands, confirm also refuses to exchange a device
code carrying that `client_id`; the code stays unspent and exchanges after the
restore. So a restored kill switch lets the client back in for tokens and
pairings issued after the kill, not for what existed at it. The kill switch
keys on the `client_id` a pairing declares, which the browser chooses: a client
that declares a different id is not stopped by it, at the api or at the
exchange. Cut a specific customer with `customer-client` instead. `restore-session`
writes no stamp: it serves the one named access token again and nothing else.

**Redis 5.0 or later, 7.0 or later recommended, with scripting enabled.** The
customer revocation script reads `TIME` and then writes, which is safe only
under effects replication. The Redis scripting introduction
(https://redis.io/docs/latest/develop/programmability/eval-intro/, fetched
1 October 2026): "In Redis 5.0, effects replication became the default mode. As
of Redis 7.0, verbatim replication is no longer supported." The script cache is
volatile, which needs no action: redis-py's `eval` sends the script body on
every call.

**`maxmemory-policy noeviction`.** The Redis behind Postern holds session-store
contexts with TTLs, device codes with TTLs, refresh families with TTLs, and
revocation entries without TTLs. Under eviction policies (`allkeys-lru`,
`allkeys-lfu`, `allkeys-random`) Redis can silently evict any keys when memory
is constrained, including revocation entries (per-session, per-customer+client,
kill-switch) whose loss means a revoked session or customer becomes valid again
(ZT-7 bypass). Set `maxmemory-policy noeviction` so Redis returns an error on
writes instead of evicting; reads continue to work normally. Write failures raise
`SessionStoreUnavailable` or `RevocationStoreUnavailable` in the application, and
the middleware refuses the call (fail-closed). Verify the setting with `redis-cli
CONFIG GET maxmemory-policy`.

Both services check this at startup when `POSTERN_REDIS_URL` is set and
**refuse to start** (`RedisPreflightError`, from `postern_core.auth.redis_preflight`)
unless `CONFIG GET maxmemory-policy` answers exactly `noeviction`. If the server
refuses `CONFIG`, as managed Redis often does, the policy cannot be verified: one
warning is logged and the service starts, so check the setting by hand there. The
check runs once at boot; a later `CONFIG SET` is not detected.

**Clock skew under 2 seconds.** Keep the offset between the confirm service host and this Redis under 2 seconds (NTP or chrony on both, with monitoring). The approval check (`APPROVAL_CLOCK_TOLERANCE_MS`) and the per-pair and per-client revocation floors (`PAIR_IAT_TOLERANCE_MS`) compare confirm's clock with Redis `TIME` and allow 2000 ms. Beyond that, a revocation stamp can miss an approval it should refuse, and tokens minted just before a per-pair or per-client stamp pass the api's floor, so a restore revives them.

Both services measure this at startup when `POSTERN_REDIS_URL` is set and
**refuse to start** (`RedisPreflightError`) when the skew is past 2000 ms. The
check calls Redis `TIME` once, brackets it with the local clock, and refuses
only when the skew minus half the round trip still exceeds the tolerance, so a
slow round trip cannot refuse a healthy deployment. There is no setting that
skips it. It runs at boot only: drift after boot is not detected, so the NTP
monitoring above is still yours.

Accept the startup failure mode: with `POSTERN_REDIS_URL` set, Redis must be reachable before either service will start (connection refused fails in about 0.02 s, a blackholed host after the 5 s socket timeout, once per worker process), so deploy Redis before the services.

## The local stack's Redis: TLS, ACL users, no published port

Since 3 October 2026 `docker compose up` runs Redis the way operator checklist item 6
in `CLAUDE.md` asks a deployment to, with the limits stated below.

- **TLS only.** Redis starts with `--port 0 --tls-port 6379`, so there is no plaintext
  listener. The `redis-certs` one-shot (`dev-redis/gen-certs.sh`, an `alpine/openssl`
  image) writes a 30-day dev CA and a server certificate whose SANs are `DNS:redis` and
  `DNS:localhost` to named volumes at `up` time. Nothing is committed. The services
  mount only the CA certificate (`redis-ca`) and trust it through the URL:
  `rediss://...@redis:6379/0?ssl_ca_certs=/redis-ca/ca.crt&ssl_check_hostname=true`.
  Every Redis client in the code is built by `redis.from_url` or
  `redis.Redis.from_url`, the startup preflight included, so those query parameters
  reach all of them.
- **AUTH with one ACL user per service.** `dev-redis/users.acl` turns the `default` user
  off and defines `postern_api`, `postern_confirm` and a ping-only `postern_health`
  for the healthcheck. `tests/test_redis_acl_users.py` loads that file into a throwaway
  Redis and drives the real stores through each user, so a command the code issues and
  the file does not grant fails `make ci`.
- **No published port.** `redis` has no `ports:` mapping. Reach it from the host with
  `docker compose exec redis redis-cli --tls --cacert /tls/ca.crt --user ... --pass ...`.

What it is not: the certificates are throwaway dev certificates, not an operator's PKI;
`--tls-auth-clients no` means Redis does not ask a client for a certificate (the ACL
password is the credential, so mutual TLS is not exercised); the passwords are plaintext
in `dev-redis/users.acl` and `docker-compose.yml`; the `api` fetch of `confirm`'s JWKS is
still plain HTTP inside the compose network. `create_device_code_store` logs the Redis
URL at INFO on startup with the password replaced by `***` (`postern_core.config.redact_url`),
so the username, host, port and query stay in the log line and the password does not.
If you log the URL anywhere else, redact it the same way.

### Which service touches which keys, and with which commands

Derived from the code, not from a command category. The key patterns assume the default
`POSTERN_REDIS_KEY_PREFIX` of `postern:`; set another prefix and the patterns in
`dev-redis/users.acl` must follow.

| User | Key pattern | Commands | Issued by |
|------|-------------|----------|-----------|
| `postern_api` | `postern:revoked:*` (read-only, `%R~`) | `SISMEMBER`, `GET` | `RedisRevocationStore.is_revoked`, called by `RevocationMiddleware` |
| `postern_api` | `postern:risk:*` | `GET`, `SETEX`, `DEL`, `EXPIRE` | `RedisSessionStore.load`, `save`, `remove` |
| `postern_confirm` | `postern:device:*` | `SET` (NX EX, KEEPTTL), `SETEX`, `GET`, `DEL`, `ZADD`, `ZREM`, `ZREMRANGEBYSCORE`, `ZCARD`, `WATCH`, `EVAL` (script runs `GET` and `DEL`) | `RedisDeviceCodeStore` |
| `postern_confirm` | `postern:refresh:*` | `SET` (NX EX, KEEPTTL), `GET`, `DEL`, `ZADD`, `ZREM`, `ZREMRANGEBYSCORE`, `ZCARD`, `WATCH` | `RedisRefreshSessionStore` |
| `postern_confirm` | `postern:revoked:sessions`, `postern:revoked:sessions:exp` (write) | `EVAL` (scripts run `SADD`, `ZSCORE`, `ZADD`, `ZRANGEBYSCORE`, `SREM`, `ZREM`) | `RedisRevocationStore.revoke_session`, `prune_sessions` |
| `postern_confirm` | `postern:revoked:*` (read-only, `%R~`) | `SISMEMBER`, `SMEMBERS`, `GET` | `is_revoked`, `is_customer_revoked`, `customer_revoked_at`, `client_revoked_at` |
| `postern_confirm` | `postern:ratelimit:*` | `SET` (NX EX), `INCRBY` (what redis-py sends for `incr`), `TTL` | `RedisCustomerRateLimitStore.charge` |
| both | none | `TIME`, `CONFIG GET`, `CLIENT SETINFO` | `run_redis_preflight`; redis-py on connect |
| `postern_confirm` | none | `MULTI`, `EXEC`, `UNWATCH` | the transaction envelope redis-py wraps around `WATCH` |
| `postern_operator` | `postern:revoked:*` (read and write) | direct: `EVAL`, `SADD`, `SREM`, `SMEMBERS`, `SCARD`, `ZREM`, `ZCARD`, `MULTI`, `EXEC`; inside the Lua scripts only: `TIME`, `SADD`, `SREM`, `SET`, `ZADD`, `ZSCORE`, `ZREM`, `ZRANGEBYSCORE` | the `RedisRevocationStore` methods `postern_core.auth.revoke_cli` calls: `revoke_session`, `restore_session`, `prune_sessions`, `unindexed_session_count`, `revoke_customer_client`, `restore_customer_client`, `kill_switch`, `restore_client`, `entries` |
| `postern_operator` | none | `CLIENT SETINFO` | redis-py on connect |

`api` cannot touch device codes, refresh families or rate-limit counters, and `confirm`
cannot touch `postern:risk:*`. `api` cannot write the revocation list at all, and
`confirm` writes only the two session keys: the kill-switch set (`revoked:clients`) and
the customer-client set (`revoked:customer-clients`) are operator-owned and `confirm`
can read them but not `SADD` or `SREM` them. Neither user holds `+@all`, `KEYS`, `SCAN`,
`FLUSHALL`, `CONFIG SET` or `ACL`.

**The cost of `CONFIG GET`.** Redis 7 cannot narrow it to one parameter:
`+config|get|maxmemory-policy` is rejected ("Allowing first-arg of a subcommand is not
supported", measured against `redis:7-alpine`), so granting it lets both service users
run `CONFIG GET *`. That reads every configuration value, including `masterauth` and
`tls-key-file-pass` in clear on a deployment that sets them (empty in this stack, which
sets neither). The choice is yours. Grant `+config|get` only if you keep the preflight's
`maxmemory-policy` check working; or deny it and accept that the check then logs its
"cannot be verified" warning and the service starts, leaving you to check `noeviction`
by hand. The compose stack grants it.

Not granted to either service, deliberately: `revoke_customer_client`, `kill_switch`,
`restore_*`, `entries` and `unindexed_session_count` need write access to the
operator-owned revocation keys, `SET`, `SCARD` and `ZCARD`, and are called only by the
operator CLI (`tools/revoke.py`, which is `postern_core.auth.revoke_cli`), never by a
service. Run as a service user the CLI is partly or wholly refused:
`postern_api` can run none of its verbs, because it holds only `SISMEMBER` and `GET`
on the revocation keys. `postern_confirm` can run `session`, `restore-session` and
`list` (its grants on the two session keys and its `SMEMBERS` read), cannot finish
`prune-sessions` (the prune script runs, but the `SCARD` and `ZCARD` count that follows
is refused and the CLI reports a failure), and cannot run `customer-client`,
`restore-customer-client`, `kill-switch` or `restore-kill-switch`. That is read off the
ACL file, not measured for each verb.

**The operator user.** `dev-redis/users.acl` carries a third user, `postern_operator`
(dev password `postern-operator-dev`), with the commands in the table on
`~postern:revoked:*` and nothing else: no `KEYS`, `SCAN`, `FLUSH*`, `CONFIG` or `ACL`,
and no key outside that prefix (`tests/test_redis_acl_users.py::TestOperatorUser` runs
every store method the CLI calls as this user except the plain `GET` of
`customer_revoked_at`, which no verb issues, and shows each refusal). Neither service is configured with it. Redis is not published,
so the supported way to run the CLI against the compose stack is the `revoke` one-shot,
which sits in the `operator` profile, so `docker compose up` does not start it, builds
the `api` target (the same layers under its own image tag), joins the compose network
and mounts the CA volume read-only:

```bash
docker compose run --rm revoke session <jti>
docker compose run --rm revoke prune-sessions
docker compose run --rm revoke list
```

In a deployment, give the operator's own ACL user the same grants, a real password and
`rediss://`, and run the CLI from a bastion or one-off task that can reach Redis. The
patterns follow `POSTERN_REDIS_KEY_PREFIX` if you change it.

Since 3 October 2026 `kill-switch` is one `EVAL` whose script runs `TIME`, `SADD` on
`postern:revoked:clients` and `SET ... EX` on `postern:revoked:client-at:<client_id>`
(before, it was a bare `SADD`). `postern_operator` already covers it: `+time`,
`+eval`, `+sadd` and `+set` on `~postern:revoked:*`, and `TestOperatorUser` runs
`kill_switch` as that user with no ACL denial. If you write your own operator user
with narrower patterns, it needs `SET` on `revoked:client-at:*` as well as `SADD` on
`revoked:clients`. `restore-kill-switch` is still a bare `SREM` on
`postern:revoked:clients` and leaves the stamp.

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
    async def consume_device_code(self, device_code: str, *, session_id: str) -> bool: ...
    @abstractmethod
    async def claim_scan(
        self, device_code: str, customer_ref: str, *, scanner_ip: str | None
    ) -> ScanClaim: ...
    @abstractmethod
    async def approve_scanned(self, device_code: str, customer_ref: str) -> bool: ...
    @abstractmethod
    async def revoke_device_code(self, device_code: str) -> None: ...
```

There is no whole-row write. `consume_device_code`, `claim_scan` and
`approve_scanned` are compare-and-set operations -- `WATCH`/`MULTI` on Redis, no
`await` between read and write in memory -- because a snapshot read before one of
them and written back after it would silently undo it. On the Redis backend the two lookups are
secondary keys created with `SET NX EX`, deleted on revoke and left in place by
consume; the in-memory backend keeps them in dicts. A secondary key is deleted
only while it still names the code being revoked, through a one-line Lua
compare-and-delete sent with `EVAL`, so the Redis you point `POSTERN_REDIS_URL` at
must allow scripting: a managed Redis with `EVAL` disabled fails every revoke.

Factory: `create_device_code_store()` picks the backend based on `POSTERN_REDIS_URL`.

## Source References

| Component | File |
|-----------|------|
| Risk session store | [`packages/postern-core/src/postern_core/risk/session.py`](../../../packages/postern-core/src/postern_core/risk/session.py) |
| Device code store | [`packages/postern-core/src/postern_core/auth/device_codes.py`](../../../packages/postern-core/src/postern_core/auth/device_codes.py) |
| Revocation list | [`packages/postern-core/src/postern_core/auth/revocation.py`](../../../packages/postern-core/src/postern_core/auth/revocation.py) |
| Risk context (serialization) | [`packages/postern-core/src/postern_core/risk/context.py`](../../../packages/postern-core/src/postern_core/risk/context.py) |

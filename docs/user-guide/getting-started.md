# Getting Started

Prerequisites, installation, configuration, and local development stack.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.12+ | Pinned in `.python-version` |
| uv | Latest stable | Project dependency manager and runner |
| PostgreSQL | 15+ | For consents, audit_log, challenges tables |
| Docker / Podman | Any recent | For local development stack (optional) |
| Redis | 7+ | Required in production (`POSTERN_REQUIRE_REDIS=1`); optional locally |

## Installation

### Clone and sync dependencies

```bash
git clone https://github.com/YOUR_ORG/postern.git
cd postern
uv sync
```

### Verify the toolchain

```bash
make ci
```

This runs: `lint`, `fmt-check`, `type`, `imports`, `lock`, `citations`, `test`.
Run locally because GitHub Actions minutes are billed on private repos.

### Format code

```bash
make fmt        # format all Python files in packages, services, tests
```

> **Note:** `fmt-check` is scoped to `packages services tests`, not `.`, because
> `ruff format` on `.` also rewrites the Python code fences inside markdown design docs.

## Configuration

Both services read configuration from environment variables prefixed with `POSTERN_`.
The table below lists every variable, grouped by service.

### API Service (`services/api/settings.py`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTERN_BACKEND_BASE_URL` | **Yes** | - | Base URL of the operator's backend (accounts.svc, payments.svc) |
| `POSTERN_DATABASE_URL` | No | `postgresql+asyncpg://postern:postern@localhost:5432/postern` | Postgres connection string for audit + consent tables |
| `POSTERN_READ_KEY_PEM_PATH` | No | - | Path to the PEM file for signing internal read tokens. If unset, an ephemeral key is generated in-process (not suitable for production) |
| `POSTERN_READ_KEY_KID` | No | `read-1` | Key ID published in the read JWKS |
| `POSTERN_READ_TOKEN_ISSUER` | No | `https://mcp-read.internal` | `iss` claim on internal read tokens |
| `POSTERN_JWKS_URI` | No | - | URL where customer JWTs were signed (for consent enforcement). Leave unset for no-auth mode |
| `POSTERN_TOKEN_ISSUER` | No | - | Expected issuer of customer JWTs. Leave unset for no-auth mode |
| `POSTERN_AUDIENCE` | No | `postern` | Expected `aud` claim on customer JWTs |
| `POSTERN_STRICT_HEADERS` | No | `0` | Enable strict MCP Streamable HTTP header validation (Mcp-Method/Mcp-Name must match body) |
| `POSTERN_TRUSTED_PROXY_HOPS` | No | `0` | Proxies in front of this service that append to `X-Forwarded-For`; the risk engine reads the n-th entry from the right. **Zero or greater**; zero trusts the header for nothing and uses the socket peer |
| `POSTERN_CACHE_TTL_SECONDS` | No | `60` | Consent domain cache TTL per request. **At least 1**; FastMCP refuses a cache TTL of zero when the server is built |
| `POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS` | No | `2.0` | Backend connection timeout (seconds). **Greater than 0**; at zero every backend request fails `ConnectTimeout` |
| `POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS` | No | `2.0` | Backend write timeout (seconds). **Greater than 0** |
| `POSTERN_BACKEND_READ_TIMEOUT_SECONDS` | No | `5.0` | Backend read timeout (seconds). **Greater than 0** |
| `POSTERN_BACKEND_POOL_TIMEOUT_SECONDS` | No | `1.0` | Backend connection pool timeout (seconds). **Zero or greater**; zero sheds rather than queueing when the pool is saturated |
| `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` | No | `2.0` | Database connection timeout (seconds). **Greater than 0**; at zero every connection raises `TimeoutError` |
| `POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS` | No | `3.0` | Database statement timeout (seconds). **Greater than 0**; asyncpg rejects zero itself, at the first connect |
| `POSTERN_DATABASE_POOL_TIMEOUT_SECONDS` | No | `1.0` | Database pool timeout (seconds). **Zero or greater**; zero sheds rather than queueing when the pool is saturated |
| `POSTERN_DATABASE_POOL_SIZE` | No | `5` | Connections this replica keeps open. **At least 1**; zero is SQLAlchemy's spelling of "unlimited", not of "small" |
| `POSTERN_DATABASE_MAX_OVERFLOW` | No | `10` | Connections this replica may open above `POSTERN_DATABASE_POOL_SIZE` and close again on return. **Zero or greater**; zero means no burst, and `-1` is the off switch |
| `POSTERN_MAX_BODY_BYTES` | No | `1048576` (1 MiB) | Maximum request body size in bytes. **At least 1**; at zero every request carrying a body is refused 413 |
| `POSTERN_REQUEST_DEADLINE_SECONDS` | No | `101.0` | Wall-clock bound on the whole HTTP request (see [Audit System](components/audit.md)). **Greater than 0**, and finite: there is no off switch, raise the number instead |
| `POSTERN_REQUIRE_PEM_KEY` | No | - | Set to `"1"` to refuse startup with an ephemeral read key |
| `POSTERN_REQUIRE_REDIS` | No | - | Set to exactly `"1"` to refuse startup without `POSTERN_REDIS_URL`. Enforced by **both** services since 26 September 2026; `services/api` alone before that. No other spelling arms it — `true` and `yes` are silently ignored |
| `POSTERN_REDIS_URL` | No | - | Redis connection string (for sessions, device codes, revocation lists, per-customer approval counters). Unset, each is per-replica: a revocation cuts one replica, a spent device code stays redeemable on the others, and R replicas admit R times the per-customer ceilings below. Point **both** services at the same instance — nothing checks that they agree |
| `POSTERN_REDIS_SESSION_TTL` | No | `1800` (30 min) | How long a risk context accumulates its ZT-5 budget, on the Redis session store. **At least 1**; at zero every load answers `None`, so every call starts from an empty budget |

### Confirm Service (`services/confirm/settings.py`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTERN_APP_ASSERTION_JWKS_URI` | **Yes** | - | JWKS of the operator's banking-app backend, used to verify inbound assertions |
| `POSTERN_APP_ASSERTION_ISSUER` | **Yes** | - | Expected `iss` on inbound app assertions |
| `POSTERN_APP_ASSERTION_AUDIENCE` | **Yes** | - | Expected `aud` on inbound app assertions. Must **not** equal the API service's `POSTERN_AUDIENCE` |
| `POSTERN_USER_CODE_MAX_ATTEMPTS` | No | `3` | Wrong pairing codes at `/approve` before the device code is revoked (RFC 8628 §5.2). **At least 1**, which is already zero tolerance: one typo then revokes the code |
| `POSTERN_WRITE_KEY_PEM_PATH` | No | - | Path to the PEM file for signing internal write tokens |
| `POSTERN_WRITE_KEY_KID` | No | `write-1` | Key ID published in the write JWKS |
| `POSTERN_WRITE_TOKEN_ISSUER` | No | `https://mcp-write.internal` | `iss` claim on internal write tokens |
| `POSTERN_CONFIRM_MAX_BODY_BYTES` | No | `65536` (64 KiB) | Maximum request body size in bytes on the write path, separate from the API service's `POSTERN_MAX_BODY_BYTES`. **At least 1** |
| `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` | No | `0` | Proxies in front of this service that append to `X-Forwarded-For`. **Zero or greater**; zero trusts the header for nothing and uses the socket peer |
| `POSTERN_MAX_DEVICE_CODES` | No | `10000` | Device codes the store will hold before refusing new pairings. **At least 1**; at zero the cap is met by an empty store |
| `POSTERN_MAX_SCOPES_LENGTH` | No | `512` | Ceiling on the `scopes` string at `/device_authorization`. **At least 42**, the length of the default this endpoint substitutes when a caller sends none |
| `POSTERN_MAX_CLIENT_ID_LENGTH` | No | `256` | Ceiling on the `client_id` string. **At least 1**; `client_id` is required and non-empty |
| `POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION` | No | `60` | Requests per minute per client address bucket. **At least 1**; there is no value that disables the limit |
| `POSTERN_CONFIRM_RATE_LIMIT_TOKEN` | No | `300` | As above, for `/token` |
| `POSTERN_CONFIRM_RATE_LIMIT_APPROVE` | No | `60` | As above, for `/approve`. Raise this if the banking app calls from its own backend rather than from the phone |
| `POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE` | No | `60` | As above, for the challenge approval callback |
| `POSTERN_CONFIRM_RATE_LIMIT_DEFAULT` | No | `60` | As above, for every other path |
| `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_APPROVE` | No | `10` | Requests per minute per **customer** (the verified assertion `sub`), for `/approve`. A second limiter behind the assertion check; the address-keyed one above stays in front. **At least 1** |
| `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE` | No | `10` | As above, for the challenge approval callback. One payment approval is one tap on a phone, so ten a minute is already well above what a person does |
| `POSTERN_DEVICE_VERIFICATION_URI` | No | `https://auth.postern.internal/verify` | Base URI for the user verification page (QR code target) |
| `POSTERN_DEVICE_CODE_TTL_SECONDS` | No | `900` (15 min) | Lifetime of a device code. Refused at startup below 30 seconds — the Redis store cannot represent a shorter one |
| `POSTERN_REDIS_DEVICE_CODE_TTL` | No | `900` (15 min) | Lifetime a device code gets when the caller passes no `expires_in`, on the Redis store. Refused below the same 30 seconds, and for the same reason: it sets the lifetime of the same object |
| `POSTERN_DEVICE_POLL_INTERVAL_SECONDS` | No | `5` | Minimum seconds between token polls. **At least 1**; must also stay below `POSTERN_DEVICE_CODE_TTL_SECONDS`, which is not checked: an interval at or above the lifetime expires the code before the browser may poll once |
| `POSTERN_READ_KEY_PEM_PATH` | No | - | Read key PEM path (needed for device grant token exchange) |
| `POSTERN_READ_KEY_KID` | No | `read-1` | Read key ID (must match API service) |
| `POSTERN_READ_TOKEN_ISSUER` | No | `https://mcp-read.internal` | Read token issuer (must match API service) |
| `POSTERN_BACKEND_BASE_URL` | No | `https://backend.internal` | Base URL for backend write endpoints (payments.svc, cards.svc) |
| `POSTERN_DATABASE_URL` | No | `postgresql+asyncpg://postern:postern@localhost:5432/postern` | Postgres connection string for challenges table |
| `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` | No | `2.0` | Database connection timeout (seconds). **Greater than 0**; at zero every connection raises `TimeoutError` |
| `POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS` | No | `3.0` | Database statement timeout (seconds). **Greater than 0**; asyncpg rejects zero itself, at the first connect |
| `POSTERN_DATABASE_POOL_TIMEOUT_SECONDS` | No | `1.0` | Database pool timeout (seconds). **Zero or greater**; zero sheds rather than queueing when the pool is saturated |
| `POSTERN_CONFIRM_DATABASE_POOL_SIZE` | No | `5` | Connections this replica keeps open, separate from the API service's `POSTERN_DATABASE_POOL_SIZE`. **At least 1** |
| `POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW` | No | `5` | Burst above `POSTERN_CONFIRM_DATABASE_POOL_SIZE`. **Zero or greater**. Lower than the API service's 10 because one approval is one person tapping a phone, and both services draw on one `max_connections` |

The three `POSTERN_APP_ASSERTION_*` variables are the only **required** settings on
either service. `create_confirm_app()` raises `ValueError` and the process does not
start without all three. The API service may run with no authentication for local
development; the confirm service may not, because it holds the write signing key and
its endpoints approve money movement.

Setting `POSTERN_APP_ASSERTION_AUDIENCE` to the same value as the API service's
`POSTERN_AUDIENCE` would mean a customer token good enough to list a balance is also
good enough to approve a payment. Neither process can detect that — they are separate
deployments reading separate environments — so keeping them distinct is an operator
requirement, not something a gate here will catch.

### Sizing the connection pools

The four pool variables above are the one set of numbers this repository cannot
pick for you, because the constraint involves your replica count and your
database's limit and neither is visible from here:

```
  api_replicas     x (POSTERN_DATABASE_POOL_SIZE + POSTERN_DATABASE_MAX_OVERFLOW)
+ confirm_replicas x (POSTERN_CONFIRM_DATABASE_POOL_SIZE + POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW)
+ migrations, psql, monitoring, backups
<= max_connections - superuser_reserved_connections
```

Both services connect to the same database, so both sides count against one
limit. On an unmodified PostgreSQL 17 those two server settings are 100 and 3
(measured); a managed instance sets its own, so read them with
`SHOW max_connections` against the instance you will actually deploy against.
Going over is not a slowdown, it is a refusal at connect:
`asyncpg.exceptions.TooManyConnectionsError: sorry, too many clients already`.

At the defaults, four API replicas and two confirm replicas hold
`4x15 + 2x10 = 80` connections, which leaves 17 of the default 100 once the 3
reserved slots are taken. Six and three would need 120 and does not fit.

A pool holds one connection per in-flight *request*, not per request's worth of
work: a tool call costs two to seven checkouts one after another, and an
approval costs four. `dev-docs/decisions/0013-connection-pool-ceiling.md` has
the derivation, what a saturated pool looks like from the customer's side, and
when raising these is the right response.

### Environment variable conventions

- **Empty string = off**: For optional settings like `POSTERN_JWKS_URI`, setting the value
  to `""` is treated as unset (collapsed to `None`). This lets docker-compose use
  `POSTERN_JWKS_URI=""` to disable a feature. Numeric settings follow the same rule: an empty
  string means "keep the default", never "zero".
- **Numeric settings are bounded at startup**: every number above is checked when
  `from_env()` runs, and a value outside its stated range raises a `ValueError` naming the
  variable, the bound and the value that was set. The process then fails to start rather
  than serving requests on a setting that cannot work. A bound says what is
  *representable*, never what is *advisable*: `POSTERN_MAX_BODY_BYTES=1` is accepted and
  is still a service that refuses almost every request.
- **Production hardening flags**: `POSTERN_REQUIRE_PEM_KEY=1` and `POSTERN_REQUIRE_REDIS=1`
  cause the service to refuse startup if the required resource is not configured. These
  should be set in all production deployments.

## Local Development Stack

The project ships a `docker-compose.yml` that brings up:

| Service | Port | Purpose |
|---------|------|---------|
| `db` (PostgreSQL) | 5432 | Audit log, consents, challenges tables |
| `backend-stub` | 8081 | Stub operator backend with local IdP (JWKS + token minting) |
| `api` | 8080 | MCP read path: tools, OAuth endpoints |
| `confirm` | 8082 (mapped to 8080 inside container) | Write path: device auth, approval callback |

### Start the stack

```bash
docker compose up --build
```

The API service will be available at `http://localhost:8080/mcp`.

### Run migrations

```bash
uv run alembic upgrade head
```

Migrations live in `migrations/versions/`. Each migration adds or alters a table/column
used by the audit log, consent enforcement, risk signals, or challenges.

### Run tests

```bash
uv run pytest                    # all tests (requires Docker for DB-backed tests)
uv run pytest -m "not db"       # skip database-backed tests (no Docker needed)
```

### Run a single service directly

```bash
# API service (read path)
uv run uvicorn services.api.main:app --reload --port 8080

# Confirm service (write path) — the three assertion variables are REQUIRED;
# without them the process exits at startup instead of serving unauthenticated.
POSTERN_APP_ASSERTION_JWKS_URI=http://localhost:8081/.well-known/jwks.json \
POSTERN_APP_ASSERTION_ISSUER=https://postern-local-dev.invalid \
POSTERN_APP_ASSERTION_AUDIENCE=postern-confirm \
  uv run uvicorn services.confirm.main:app --reload --port 8082
```

`docker compose up` sets all three for the `confirm` container already; only the
bare `uvicorn` invocation above needs them spelled out.

## Production Deployment

Before deploying, ensure the following configuration items are set:

| Item | Variable(s) | Purpose |
|------|-------------|---------|
| Persisted read key | `POSTERN_READ_KEY_PEM_PATH` | Not ephemeral: survives restarts |
| Persisted write key | `POSTERN_WRITE_KEY_PEM_PATH` | Not ephemeral: survives restarts |
| Redis backend | `POSTERN_REDIS_URL`, `POSTERN_REQUIRE_REDIS=1` | Session store and device code persistence |
| JWKS / issuer URIs | `POSTERN_JWKS_URI`, `POSTERN_TOKEN_ISSUER` | Customer JWT validation |
| Strict headers | `POSTERN_STRICT_HEADERS=1` | Enforce MCP Streamable HTTP header compliance |
| Require PEM key | `POSTERN_REQUIRE_PEM_KEY=1` | Refuse startup with ephemeral keys |
| Istio JWT validation | - | Domain services must scope queries by token `sub` |
| Database migrations | - | Run `alembic upgrade head` before first startup |

## Next Steps

- Read the [API Service](components/api-service.md) chapter for details on MCP tools,
  OAuth endpoints, and consent enforcement.
- Read the [Confirm Service](components/confirm-service.md) chapter for device auth,
  approval callbacks, and payment execution.
- Read the [Glossary](glossary.md) for key terms across the platform.
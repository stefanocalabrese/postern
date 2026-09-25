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
| `POSTERN_CACHE_TTL_SECONDS` | No | `60` | Consent domain cache TTL per request |
| `POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS` | No | `2.0` | Backend connection timeout (seconds) |
| `POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS` | No | `2.0` | Backend write timeout (seconds) |
| `POSTERN_BACKEND_READ_TIMEOUT_SECONDS` | No | `5.0` | Backend read timeout (seconds) |
| `POSTERN_BACKEND_POOL_TIMEOUT_SECONDS` | No | `1.0` | Backend connection pool timeout (seconds) |
| `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` | No | `2.0` | Database connection timeout (seconds) |
| `POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS` | No | `3.0` | Database statement timeout (seconds) |
| `POSTERN_DATABASE_POOL_TIMEOUT_SECONDS` | No | `1.0` | Database pool timeout (seconds) |
| `POSTERN_MAX_BODY_BYTES` | No | `1048576` (1 MiB) | Maximum request body size in bytes |
| `POSTERN_REQUEST_DEADLINE_SECONDS` | No | `101.0` | Wall-clock bound on the whole HTTP request (see [Audit System](components/audit.md)) |
| `POSTERN_REQUIRE_PEM_KEY` | No | - | Set to `"1"` to refuse startup with an ephemeral read key |
| `POSTERN_REQUIRE_REDIS` | No | - | Set to `"1"` to refuse startup without `POSTERN_REDIS_URL` |
| `POSTERN_REDIS_URL` | No | - | Redis connection string (for sessions, device codes, revocation lists) |

### Confirm Service (`services/confirm/settings.py`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTERN_APP_ASSERTION_JWKS_URI` | **Yes** | - | JWKS of the operator's banking-app backend, used to verify inbound assertions |
| `POSTERN_APP_ASSERTION_ISSUER` | **Yes** | - | Expected `iss` on inbound app assertions |
| `POSTERN_APP_ASSERTION_AUDIENCE` | **Yes** | - | Expected `aud` on inbound app assertions. Must **not** equal the API service's `POSTERN_AUDIENCE` |
| `POSTERN_USER_CODE_MAX_ATTEMPTS` | No | `3` | Wrong pairing codes at `/approve` before the device code is revoked (RFC 8628 §5.2) |
| `POSTERN_WRITE_KEY_PEM_PATH` | No | - | Path to the PEM file for signing internal write tokens |
| `POSTERN_WRITE_KEY_KID` | No | `write-1` | Key ID published in the write JWKS |
| `POSTERN_WRITE_TOKEN_ISSUER` | No | `https://mcp-write.internal` | `iss` claim on internal write tokens |
| `POSTERN_DEVICE_VERIFICATION_URI` | No | `https://auth.postern.internal/verify` | Base URI for the user verification page (QR code target) |
| `POSTERN_DEVICE_CODE_TTL_SECONDS` | No | `900` (15 min) | Lifetime of a device code. Refused at startup below 30 seconds — the Redis store cannot represent a shorter one |
| `POSTERN_DEVICE_POLL_INTERVAL_SECONDS` | No | `5` | Minimum seconds between token polls |
| `POSTERN_READ_KEY_PEM_PATH` | No | - | Read key PEM path (needed for device grant token exchange) |
| `POSTERN_READ_KEY_KID` | No | `read-1` | Read key ID (must match API service) |
| `POSTERN_READ_TOKEN_ISSUER` | No | `https://mcp-read.internal` | Read token issuer (must match API service) |
| `POSTERN_BACKEND_BASE_URL` | No | `https://backend.internal` | Base URL for backend write endpoints (payments.svc, cards.svc) |
| `POSTERN_DATABASE_URL` | No | `postgresql+asyncpg://postern:postern@localhost:5432/postern` | Postgres connection string for challenges table |
| `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` | No | `2.0` | Database connection timeout (seconds) |
| `POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS` | No | `3.0` | Database statement timeout (seconds) |
| `POSTERN_DATABASE_POOL_TIMEOUT_SECONDS` | No | `1.0` | Database pool timeout (seconds) |

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

### Environment variable conventions

- **Empty string = off**: For optional settings like `POSTERN_JWKS_URI`, setting the value
  to `""` is treated as unset (collapsed to `None`). This lets docker-compose use
  `POSTERN_JWKS_URI=""` to disable a feature.
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
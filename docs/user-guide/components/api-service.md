# API Service (Read Path)

MCP tools, OAuth endpoints, consent checks, the read-facing deployable.

## Overview

The API service exposes MCP tools to AI clients over HTTP (Streamable HTTP transport).
It is the **read path** of Postern: all registered tools are read-only. Write operations
(proposed by the model via `payments.create_payment`) trigger a verification challenge
that is executed server-side through the confirm service.

```
packages/postern-core/src/postern_core/facade/     HTTP client to operator backend
services/api/main.py                                Composition root (create_app)
services/api/server.py                              FastMCP server builder
services/api/tools/                                 MCP tool handlers (accounts, transactions, cards)
services/api/asgi/request_deadline.py               Outermost ASGI middleware, request deadline
services/api/asgi/header_validation.py              MCP Streamable HTTP header/body validation
services/api/consent.py                             Per-tool consent authorization
services/api/middleware/risk.py                     Risk middleware, per-session context tracking
services/api/middleware/audit.py                    Two-row audit pattern, fail-closed writes
```

## Composition Root

The app is assembled by `create_app()` in [`services/api/main.py`](../../../services/api/main.py).
The function is called lazily via PEP 562 `__getattr__` so that `import services.api.main`
does not require a full production environment at import time.

```python
# Lazy module attribute, create_app() called only when `app` is accessed
def __getattr__(name: str) -> object:
    if name == "app":
        return create_app()
    raise AttributeError(...)
```

Production starts the process with: `uvicorn services.api.main:app`.

### Startup sequence

1. **Key source resolution**, reads `POSTERN_READ_KEY_PEM_PATH` or generates an ephemeral key
2. **Minter construction**, `ReadTokenMinter` wraps `InternalTokenMinter` with
   continuous authorization (revocation list + JTI replay cache)
3. **Startup probe**, mints one token, verifies it against the JWKS this process publishes;
   refuses to start on mismatch ([ADR-0003](../../decisions/0003-composition-root.md))
4. **Backend client**, `BackendClient` with timeout budgets and audit hook
5. **Database**, async SQLAlchemy engine with per-phase timeouts
6. **Consent DB**, wired only when real customer auth is configured
7. **Session store**, in-memory (dev) or Redis (production) via `create_session_store()`
8. **Server builder**, FastMCP server with middleware chain
9. **JWKS route**, appended to router at `/.well-known/jwks.json`

## ASGI Middleware Chain

Middleware is installed inside `server.http_app()`. Starlette wraps the list in reverse,
so index 0 is the **outermost** (first to receive a request):

```
Request → [Deadline] → [HeaderValidation] → FastMCP server
                                         → [AuditMiddleware]
                                         → [RiskMiddleware]
                                         → Tool handler
```

### Request Deadline (`services/api/asgi/request_deadline.py`)

Bounds the **entire HTTP request** from first byte to last. Prevents worker leaks when
both the database and backend are silent (no timeout fires on a path that returns nothing).

- Default: `101.0` seconds (`POSTERN_REQUEST_DEADLINE_SECONDS`)
- Derived from: DB operation ceiling (13.0s) × 4 + backend request (10.0s) + consent
  lookups (5 × 13.0s). Realistic success ceiling: ~49.0s; realistic denial ceiling: ~78.0s
- Zero and negative values are refused at startup (no off switch)

### Header/Body Validation (`services/api/asgi/header_validation.py`)

Enforces MCP Streamable HTTP spec compliance:

- Rejects requests where `Mcp-Method` / `Mcp-Name` headers don't match body values
  (HTTP 400 + JSON-RPC `-32020`)
- Bounds request body to `POSTERN_MAX_BODY_BYTES` (default 1 MiB)
- Prevents request smuggling via header/body mismatch

## MCP Tools

Five read-only tools are registered. Every one except `start_session` is gated by a
Postgres-backed consent check:

| Tool | Domain | Consent Required | Description |
|------|--------|-----------------|-------------|
| `start_session` | - | No | Initiates an RFC 8628 device grant flow |
| `accounts.list` | accounts.svc | Yes | Lists customer accounts |
| `accounts.get_balance` | accounts.svc | Yes | Returns balance for a specific account |
| `transactions.list` | transactions.svc | Yes | Lists transactions with date range filter |
| `cards.list` | cards.svc | Yes | Lists customer cards |

### Tool handler pattern

Each tool follows the same structure:

1. Extract and validate arguments via FastMCP parameters
2. Look up `RiskContext` from the current session (via ContextVar)
3. Record data touches (`record_data_touch`) before reaching the backend
4. Call `BackendClient` with internal JWT authorization
5. Project and mask response through `build_model` wrapper

See [`packages/postern-core/src/postern_core/facade/projection.py`](../../../packages/postern-core/src/postern_core/facade/projection.py)
for the `build_model` wrapper that catches pydantic validation errors and re-raises as
`BackendError(502, ...)`, preventing raw value leakage.

## OAuth & Authentication

### Customer JWT Verification

When `POSTERN_JWKS_URI` and `POSTERN_TOKEN_ISSUER` are both set, the server builds a
`JWTVerifier` and requires every tool call to carry a validated customer access token.

When either is unset (or both are `""`), the server runs in **no-auth mode**, suitable
for local development and testing. A token is still minted internally for the stub IdP,
but no verification occurs.

### Internal Token Minting (`packages/postern-core/src/postern_core/auth/read_minter.py`)

The `ReadTokenMinter` wraps `InternalTokenMinter` and adds continuous authorization:

```python
read_minter = ReadTokenMinter(
    InternalTokenMinter(issuer=settings.read_token_issuer, key_source=read_key_source),
    revocation_list=revocation_list,   # O(1) set lookups
    jti_cache=jti_cache,               # In-memory replay cache (60s window)
)
```

`READ_SCOPES` maps audiences to OAuth scopes. The `payments.svc` audience is
**deliberately absent**, read tokens cannot reach write endpoints.

### JWKS Endpoint

The public half of the signing key is published at `/.well-known/jwks.json` on the
API service router. This route is **unauthenticated**, any gateway or client fetching
the key set must reach it without a valid token.

## Consent Enforcement (`services/api/consent.py`)

Per-tool authorization via a Postgres-backed consent table. `consent_for(domain, db)`
returns an `AuthCheck` that:

1. Queries the consents table for the customer's consent on a given domain
2. Filters the tool catalogue (hides tools without consent from `tools/list`)
3. Refuses calls to hidden tools with a recorded refusal reason

> **Warning:** Filtering `tools/list` alone is insufficient, hidden tools are still
> callable by name. Every tool call passes through `AuthCheck` regardless of catalogue
> visibility.

Consent domains are cached per request on `request.state` to avoid repeated database
lookups.

## Backend Client (`packages/postern-core/src/postern_core/facade/client.py`)

The `BackendClient` is the HTTP façade to the operator's backend services:

- **Path validation**: rejects absolute URLs, protocol-relative URLs, and `..` segments
- **Error scrubbing**: passes backend error bodies through `FreeText` redaction before
  truncating to 200 characters (prevents PAN/IBAN leakage in error responses)
- **Timeout budgets**: four independent timeouts per phase (connect, write, read, pool)
  summing to a worst-case 10.0s per backend request

## Timeout Architecture

Timeouts are configured in [`services/api/settings.py`](../../../services/api/settings.py):

| Phase | Timeout | Purpose |
|-------|---------|---------|
| Backend connect | 2.0s | TCP + TLS handshake to backend |
| Backend write | 2.0s | Request body transmission |
| Backend read | 5.0s | Response body reception (largest share for transaction exports) |
| Backend pool | 1.0s | Connection pool acquisition |
| DB connect | 2.0s | TCP + TLS handshake to Postgres |
| DB command | 3.0s | Single statement execution (SELECT or INSERT) |
| DB pool | 1.0s | Connection pool acquisition |

The request deadline (101.0s) is derived from the sum of all possible operations per call:
DB ceiling (13.0s) × 4 + backend request (10.0s) = ~62.0s, with headroom for consent
lookups that raise (up to 5 evaluations × 13.0s).

## Source References

| Component | File |
|-----------|------|
| Composition root | [`services/api/main.py`](../../../services/api/main.py) |
| Settings | [`services/api/settings.py`](../../../services/api/settings.py) |
| Server builder | [`services/api/server.py`](../../../services/api/server.py) |
| Consent enforcement | [`services/api/consent.py`](../../../services/api/consent.py) |
| Request deadline middleware | [`services/api/asgi/request_deadline.py`](../../../services/api/asgi/request_deadline.py) |
| Header/body validation | [`services/api/asgi/header_validation.py`](../../../services/api/asgi/header_validation.py) |
| Risk middleware | [`services/api/middleware/risk.py`](../../../services/api/middleware/risk.py) |
| Audit middleware | [`services/api/middleware/audit.py`](../../../services/api/middleware/audit.py) |
| Backend client | [`packages/postern-core/src/postern_core/facade/client.py`](../../../packages/postern-core/src/postern_core/facade/client.py) |
| Projection wrapper | [`packages/postern-core/src/postern_core/facade/projection.py`](../../../packages/postern-core/src/postern_core/facade/projection.py) |
| Read token minter | [`packages/postern-core/src/postern_core/auth/read_minter.py`](../../../packages/postern-core/src/postern_core/auth/read_minter.py) |
| Internal JWT minter | [`packages/postern-core/src/postern_core/auth/internal_jwt.py`](../../../packages/postern-core/src/postern_core/auth/internal_jwt.py) |
| Revocation list | [`packages/postern-core/src/postern_core/auth/revocation.py`](../../../packages/postern-core/src/postern_core/auth/revocation.py) |
# API Service (Read Path)

MCP tools, OAuth endpoints, consent checks, the read-facing deployable.

## Overview

The API service exposes MCP tools to AI clients over HTTP (Streamable HTTP transport).
It is the **read path** of Postern. With `POSTERN_PAYMENTS_ENABLED` off, the default,
every registered tool is read-only. With it on, `payments.create_payment` records a
payment proposal as a pending verification challenge and `payments.get_payment_status`
reports it; the customer approves on their own device and the confirm service executes
server-side. Neither tool can approve or execute.

```
packages/postern-core/src/postern_core/facade/     HTTP client to operator backend
services/api/main.py                                Composition root (create_app)
services/api/server.py                              FastMCP server builder, module registration loop
services/api/tools/                                 built-in read modules (start_session, accounts, transactions)
services/api/tools/payments.py                      the payments producer, flag-gated, not a module
packages/postern-cards/                             the cards module's read half, found by entry point
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

### Driver errors in the client's reply and in the log

The server is built with `mask_error_details=True`: an exception a tool raises other than a `ToolError`
reaches the client as `Error calling tool 'x'`, and `AuditMiddleware` replaces any other exception whose
chain holds a SQL driver error (a completion-row audit failure, for one) with `ToolError("internal
error")`, so neither the driver's message nor the bound value is in the model's channel. Both database
engines hide bound parameters, and `create_app` calls `postern_core.log_safety.install_sql_safe_logging()`,
which sanitises every log record in the process: the traceback frames and each exception's type and
SQLSTATE stay, the driver's message, the SQL and the parameters do not. For an error Postgres raised, its own log has the message, the DETAIL and the statement at the same time (with `log_min_error_statement` at its default `error`; to match on a SQLSTATE put `%e` in `log_line_prefix`, the default `%m [%p] ` carries none). Errors asyncpg raises in the client while encoding a parameter (for example `DataError`, "invalid input for query argument") never reach the server and leave no record anywhere; the sanitised line says `client-side` for them. Postgres' log then holds the values these logs withhold (DETAIL `Failing row contains (...)`): treat it as customer data.

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

- Default: `105.0` seconds (`POSTERN_REQUEST_DEADLINE_SECONDS`)
- Derived from: DB operation ceiling (13.0s) × 4 + backend request (10.0s) + consent
  lookups (5 × 13.0s). Realistic success ceiling: ~49.0s; realistic denial ceiling: ~78.0s
- Zero and negative values are refused at startup (no off switch)

### Header/Body Validation (`services/api/asgi/header_validation.py`)

Enforces MCP Streamable HTTP spec compliance:

- Rejects requests where `Mcp-Method` / `Mcp-Name` headers don't match body values
  (HTTP 400 + JSON-RPC `-32020`)
- Answers any body it cannot parse strictly with HTTP 400 and JSON-RPC `-32700` "Parse error"
  before FastMCP sees it: not JSON, not UTF-8, nested past the recursion limit, an integer past
  the interpreter's digit limit, or holding `NaN`, `Infinity`, `-Infinity` or an overflowing
  literal such as `1e999`. FastMCP's own parsers accept some of these, so a body the middleware
  cannot read is never handed to a second parser. A JSON value that is not an object (an array)
  is not refused here and goes downstream
- Bounds request body to `POSTERN_MAX_BODY_BYTES` (default 1 MiB)
- Prevents request smuggling via header/body mismatch

## MCP Tools

With the flag off, five read-only tools are registered. Every one except `start_session` is gated by a
Postgres-backed consent check:

| Tool | Domain | Consent Required | Description |
|------|--------|-----------------|-------------|
| `start_session` | - | No | Initiates an RFC 8628 device grant flow |
| `accounts.list` | accounts.svc | Yes | Lists customer accounts |
| `accounts.get_balance` | accounts.svc | Yes | Returns balance for a specific account |
| `transactions.list` | transactions.svc | Yes | Lists transactions with date range filter |
| `cards.list` | cards.svc | Yes | Lists customer cards |

### Payments producer (behind `POSTERN_PAYMENTS_ENABLED`)

Two more tools, registered only with the flag on and always gated on the `payments`
consent domain, even in a no-auth stack, where they are therefore listed to nobody.
They live in `services/api/tools/payments.py` and are not a module.

| Tool | Reads | Writes | Consent Required |
|------|-------|--------|-----------------|
| `payments.create_payment` | balance (`accounts.svc`), payee (`payments.svc`, `payments:read`) | one pending `challenges` row, or the one already pending for the same request | Yes, `payments` |
| `payments.get_payment_status` | the caller's own payment challenge | `pending` to `expired` once the deadline has passed | Yes, `payments` |

Refusals are fixed strings: `account not found`, `payee not found`, `amount must be a
positive decimal with at most 4 decimal places`, `reference is limited to 140 characters`,
`reference may contain only printable characters`, `challenge not found`,
`the payment could not be recorded`, `the payment status could not be read`. An `approved`
status means the customer approved; it does not mean the bank executed the payment, and it does not necessarily mean the bank refused it: the bank may have refused it, execution may still be in flight, the outcome may be unknown, or the bank may have accepted it while recording `executed` failed (the confirm service's 202 `accepted_unrecorded`). For an `approved` status the tool description tells the model not to propose the same payment again unless the customer asks directly in the conversation, and to tell the customer the outcome is unconfirmed.

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
`SessionTokenVerifier` (`services/api/session_verifier.py`, a `JWTVerifier` subclass)
and requires every tool call to carry a validated layer-1 session token: the access
token `services/confirm` issues at `POST /token`, signed by its SESSION key and fetched
from `POSTERN_JWKS_URI` (confirm's `/session/jwks.json`). On top of the parent's
signature, `iss` and `aud` checks it requires `exp` and bounds `exp`, `iat` and `nbf`,
bounds the JWKS cache, and drops any fetched key whose RFC 7638 thumbprint equals this
service's own READ key. Startup refuses a `POSTERN_AUDIENCE` that is not an absolute
`https` URI in normal form unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set. The fetch
must run over TLS outside a local stack: whoever can answer it can plant a key and
forge any customer's token.

**Runbook (2 October 2026): the api's availability depends on `services/confirm`'s
`/session/jwks.json`.** The verifier (`services/api/session_verifier.py`) trusts the key
set it fetched for `POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS` (300 by default). A refresh
that fails (an HTTP error, a fetch longer than 5 seconds, or an answer that is not a
key set) keeps the old set and is retried at most once per 30 seconds, but the old set
is not served past its TTL. So when confirm's key set becomes unreachable, the api keeps
verifying for what is left of one TTL and then refuses every session token until a
fetch succeeds. That is intended: a key set that cannot be re-read cannot show that a
key was not withdrawn. Alert on confirm's `/session/jwks.json` before the api's 401s.

When either is unset (or both are `""`), the server runs in **no-auth mode**, suitable
for local development and testing. A token is still minted internally for the stub IdP,
but no verification occurs.

### Internal Token Minting (`packages/postern-core/src/postern_core/auth/read_minter.py`)

The `ReadTokenMinter` wraps `InternalTokenMinter` and adds continuous authorization:

```python
read_minter = ReadTokenMinter(
    InternalTokenMinter(issuer=settings.read_token_issuer, key_source=read_key_source),
    jti_cache=jti_cache,   # uuid4 collision detector, not a replay check
)
```

Revocation is not an argument here. The revocation store is consulted once per
request by the middleware, which holds the validated token and therefore the
real `client_id`, and the minter reads that request's answer.

**The `jti` cache is not replay protection, whatever its class name says.** It
holds only the `jti` values this process generated while minting, so a hit
means `uuid.uuid4()` repeated itself. A replayed token is recognised by
whoever receives it, which for these tokens is your gateway and your domain
services. If you want replay detection, that is where to build it. See
`dev-docs/decisions/0014-jti-cache-detects-randomness-not-replay.md`.

`READ_SCOPES` maps audiences to OAuth scopes, all of them read scopes. The
`payments.svc` audience maps to `payments:read`, which the payments producer uses
for its payee lookup (decision 0022), and **never** to `payments:execute`. The
minter binds the scope to the audience, not to a path: any `get_json(<any GET
path>, audience="payments.svc")`, a third-party `ReadModule`'s included, receives a
read-signed token with scope `payments:read`. Read tokens cannot reach write
endpoints provided your payments gateway or backend checks the signing key and the
scope per path; the minter does not restrict the path. An audience with no entry
raises `KeyError`.

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

The request deadline (105.0s) is derived from the sum of all possible operations per call:
DB ceiling (13.0s) × 4 + backend request (14.0s) = ~66.0s, with headroom for consent
lookups that raise (up to 5 evaluations × 13.0s). The backend request term is 14.0s and
not 10.0s because minting the internal token is a Vault round trip under its own
four-phase budget (4 × `POSTERN_VAULT_TIMEOUT_SECONDS`, 1.0s by default).

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
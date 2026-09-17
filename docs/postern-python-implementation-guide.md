# Postern — Python / FastMCP Implementation Guide

**Third document in the set.** Read `postern-design-handoff.md` (architecture) and `postern-zero-trust-plan.md` (security) first. §N.N references point to the handoff; ZT-N references point to the zero-trust plan.

**Purpose:** turn the design into a repo. This document covers framework specifics, project layout, and the code patterns that carry security properties.

---

## 0. Verification protocol — read before writing any code

### 0.1 What was verified, when, and how

Everything in §1 was checked against primary sources on **12 September 2026**. Anything not in §1 is design reasoning, not a verified framework fact.

| Fact | Source | Verified |
|---|---|---|
| FastMCP current version **4.0.3**, released 2026-09-05 | GitHub releases, PrefectHQ/fastmcp | ✅ |
| Repo moved **jlowin → PrefectHQ** | Repo README | ✅ |
| v4 release notes cite **SEP-2322 / SEP-2575** | v4.0.3 release notes | ✅ |
| `@mcp.tool` — **no parentheses** in v4 | README quickstart | ✅ |
| `mcp.http_app(path=, stateless_http=, json_response=, middleware=)` | FastMCP docs, Posit Connect docs | ✅ |
| `JWTVerifier` in `fastmcp.server.auth.providers.jwt` | gofastmcp.com/servers/auth/token-verification | ✅ |
| `IntrospectionTokenVerifier` in `fastmcp.server.auth.providers.introspection` | same | ✅ |
| `StaticTokenVerifier`, `DebugTokenVerifier`, `RSAKeyPair` for dev | same | ✅ |
| `MultiAuth` composing `OAuthProxy` + verifiers | gofastmcp.com/servers/auth/multi-auth | ✅ |
| `Middleware`, `MiddlewareContext` in `fastmcp.server.middleware`; hooks `on_call_tool`, `on_list_tools`, `on_list_resources`, `on_read_resource`, `on_list_prompts`, `on_get_prompt` | gofastmcp.com API docs | ✅ |
| Built-in **authorization middleware** filters `tools/list` by auth checks | gofastmcp.com/python-sdk/fastmcp-server-middleware-authorization | ✅ |
| `get_access_token`, `get_context`, `get_http_request`, `get_http_headers`, `get_server` in `fastmcp.server.dependencies` | gofastmcp.com/servers/dependency-injection | ✅ |
| `CurrentContext()`, `CurrentFastMCP()` in `fastmcp.dependencies` (preferred since 2.14) | same | ✅ |
| `ToolError` in `fastmcp.exceptions` | FastMCP docs | ✅ |
| `context.fastmcp_context.set_state(k, v)` for per-request state | FastMCP docs | ✅ |

### 0.2 Explicitly NOT verified — check these yourself

| Item | Why it matters | How to check |
|---|---|---|
| **v3 → v4 breaking changes** | Most blog posts and LLM training data predate v4. Assume examples found online are v2/v3. | `https://gofastmcp.com/getting-started/upgrading/from-fastmcp-3` |
| **`httpx2` vs `httpx`** | FastMCP auth docs show `httpx2.AsyncClient`. Unclear whether this is a real dependency or a docs artifact. | `uv add fastmcp` then inspect the lockfile |
| **Tool annotation syntax** (`readOnlyHint`, `destructiveHint`) in v4 | §6.2 depends on these | Docs + `inspect.signature(mcp.tool)` |
| **MRTR support** | §3.5 | Search docs for `input_required` / MRTR |
| **Session semantics** | FastMCP docs still describe `Mcp-Session-Id` credential binding; SEP-2567 removed protocol sessions. FastMCP supports **mixed-era** backends, so both may exist. | Upgrade guide + spec changelog |
| **Whether `server/discover` carries `instructions`** | §4.1 | `https://modelcontextprotocol.io/specification/2026-07-28` |

**Rule: if a fact is not in §0.1 and you have not checked it this session, verify before relying on it.** FastMCP's docs are published in [llms.txt format](https://gofastmcp.com/llms.txt) — fetch the index, then the specific page. Do not reconstruct API shapes from memory.

### 0.3 Package identity — do not mix these up

Two different packages, both called "FastMCP" in casual usage:

| | Package | Import | Notes |
|---|---|---|---|
| **This project uses** | `fastmcp` (PrefectHQ) | `from fastmcp import FastMCP` | v4.x, standalone, actively maintained |
| Not this | `mcp` (official SDK) | `from mcp.server.mcpserver import ...` | FastMCP 1.0 was absorbed into the official SDK in 2024; the official SDK v2 renamed `mcp.server.fastmcp.*` → `mcp.server.mcpserver.*` |

Mixing imports between them produces confusing type errors. Pin `fastmcp>=4.0.3,<5`.

---

## 1. Repo bootstrap

### 1.1 `pyproject.toml`

```toml
[project]
name = "postern"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastmcp>=4.0.3,<5",
    "pydantic>=2.9",
    "httpx",                  # confirm httpx vs httpx2 — see §0.2
    "sqlalchemy[asyncio]>=2.0",
    "asyncpg",
    "alembic",
    "joserfc",                # internal JWT minting (§4)
    "structlog",
    "opentelemetry-sdk",
    "opentelemetry-instrumentation-httpx",
    "uvicorn[standard]",
]

[dependency-groups]
dev = [
    "pytest", "pytest-asyncio", "respx",
    "testcontainers[postgres]",
    "ruff", "mypy", "import-linter",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"

[tool.mypy]
strict = true
```

`uv sync` to install. `uv lock` committed.

### 1.2 Layout

Two deployables sharing a core library (§8.2 of the handoff — this is a decision, not a preference):

```
postern/
├── pyproject.toml
├── Dockerfile                       # multi-target, see §8
├── migrations/                      # Alembic env.py + versions/
├── packages/postern-core/src/postern_core/
│   ├── identity.py                  # CustomerRef, CustomerResolver
│   ├── domain/
│   │   ├── masking.py               # MaskedPan, MaskedIban, FreeText
│   │   ├── money.py                 # Money
│   │   └── models.py                # Account, Balance, Transaction, Card, SessionInfo
│   ├── facade/
│   │   ├── client.py                # httpx + internal JWT + tracing
│   │   └── accounts.py cards.py transactions.py payments.py
│   ├── store/
│   │   ├── models.py
│   │   └── consents.py challenges.py audit.py
│   ├── auth/
│   │   ├── keys.py                  # KeySource: generated, file, or Vault
│   │   └── internal_jwt.py          # mint() — role injected at construction
│   └── risk/
│       └── tiers.py                 # tier selection (§7.4)
├── services/api/                    # postern-api — READ Vault role
│   ├── main.py                      # composition root, ASGI `app`
│   ├── server.py                    # FastMCP assembly
│   ├── consent.py                   # tool visibility by consent
│   ├── tools/
│   │   ├── bootstrap.py accounts.py cards.py transactions.py payments.py
│   ├── oauth/
│   │   ├── authorize.py token.py device_flow.py qr.py
│   ├── asgi/
│   │   └── header_validation.py     # §3.3, ASGI not FastMCP middleware
│   └── middleware/
│       └── cache_scope.py           # §3.4
├── services/confirm/                # postern-confirm — WRITE Vault role
│   ├── callback.py
│   └── execute.py
└── tests/
    ├── test_masking_golden.py
    ├── test_header_body_mismatch.py
    ├── test_no_write_from_api.py
    └── test_cross_customer.py
```

### 1.3 Import boundary (enforced, not documented)

`.importlinter`:

```ini
[importlinter]
root_packages =
    services
    postern_core

[importlinter:contract:api-cannot-write]
name = API service must not import the write path
type = forbidden
source_modules = services.api
forbidden_modules = services.confirm
```

Run in CI. This is the ZT/A3 control expressed as a lint rule.

---

## 2. Server assembly

`services/api/server.py`:

```python
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier

from services.api.asgi.header_validation import HeaderBodyValidation
from services.api.middleware.consent_scope import ConsentScope

verifier = JWTVerifier(
    jwks_uri=settings.customer_jwks_uri,
    issuer=settings.customer_token_issuer,
    audience="postern",
    required_scopes=None,          # scope checks are per-tool, not global
)

mcp = FastMCP(name="postern", auth=verifier, instructions=SERVER_INSTRUCTIONS)

mcp.add_middleware(HeaderBodyValidation())
mcp.add_middleware(ConsentScope())

register_bootstrap(mcp)
register_accounts(mcp)
register_cards(mcp)
register_transactions(mcp)
register_payments(mcp)

# ASGI export, in `services/api/main.py`. stateless_http + json_response are
# required for horizontal scaling behind an ALB (§3.2) — no sticky sessions, no SSE.
app = mcp.http_app(
    path="/mcp",
    stateless_http=True,
    json_response=True,
)
```

**Notes:**
- `JWTVerifier` makes this a pure resource server — the customer token is minted by the OAuth endpoints in `services/api/oauth/`, which are mounted separately (§3).
- `instructions=` — confirm where the field surfaces under `2026-07-28` (§0.2). Regardless, the bootstrap tool (§5) is the load-bearing delivery mechanism.
- Verify `add_middleware` is the v4 registration API; earlier versions differed.

---

## 3. OAuth endpoints and the device grant

FastMCP's `JWTVerifier` validates tokens; it does not issue them. The QR / device-grant flow (§7.3) is **your own Starlette routes**, mounted alongside the MCP app.

Two viable shapes — pick one and record the decision:

1. **Mount both under one ASGI app.** A parent Starlette/FastAPI app mounts `mcp.http_app(path="/")` at `/mcp` and your OAuth router at `/oauth`. **Pass the MCP app's lifespan to the parent** — omitting it leaves the session manager uninitialised. This is a documented FastMCP footgun.
2. **`MultiAuth`** if you also need machine-to-machine tokens from a second issuer alongside the customer OAuth path.

Endpoints to implement (RFC 8628 shapes):

| Route | Purpose |
|---|---|
| `GET /oauth/authorize` | Creates the challenge, renders the QR + pairing code page |
| `GET /oauth/qr/{device_code}` | Rotating QR frame — polled ~1/s (§7.3) |
| `POST /oauth/token` | Device-code polling → `authorization_pending` \| tokens \| `expired_token` |
| `POST /oauth/callback/approval` | Signed approval from the confirmation service |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 metadata |

**Serve the QR page and its refresh endpoint from a separate lightweight path** — not the handler holding Postgres connections and cached signing keys.

---

## 4. Internal JWT minting (§7.2)

`packages/postern-core/src/postern_core/auth/internal_jwt.py`:

```python
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import uuid
from joserfc import jwt
from joserfc.jwk import RSAKey

@dataclass(frozen=True)
class InternalTokenMinter:
    """One instance per Vault role. The API service constructs the READ minter
    only; the confirm service constructs the WRITE minter only. There is no
    code path that gives a process both."""
    issuer: str            # https://mcp-read.internal | mcp-write...
    key: RSAKey            # fetched from Vault at startup, cached, rotated
    actor: str = "svc:postern"

    def mint(
        self,
        *,
        subject: str,          # opaque customer ref — NEVER an IBAN or national id
        audience: str,         # e.g. "payments.svc"
        scope: str,
        consent_id: str,
        client_id: str,
        challenge_id: str | None = None,
    ) -> str:
        now = datetime.now(timezone.utc)
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "act": {"sub": self.actor},        # RFC 8693 delegation
            "aud": audience,
            "scope": scope,
            "consent_id": consent_id,
            "client_id": client_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=60)).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        if challenge_id is not None:
            claims["challenge_id"] = challenge_id
        return jwt.encode({"alg": "RS256", "kid": self.key.kid}, claims, self.key)
```

**Rules:**
- **Sign locally.** Never a Vault round trip per request (§7.2).
- **60-second expiry.** One internal hop.
- **No PII in claims.** JWTs land in logs and traces.
- `challenge_id` only on write tokens — it is what lets the payments service independently verify a confirmed challenge backs the execution (ZT / A9).

---

## 5. The bootstrap tool (§4.2)

Load-bearing, because client support for server `instructions` varies and we design for the weakest client.

```python
@mcp.tool
async def start_session(ctx: Context = CurrentContext()) -> SessionInfo:
    """Start here. Returns your available accounts, what this session may do,
    and how confirmations work. Call this before any other banking tool."""
    token = get_access_token()
    customer = customer_ref_from(token)
    consents = await consent_store.for_customer(customer)
    return SessionInfo(
        accounts=[...],          # labels + opaque refs, never IBANs
        granted=[...],
        write_enabled=[...],
        confirmation_note="Payments and card changes are confirmed in your "
                          "banking app. You will be told when to check your phone.",
    )
```

Return **account labels and opaque refs**, never IBANs (§6.5). Personalised context beats a static instruction blob.

---

## 6. The patterns that carry security properties

### 6.1 Masked types

```python
from typing import Annotated
from pydantic import AfterValidator

def _mask_pan(v: str) -> str:
    digits = "".join(c for c in str(v) if c.isdigit())
    if len(digits) < 4:
        raise ValueError("insufficient digits for masking")
    return f"•••• {digits[-4:]}"

MaskedPan = Annotated[str, AfterValidator(_mask_pan)]
```

`Card.pan` is `MaskedPan` and `Account.iban` is `MaskedIban`, the only two masked-type fields in the model; masking happens in the validator, so a handler that forgets fails validation rather than leaking. **Prefer the backend returning pre-masked values** — then the MCP server never holds a full `Card.pan` (§6.5, §10.17, tracked as a live dependency in the zero-trust plan §8). That does not settle PCI DSS scope on its own: a PAN a merchant typed into a descriptor arrives raw in the five `FreeText` fields (`Account.label`, `Transaction.counterparty_name`, `Transaction.description`, `Card.label`, `SessionInfo.confirmation_note`, lines 21, 37, 38, 59 and 76 of `packages/postern-core/src/postern_core/domain/models.py`) and in every agent-supplied tool argument; `FreeText` redacts it at validation time, once the raw value has already reached the process.

### 6.2 Consent-scoped tool visibility

Use FastMCP's `on_list_tools` middleware hook to filter the catalog by consent state. FastMCP ships an authorization middleware that already does exactly this shape — check whether it fits before writing your own.

**Set `cacheScope` per-user, never global** (§3.4). The catalog varies by consent; a shared cache leaks which accounts a customer has.

### 6.3 Header/body validation (§3.3)

```python
class HeaderBodyValidation(Middleware):
    async def on_call_tool(self, context, call_next):
        headers = get_http_headers()
        if headers.get("mcp-name") not in (None, context.message.name):
            raise ToolError("header/body mismatch")   # must surface as 400 / -32020
        return await call_next(context)
```

Confirm the error path actually produces HTTP 400 with JSON-RPC `-32020`; a generic `ToolError` may not. **Write the test first.**

### 6.4 Tool handlers never execute writes

```python
@mcp.tool
async def create_payment(
    from_account_ref: str,
    payee_ref: str,                  # NEVER a raw IBAN (§6.5)
    amount: Money,
    ctx: Context = CurrentContext(),
) -> PaymentChallenge:
    """Propose a payment. Does not execute — the customer confirms in the app."""
    tier = select_tier(amount=amount, payee_ref=payee_ref, customer=...)
    challenge = await challenges.create(...)   # full payload persisted
    await confirmation.open(challenge.id)      # push built server-side from the row
    return PaymentChallenge(
        challenge_id=challenge.id,
        status="pending",
        human_summary=f"Approve {amount} to {payee_name} in your banking app.",
    )
```

There is **no** `submit_payment` tool. Execution lives in `services/confirm/execute.py`, reachable only from a signed approval.

---

## 7. Testing

| Test | Asserts |
|---|---|
| `test_masking_golden.py` | No tool output matches a PAN or IBAN regex, across every tool against fixtures |
| `test_header_body_mismatch.py` | Mismatch → 400 + `-32020` |
| `test_no_write_from_api.py` | The API service's minter cannot produce a write-audience token |
| `test_cross_customer.py` | Customer A's token requesting B's account → 404, byte-identical to a nonexistent account ref so the refusal does not confirm B's account exists; A's own account still returns A's data (ZT-2) |

Use FastMCP's in-process `Client` against the server object for tool tests — no network, fast. `respx` mocks the backend; `testcontainers` gives real Postgres. `RSAKeyPair.generate()` and `StaticTokenVerifier` cover auth fixtures without external infrastructure.

Before wiring any real client: `npx @modelcontextprotocol/inspector`.

---

## 8. Dockerfile

```dockerfile
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY . .
RUN uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime-slim
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
COPY --from=builder /app /app
WORKDIR /app
USER 1000:1000

FROM runtime-slim AS api
CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8080"]

FROM runtime-slim AS confirm
CMD ["uvicorn", "services.confirm.callback:app", "--host", "0.0.0.0", "--port", "8080"]
```

Build `--target api` and `--target confirm` (§12.2). For production, swap `runtime-slim` for distroless — **but see §12.2 of the handoff: distroless removes the shell and therefore ECS Exec.** Build `--platform linux/arm64` for Graviton. Pin base images **by digest** before merging.

---

## 9. Milestones

| # | Deliverable | Done when |
|---|---|---|
| 1 | Repo, `uv sync`, ruff + mypy + import-linter green | CI passes on an empty server |
| 2 | Domain model + masked types | `test_masking_golden.py` passes with zero tools |
| 3 | `accounts.list`, `accounts.get_balance` against a stubbed backend | Visible and callable in MCP Inspector |
| 4 | Bootstrap tool + instructions | Verified against two different MCP clients |
| 5 | Middleware: header validation, cache scope, consent scope | Tests 2 and 3 from §7 pass |
| 6 | Postgres: consents, challenges, audit | Alembic migrations run clean |
| 7 | Vault key fetch + internal JWT minting | Read minter cannot produce write tokens |
| 8 | Device grant + QR + pairing code | Headless-SSH path works end to end |
| 9 | `cards.freeze_card` at tier 1 | Full challenge → confirmation → execution round trip |
| 10 | `payments.create_payment` at tier 2 | Only after handoff questions 4, 10 and 13 are answered |

**Do not start milestone 10 until those three cross-team questions are resolved.** The payment path cannot be built correctly without knowing where dynamic linking is enforced.

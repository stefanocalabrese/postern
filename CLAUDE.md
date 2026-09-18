# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

Working software, not a skeleton. `make ci` exits 0 on 871 tests, measured 18 September 2026. What exists: five read tools (`start_session`, `accounts.list`, `accounts.get_balance`, `transactions.list`, `cards.list`), four of them behind a Postgres-backed consent check; an append-only `audit_log` carrying up to two rows per tool call, both fail-closed per `docs/decisions/0006-audit-write-failure.md` -- one committed before the operator's backend is reached (`outcome='reaching'`, written from the facade hook `services/api/main.py` wires) and one after the call finishes, correlated by `call_id`; seven migrations; customer tokens verified by FastMCP's `JWTVerifier` against a configured JWKS and issuer; the read/write signing-key split, with each service publishing only its own key at `/.well-known/jwks.json`; bounded connect, command and pool timeouts on the database. What does not: any payments tool, the approval callback (`services/confirm` publishes its JWKS and nothing else), the RFC 8628 device grant and its QR flow, and Vault itself, since `KeySource` is the seam Vault lands behind and a key today comes from a PEM on disk or is generated in process. Read "Architecture" and "Hard rules" below as the target, and the two lists above as how much of it has landed.

**Naming is settled: `postern`.** Docs and code agree: `postern`, `postern_core`, `services/api`, `services/confirm`. The three design docs carried a `bank-mcp-` prefix until 17 September 2026 and were renamed then, along with the MCP tool `banking_start_session`, which is now `start_session`. The dated records under `docs/verification/` and `docs/decisions/` still carry the old names and are left that way on purpose: they record what was observed on a date. The PyPI distribution name must be `postern-mcp`, since bare `postern` is taken.

## Source documents, in reading order

1. `docs/postern-design-handoff.md`: the architecture.
2. `docs/postern-zero-trust-plan.md`: threat model, ZT-1..ZT-8 work items, CI gates, sequencing.
3. `docs/postern-python-implementation-guide.md`: FastMCP specifics, repo layout, code patterns.

Cross-references: `§N.N` points at the handoff, `ZT-N` at the zero-trust plan, `A1..A11` at the attack scenarios in its §3.2.

Also current, and corrected against what execution actually found: `docs/superpowers/plans/postern-foundation-and-read-surface-2026-09-12.md` (the 15-task plan being executed, task by task), `docs/decisions/` (decision records), `README.md`. Where a design doc and the plan disagree, the plan is newer.

## What this is

An MCP server exposing an operator's own backend services to external consumer AI clients (Claude, ChatGPT, Perplexity) as tools across four domains: accounts, transactions, cards, payments.

**The operator is the ASPSP, not the TPP.** This inverts almost all public Open Banking prior art, where every project is a third party reading accounts through an aggregator. No inbound TPP certificate verification, no multi-ASPSP adapter layer, no eIDAS certificates presented outbound. Tool contracts borrow Open Banking semantics for familiarity only.

The defining property that drives every decision: an LLM the operator does not control chooses which tools to call, against real money, with attacker-controllable text (transaction memos, payee names, merchant strings) in its context. The operating assumption is not "the network is hostile" but **"the caller is under adversarial influence at all times, even when correctly authenticated."**

## Architecture

Two deployables over one shared library. This is a decision, not a preference (handoff §8.2):

| Service | Holds | Vault role | Can reach |
|---|---|---|---|
| `services/api` | MCP tools, OAuth/device-grant endpoints, QR page | **read** | backend read endpoints only |
| `services/confirm` | approval callback, execution | **write** | backend write endpoints |

`packages/postern-core/src/postern_core/` carries `domain/` (masked types), `facade/` (httpx2 + internal JWT), `store/` (SQLAlchemy + Alembic), `auth/` (Vault key fetch, JWT minting), `risk/` (tier selection).

Two authentication layers that must never be conflated (handoff §7.1):
- **Agent to MCP server**: OAuth 2.1, CIMD over deprecated DCR, RFC 8628 device grant with a QR flow.
- **MCP server to backend**: Vault-signed JWT through an Istio ingress gateway over PrivateLink, 60-second expiry, RFC 8693 delegation shape (`sub` = customer, `act.sub` = service).

The read/write Vault key split is what makes "the tool handler cannot reach a backend write endpoint" an infrastructure property rather than a code-review promise. A compromised tool handler cannot mint a token the payments service accepts, because it does not hold the key.

The write path never returns through the model's channel: `create_payment` persists a challenge row and returns a `challenge_id` immediately; the push notification payload is built server-side **from that stored row**; the user approves on their own device; the approval callback (not the tool handler, not the agent) calls the backend write endpoint. An injected agent can propose a wrong payee but cannot change what the user is shown.

## Hard rules

These are decisions carried over from the design conversation. Do not relitigate them in code.

- **No payment execution tool exists.** Only `payments.create_payment` and `payments.get_payment_status`. A `submit_payment` in the schema hands the model an execution capability and makes safety depend on it choosing not to use it. Remove the capability instead.
- **Execution belongs to the approval callback**, never a tool handler. The tool-handler process must not hold the credentials or network permission to reach backend write endpoints.
- **The confirmation payload is built server-side from the stored challenge row**, never from agent input. This is the property that makes prompt injection at tool-call time survivable.
- **Never accept `user_id` as a tool argument** and never hand it to the client. The server derives the customer from the token on every call. A user identifier the model can set is a direct object reference an agent can be talked into changing.
- **Never write "Face ID" anywhere in this codebase or its docs.** The operator's app brands its identity-verification feature that way, but it is server-side selfie matching in the backend cluster, not Apple's on-device feature. Any reader, human or model, will implement the wrong thing. Use "app identity verification"; write "device unlock biometric" when the phone's own biometric is meant.
- **Masking is a type property, not a function someone remembers to call.** `MaskedPan`, `MaskedIban` via `Annotated` + Pydantic validator, whose only constructor masks. A handler that forgets must fail validation, not leak. Prefer the backend returning pre-masked values so the server never holds a full PAN and stays out of PCI DSS scope.
- **A `ValidationError` from a masked type carries the raw PAN or IBAN.** `hide_input_in_errors` covers only `str()` and `repr()` of the exception; its structured `errors()` output and `.json()` still contain the raw offending value by default. Any handler that serializes a masking `ValidationError` toward a client must call `errors(include_input=False)` or `json(include_input=False)`, or the value the type exists to protect leaks through the error instead of the response.
- **`payments.create_payment` takes a `payee_ref`, never a raw IBAN.** A new payee's IBAN is typed in the bank app during confirmation and never passes through the agent channel.
- **`cacheScope` is `"private"`, never `"public"`.** Those are the only two values the spec allows, and `"private"` means "MUST NOT be shared across authorization contexts". The tool catalog varies by consent state; a shared cache leaks which accounts and permissions a customer has. That is a data leak, not a performance bug. `ttlMs` and `cacheScope` are both required fields on `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list` and `resources/read`.
- **Validate `Mcp-Method` / `Mcp-Name` headers against the body** before any handler runs; mismatch returns 400 with JSON-RPC `-32020`. A load balancer routing on a header while the server executes on the body is a request-smuggling shape. **This must be ASGI middleware, not FastMCP middleware**, for the reason in "Version traps" below.
- **MRTR is for disambiguation only** (which account, which card, which date range). Never for authorizing money movement, because the answer routes back through the model's channel.
- **Tier 1 is the default for writes, not tier 2.** Tier 2 adds server-side identity verification, which is a GDPR Article 9 special-category processing event on every single use, costs 5 to 15 seconds, and fails a real percentage of the time. Tier 1 already satisfies SCA with two factors.
- **Declare the verification tier on the tool definition.** Never derive it from the HTTP verb: search endpoints are POST because the body is large, and a five-year transaction export is a GET.
- **Do not cite network isolation as a zero-trust control.** PrivateLink is blast-radius reduction. The identity layer is the control.
- **Tool definitions are static config versioned in the repo**, never registered at runtime by backend services. Runtime registration breaks the PrivateLink design and makes the tool surface impossible to diff between deploys.
- **Do not map backend endpoints 1:1 to tools.** OpenAPI-to-MCP generators are unusable here: they would expose a directly callable payment endpoint and discard the challenge flow, consent checks, idempotency and audit chain.

## Version traps

Both of these will produce plausible, wrong code from memory. Verify before relying on either.

- **FastMCP is at v4.0.3 (2026-09-05), under the `PrefectHQ` org, not `jlowin`.** Nearly every FastMCP example in training data and on the web is v2 or v3. Docs are in llms.txt format at `https://gofastmcp.com/llms.txt`: fetch the index, then the page. The implementation guide's §0.1 lists what was verified on 12 September 2026; anything outside it is design reasoning, not a verified framework fact.
- **`ToolError` cannot produce an HTTP status.** FastMCP 4 returns it as `CallToolResult(is_error=True)` inside an HTTP **200**, and exposes no documented way to set the status from a tool or a middleware hook. The implementation guide §6.3 shows header/body validation as a FastMCP `Middleware` raising `ToolError`; that is wrong and cannot satisfy the spec's "MUST return 400". Any control that owes an HTTP status belongs in ASGI middleware passed to `http_app(middleware=[...])`. `McpError(code=..., message=...)` sets an arbitrary JSON-RPC code but still not a status.
- **The HTTP client is `httpx2`, not `httpx`.** `fastmcp` 4.0.3 pulls `fastmcp-slim[client,server]`, which declares `httpx2>=2.5.0` and no `httpx`. `respx` cannot mock it: it type-checks against `httpx.Response` and raises `TypeError` at mock-setup time, before any request. Backend tests inject `httpx2.MockTransport(handler)` instead, which does carry an `Authorization` header through to the handler. `respx` has been removed from the dev group. See `docs/decisions/0001-facade-http-client.md`.
- **Smaller v4 facts, all verified:** `@mcp.tool` works bare *and* with parentheses. Tool annotations come from `mcp.types.ToolAnnotations`, not from fastmcp. `ctx.set_state` / `get_state` are **async** (`await`). `FastMCP()` accepts `cache_scope` and `cache_ttl` directly. The in-process test `Client(transport=server)` accepts **no auth argument**, which is why tools resolve the customer through an injected `CustomerResolver` rather than reading the token directly.
- **Package identity:** this project uses `fastmcp` (PrefectHQ, `from fastmcp import FastMCP`), not the official `mcp` SDK (`mcp.server.mcpserver.*`). Mixing imports produces confusing type errors. Pin `fastmcp>=4.0.3,<5`.
- **MCP protocol `2026-07-28` removed the `initialize`/`initialized` handshake and protocol-level sessions**, including `Mcp-Session-Id`. Every request is self-describing and any request can land on any instance. No in-process session state at all: mint an explicit handle and have the model pass it back as an argument, which is exactly what the challenge ID does. Server-level `instructions` now lives on the `server/discover` result. There is a third mandatory header, `MCP-Protocol-Version`, alongside `Mcp-Method` and `Mcp-Name`. SSE resumability is gone, so a dropped stream loses the in-flight request and the client re-issues it with a new id: **every handler must be safe to re-run**. MRTR's `requestState` is attacker-controlled and MUST be integrity-protected (HMAC or AEAD) if it influences authorization.
- **DPoP is not in the spec.** A search of the entire `2026-07-28` tree, security-considerations page included, returns zero hits for DPoP, RFC 9449, sender-constrained tokens or mTLS. The only token-binding mechanism is audience restriction via RFC 8707 resource indicators. This closes ZT-6's first branch: it resolves to a written decision record plus compensating controls, not to implementing DPoP.

## Commands

```bash
uv sync                                                  # uv.lock is committed
make ci                                                  # lint fmt-check type imports lock test
make fmt                                                 # ruff format
uv run pytest tests/test_masking_golden.py::test_name    # single test
uv run --with pillow python tools/render_auth_flow.py    # regenerate the README diagram
```

`make ci` is the gate runner and must exit 0 before any commit. It runs locally rather than in Actions because minutes are billed on private repos; the workflow file arrives in Task 14 with `on: workflow_dispatch` only.

`asyncio_mode = "auto"` is set, so async tests need no marker. Use FastMCP's in-process `Client(transport=server)` for tool tests (no network), `httpx2.MockTransport` for the backend, `testcontainers.community.postgres` for a real database (the old `testcontainers.postgres` path is deprecated), and `RSAKeyPair.generate()` + `StaticTokenVerifier` for auth fixtures.

Images are two targets from one multi-stage Dockerfile:

```bash
docker build --target api --platform linux/arm64 .
docker build --target confirm --platform linux/arm64 .
npx @modelcontextprotocol/inspector    # test before wiring any real client
```

Local development needs no VPC: `docker compose` with Postgres and stubbed backends, uvicorn, a fake Vault key from file.

## Toolchain gotchas, each found the hard way

- **`.importlinter` needs `root_packages` (plural) listing both `services` and `postern_core`.** With only `services`, import-linter never graphs the shared library, so `services.api -> postern_core -> services.confirm` reports **KEPT with exit 0**. That two-hop route through the one library both services import is the realistic regression path, so the singular form makes the contract decorative.
- **`.python-version` pins 3.12.** Without it `requires-python = ">=3.12"` lets uv resolve 3.13 while mypy targets `python_version = "3.12"`, ruff targets `py312`, and the Dockerfile ships `python:3.12-slim`.
- **`packages/postern-core/src/postern_core/py.typed` is required.** Without the PEP 561 marker, any mypy run that does not pass `packages` and `services` in one invocation degrades to `Skipping analyzing "postern_core"`.
- **`ruff format --check` is scoped to `packages services tests`, never `.`.** Unscoped it also rewrites the Python code fences inside the markdown design docs.
- **`S101` is ignored per-file for `tests/**` only.** A global ignore lets a bare `assert` into production masking and auth code, where `python -O` strips it.
- **Pydantic: prefer `AfterValidator` to `BeforeValidator`** for the masked types; the function is then guaranteed a `str`. `Annotated` metadata applies right-to-left, so a `StringConstraints` placed before the masking validator fires against the unmasked value.

## CI gates that block the build

Four from handoff §8.7, plus three from the zero-trust plan §6.1. These block, they do not warn:

1. **Golden masking test**: every tool against fixtures, assert no output matches a PAN or IBAN regex. Add it while there are four tools, not later with twenty.
2. **Header/body mismatch** returns 400 + `-32020`. Write this test first; a generic `ToolError` may not produce the right status.
3. **Import-linter**: `services.api` must not import `services.confirm`. This is the A3 control expressed as a lint rule.
4. **Backend OpenAPI contract tests** against published artifacts.
5. **IAM policy test**: the read role cannot assume the write role or read its Vault path.
6. **Cross-customer contract tests** per domain service (ZT-2).
7. **Cosign signature + SBOM verification at deploy**, as a hard gate. Signing without verification is ceremony.

## Before implementing

**ZT-2 is the critical path and is answered by another team.** Istio validates the JWT; the domain services must enforce on it. If any handler scopes its query by an account ID from the request body rather than by the token `sub`, the entire authorization layer is decorative and cross-customer access (A5) is live. Finding that out six weeks in is the worst outcome available. The zero-trust plan §7 puts this in week one.

Handoff §10 lists 28 open questions. Several change the architecture rather than the code, and four gate the payment path specifically: headless challenge initiation (§10.4), the app's pairing-code screen (§10.10), where dynamic linking is enforced (§10.13), and whether domain teams will expose pre-masked projections (§10.17). Build all four domains' tool contracts up front but ship payments last, so those three cross-team dependencies do not block reads and tier-1 writes.

The §5 residual risks in the zero-trust plan are bounded, not closed: client runtime integrity cannot be attested, third-party retention is unrecallable, rendering is outside the operator's control, and the regulatory treatment of consumer AI agents against bank APIs is unsettled. Do not let anyone record them as solved.

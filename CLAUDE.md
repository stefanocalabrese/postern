# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

Docs only. No code, no `pyproject.toml`, no commit history (`git rev-list --count --all` returns 0). Everything below describes a design that has been agreed and not yet built.

**Naming is unresolved.** The repo is `postern`; all three design docs call the project `bank-mcp` and name the package `bank_mcp_core`, the services `bank-mcp-api` / `bank-mcp-confirm`, and the PyPI distribution `bank-mcp`. The docs predate the name. Ask before picking one. If Postern wins, the PyPI distribution name must be `postern-mcp` (bare `postern` is taken on PyPI).

## Source documents, in reading order

1. `docs/bank-mcp-design-handoff (7).md` (868 lines): the architecture. Note the space and `(7)` in the filename; quote it in shell.
2. `docs/bank-mcp-zero-trust-plan.md` (315 lines): threat model, ZT-1..ZT-8 work items, CI gates, sequencing.
3. `docs/bank-mcp-python-implementation-guide.md` (431 lines): FastMCP specifics, repo layout, code patterns.

Cross-references: `§N.N` points at the handoff, `ZT-N` at the zero-trust plan, `A1..A11` at the attack scenarios in its §3.2.

## What this is

An MCP server exposing a bank's own backend services to external consumer AI clients (Claude, ChatGPT, Perplexity) as tools across four domains: accounts, transactions, cards, payments.

**The bank is the ASPSP, not the TPP.** This inverts almost all public Open Banking prior art, where every project is a third party reading accounts through an aggregator. No inbound TPP certificate verification, no multi-ASPSP adapter layer, no eIDAS certificates presented outbound. Tool contracts borrow Open Banking semantics for familiarity only.

The defining property that drives every decision: an LLM the bank does not control chooses which tools to call, against real money, with attacker-controllable text (transaction memos, payee names, merchant strings) in its context. The operating assumption is not "the network is hostile" but **"the caller is under adversarial influence at all times, even when correctly authenticated."**

## Architecture

Two deployables over one shared library. This is a decision, not a preference (handoff §8.2):

| Service | Holds | Vault role | Can reach |
|---|---|---|---|
| `services/api` | MCP tools, OAuth/device-grant endpoints, QR page | **read** | backend read endpoints only |
| `services/confirm` | approval callback, execution | **write** | backend write endpoints |

`packages/bank_mcp_core/` carries `domain/` (masked types), `facade/` (httpx + internal JWT), `store/` (SQLAlchemy + Alembic), `auth/` (Vault key fetch, JWT minting), `risk/` (tier selection).

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
- **Never write "Face ID" anywhere in this codebase or its docs.** The bank app brands its identity-verification feature that way, but it is server-side selfie matching in the backend cluster, not Apple's on-device feature. Any reader, human or model, will implement the wrong thing. Use "app identity verification"; write "device unlock biometric" when the phone's own biometric is meant.
- **Masking is a type property, not a function someone remembers to call.** `MaskedPan`, `MaskedIban` via `Annotated` + Pydantic validator, whose only constructor masks. A handler that forgets must fail validation, not leak. Prefer the backend returning pre-masked values so the server never holds a full PAN and stays out of PCI DSS scope.
- **`payments.create_payment` takes a `payee_ref`, never a raw IBAN.** A new payee's IBAN is typed in the bank app during confirmation and never passes through the agent channel.
- **`cacheScope` is per-user, never global.** The tool catalog varies by consent state; a shared cache leaks which accounts and permissions a customer has. That is a data leak, not a performance bug.
- **Validate `Mcp-Method` / `Mcp-Name` headers against the body** in middleware before any handler runs; mismatch returns 400 with JSON-RPC `-32020`. A load balancer routing on a header while the server executes on the body is a request-smuggling shape.
- **MRTR is for disambiguation only** (which account, which card, which date range). Never for authorizing money movement, because the answer routes back through the model's channel.
- **Tier 1 is the default for writes, not tier 2.** Tier 2 adds server-side identity verification, which is a GDPR Article 9 special-category processing event on every single use, costs 5 to 15 seconds, and fails a real percentage of the time. Tier 1 already satisfies SCA with two factors.
- **Declare the verification tier on the tool definition.** Never derive it from the HTTP verb: search endpoints are POST because the body is large, and a five-year transaction export is a GET.
- **Do not cite network isolation as a zero-trust control.** PrivateLink is blast-radius reduction. The identity layer is the control.
- **Tool definitions are static config versioned in the repo**, never registered at runtime by backend services. Runtime registration breaks the PrivateLink design and makes the tool surface impossible to diff between deploys.
- **Do not map backend endpoints 1:1 to tools.** OpenAPI-to-MCP generators are unusable here: they would expose a directly callable payment endpoint and discard the challenge flow, consent checks, idempotency and audit chain.

## Version traps

Both of these will produce plausible, wrong code from memory. Verify before relying on either.

- **FastMCP is at v4.0.3 (2026-09-05), under the `PrefectHQ` org, not `jlowin`.** Nearly every FastMCP example in training data and on the web is v2 or v3. In v4, `@mcp.tool` takes no parentheses. Docs are published in llms.txt format at `https://gofastmcp.com/llms.txt`: fetch the index, then the page. The implementation guide's §0.1 lists what was verified on 12 September 2026 and §0.2 lists what was explicitly not (v3 to v4 breaking changes, `httpx` vs `httpx2`, tool annotation syntax, MRTR support, session semantics). Anything outside §0.1 is design reasoning, not a verified framework fact.
- **Package identity:** this project uses `fastmcp` (PrefectHQ, `from fastmcp import FastMCP`), not the official `mcp` SDK (`mcp.server.mcpserver.*`). Mixing imports produces confusing type errors. Pin `fastmcp>=4.0.3,<5`.
- **MCP protocol `2026-07-28` removed the `initialize`/`initialized` handshake and protocol-level sessions**, including `Mcp-Session-Id`. Every request is self-describing and any request can land on any instance. No in-process session state at all: mint an explicit handle and have the model pass it back as an argument, which is exactly what the challenge ID does. Server-level `instructions` used to live on `InitializeResult`, which no longer exists; confirm where it lives now.

## Commands

None of these run yet, since the repo has no `pyproject.toml`. They are what the implementation guide §1.1 and §8 specify for the skeleton:

```bash
uv sync                      # install; uv.lock is committed
uv run ruff check .
uv run mypy .                # [tool.mypy] strict = true
uv run lint-imports          # import-linter, reads .importlinter
uv run pytest
uv run pytest tests/test_masking_golden.py::test_name   # single test
```

`asyncio_mode = "auto"` is set in `[tool.pytest.ini_options]`, so async tests need no marker. Use FastMCP's in-process `Client` against the server object for tool tests (no network), `respx` for the backend, `testcontainers[postgres]` for a real database, and `RSAKeyPair.generate()` + `StaticTokenVerifier` for auth fixtures.

Images are two targets from one multi-stage Dockerfile:

```bash
docker build --target api --platform linux/arm64 .
docker build --target confirm --platform linux/arm64 .
npx @modelcontextprotocol/inspector    # test before wiring any real client
```

Local development needs no VPC: `docker compose` with Postgres and stubbed backends, uvicorn, a fake Vault key from file.

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

The §5 residual risks in the zero-trust plan are bounded, not closed: client runtime integrity cannot be attested, third-party retention is unrecallable, rendering is outside the bank's control, and the regulatory treatment of consumer AI agents against bank APIs is unsettled. Do not let anyone record them as solved.

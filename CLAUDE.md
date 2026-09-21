# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository state

Working software, not a skeleton. `make ci` exits 0 on 1168 tests (measured 20 September 2026); `make ci` + deploy workflow tests exit 0 on 1188 (20 September 2026). What exists: five read tools (`start_session`, `accounts.list`, `accounts.get_balance`, `transactions.list`, `cards.list`), four of them behind a Postgres-backed consent check; an append-only `audit_log` carrying up to two rows per tool call, both fail-closed per `dev-docs/decisions/0006-audit-write-failure.md` -- one committed before the operator's backend is reached (`outcome='reaching'`, written from the facade hook `services/api/main.py` wires, carrying in `reaching_at` the last reading taken before that touch, which errs early and is distinct from `at`, the call's arrival) and one after the call finishes, correlated by `call_id`; risk signals from ``RiskEngine`` + ``IpAnomalyDetector`` stored as JSONB on the completion row for Postgres-queryable anomaly tracking; ten migrations (plus one pending: ``0de54913a8b2`` adds the ``risk_signals`` JSONB column to ``audit_log``); customer tokens verified by FastMCP's `JWTVerifier` against a configured JWKS and issuer; the read/write signing-key split, with each service publishing only its own key at `/.well-known/jwks.json`; bounded connect, command and pool timeouts on the database; ZT-5 risk engine (per-session budgets, tier escalation, IP/ASN anomaly detection via ``IpTracker`` and ``IpAnomalyDetector`` — impossible travel, excessive IP diversity); pluggable session store backend (in-memory for dev/test, Redis-compatible — AWS ElastiCache, Google Memorystore, Azure Cache for Redis — for production via ``POSTERN_REDIS_URL``); ZT-4 microsegmentation tests; ZT-3 workload attestation (digest drift detection via ``test_zt3_digest_drift.py``, deploy pipeline with cosign signing + verification, SBOM generation via syft, Trivy vulnerability scanning — ``.github/workflows/deploy.yml``, decision record 0011); ZT-7 revocation list (per-session, per-customer+client, kill-switch); ZT-8 default-deny egress analysis (no hardcoded external endpoints in application code); ZT-1 continuous authorization and revocation (revocation check on every token mint, jti replay cache for A10); ZT-6 sender-constrained tokens — DPoP not viable (absent from MCP 2026-07-28 spec, no client vendor support), resolved by decision record 0010 with compensating controls (60s TTL, jti replay cache, revocation on mint, audience scoping). What does not: any payments tool, the approval callback (`services/confirm` publishes its JWKS and nothing else), the RFC 8628 device grant and its QR flow, and Vault itself, since `KeySource` is the seam Vault lands behind and a key today comes from a PEM on disk or is generated in process. Read "Architecture" and "Hard rules" below as the target, and the two lists above as how much of it has landed.

**Naming is settled: `postern`.** Docs and code agree: `postern`, `postern_core`, `services/api`, `services/confirm`. The three design docs carried a `bank-mcp-` prefix until 17 September 2026 and were renamed then, along with the MCP tool `banking_start_session`, which is now `start_session`. The dated records under `docs/verification/` and `dev-docs/decisions/` still carry the old names and are left that way on purpose: they record what was observed on a date. The PyPI distribution name must be `postern-mcp`, since bare `postern` is taken.

---

## ⚠️ EVERY OPERATOR MUST DO THESE THINGS THEMSELVES — NOTHING HERE IS DONE FOR YOU

This repo is a **framework**, not a turnkey deployment. Every company that wants to run Postern must implement the items below in their own infrastructure, their own repos, and their own teams. **None of these are optional.** If you skip any of them, the zero-trust guarantees do not hold.

### 1. Backend domain service subject enforcement (ZT-2 — CRITICAL PATH)
**You must audit every handler in your backend services.** Each one must scope queries by the JWT `sub` claim, not by any request body field. If a handler accepts an account ID from the request instead of deriving it from the token, cross-customer data access (A5) is live. This is not a code change in this repo — it lives in your backend repos. **Answer this before writing any other ZT control.** If the domain services don't enforce on `sub`, nothing else matters.

### 2. Infrastructure (Terraform repo — gate 5)
This repo has zero Terraform files. You must create them:

- **ECR repositories** — one per image (`postern-api`, `postern-confirm`) with lifecycle rules
- **ECS cluster + services** — Fargate tasks, each referencing images by sha256 digest (not tag)
- **Separate task roles** — read role must NOT be able to assume the write role or access its Vault path
- **VPC / subnets** — private subnets, NAT Gateway (or egress deny per ZT-8), PrivateLink to your Istio gateway
- **SSM Parameter Store** — publish ECR URIs, cluster name, service names, subnet IDs under `/postern/<env>/`

### 3. AWS-level tests (in your Terraform repo)
- **IAM policy test** — assert read role cannot assume write role or read its Vault path
- **ECS task definition validation** — assert digest references, `awsvpc` mode, `readonlyRootFilesystem = true`
- **Security group validation** — assert read SG cannot reach write endpoints; no `0.0.0.0/0` egress except known AWS endpoints
- **Cosign integration test** — push an unsigned image to ECR, run the deploy workflow's cosign verify step, assert it fails

### 4. GitHub configuration (manual, one-time)
- Create two **GitHub Environments** (`staging`, `production`) with required reviewers
- Add repository secrets: `AWS_ROLE_ARN` (OIDC role for the pipeline), `AWS_ECR_REGISTRY`
- The deploy workflow (`.github/workflows/deploy.yml`) is ready — it just needs these secrets to run

### 5. Platform team requirements (handoff §10.26)
- **SBOM format** — confirm what your org requires (SPDX, CycloneDX?)
- **Cosign signing** — confirm if keyless OIDC is acceptable or if you need KMS-backed keys
- **Approved base images** — does your org have a curated image list?
- **Trivy ignore file** — which CVEs are acceptable risks for your org?

### 6. Vault integration
This repo uses a `KeySource` seam — today it loads from PEM files or generates keys in process. You must wire the real Vault backend:
- **Two signing roles** — read role and write role, separate keys (handoff §7.2)
- **JWKS hosting** — each service publishes its own key at `/.well-known/jwks.json`
- **Sidecar pattern** — how Vault secrets reach the containers (handoff §10.27)

### 7. Backend OpenAPI contract tests (gate 4)
Your backend teams must publish:
- An **OpenAPI document** for each domain service
- An **`mcp-tools.yaml` manifest** mapping OpenAPI endpoints to MCP tools
- Contract tests that validate the MCP tool layer against those documents

### 8. GuardDuty Runtime Monitoring
Enable runtime threat detection on your Fargate tasks. This requires the EKS/Fargate agent and GuardDuty enablement — a platform team operation.

### 9. Red team scenarios (§6.2 of zero-trust plan)
Before production, run these six scenarios against your deployment:
1. Injected instruction in a transaction memo attempting to initiate a payment (A1)
2. QR relay to a separate browser; confirm pairing-code mismatch blocks it (A2)
3. Token captured from one client, replayed from different infrastructure (A4, ZT-6)
4. Cross-customer account access with a valid token (A5, ZT-2)
5. Bulk transaction extraction across many calls; confirm alerting fires (A6, ZT-5)
6. Session revocation mid-conversation; confirm timing (ZT-1, ZT-7)

### 10. Compliance sign-off
- **§5.3 rendering risk** — conduct/compliance position on erroneous rendering by third-party clients
- **§5.4 regulatory treatment** — compliance opinion on whether consumer AI agents acting for a bank's customers constitute an account information service (PSD2)
- **Art. 9 basis and DPIA** — DPO approval for identity verification processing (handoff §10.9)
- **Third-party disclosure analysis** — DPO review of what data lands in AI vendor chat histories (§10.19)

---

## Source documents, in reading order

1. `dev-docs/postern-design-handoff.md`: the architecture.
2. `dev-docs/postern-zero-trust-plan.md`: threat model, ZT-1..ZT-8 work items, CI gates, sequencing.
3. `dev-docs/postern-python-implementation-guide.md`: FastMCP specifics, repo layout, code patterns.

Cross-references: `§N.N` points at the handoff, `ZT-N` at the zero-trust plan, `A1..A11` at the attack scenarios in its §3.2.

Also current, and corrected against what execution actually found: `docs/superpowers/plans/postern-foundation-and-read-surface-2026-09-12.md` (the 15-task plan being executed, task by task), `dev-docs/decisions/` (decision records), `README.md`. Where a design doc and the plan disagree, the plan is newer.

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
- **The HTTP client is `httpx2`, not `httpx`.** `fastmcp` 4.0.3 pulls `fastmcp-slim[client,server]`, which declares `httpx2>=2.5.0` and no `httpx`. `respx` cannot mock it: it type-checks against `httpx.Response` and raises `TypeError` at mock-setup time, before any request. Backend tests inject `httpx2.MockTransport(handler)` instead, which does carry an `Authorization` header through to the handler. `respx` has been removed from the dev group. See `dev-docs/decisions/0001-facade-http-client.md`.
- **Smaller v4 facts, all verified:** `@mcp.tool` works bare *and* with parentheses. Tool annotations come from `mcp.types.ToolAnnotations`, not from fastmcp. `ctx.set_state` / `get_state` are **async** (`await`). `FastMCP()` accepts `cache_scope` and `cache_ttl` directly. The in-process test `Client(transport=server)` accepts **no auth argument**, which is why tools resolve the customer through an injected `CustomerResolver` rather than reading the token directly.
- **Package identity:** this project uses `fastmcp` (PrefectHQ, `from fastmcp import FastMCP`), not the official `mcp` SDK (`mcp.server.mcpserver.*`). Mixing imports produces confusing type errors. Pin `fastmcp>=4.0.3,<5`.
- **MCP protocol `2026-07-28` removed the `initialize`/`initialized` handshake and protocol-level sessions**, including `Mcp-Session-Id`. Every request is self-describing and any request can land on any instance. No in-process session state at all: mint an explicit handle and have the model pass it back as an argument, which is exactly what the challenge ID does. Server-level `instructions` now lives on the `server/discover` result. There is a third mandatory header, `MCP-Protocol-Version`, alongside `Mcp-Method` and `Mcp-Name`. SSE resumability is gone, so a dropped stream loses the in-flight request and the client re-issues it with a new id: **every handler must be safe to re-run**. MRTR's `requestState` is attacker-controlled and MUST be integrity-protected (HMAC or AEAD) if it influences authorization.
- **DPoP is not in the spec.** A search of the entire `2026-07-28` tree, security-considerations page included, returns zero hits for DPoP, RFC 9449, sender-constrained tokens or mTLS. The only token-binding mechanism is audience restriction via RFC 8707 resource indicators. This closes ZT-6's first branch: it resolves to a written decision record plus compensating controls, not to implementing DPoP.

## Commands

```bash
uv sync                                                  # uv.lock is committed
make ci                                                  # lint fmt-check type imports lock citations test
make fmt                                                 # ruff format
make citations-baseline                                  # regenerate tools/citations-baseline.json
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

Four from handoff §8.7, plus three from the zero-trust plan §6.1. Gates 1, 2 and 3 exist and run in `make ci`; gate 6 runs there too, but against this repo's stub rather than the domain services it names (item 6); gate 7a (digest drift) also runs in `make ci`; gate 7b (cosign + SBOM deploy pipeline, ZT-3) also exists as ``.github/workflows/deploy.yml`` and is validated by ``test_zt3_deploy_pipeline.py`` (20 tests); gate 7c (no hardcoded external endpoints, ZT-8) also runs in `make ci`. Where a gate exists, it blocks, it does not warn. Gates 4 and 5 do not exist in this repo, verified by search on 18 September 2026, and each names below what it is blocked on:

1. **Golden masking test**: every tool against fixtures, assert no output matches a PAN or IBAN regex. Add it while there are four tools, not later with twenty.
2. **Header/body mismatch** returns 400 + `-32020`. Write this test first; a generic `ToolError` may not produce the right status.
3. **Import-linter**: `services.api` must not import `services.confirm`. This is the A3 control expressed as a lint rule.
4. **Backend OpenAPI contract tests** against published artifacts. **Not built, blocked on the domain teams publishing an artifact.** No OpenAPI document, no `mcp-tools.yaml` manifest and no contract test exists here, and handoff §8.5 steps 1 to 3 put all three in the backend repos, so there is nothing to test against. `packages/postern-core/src/postern_core/domain/models.py` is this repo's MCP-facing contract and is deliberately not the backend's shapes.
5. **IAM policy test**: the read role cannot assume the write role or read its Vault path. **Not built, blocked on infrastructure that is not in this repo.** Zero IAM policies, zero Terraform files, no `hvac` and no Vault: `packages/postern-core/src/postern_core/auth/keys.py` is the seam Vault lands behind and its docstring records that no test here touches Vault, and handoff §12 puts infrastructure in a separate Terraform repo. The code-level half of the same property is pinned by `tests/test_key_split_is_a_property.py` and `.importlinter`, which is a different assertion from an IAM one.
6. **Cross-customer contract tests** per domain service (ZT-2). **What runs is against this repo's stub, not per domain service.** `tests/test_stub_subject_scoping.py` (325 lines, 86 tests) drives `stub/backend.py`'s four domain routes over ASGI with a second customer's token and asserts the other customer's values are absent from the body, not only that the status is 404. It blocks like the rest. The gate itself is still owed by the teams that own the domain services, which are not in this repo: `dev-docs/postern-zero-trust-plan.md` §3.2's A5 row records that enforcement as unverified, and no test here can settle it.
7. **Cosign signature + SBOM verification at deploy**, as a hard gate. Signing without verification is ceremony. **Fully built: gate 7a (digest drift, `make ci` runs ``test_zt3_digest_drift.py``) and gate 7b (cosign sign + verify, SBOM generation via syft, Trivy scanning — ``.github/workflows/deploy.yml``, validated by ``test_zt3_deploy_pipeline.py``).** The deploy workflow signs images with cosign (keyless/OIDC), generates SPDX SBOMs, scans for HIGH/CRITICAL vulnerabilities with Trivy, verifies signatures against the Sigstore Rekor transparency log before deploy, and requires GitHub Environment approval for staging/production. The pipeline triggers on `workflow_dispatch` only (no auto-triggers to avoid billed minutes). What remains: actual AWS credentials (ECR registry, ECS cluster) and the platform team's signing/SBOM requirements (handoff §10.26).

## Before implementing

**ZT-2 is the critical path and is answered by another team.** Istio validates the JWT; the domain services must enforce on it. If any handler scopes its query by an account ID from the request body rather than by the token `sub`, the entire authorization layer is decorative and cross-customer access (A5) is live. Finding that out six weeks in is the worst outcome available. The zero-trust plan §7 puts this in week one.

Handoff §10 lists 28 open questions. Several change the architecture rather than the code, and four gate the payment path specifically: headless challenge initiation (§10.4), the app's pairing-code screen (§10.10), where dynamic linking is enforced (§10.13), and whether domain teams will expose pre-masked projections (§10.17). Build all four domains' tool contracts up front but ship payments last, so those three cross-team dependencies do not block reads and tier-1 writes.

The §5 residual risks in the zero-trust plan are bounded, not closed: client runtime integrity cannot be attested, third-party retention is unrecallable, rendering is outside the operator's control, and the regulatory treatment of consumer AI agents against bank APIs is unsettled. Do not let anyone record them as solved.

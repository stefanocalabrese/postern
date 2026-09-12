# Postern

A small guarded gate, not the main entrance.

Postern is an MCP server that exposes a bank's own backend services to external AI
clients (Claude, ChatGPT, Perplexity) as tools, across four domains: accounts,
transactions, cards, payments. The bank is the ASPSP. Customers are the bank's own,
and they authenticate directly with Postern through a QR device-grant flow; the AI
vendor is a software supplier, closer to a browser than to a payment institution.

That inverts nearly all public Open Banking prior art, where the project is a third
party reading accounts through an aggregator. A survey of 24 public "open banking
mcp server" repos in September 2026 found the read-only surface crowded, the write
surface essentially unbuilt, and nothing at all for the bank-internal first-party
case.

## Status

Skeleton. Tasks 0 and 1 of a 15-task plan are done. There are no tools yet, no
database, no authentication, and no backend calls.

What exists: a uv workspace, a six-gate `make ci`, an import-linter contract that
blocks the read path from importing the write path, and one decision record.

Do not read the green gates as working software. `docs/superpowers/plans/postern-foundation-and-read-surface-2026-09-12.md`
has a section named "What this plan deliberately does not establish" listing the
seven things that are still absent, including any real authentication and the Vault
read/write key split.

## The design in one paragraph

An LLM the bank does not control decides which tools to call, on behalf of a
customer, against their real money, with attacker-controllable text (transaction
memos, payee names, merchant strings) sitting in its context. So the operating
assumption is not "the network is hostile" but "the caller is under adversarial
influence at all times, even when correctly authenticated". Everything else follows
from that sentence.

Two deployables share one library. `services/api` holds the tools and a read-only
Vault role. `services/confirm` holds the approval callback and the write role. A
compromised tool handler cannot mint a token the payments service will accept,
because it does not hold the key. That is an infrastructure property, not a
code-review promise.

## Flow

The diagram below covers both phases end to end. Phase A is the RFC 8628 device
grant: the customer scans a rotating QR or opens a universal link, confirms a
pairing code in their own bank app, and the signed approval becomes a customer
access token. Phase B is a single tool call: Postern verifies the customer token,
mints a short-lived internal JWT from a Vault-cached signing key, and Istio
enforces that internal JWT before a domain service returns rows that Postern
projects and masks back to the client.

![Sequence diagram of the Postern device-grant authorization flow and a tool call reaching a domain service behind Istio](docs/images/auth-flow.png)

## Rules that are decisions, not preferences

Read `CLAUDE.md` before changing anything. The load-bearing ones:

- **There is no payment execution tool.** `payments.create_payment` proposes;
  `payments.get_payment_status` observes. Execution is triggered by the customer's
  confirmation on their own device and runs in the approval callback. A
  `submit_payment` in the schema hands the model an execution capability and makes
  safety depend on it choosing not to use it.
- **The confirmation payload is built server-side from the stored challenge row**,
  never from agent input. An injected agent can propose a wrong payee. It cannot
  change what the customer is shown before they approve.
- **The token is the identity.** `user_id` is never a tool argument and is never
  returned to the client.
- **Masking is a type property.** `MaskedPan` and `MaskedIban` mask on construction.
  A handler that forgets fails validation instead of leaking. Counterparty account
  numbers are omitted entirely: name only.
- **Never write "Face ID" in this codebase.** The bank app brands its
  identity-verification feature that way, but it is server-side selfie matching in
  the backend cluster, not Apple's on-device feature. Any reader, human or model,
  will build the wrong thing. Write "app identity verification", and "device unlock
  biometric" when the phone's own biometric is meant.

## Running the gates

```bash
uv sync
make ci
```

`make ci` runs six gates: `lint`, `fmt-check`, `type`, `imports`, `lock`, `test`.
They run locally because GitHub Actions minutes are billed on private repos. A
workflow file lands in Task 14 with `on: workflow_dispatch` only, so nothing fires
on push until someone decides to spend the minutes.

`make fmt` formats. Note that `fmt-check` is scoped to `packages services tests`
rather than `.`, because `ruff format` on `.` also rewrites the Python code fences
inside the markdown design docs.

## Layout

```
packages/postern-core/     shared library: domain types, façade, identity
services/api/              read path, MCP tools, OAuth endpoints
services/confirm/          write path, approval callback, execution
docs/                      design handoff, zero-trust plan, implementation guide
docs/decisions/            decision records
docs/superpowers/plans/    the implementation plan being executed
```

The `.importlinter` contract forbids `services.api` from importing
`services.confirm`, and it scans `postern_core` too. With only `services` in
`root_packages` the two-hop route `services.api -> postern_core ->
services.confirm` is reported as KEPT with exit 0, which is the route a real
regression would take through the one library both services import.

## Stack

Python 3.12 (pinned in `.python-version`), fastmcp 4.0.3, pydantic 2.13.5,
httpx2 2.12.0, SQLAlchemy 2.0 async, Alembic, uv.

Two version traps will produce plausible and wrong code from memory:

1. **FastMCP is v4, under `PrefectHQ`, not `jlowin`.** Almost every FastMCP example
   in training data and on the web is v2 or v3. Docs are published in llms.txt form
   at https://gofastmcp.com/llms.txt.
2. **MCP `2026-07-28` removed the `initialize` handshake and protocol-level
   sessions**, including `Mcp-Session-Id`. Every request is self-describing, so
   there is no in-process session state anywhere.

The HTTP client is `httpx2`, not `httpx`, because that is what FastMCP 4 depends on.
`respx` cannot mock it: it type-checks against `httpx.Response` and raises
`TypeError` at mock-setup time. Backend tests inject an `httpx2.MockTransport`
instead. See `docs/decisions/0001-facade-http-client.md`.

## Design documents

Read in this order:

1. `docs/bank-mcp-design-handoff (7).md`, the architecture, 868 lines. Section 10
   lists 28 open questions; several change the architecture rather than the code.
2. `docs/bank-mcp-zero-trust-plan.md`, the threat model and work items ZT-1 to ZT-8.
3. `docs/bank-mcp-python-implementation-guide.md`, framework specifics and code
   patterns. Its section 0 verification protocol is mandatory.

**ZT-2 is the critical path and it is not answered in this repo.** Istio validates
the JWT; the bank's domain services must enforce on it. If any handler scopes its
query by an account ID taken from the request body rather than by the token `sub`,
the whole authorization layer is decorative and cross-customer access is live.

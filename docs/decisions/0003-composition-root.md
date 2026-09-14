# 0003: Composition root -- the four questions Task 12 owns

**Date:** 2026-09-14

## Question

Tasks 4 through 11 each deferred a lifecycle or configuration question to
"Task 12, the composition root" rather than deciding it locally, because
`services/api/main.py` is the first place all the pieces are assembled into
something uvicorn can actually serve. This record answers the four
questions, plus one the adversarial pass raised, and documents a defect
found while proving the answers actually work.

## 1. `BackendClient` lifecycle and `aclose()`

**Decision: one `BackendClient` per process, closed on ASGI shutdown.**

Nothing before this task constructed a concrete `BackendClient` outside a
test, so the lifecycle was unset. Per-request construction was considered
and rejected: `httpx2.AsyncClient` owns a connection pool specifically so
concurrent requests can reuse connections, and constructing one per request
throws that away for no benefit here (`BackendClient` holds no
per-request-scoped state -- the customer and token are both call arguments,
not constructor state).

`create_app` therefore builds exactly one `BackendClient` and stores it on
`app.state.backend_client`. Closing it needs to hook the ASGI `lifespan`
protocol, and `FastMCP.http_app()` returns a `StarletteWithLifespan` whose
own lifespan starts and stops FastMCP's session manager -- FastMCP's docs
warn that nesting apps without passing that lifespan through leaves the
session manager uninitialised. `_close_backend_after_fastmcp_shutdown` in
`services/api/main.py` does not replace `app.router.lifespan_context`; it
reads the existing one, wraps it (`async with original_lifespan(app): yield`,
then `await backend.aclose()` after the `async with` exits), and writes the
wrapped version back. FastMCP's own startup/shutdown run completely
unchanged inside the `async with`; the backend is closed only once that
block has exited, i.e. only after FastMCP's shutdown has finished, so no
in-flight request can observe a closed client.

**Proof both run:**
`tests/test_asgi_app.py::test_lifespan_runs_fastmcps_own_startup_then_closes_the_backend_client_after_its_shutdown`
drives the ASGI lifespan protocol by hand (no lifespan-manager dependency is
installed), makes a real `tools/call` request while the app is "running"
(this can only succeed if FastMCP's own lifespan started the session
manager -- there is no other code path that initialises it), asserts the
spy on `backend.aclose` has not fired yet, drives `lifespan.shutdown`, and
only then asserts it fired exactly once and `backend._client.is_closed` is
`True`.

## 2. The façade's real timeout budget

**Decision: an explicit `httpx2.Timeout` built from four `Settings` fields,
summing to a stated 10-second worst case by default.**

`BackendClient(timeout=10.0)`'s bare float applies independently to
httpx2's connect, read, write and pool phases (Task 6 measured this against
httpx2 2.12.0), so the apparent "10 seconds" was a worst case of up to 40.
`create_app` now always constructs an explicit `httpx2.Timeout` from four
new `Settings` fields (`backend_connect_timeout_seconds`,
`backend_write_timeout_seconds`, `backend_read_timeout_seconds`,
`backend_pool_timeout_seconds`), individually configurable by environment
variable (`POSTERN_BACKEND_{CONNECT,WRITE,READ,POOL}_TIMEOUT_SECONDS`).

Defaults sum to 10.0 seconds -- the budget the old single value was clearly
meant to express -- allocated by phase for a same-VPC/PrivateLink backend
rather than split evenly: connect (2.0s) and pool-acquisition (1.0s) should
be sub-second in practice inside the bank's own network, so their budgets
are slack for jitter, not genuine expected latency; write (2.0s) and read
(5.0s) carry the actual request/response bodies, and read gets the largest
share because a transaction export is the largest realistic response this
server proxies. A deployment that measures different real behaviour can
retune any of the four independently without a code change.

`postern_core.facade.client.BackendClient.__init__`'s `timeout` parameter
was widened from `float` to `float | httpx2.Timeout` to accept this --
`httpx2.AsyncClient(timeout=...)` already accepted a `Timeout` instance;
this is a type-hint correction, not a behaviour change to that module.

**Proof:** `test_backend_timeout_is_wired_from_settings_per_phase` asserts
the constructed client's `.timeout` matches all four settings;
`test_backend_timeout_worst_case_total_is_bounded_at_ten_seconds` asserts
the four env-sourced defaults sum to exactly 10.0.

## 3. `HeaderBodyValidation.max_body_bytes`

**Decision: 1 MiB (1,048,576 bytes) by default, configurable via
`POSTERN_MAX_BODY_BYTES`.**

Task 5 built the cap mechanism and deliberately shipped it unset (unbounded
buffering) because nothing in that task's scope could pick a number on a
deployment's behalf. This server's entire tool surface is read-only
JSON-RPC: a tool name plus small filter arguments (refs, date ranges,
day counts) -- there are no file uploads and no bulk-write bodies in this
plan's tool set. 1 MiB is generous headroom over any legitimate request
while still bounding the in-memory buffer `_drain` builds before any of
this middleware's checks run, which is otherwise an unbounded
denial-of-service surface (docs/decisions/0002-header-validation.md already
names this).

**What a deployment should consider before changing it:** the number
trades memory-exhaustion resistance against legitimate request size. Raise
it deliberately, not defensively, if a future tool genuinely needs a larger
body (a bulk import, say) -- and re-check it against whatever request size
limit the ingress load balancer or gateway in front of this service already
enforces, so the two limits do not silently disagree about which layer
rejects an oversized request first.

**Proof:** `test_create_app_wires_max_body_bytes_from_settings` (custom
value reaches the middleware), `test_default_max_body_bytes_is_one_mebibyte`
(the default), `test_end_to_end_body_over_max_body_bytes_returns_413`
(the real 413 through the full stack via `httpx2.ASGITransport`).

## 4. `strict_headers`

**Decision: left off (`False`) by default, per Task 5's design decision D2**
(flip it on only once the client allowlist is entirely on the `2026-07-28`
revision) **-- confirmed genuinely reachable by environment variable.**

`Settings.from_env()` already read `POSTERN_STRICT_HEADERS` before this
task; what Task 12 had to confirm is that the value actually reaches the
installed `HeaderBodyValidation` instance through `create_app`, not just
through `Settings`. It does:
`Middleware(HeaderBodyValidation, strict=settings.strict_headers, ...)` in
`create_app`.

**Proof:** `test_create_app_wires_strict_headers_from_settings` sets
`POSTERN_STRICT_HEADERS=1` as an actual environment variable (not a
`Settings(...)` literal), calls `create_app()` with no `settings` argument
(forcing `Settings.from_env()`), and inspects the installed middleware's own
`kwargs["strict"]`; `test_strict_headers_defaults_to_false_when_unset`
pins the default the other way.

## Adversarial-pass finding: `StubTokenMinter` must not run silently

`create_app`'s only available `TokenMinter` today is `StubTokenMinter`
(client.py: "Never deploy this... mints a fake bearer token no real backend
accepts"); the Vault-backed `InternalTokenMinter` meant to replace it is a
later plan's deliverable and does not exist in this codebase yet.

**Decision: refuse to start by default when the configuration looks
production-shaped, with a named, explicit override.** "Production-shaped"
reuses the exact signal `build_server` already uses to decide whether real
customer-facing JWT auth is configured (`customer_jwks_uri` and
`customer_token_issuer` both set) -- the only signal this codebase currently
has to distinguish a real deployment from `Settings.for_testing()` or the
local no-auth docker-compose stack. `build_server` already fails closed on
the half-configured version of that same pair; `create_app` applies the
same posture to the other authentication axis.

An unconditional refusal was rejected: it would make the composition root
permanently undeployable until the Vault-backed minter exists, which
contradicts this task's own stated goal ("the first time all the pieces are
assembled into something uvicorn can actually serve"). `Settings.allow_stub_token_minter`
(env `POSTERN_ALLOW_STUB_TOKEN_MINTER=1`) is the explicit, named override for
a deliberate early rollout -- real customer auth already live, backend still
a controlled sandbox -- that must not be mistaken for silence. Grep for it
before any milestone that touches real customer money; delete both the flag
and the check the day the real minter exists.

**Proof:**
`test_create_app_refuses_stub_minter_against_a_production_shaped_configuration`,
`test_create_app_allows_stub_minter_when_customer_auth_is_unset`,
`test_create_app_allows_stub_minter_when_explicitly_overridden`.

## Defect found while proving the above: `app = create_app()` at import time

The plan's own draft ended `main.py` with a bare `app = create_app()`. This
reproduces, one file over, the exact problem the plan's Task 12 preamble
warns about for `server.py` ("`Settings.from_env()` must not run at import
time... or every test that imports it needs the full environment"):
`create_app()` with no arguments calls `Settings.from_env()` unconditionally,
which requires three environment variables with no default.

Measured directly: `uv run pytest tests/test_asgi_app.py` failed at
*collection*, before any test ran, with `KeyError:
'POSTERN_BACKEND_BASE_URL'`, because `from services.api.main import
create_app` executes the module's top level regardless of which name a test
actually imports.

**Fix:** replaced the module-level assignment with a PEP 562 module
`__getattr__` that calls `create_app()` lazily, only when the `app`
attribute is actually looked up:

```python
def __getattr__(name: str) -> object:
    if name == "app":
        return create_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
```

`import services.api.main` (what every test does) no longer touches the
environment. `uvicorn services.api.main:app` resolves its target the same
way `getattr(import_module("services.api.main"), "app")` would, so
production is unaffected: it still gets a real, fully configured app built
from the full environment, at the only time it actually needs to exist.

**Proof:** `test_create_app_fails_clearly_on_incomplete_environment` calls
`create_app()` directly (not `main.app`) with the three required variables
unset and asserts the `KeyError` names `POSTERN_BACKEND_BASE_URL`; the rest
of `tests/test_asgi_app.py` collecting and passing at all is the proof the
lazy attribute stopped breaking import.

## Test seams added to `create_app`

The plan's draft signature, `create_app(settings: Settings | None = None)`,
has no way to inject a customer or a mocked backend transport. Two
keyword-only parameters were added -- `resolver: CustomerResolver | None`
and `transport: httpx2.AsyncBaseTransport | None`, both `None` in
production -- because the adversarial pass explicitly requires driving
`create_app()` itself end to end (a real `tools/call` reaching a tool and
returning masked data; a header/body mismatch producing a real 400; an
oversized body producing a real 413), and there is no live customer token
or reachable bank backend in CI. This mirrors the DI seam `build_server`
already established for the same reason (design decision D3): production
always resolves the customer from the validated access token and always
reaches the backend over the real network; tests inject a fixed customer
and an `httpx2.MockTransport`, exactly as every other task in this plan
already mocks the backend.

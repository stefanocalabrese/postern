"""Composition root. uvicorn targets `services.api.main:app`.

Four questions earlier tasks deliberately deferred here ("Task 12 owns
composition"); the reasoning for each lives in
`docs/decisions/0003-composition-root.md` and is summarised at its wiring
site below:

1. `BackendClient` lifecycle and `aclose()` on shutdown, joined by `Database`
   lifecycle (Task 6) -- `_close_resources_after_fastmcp_shutdown`.
2. The façade's real per-call timeout budget -- `_backend_timeout`.
3. `HeaderBodyValidation.max_body_bytes`, sourced from `Settings` -- wired
   into the `Middleware(...)` call below.
4. `strict_headers`, sourced from `Settings` -- wired into the same call.

Plus one the adversarial pass added: `create_app` refuses to start
`StubTokenMinter` against a configuration that looks production-shaped,
rather than silently minting fake bearer tokens no real backend accepts.

Plan 3 Task 2 replaces that stub here. This process now builds one
`ReadTokenMinter` over an `InternalTokenMinter` holding a READ key, and
holds no write key and no write scope: `READ_SCOPES` has no `payments.svc`
entry, so a write audience raises `KeyError` instead of minting. The guard
below is left byte-identical, which has two consequences worth naming. Its
docstring's "does not exist in this codebase yet" is stale as of this
commit. And with no `StubTokenMinter` constructed in this module any more,
it no longer gates a minter choice at all: it is now an unconditional
refusal to start under a production-shaped configuration
(`customer_jwks_uri` and `customer_token_issuer` both set) unless
`allow_stub_token_minter` is on, which every deployment running real
customer auth against this read key will trip. Whether that refusal still
earns its place belongs to the task that removes the flag, not to this one.

Task 6 adds the database: one `Database` per process, built unconditionally
from `settings.database_url` (the constructor never connects --
`create_async_engine` is lazy), handed to `AuditMiddleware` so every tool
call is recorded regardless of whether real customer auth is configured, and
closed on shutdown alongside the backend client. Consent enforcement keeps
its own, narrower condition (`has_real_customer_auth`, unchanged from Task
4): `build_server` only receives a `db` to check consent against when there
is a validated token's subject to check it for, since consent has nowhere to
read a customer from otherwise.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx2
from fastmcp.server.auth import AuthProvider
from fastmcp.server.http import StarletteWithLifespan
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import FileKeySource, GeneratedKeySource, KeySource
from postern_core.auth.read_minter import ReadTokenMinter
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerResolver
from postern_core.store.engine import Database
from starlette.middleware import Middleware

from services.api.asgi.header_validation import HeaderBodyValidation
from services.api.middleware.audit import AuditMiddleware
from services.api.server import build_server, token_customer_resolver
from services.api.settings import Settings


def _refuse_stub_minter_in_production(settings: Settings) -> None:
    """`StubTokenMinter` mints a bearer token no real backend accepts
    (its own docstring: "Never deploy this"). The Vault-backed
    `InternalTokenMinter` meant to replace it is a later plan's deliverable
    and does not exist in this codebase yet, so there is nothing else to
    wire in its place today.

    "Production-shaped" reuses the exact signal `build_server` already uses
    to decide whether real customer-facing JWT auth is configured
    (`customer_jwks_uri` and `customer_token_issuer` both set): that is the
    only way this codebase currently distinguishes a real deployment from
    `Settings.for_testing()` or the local no-auth docker-compose stack, and
    `build_server` already fails closed on the half-configured version of
    the same pair. Refusing to start here is the same fail-closed posture,
    applied to the other authentication axis: this server has no business
    accepting real customer tokens while minting fake ones for the backend.

    `settings.allow_stub_token_minter` is the named, explicit override for a
    deliberate early rollout (real customer auth already live, backend
    still a controlled sandbox): raising unconditionally here would leave
    the composition root permanently undeployable until the Vault-backed
    minter exists, which contradicts this task's own goal of being "the
    first time all the pieces are assembled into something uvicorn can
    actually serve." The override must be set explicitly; the default stays
    fail-closed.
    """
    if settings.allow_stub_token_minter:
        return
    if settings.customer_jwks_uri is not None and settings.customer_token_issuer is not None:
        raise RuntimeError(
            "create_app refuses to start with StubTokenMinter against a "
            "production-shaped configuration (customer_jwks_uri and "
            "customer_token_issuer are both set). StubTokenMinter mints a "
            "fake bearer token no real backend accepts; wire the "
            "Vault-backed InternalTokenMinter before deploying with real "
            "customer authentication, or set "
            "POSTERN_ALLOW_STUB_TOKEN_MINTER=1 to override deliberately."
        )


def _read_key_source(settings: Settings) -> KeySource:
    """The READ signing key, from a PEM when a deployment names one.

    A set `read_key_pem_path` is the Vault Agent shape: the sidecar renders
    the private key to a file and this process reads it once at startup, so
    `FileKeySource`'s public-key rejection fires before uvicorn serves rather
    than at the first customer request. Unset means generate 2048 bits in
    process, which `Settings.for_testing()` and the local docker-compose
    stack both want: nothing verifies these tokens locally (the backend stub
    reads `sub` out of the payload without checking the signature, by
    design), so a generated key needs no secret on disk and no key rotation.

    A process restart throws a generated key away, which is exactly why a
    deployment must set the path: the JWKS Task 3 publishes would otherwise
    change under every verifier on every restart.
    """
    if settings.read_key_pem_path is not None:
        return FileKeySource(Path(settings.read_key_pem_path), kid=settings.read_key_kid)
    return GeneratedKeySource(kid=settings.read_key_kid)


def _backend_timeout(settings: Settings) -> httpx2.Timeout:
    """A bare `float` passed to `httpx2.AsyncClient(timeout=...)` applies
    independently to connect, read, write and pool (Task 6 measured this),
    so the constructor's old `timeout: float = 10.0` default was a worst
    case of up to 40 seconds, not 10. `Settings` now owns four phase
    budgets that a deployment can tune independently; see the field
    comments in `services/api/settings.py` for the reasoning behind the
    defaults.
    """
    return httpx2.Timeout(
        connect=settings.backend_connect_timeout_seconds,
        read=settings.backend_read_timeout_seconds,
        write=settings.backend_write_timeout_seconds,
        pool=settings.backend_pool_timeout_seconds,
    )


def _close_resources_after_fastmcp_shutdown(
    app: StarletteWithLifespan, backend: BackendClient, db: Database
) -> None:
    """Wires `backend.aclose()` and (Task 6) `db.close()` into the app's own
    ASGI lifespan.

    `FastMCP.http_app()` returns a `StarletteWithLifespan` whose lifespan
    starts and stops FastMCP's session manager (`fastmcp/server/http.py`).
    FastMCP's docs warn that nesting apps without passing that lifespan
    through leaves the session manager uninitialised, so this does not
    replace it: it reads the existing `app.router.lifespan_context`,
    wraps it, and writes the wrapped version back. FastMCP's startup and
    shutdown run completely unchanged inside the `async with`; the backend
    client and the database are closed only after that block exits, i.e.
    only after FastMCP's own shutdown has finished, so no in-flight request
    can observe either as closed. Proven in `tests/test_asgi_app.py`
    (`test_lifespan_runs_fastmcps_own_startup_then_closes_the_backend_client_after_its_shutdown`):
    a real tool call succeeds while the app is running (which requires
    FastMCP's own lifespan to have started the session manager), and both
    the backend and the database are confirmed closed exactly once, only
    after shutdown completes.
    """
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: StarletteWithLifespan) -> AsyncIterator[None]:
        async with original_lifespan(app):
            yield
        await backend.aclose()
        await db.close()

    app.router.lifespan_context = lifespan


def create_app(
    settings: Settings | None = None,
    *,
    resolver: CustomerResolver | None = None,
    transport: httpx2.AsyncBaseTransport | None = None,
    auth_override: AuthProvider | None = None,
) -> StarletteWithLifespan:
    """Assemble the read-path ASGI app.

    `resolver`, `transport` and `auth_override` are keyword-only test seams:
    production (the module-level `app` attribute below, built by
    `__getattr__`) always resolves the customer from the validated access
    token, always reaches the backend over the real network, and always
    builds its `JWTVerifier` from `Settings`. Tests inject a fixed customer,
    an `httpx2.MockTransport`, and (Task 4) a `JWTVerifier` built from a
    generated key pair so a consent-enforcement test can mint its own
    tokens, the same way every other task in this plan already mocks its
    external dependencies because there is no live customer token, real
    bank or real identity provider to call against in CI.
    """
    settings = settings or Settings.from_env()
    _refuse_stub_minter_in_production(settings)

    # Plan 3 Task 2: one minter, built over the READ key only. `BackendClient`
    # calls a `TokenMinter` (`customer, audience -> str`); `ReadTokenMinter`
    # is the adapter onto `InternalTokenMinter.mint`, whose signature is
    # wider. `consent_id` and `client_id` from handoff §7.2 are not supplied
    # yet: `client_id` is reachable only from `get_access_token()`, which
    # `BackendClient.get_json` has no access to, and `consent_id` needs the
    # tool layer to pass the `consents` row id, so both are façade-signature
    # plumbing a later task owns rather than a value that could be guessed
    # here.
    read_key_source = _read_key_source(settings)
    backend = BackendClient(
        settings.backend_base_url,
        ReadTokenMinter(
            InternalTokenMinter(issuer=settings.read_token_issuer, key_source=read_key_source)
        ),
        transport=transport,
        timeout=_backend_timeout(settings),
    )
    # Task 6: one `Database` per process, built unconditionally.
    # `create_async_engine` is lazy (Task 1's own tests construct one against
    # an address that is never reached), so this never blocks startup and
    # never requires a reachable Postgres just to assemble the app -- only
    # the first actual query does. Built here, not gated the way `consent_db`
    # below is, because `AuditMiddleware` must record every call regardless
    # of whether real customer auth is configured: the local docker-compose
    # stack and `Settings.for_testing()` both still want an audit trail.
    db = Database(settings.database_url)

    # Consent is enforced against `AuthContext.token`, which only exists when
    # real customer authentication is configured. `has_real_customer_auth`
    # reuses the exact signal `_refuse_stub_minter_in_production` already
    # uses for "is this production-shaped": both jwks_uri and issuer set, or
    # (Task 4) a test-injected `auth_override`. Passing `db` into
    # `build_server` regardless would deny every consent-gated call in the
    # documented no-auth path (`Settings.for_testing()`, the local
    # docker-compose stack) -- there is no validated token there for
    # `services.api.consent` to read a subject from -- which would silently
    # break that path's own stated purpose the moment this feature landed.
    # Measured: every `tests/test_asgi_app.py` end-to-end call regressed to
    # `Unknown tool` until this was scoped to real customer auth only. This
    # condition is about consent only; it does not gate whether `db` itself
    # is built or whether audit runs.
    has_real_customer_auth = (
        settings.customer_jwks_uri is not None and settings.customer_token_issuer is not None
    ) or auth_override is not None
    consent_db = db if has_real_customer_auth else None
    server = build_server(
        settings,
        resolver or token_customer_resolver,
        backend,
        db=consent_db,
        auth_override=auth_override,
    )
    # Task 6: one audit row per tool call, success or failure, regardless of
    # whether consent enforcement itself is active -- see the module
    # docstring and `services/api/middleware/audit.py`.
    server.add_middleware(AuditMiddleware(db))
    app = server.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        middleware=[
            Middleware(
                HeaderBodyValidation,
                strict=settings.strict_headers,
                max_body_bytes=settings.max_body_bytes,
            )
        ],
    )
    # Exposed on `app.state` (Starlette's own convention for app-scoped
    # resources) so tests can observe the exact `BackendClient` instance
    # `create_app` built -- its timeout, and that `aclose` was actually
    # called on shutdown -- without reaching into `build_server`/`server`
    # internals that have no reason to hold a reference to it themselves.
    # `postern_server` and `postern_database` (Task 6) exist for the same
    # reason: proving the audit middleware is installed on the real server
    # object, and that the real database gets closed on shutdown.
    app.state.backend_client = backend
    app.state.postern_server = server
    app.state.postern_database = db
    # The public half of the key the minter above signs with. Task 3's JWKS
    # route serves it, and it is the only handle on that key outside the
    # `BackendClient` the minter is buried in.
    app.state.postern_read_key_source = read_key_source
    _close_resources_after_fastmcp_shutdown(app, backend, db)
    return app


def __getattr__(name: str) -> object:
    """PEP 562 lazy module attribute.

    A bare `app = create_app()` at import time -- as the plan originally
    drafted this file -- calls `Settings.from_env()` unconditionally, which
    needs the full production environment. That is exactly the failure
    mode the plan's own preamble warns about for `server.py` ("must not run
    at import time... or every test that imports it needs the full
    environment"), just moved one file over: measured directly, `uv run
    pytest tests/test_asgi_app.py` failed at *collection*, before any test
    ran, with `KeyError: 'POSTERN_BACKEND_BASE_URL'`, because `from
    services.api.main import create_app` executes this module's top level
    regardless of which name a test actually imports. Deferring the call to
    attribute access means `import services.api.main` (what every test
    does) is free, while `uvicorn services.api.main:app` -- which resolves
    the target the same way `getattr(import_module("services.api.main"),
    "app")` would -- still gets a real, fully configured app at process
    start, which is the only time it actually needs to exist.
    """
    if name == "app":
        return create_app()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

"""Composition root. uvicorn targets `services.api.main:app`.

Four questions earlier tasks deliberately deferred here ("Task 12 owns
composition"); the reasoning for each lives in
`docs/decisions/0003-composition-root.md` and is summarised at its wiring
site below:

1. `BackendClient` lifecycle and `aclose()` on shutdown --
   `_close_backend_after_fastmcp_shutdown`.
2. The façade's real per-call timeout budget -- `_backend_timeout`.
3. `HeaderBodyValidation.max_body_bytes`, sourced from `Settings` -- wired
   into the `Middleware(...)` call below.
4. `strict_headers`, sourced from `Settings` -- wired into the same call.

Plus one the adversarial pass added: `create_app` refuses to start
`StubTokenMinter` against a configuration that looks production-shaped,
rather than silently minting fake bearer tokens no real backend accepts.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx2
from fastmcp.server.auth import AuthProvider
from fastmcp.server.http import StarletteWithLifespan
from postern_core.facade.client import BackendClient, StubTokenMinter
from postern_core.identity import CustomerResolver
from postern_core.store.engine import Database
from starlette.middleware import Middleware

from services.api.asgi.header_validation import HeaderBodyValidation
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


def _close_backend_after_fastmcp_shutdown(
    app: StarletteWithLifespan, backend: BackendClient
) -> None:
    """Wires `backend.aclose()` into the app's own ASGI lifespan.

    `FastMCP.http_app()` returns a `StarletteWithLifespan` whose lifespan
    starts and stops FastMCP's session manager (`fastmcp/server/http.py`).
    FastMCP's docs warn that nesting apps without passing that lifespan
    through leaves the session manager uninitialised, so this does not
    replace it: it reads the existing `app.router.lifespan_context`,
    wraps it, and writes the wrapped version back. FastMCP's startup and
    shutdown run completely unchanged inside the `async with`; the backend
    client is closed only after that block exits, i.e. only after FastMCP's
    own shutdown has finished, so no in-flight request can observe a closed
    client. Proven in `tests/test_asgi_app.py`
    (`test_lifespan_runs_fastmcps_own_startup_then_closes_the_backend_client_after_its_shutdown`):
    a real tool call succeeds while the app is running (which requires
    FastMCP's own lifespan to have started the session manager), and the
    backend is confirmed closed only once, after shutdown completes.
    """
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: StarletteWithLifespan) -> AsyncIterator[None]:
        async with original_lifespan(app):
            yield
        await backend.aclose()

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

    backend = BackendClient(
        settings.backend_base_url,
        StubTokenMinter(),
        transport=transport,
        timeout=_backend_timeout(settings),
    )
    # Consent is enforced against `AuthContext.token`, which only exists when
    # real customer authentication is configured. `has_real_customer_auth`
    # reuses the exact signal `_refuse_stub_minter_in_production` already
    # uses for "is this production-shaped": both jwks_uri and issuer set, or
    # (Task 4) a test-injected `auth_override`. Wiring a `Database` in
    # regardless would deny every consent-gated call in the documented
    # no-auth path (`Settings.for_testing()`, the local docker-compose
    # stack) -- there is no validated token there for `services.api.consent`
    # to read a subject from -- which would silently break that path's own
    # stated purpose the moment this feature landed. Measured: every
    # `tests/test_asgi_app.py` end-to-end call regressed to `Unknown tool`
    # until this was scoped to real customer auth only.
    has_real_customer_auth = (
        settings.customer_jwks_uri is not None and settings.customer_token_issuer is not None
    ) or auth_override is not None
    db = Database(settings.database_url) if has_real_customer_auth else None
    server = build_server(
        settings,
        resolver or token_customer_resolver,
        backend,
        db=db,
        auth_override=auth_override,
    )
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
    app.state.backend_client = backend
    _close_backend_after_fastmcp_shutdown(app, backend)
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

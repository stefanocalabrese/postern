"""Composition root. uvicorn targets `services.api.main:app`.

Four questions earlier tasks deliberately deferred here ("Task 12 owns
composition"); the reasoning for each lives in
`dev-docs/decisions/0003-composition-root.md` and is summarised at its wiring
site below:

1. `BackendClient` lifecycle and `aclose()` on shutdown, joined by `Database`
   lifecycle (Task 6) -- `_close_resources_after_fastmcp_shutdown`.
2. The façade's real per-call timeout budget -- `_backend_timeout`.
3. `HeaderBodyValidation.max_body_bytes`, sourced from `Settings` -- wired
   into the `Middleware(...)` call below.
4. `strict_headers`, sourced from `Settings` -- wired into the same call.

Plan 3 Task 2 built the real minter here, replacing `StubTokenMinter` and
its fake bearer token no backend accepts. This process now holds one
`ReadTokenMinter` over an `InternalTokenMinter` carrying a READ key, and no
write key and no write scope: `READ_SCOPES` has no `payments.svc` entry, so
a write audience raises `KeyError` instead of minting.

`_refuse_stub_minter_in_production` and the `allow_stub_token_minter` flag
that disarmed it are deleted with this commit. That guard read a settings
shape (`customer_jwks_uri` and `customer_token_issuer` both set) and never
which minter `create_app` built, so once the stub stopped being constructed
here it refused exactly the deployments running the genuine minter.
Measured before removal against that settings shape: no flag raised
`RuntimeError` naming `StubTokenMinter`, and `POSTERN_ALLOW_STUB_TOKEN_MINTER=1`
started the app with a `ReadTokenMinter`. Between that deletion and 2026-09-18
nothing checked minter identity or deployment shape at startup, and the
ephemeral-key warning below restored none of it: that fires on a generated
signing key, which is a different hazard. What checks it now is
`postern_core.auth.minter_probe.refuse_unverifiable_minter`, called in
`create_app` below on the minter that function has just built: one probe
token, verified against the key set this same process publishes, and no start
if the two disagree. It reads no settings, so the shape the deleted guard
mistook for a deployment never enters into it, and it has no override flag.
`dev-docs/decisions/0003-composition-root.md` and `0004-base-images.md` each carry
dated amendments recording the deletion and what did and did not replace it.

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

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx2
from fastmcp.server.auth import AuthProvider
from fastmcp.server.http import StarletteWithLifespan
from postern_core.auth.internal_jwt import _LIFETIME, InternalTokenMinter
from postern_core.auth.keys import (
    FileKeySource,
    GeneratedKeySource,
    KeySource,
    warn_ephemeral_signing_key,
)
from postern_core.auth.minter_probe import refuse_unverifiable_minter
from postern_core.auth.read_minter import JtiReplayCache, ReadTokenMinter
from postern_core.auth.revocation import RevocationList
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerRef, CustomerResolver
from postern_core.store.engine import Database
from starlette.middleware import Middleware

from services.api.asgi.header_validation import HeaderBodyValidation
from services.api.asgi.request_deadline import RequestDeadline
from services.api.jwks import jwks_route
from services.api.middleware.audit import AuditMiddleware, record_data_touch
from services.api.middleware.risk import RiskMiddleware
from services.api.server import build_server, token_customer_resolver
from services.api.settings import Settings

# Subject of the one token `create_app` mints to check its own minter. It is a
# reference to nobody: `CustomerRef` accepts it (the pattern is `cust[:_]`
# followed by alphanumerics) and no fixture, `stub/backend.py::OWNERS` entry
# or test in this repository uses it. The token it appears in is verified in
# process and discarded; nothing sends it anywhere.
_STARTUP_PROBE = CustomerRef(value="cust_startupprobe")


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
    change under every verifier on every restart. That sentence has been in
    this docstring since Plan 3 Task 2 and the code said nothing at runtime;
    since 2026-09-18 the generated branch warns, unconditionally and without
    refusing. `warn_ephemeral_signing_key` carries why it is neither gated
    nor fatal, and `docs/verification/2026-09-18-multi-replica-jwks.md`
    measures what the discarded key costs a caller.

    Production deployments MUST set ``POSTERN_REQUIRE_PEM_KEY=1`` to refuse
    startup with an ephemeral key. Without it, a restart changes the JWKS
    and every verifier rejects all tokens until they re-fetch.
    """
    if settings.read_key_pem_path is not None:
        return FileKeySource(Path(settings.read_key_pem_path), kid=settings.read_key_kid)
    # Warn AFTER the key exists, not on `read_key_pem_path is None` read a
    # second time from settings: the lesson of `d203606` is that a control
    # keyed on configuration shape drifts away from what the process actually
    # built. This fires only on the object below having been constructed.
    source = GeneratedKeySource(kid=settings.read_key_kid)
    warn_ephemeral_signing_key(
        role="READ", kid=settings.read_key_kid, pem_env_var="POSTERN_READ_KEY_PEM_PATH"
    )
    # Audit finding (2026-09-21): refuse to start with ephemeral key when
    # the operator has explicitly required a persisted PEM. Without this,
    # a restart changes the JWKS and every verifier rejects all tokens.
    if os.environ.get("POSTERN_REQUIRE_PEM_KEY") == "1":
        raise RuntimeError(
            "POSTERN_REQUIRE_PEM_KEY=1 but POSTERN_READ_KEY_PEM_PATH is not set. "
            "A persisted PEM key is required for production: a restart with an "
            "ephemeral key changes the JWKS and invalidates all existing tokens."
        )
    return source


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
    operator backend or real identity provider to call against in CI.
    """
    settings = settings or Settings.from_env()

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
    # ZT-1: continuous authorization — revocation list and jti replay cache.
    # The revocation list is checked before mint (customer+client, kill-switch);
    # the jti cache is checked after mint (session replay, A10). Both are
    # in-memory and stateless — a production deployment would back them with
    # Redis or a database table.
    revocation_list = RevocationList()
    jti_cache = JtiReplayCache(max_age_seconds=_LIFETIME.total_seconds())
    read_minter = ReadTokenMinter(
        InternalTokenMinter(issuer=settings.read_token_issuer, key_source=read_key_source),
        revocation_list=revocation_list,
        jti_cache=jti_cache,
    )
    # Before that minter reaches anything that could send one of its tokens:
    # mint one, and refuse to start unless it verifies against the key set
    # `jwks_route` below publishes from this same `read_key_source`. Keyed on
    # the object above having been BUILT, never on a settings shape, for the
    # reason `d203606` left in the module docstring.
    # `refuse_unverifiable_minter` carries the rest: why this one refuses
    # where `warn_ephemeral_signing_key` above only warns, why neither takes
    # an override flag, and why the write path has no equivalent call yet.
    #
    # HERE and not lower down, for a reason worth stating: `BackendClient`
    # opens an `httpx2.AsyncClient` and `Database` builds an engine, and both
    # are closed only by `_close_resources_after_fastmcp_shutdown`, which a
    # `RuntimeError` out of this function means never runs. Refusing before
    # either exists abandons no open resource.
    refuse_unverifiable_minter(
        lambda: read_minter(_STARTUP_PROBE, "accounts.svc"),
        built=read_minter,
        key_source=read_key_source,
        role="READ",
    )
    backend = BackendClient(
        settings.backend_base_url,
        read_minter,
        transport=transport,
        timeout=_backend_timeout(settings),
        # The entry audit row, committed before this client reaches the
        # operator's backend and failing the call if it cannot be
        # (`services/api/middleware/audit.py`, and
        # `dev-docs/decisions/0006-audit-write-failure.md` for why closed rather
        # than open). Wired here because this is the only place that holds
        # both halves: the façade that will make the request, and the
        # middleware module that knows what to record about it.
        #
        # The hook is a module-level function, not a bound method, and that
        # is the shape the mismatch forces: this client is built once per
        # process while the row is per call, so `record_data_touch` reads the
        # per-call values off a `ContextVar` the middleware sets. Nothing
        # about a tool, an argument or a store crosses into
        # `postern_core.facade` -- it depends on a zero-argument callable
        # Protocol and nothing else.
        before_backend_request=record_data_touch,
    )
    # Task 6: one `Database` per process, built unconditionally.
    # `create_async_engine` is lazy (Task 1's own tests construct one against
    # an address that is never reached), so this never blocks startup and
    # never requires a reachable Postgres just to assemble the app -- only
    # the first actual query does. Built here, not gated the way `consent_db`
    # below is, because `AuditMiddleware` must record every call regardless
    # of whether real customer auth is configured: the local docker-compose
    # stack and `Settings.for_testing()` both still want an audit trail.
    #
    # The three timeouts are the store's equivalent of `_backend_timeout`
    # above, and they are passed as asyncpg `connect_args` rather than in the
    # URL, which silently hands the driver a string it cannot add to a float.
    # They bound the connect, every statement, and the wait for a pooled
    # connection; `Database.__init__` carries the per-phase reasoning and,
    # more importantly, what the command timeout costs. In short: under
    # `dev-docs/decisions/0006-audit-write-failure.md` a failed audit write fails
    # the call, so a store slow enough to blow the statement budget now fails
    # calls it would previously have served late. That is the trade, taken
    # against a path whose two queries are one indexed SELECT and one INSERT.
    db = Database(
        settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        command_timeout_seconds=settings.database_command_timeout_seconds,
        pool_timeout_seconds=settings.database_pool_timeout_seconds,
    )

    # Consent is enforced against `AuthContext.token`, which only exists when
    # real customer authentication is configured. `has_real_customer_auth`
    # reuses the exact signal `services/api/server.py::build_server` builds
    # its `JWTVerifier` from: both jwks_uri and issuer set, or (Task 4) a
    # test-injected `auth_override`. Passing `db` into
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
    # ZT-5: per-session risk tracking — factory picks in-memory (dev) or
    # Redis (production, via POSTERN_REDIS_URL).  Compatible with AWS
    # ElastiCache, Google Memorystore, Azure Cache for Redis.
    from postern_core.risk.session import create_session_store

    session_store = create_session_store()

    # Audit finding (2026-09-21): refuse to start without Redis when the
    # operator has explicitly required it. Without Redis, sessions live only
    # in process memory (lost on restart), revocation is lost on restart,
    # and JTI replay protection is lost on restart. A production deployment
    # that sets POSTERN_REQUIRE_REDIS=1 must also set POSTERN_REDIS_URL.
    if os.environ.get("POSTERN_REQUIRE_REDIS") == "1":
        redis_url = os.environ.get("POSTERN_REDIS_URL")
        if not redis_url:
            raise RuntimeError(
                "POSTERN_REQUIRE_REDIS=1 but POSTERN_REDIS_URL is not set. "
                "This guard only checks that POSTERN_REDIS_URL is configured, "
                "which backs the session store; revocation lists and JTI "
                "replay protection remain in-process per replica regardless "
                "of this setting."
            )

    # ONE resolver object, handed to both `build_server` and `RiskMiddleware`
    # below. The middleware charges a call's record and account budgets to
    # whichever customer this answers, and the tools read whichever customer
    # this answers; two separate reads of the identity could disagree, and a
    # budget charged to a different customer than the one whose data was
    # returned is not a budget.
    customer_resolver = resolver or token_customer_resolver
    server = build_server(
        settings,
        customer_resolver,
        backend,
        db=consent_db,
        auth_override=auth_override,
    )
    # Task 6: an audit row per tool call, success or failure, regardless of
    # whether consent enforcement itself is active -- see the module
    # docstring and `services/api/middleware/audit.py`. Since 2026-09-18 a
    # call that reaches the operator's backend writes a second, earlier row,
    # through the `before_backend_request` hook wired above; installing this
    # middleware is what makes that hook resolvable at all, so the two go
    # together and neither is conditional.
    server.add_middleware(AuditMiddleware(db))
    # ZT-5: the risk layer. INSIDE `AuditMiddleware` (added second, so it
    # runs nested within it), which is what lets the audit row carry this
    # call's risk signals: `AuditMiddleware` reads `get_current_session()`
    # after this middleware returns or raises, so the contextvar must still
    # be set by then. A refusal from here therefore still writes a completion
    # row, with `outcome='raised'` and the signals that caused it.
    server.add_middleware(
        RiskMiddleware(
            session_store,
            customer_resolver,
            trusted_proxy_hops=settings.trusted_proxy_hops,
        )
    )
    app = server.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        middleware=[
            # FIRST, and that means OUTERMOST: Starlette wraps
            # `user_middleware` in reverse
            # (`starlette/applications.py::build_middleware_stack`), so entry
            # zero is the last one applied and therefore the first one a
            # request reaches. That position is the point. Inside
            # `HeaderBodyValidation` this would not cover that middleware's
            # own `_drain`, which awaits `receive()` with no deadline while it
            # buffers up to `max_body_bytes` -- a body that arrives one byte
            # at a time parks a worker there, before any store or backend
            # timeout is reachable. The cost of being outermost is that the
            # body is unparsed, so an expiry cannot echo the JSON-RPC id.
            # `services/api/asgi/request_deadline.py` carries the rest,
            # including the two things this control does NOT do.
            Middleware(RequestDeadline, seconds=settings.request_deadline_seconds),
            Middleware(
                HeaderBodyValidation,
                strict=settings.strict_headers,
                max_body_bytes=settings.max_body_bytes,
            ),
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
    # ZT-5, same reason as the three above: a test that wants to prove a
    # budget is enforced has to be able to seed one, and the alternative --
    # driving 500 records' worth of real calls to reach the threshold -- would
    # measure the fixtures rather than the control.
    app.state.postern_session_store = session_store
    # The public half of the key the minter above signs with. Task 3's JWKS
    # route serves it, and it is the only handle on that key outside the
    # `BackendClient` the minter is buried in.
    app.state.postern_read_key_source = read_key_source
    _close_resources_after_fastmcp_shutdown(app, backend, db)
    # Plan 3 Task 3: the public half of that same key, appended to the router
    # of the object this function returns rather than served from a parent
    # Starlette app mounting this one.
    # `fastmcp/server/http.py::StarletteWithLifespan.lifespan` is a property
    # returning `self.router.lifespan_context`, and the documented parent
    # shape, `Starlette(routes=[Mount(path, app)], lifespan=app.lifespan)`,
    # evaluates that property once and stores the value it read into its own
    # router (`starlette/routing.py::Router.__init__`). A parent built before
    # the call above writes the wrapped context back therefore keeps
    # FastMCP's session manager working and every request answering normally
    # while silently dropping `backend.aclose()` and `db.close()`, with no
    # exception and no failing test. Appending here runs after the wrapper
    # and leaves `app.router.lifespan_context` untouched;
    # `tests/test_asgi_app.py` asserts both shutdown hooks still fire
    # exactly once. Order is safe because FastMCP built exactly one route
    # (`/mcp`, POST and DELETE under `stateless_http=True`) and no catch-all
    # mount, so nothing shadows this path. The route is unauthenticated by
    # construction, which is what a gateway fetching a key set needs:
    # `RequireAuthMiddleware` wraps the `/mcp` endpoint object itself
    # (`fastmcp/server/http.py::create_streamable_http_app`), not the app, and
    # `HeaderBodyValidation` returns early on any non-POST.
    app.router.routes.append(jwks_route(read_key_source))
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

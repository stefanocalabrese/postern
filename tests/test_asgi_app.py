"""ASGI composition root tests (Task 12).

Four items earlier tasks explicitly deferred to this one ("Task 12 owns
composition"), each proven here; full reasoning in
`docs/decisions/0003-composition-root.md`:

1. `BackendClient.aclose()` on shutdown, without breaking FastMCP's own
   session-manager lifespan --
   `test_lifespan_runs_fastmcps_own_startup_then_closes_the_backend_client_after_its_shutdown`.
2. The façade's real per-call timeout budget, per phase, sourced from
   `Settings` -- `test_backend_timeout_is_wired_from_settings_per_phase`.
3. `HeaderBodyValidation`'s `max_body_bytes` cap, sourced from `Settings` --
   `test_create_app_wires_max_body_bytes_from_settings`,
   `test_a_request_over_max_body_bytes_returns_413_through_the_full_stack`.
4. `strict_headers` reachable from an environment variable --
   `test_create_app_wires_strict_headers_from_settings`.

Plus the adversarial pass: `StubTokenMinter` refused under a
production-shaped configuration, `create_app()` failing clearly on an
incomplete environment, and full end-to-end proofs (a masked result, a
header/body mismatch, an oversized body) driven through `httpx2.ASGITransport`
-- `httpx` is not installed in this project (docs/decisions/0001).
"""

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import cast

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ConsentRecord
from sqlalchemy import delete, select
from starlette.middleware import Middleware
from starlette.types import Message, Scope

from services.api.asgi.header_validation import HeaderBodyValidation
from services.api.main import create_app
from services.api.settings import Settings
from tests.fixtures import backend_responses as fx

TEST_CUSTOMER = CustomerRef(value="cust_7f3a")


def _resolver() -> CustomerRef:
    return TEST_CUSTOMER


ROUTES = {"/accounts": fx.ACCOUNTS}


def _handler(request: httpx2.Request) -> httpx2.Response:
    body = ROUTES.get(request.url.path)
    return httpx2.Response(200, json=body) if body is not None else httpx2.Response(404, json={})


REQUIRED_ENV = {
    "POSTERN_BACKEND_BASE_URL": "https://backend.test",
    "POSTERN_JWKS_URI": "https://issuer.test/.well-known/jwks.json",
    "POSTERN_TOKEN_ISSUER": "https://issuer.test",
}


def _set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key, value in REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)


def _middleware_class(entry: Middleware) -> type[object]:
    """`Middleware.cls` is typed as the ParamSpec-generic `_MiddlewareFactory[P]`
    Protocol, which mypy will not compare against a concrete class without a
    cast (it reports a "non-overlapping" `==`/`is`/`in` check even though the
    runtime values are the exact same class object).
    """
    return cast(type[object], entry.cls)


def _header_validation_middleware(app: StarletteWithLifespan) -> Middleware:
    return next(m for m in app.user_middleware if _middleware_class(m) is HeaderBodyValidation)


@asynccontextmanager
async def _drive_lifespan(app: StarletteWithLifespan) -> AsyncIterator[None]:
    """Drives the ASGI lifespan protocol by hand.

    Neither `httpx2.ASGITransport` nor plain `httpx2.AsyncClient` runs the
    `lifespan` protocol -- they only forward HTTP requests -- and no
    lifespan-manager dependency is installed in this project. This pumps the
    two messages the spec defines directly against the app callable.
    """
    startup_complete = asyncio.Event()
    shutdown_complete = asyncio.Event()
    to_app: asyncio.Queue[Message] = asyncio.Queue()

    async def receive() -> Message:
        return await to_app.get()

    async def send(message: Message) -> None:
        if message["type"] == "lifespan.startup.complete":
            startup_complete.set()
        elif message["type"] == "lifespan.shutdown.complete":
            shutdown_complete.set()

    scope: Scope = {"type": "lifespan"}
    task = asyncio.create_task(app(scope, receive, send))
    await to_app.put({"type": "lifespan.startup"})
    await startup_complete.wait()
    try:
        yield
    finally:
        await to_app.put({"type": "lifespan.shutdown"})
        await shutdown_complete.wait()
        await task


# --- Plan's Step 1 tests ----------------------------------------------------


def test_create_app_returns_an_asgi_callable() -> None:
    app = create_app(Settings.for_testing())
    assert callable(app)


def test_create_app_installs_header_validation() -> None:
    app = create_app(Settings.for_testing())
    installed = [_middleware_class(m) for m in app.user_middleware]
    assert HeaderBodyValidation in installed


def test_the_app_exposes_a_lifespan() -> None:
    app = create_app(Settings.for_testing())
    assert app.router.lifespan_context is not None


# --- Deferred item 4: strict_headers reachable from Settings/env -----------


def test_create_app_wires_strict_headers_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required_env(monkeypatch)
    monkeypatch.setenv("POSTERN_STRICT_HEADERS", "1")
    monkeypatch.setenv("POSTERN_ALLOW_STUB_TOKEN_MINTER", "1")
    app = create_app(resolver=_resolver)
    installed = _header_validation_middleware(app)
    assert installed.kwargs["strict"] is True


def test_strict_headers_defaults_to_false_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTERN_STRICT_HEADERS", raising=False)
    app = create_app(Settings.for_testing())
    installed = _header_validation_middleware(app)
    assert installed.kwargs["strict"] is False


# --- Deferred item 3: max_body_bytes reachable from Settings/env -----------


def test_create_app_wires_max_body_bytes_from_settings() -> None:
    settings = Settings(backend_base_url="https://backend.test", max_body_bytes=4096)
    app = create_app(settings)
    installed = _header_validation_middleware(app)
    assert installed.kwargs["max_body_bytes"] == 4096


def test_default_max_body_bytes_is_one_mebibyte() -> None:
    assert Settings.for_testing().max_body_bytes == 1_048_576


# --- Deferred item 2: the real façade timeout budget -----------------------


def test_backend_timeout_is_wired_from_settings_per_phase() -> None:
    settings = Settings.for_testing()
    app = create_app(settings)
    backend = app.state.backend_client
    timeout = backend._client.timeout
    assert timeout.connect == settings.backend_connect_timeout_seconds
    assert timeout.read == settings.backend_read_timeout_seconds
    assert timeout.write == settings.backend_write_timeout_seconds
    assert timeout.pool == settings.backend_pool_timeout_seconds


def test_backend_timeout_worst_case_total_is_bounded_at_ten_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Task 6 measured that a bare float applies independently to connect,
    read, write and pool (worst case ~4x a naive '10 seconds'). The default
    settings must sum to a stated, bounded worst case, not silently allow
    the same compounding the finding was about.
    """
    _set_required_env(monkeypatch)
    for var in (
        "POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS",
        "POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS",
        "POSTERN_BACKEND_READ_TIMEOUT_SECONDS",
        "POSTERN_BACKEND_POOL_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)
    settings = Settings.from_env()
    worst_case_total = (
        settings.backend_connect_timeout_seconds
        + settings.backend_write_timeout_seconds
        + settings.backend_read_timeout_seconds
        + settings.backend_pool_timeout_seconds
    )
    assert worst_case_total == 10.0


# --- Adversarial pass: StubTokenMinter must not run in a production shape --


def test_create_app_refuses_stub_minter_against_a_production_shaped_configuration() -> None:
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri="https://issuer.test/.well-known/jwks.json",
        customer_token_issuer="https://issuer.test",  # noqa: S106
    )
    with pytest.raises(RuntimeError, match="StubTokenMinter"):
        create_app(settings)


def test_create_app_allows_stub_minter_when_customer_auth_is_unset() -> None:
    app = create_app(Settings.for_testing())
    assert callable(app)


def test_create_app_allows_stub_minter_when_explicitly_overridden() -> None:
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri="https://issuer.test/.well-known/jwks.json",
        customer_token_issuer="https://issuer.test",  # noqa: S106
        allow_stub_token_minter=True,
    )
    app = create_app(settings)
    assert callable(app)


# --- Adversarial pass: Settings.from_env() failures must name the variable -


def test_create_app_fails_clearly_on_incomplete_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("POSTERN_BACKEND_BASE_URL", raising=False)
    monkeypatch.delenv("POSTERN_JWKS_URI", raising=False)
    monkeypatch.delenv("POSTERN_TOKEN_ISSUER", raising=False)
    with pytest.raises(KeyError) as excinfo:
        create_app()
    assert excinfo.value.args[0] == "POSTERN_BACKEND_BASE_URL"


# --- Deferred item 1: aclose() wired to shutdown without breaking FastMCP's


async def test_lifespan_runs_fastmcps_own_startup_then_closes_the_backend_client_after_its_shutdown(
    monkeypatch: pytest.MonkeyPatch, pg_url: str
) -> None:
    """Three hooks must all run, in order: FastMCP's own session-manager
    lifespan, then (Task 6) both `BackendClient.aclose()` and
    `Database.close()`, only after FastMCP's shutdown has finished.

    Since Task 6, `AuditMiddleware` is installed unconditionally and writes a
    real row after every call, so this test needs a real, reachable database
    (`pg_url`) for the `tools/call` below to genuinely succeed rather than
    fail inside the audit write with the app still reporting HTTP 200 -- see
    `test_a_tool_call_still_succeeds_when_the_audit_database_is_unreachable`
    below for the case where it is not reachable.
    """
    settings = Settings(backend_base_url="https://backend.test", database_url=pg_url)
    app = create_app(settings, resolver=_resolver, transport=httpx2.MockTransport(_handler))
    backend = app.state.backend_client
    db = app.state.postern_database
    backend_close_calls: list[None] = []
    db_close_calls: list[None] = []
    original_backend_aclose = backend.aclose
    original_db_close = db.close

    async def spy_backend_aclose() -> None:
        backend_close_calls.append(None)
        await original_backend_aclose()

    async def spy_db_close() -> None:
        db_close_calls.append(None)
        await original_db_close()

    monkeypatch.setattr(backend, "aclose", spy_backend_aclose)
    monkeypatch.setattr(db, "close", spy_db_close)

    async with _drive_lifespan(app):
        # Proof FastMCP's own lifespan ran: without it, the session manager
        # is never constructed and this call cannot succeed at all.
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Method": "tools/call",
                    "Mcp-Name": "accounts.list",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "accounts.list", "arguments": {}},
                },
            )
        assert response.status_code == 200
        body = response.json()
        assert "error" not in body  # a real, successful tool call, not a leak
        assert body["result"]["isError"] is False
        assert backend_close_calls == []  # not yet -- the app is still running
        assert db_close_calls == []  # not yet -- the app is still running

    assert backend_close_calls == [None]  # closed exactly once, after shutdown
    assert db_close_calls == [None]  # closed exactly once, after shutdown
    assert backend._client.is_closed


# --- End-to-end proofs required by the adversarial pass --------------------


async def test_end_to_end_call_reaches_a_tool_and_returns_masked_data(pg_url: str) -> None:
    settings = Settings(backend_base_url="https://backend.test", database_url=pg_url)
    app = create_app(settings, resolver=_resolver, transport=httpx2.MockTransport(_handler))
    async with _drive_lifespan(app):
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Method": "tools/call",
                    "Mcp-Name": "accounts.list",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "accounts.list", "arguments": {}},
                },
            )
    assert response.status_code == 200
    rendered = response.text
    assert fx.FULL_IBAN not in rendered
    assert "••••" in rendered


async def test_end_to_end_header_body_mismatch_returns_400_and_32020() -> None:
    settings = Settings.for_testing()
    app = create_app(settings, resolver=_resolver, transport=httpx2.MockTransport(_handler))
    async with _drive_lifespan(app):
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Method": "tools/list",
                    "Mcp-Name": "accounts.list",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "accounts.list", "arguments": {}},
                },
            )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32020


# --- Task 6: wire the database into the composition root ------------------


def test_create_app_builds_a_database_from_settings() -> None:
    app = create_app(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER)
    assert getattr(app.state, "postern_database", None) is not None


def test_create_app_installs_the_audit_middleware() -> None:
    from services.api.middleware.audit import AuditMiddleware

    app = create_app(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER)
    server = app.state.postern_server
    assert any(isinstance(m, AuditMiddleware) for m in server.middleware)


async def test_the_database_is_closed_on_shutdown() -> None:
    app = create_app(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER)
    db = app.state.postern_database
    async with app.router.lifespan_context(app):
        pass
    assert db.engine.pool.status() is not None


async def test_end_to_end_body_over_max_body_bytes_returns_413() -> None:
    settings = Settings(backend_base_url="https://backend.test", max_body_bytes=64)
    app = create_app(settings, resolver=_resolver, transport=httpx2.MockTransport(_handler))
    async with _drive_lifespan(app):
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/mcp",
                headers={"Accept": "application/json, text/event-stream"},
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "accounts.list", "arguments": {"padding": "x" * 200}},
                },
            )
    assert response.status_code == 413
    assert json.loads(response.text)["error"]


# --- Adversarial pass: consent and audit running together, for real --------


async def test_end_to_end_audit_row_is_written_for_a_real_call(
    pg_url: str, database: Database
) -> None:
    """The first time consent and audit run together through the composed
    app: a real JWT (`auth_override`), a seeded consent row, a real
    `tools/call` over `httpx2.ASGITransport`, and the resulting row read
    back from Postgres through a second, independent connection -- the same
    `database` fixture `AuditMiddleware` itself writes through, per
    `test_consent_enforcement.py`'s own finding that a rolled-back session
    is invisible to the app's own connection.
    """
    key_pair = RSAKeyPair.generate()
    issuer = "https://postern-audit-e2e.invalid"
    audience = "postern"
    customer = "cust_audite2e01"

    async with database.sessionmaker() as session:
        session.add(
            ConsentRecord(
                customer_ref=customer,
                domain="accounts",
                granted=True,
                granted_at=datetime.now(UTC),
                expires_at=None,
            )
        )
        await session.commit()

    try:
        verifier = JWTVerifier(public_key=key_pair.public_key, issuer=issuer, audience=audience)
        token = key_pair.create_token(subject=customer, issuer=issuer, audience=audience)
        settings = Settings(
            backend_base_url="https://backend.test",
            database_url=pg_url,
            allow_stub_token_minter=True,
        )
        app = create_app(
            settings,
            transport=httpx2.MockTransport(_handler),
            auth_override=verifier,
        )
        async with _drive_lifespan(app):
            transport = httpx2.ASGITransport(app=app)
            async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/mcp",
                    headers={
                        "Accept": "application/json, text/event-stream",
                        "Authorization": f"Bearer {token}",
                        "Mcp-Method": "tools/call",
                        "Mcp-Name": "accounts.list",
                    },
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"name": "accounts.list", "arguments": {}},
                    },
                )
        assert response.status_code == 200
        body = response.json()
        assert "error" not in body
        assert body["result"]["isError"] is False

        async with database.sessionmaker() as session:
            rows = (
                (
                    await session.execute(
                        select(AuditEntry).where(AuditEntry.customer_ref == customer)
                    )
                )
                .scalars()
                .all()
            )
        assert [(r.tool_name, r.outcome, r.customer_ref) for r in rows] == [
            ("accounts.list", "returned", customer)
        ]
    finally:
        async with database.sessionmaker() as session:
            await session.execute(
                delete(ConsentRecord).where(ConsentRecord.customer_ref == customer)
            )
            await session.execute(delete(AuditEntry).where(AuditEntry.customer_ref == customer))
            await session.commit()


# --- Adversarial pass: the audit database is unreachable at startup --------


async def test_a_tool_call_reports_a_json_rpc_error_when_the_audit_database_is_unreachable() -> (
    None
):
    """`create_async_engine` is lazy (`Database.__init__` never connects), so
    `create_app` succeeds even when `database_url` names an address that
    will never resolve; only the first request that reaches
    `AuditMiddleware`'s write discovers it.

    Measured: the backend call itself succeeds (the `MockTransport` handler
    runs and returns data), but the audit write's connection failure is
    never caught by `AuditMiddleware.on_call_tool`'s own `try`/`except`
    (which wraps only `call_next`, not the second, unconditional `_write`
    call after it), so it propagates out of the whole tool dispatch.
    FastMCP reports it as a top-level JSON-RPC `error` (`code: 0`, a generic
    internal-error code, not a masking- or consent-specific one), still
    inside an HTTP 200 envelope rather than the request's connection being
    torn down or an ASGI 5xx being raised. The message embeds the raw
    connection target (`127.0.0.1`, `1`), an internal-infrastructure
    disclosure to the MCP client -- but not the database credentials
    themselves, since asyncpg's own `ConnectionRefusedError` carries no DSN,
    only the address it tried and failed to reach. A DNS-resolution failure
    (an unresolvable host, tried first and reverted here for a
    deterministic, environment-independent port) is even less specific: the
    message it produces carries no connection target at all, only
    `"nodename nor servname provided, or not known"`.
    """
    settings = Settings(
        backend_base_url="https://backend.test",
        database_url="postgresql+asyncpg://postern:postern@127.0.0.1:1/postern",
    )
    app = create_app(settings, resolver=_resolver, transport=httpx2.MockTransport(_handler))
    async with _drive_lifespan(app):
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Method": "tools/call",
                    "Mcp-Name": "accounts.list",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "accounts.list", "arguments": {}},
                },
            )
    assert response.status_code == 200  # never surfaces as a real HTTP failure
    body = response.json()
    assert "result" not in body
    assert body["error"]["code"] == 0
    assert "127.0.0.1" in body["error"]["message"]  # leaks the connection target
    assert "postern:postern" not in body["error"]["message"]  # not the DSN's credentials

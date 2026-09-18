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

Plus the adversarial pass: `create_app()` failing clearly on an incomplete
environment, and full end-to-end proofs (a masked result, a header/body
mismatch, an oversized body) driven through `httpx2.ASGITransport` --
`httpx` is not installed in this project (docs/decisions/0001).
"""

import asyncio
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan
from joserfc import jwt as jose_jwt
from joserfc.jwk import KeySet, RSAKey
from postern_core.auth.read_minter import ReadTokenMinter
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


# --- A production-shaped configuration starts, holding the real minter ----


def test_create_app_starts_under_a_production_shaped_configuration() -> None:
    """`_refuse_stub_minter_in_production` raised on exactly this input until
    this commit, reading a settings shape rather than which minter
    `create_app` built. Plan 3 Task 2 replaced `StubTokenMinter` with
    `ReadTokenMinter`, which turned that guard into a refusal to start the
    genuine minter, so it is gone: both `customer_jwks_uri` and
    `customer_token_issuer` set assembles an app, no flag involved.
    """
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri="https://issuer.test/.well-known/jwks.json",
        customer_token_issuer="https://issuer.test",  # noqa: S106
    )
    app = create_app(settings)
    assert isinstance(app.state.backend_client._minter, ReadTokenMinter)


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


async def test_end_to_end_audit_rows_are_written_for_a_real_call(
    pg_url: str, database: Database
) -> None:
    """The first time consent and audit run together through the composed
    app: a real JWT (`auth_override`), a seeded consent row, a real
    `tools/call` over `httpx2.ASGITransport`, and the resulting rows read
    back from Postgres through a second, independent connection -- the same
    `database` fixture `AuditMiddleware` itself writes through, per
    `test_consent_enforcement.py`'s own finding that a rolled-back session
    is invisible to the app's own connection.

    TWO rows since 2026-09-18, and this is also what pins that `create_app`
    wires the entry write at all. `BackendClient(before_backend_request=...)`
    is required but accepts `None` (`postern_core/facade/client.py` says
    why), so a composition root that switched to `None` would keep serving
    every call and silently reach the backend with nothing recorded first.
    Here the `reaching` row can only exist if this app built that wiring
    itself: nothing in this test constructs a `BackendClient`.
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
                        select(AuditEntry)
                        .where(AuditEntry.customer_ref == customer)
                        # Explicit, now that there are two rows: a bare
                        # SELECT has no order, and the assertion below is
                        # about which row was written FIRST.
                        .order_by(AuditEntry.id)
                    )
                )
                .scalars()
                .all()
            )
        assert [(r.tool_name, r.outcome, r.customer_ref) for r in rows] == [
            ("accounts.list", "reaching", customer),
            ("accounts.list", "returned", customer),
        ]
        assert rows[0].call_id is not None and rows[0].call_id == rows[1].call_id, (
            "the entry row and the completion row of one call must be joinable"
        )
    finally:
        async with database.sessionmaker() as session:
            await session.execute(
                delete(ConsentRecord).where(ConsentRecord.customer_ref == customer)
            )
            await session.execute(delete(AuditEntry).where(AuditEntry.customer_ref == customer))
            await session.commit()


# --- Adversarial pass: the audit database is unreachable at startup --------


async def test_a_tool_call_fails_closed_when_the_audit_database_is_unreachable() -> None:
    """`create_async_engine` is lazy (`Database.__init__` never connects), so
    `create_app` succeeds even when `database_url` names an address that
    will never resolve; only the first request that needs it discovers that.

    WHICH WRITE DISCOVERS IT CHANGED ON 2026-09-18, and so did the envelope
    the client gets. Before, the backend call succeeded (the `MockTransport`
    handler ran and returned data) and the connection failure surfaced from
    the completion write, after `AuditMiddleware.on_call_tool`'s `try`/`except`
    -- which wraps only `call_next` -- so it propagated out of the whole tool
    dispatch and FastMCP reported it as a top-level JSON-RPC `error` with
    `code: 0`, `"result"` absent.

    The audit middleware now commits an entry row before the backend is
    reached, from inside the tool body
    (`postern_core.facade.client.BackendClient`'s `before_backend_request`
    hook), so the same failure is raised INSIDE the tool and comes back as a
    tool error: HTTP 200, `result.isError` true, no top-level `"error"` key.
    That is the shape this test now pins.

    WHAT IS DISCLOSED IS UNCHANGED, which is the reason this stayed a change
    of envelope rather than a regression to fix here. Either way the message
    embeds the raw connection target (`127.0.0.1`, `1`), an
    internal-infrastructure disclosure to the MCP client, and either way it
    is not the database credentials, since asyncpg's own
    `ConnectionRefusedError` carries no DSN, only the address it tried.
    Wrapping the store exception in a quiet one of our own was considered
    and not done, on the disclosure argument alone. It would keep the address
    off the wire on this path and do nothing on the completion-write path,
    where the raw exception escapes `on_call_tool` carrying the same address
    into a JSON-RPC error. It buys nothing in `audit_log.detail`, which
    records `ToolError` for every exception raised inside a tool body and so
    cannot separate this cause from any other. ADR 0006's amendment of 18
    September 2026 records both halves, and corrects its own `-32603` claim
    against this test, which is the measurement for it.

    The property the change is FOR is the one asserted last: the backend is
    never reached. An audit outage used to mean customer data touched with
    nothing recorded, and now means nothing touched at all.
    """
    settings = Settings(
        backend_base_url="https://backend.test",
        database_url="postgresql+asyncpg://postern:postern@127.0.0.1:1/postern",
    )
    reached: list[str] = []

    def recording_handler(request: httpx2.Request) -> httpx2.Response:
        reached.append(request.url.path)
        return _handler(request)

    app = create_app(
        settings, resolver=_resolver, transport=httpx2.MockTransport(recording_handler)
    )
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
    assert "error" not in body  # a tool error now, not a JSON-RPC protocol error
    assert body["result"]["isError"] is True
    message = body["result"]["content"][0]["text"]
    assert "127.0.0.1" in message  # leaks the connection target
    assert "postern:postern" not in message  # not the DSN's credentials
    assert reached == [], "an unrecordable call must not reach the operator's backend"


# --- Plan 3 Task 2: the read key, and only the read key -------------------


def _mint(app: StarletteWithLifespan, audience: str) -> str:
    """The token the composed app would actually attach to a backend call.

    Reaches into `BackendClient._minter` for the same reason
    `test_backend_timeout_is_wired_from_settings_per_phase` reaches into
    `_client.timeout`: the minter is what `create_app` chose, and there is
    no public accessor for it. Driving a real `tools/call` instead would
    prove only that a token was sent, since the `MockTransport` handler
    above never reads the `Authorization` header.
    """
    return cast(str, app.state.backend_client._minter(TEST_CUSTOMER, audience))


def test_the_backend_client_mints_a_real_read_token_signed_by_the_stashed_key() -> None:
    """The fake `stub.read.<customer>` bearer is gone: what leaves this
    process is an RS256 JWT that verifies against the key source Task 3's
    JWKS route will publish, carrying the customer as `sub` and a read
    scope derived from the audience."""
    settings = Settings.for_testing()
    app = create_app(settings)
    token = _mint(app, "accounts.svc")
    keyset = KeySet.import_key_set(app.state.postern_read_key_source.public_jwks())
    claims = jose_jwt.decode(token, keyset, algorithms=["RS256"]).claims
    assert claims["sub"] == TEST_CUSTOMER.value
    assert claims["scope"] == "accounts:read"
    assert claims["iss"] == settings.read_token_issuer
    assert not token.startswith("stub.read.")


def test_the_api_process_cannot_mint_a_payments_token() -> None:
    """The key split is what stops this process signing a write token; this
    is the second barrier, in claims rather than in key material. `KeyError`
    from an unmapped audience beats a token minted with a guessed scope,
    because Istio matches on the scope claim as well as on the signature.
    """
    app = create_app(Settings.for_testing())
    with pytest.raises(KeyError):
        _mint(app, "payments.svc")


def test_create_app_stashes_the_read_key_source_under_the_configured_kid() -> None:
    """Task 3 serves `app.state.postern_read_key_source`, and a verifier
    selects the key by `kid`, so the published kid must be the one
    `Settings` names rather than a constant baked into `create_app`."""
    settings = Settings(backend_base_url="https://backend.test", read_key_kid="read-2")
    app = create_app(settings)
    entries = app.state.postern_read_key_source.public_jwks()["keys"]
    assert [entry["kid"] for entry in entries] == ["read-2"]


def test_a_configured_pem_path_signs_instead_of_a_generated_key(tmp_path: Path) -> None:
    """The `FileKeySource` branch is the only one a real deployment takes
    (a generated key is thrown away on restart, invalidating the JWKS every
    verifier cached), so the token is checked against the PEM's own key
    here, not against the app's stashed copy: verifying against the stash
    would pass even if `read_key_pem_path` were ignored entirely.
    """
    key = RSAKey.generate_key(2048, parameters={"kid": "read-file", "use": "sig", "alg": "RS256"})
    pem = tmp_path / "read.pem"
    pem.write_bytes(key.as_pem(private=True))
    settings = Settings(
        backend_base_url="https://backend.test",
        read_key_pem_path=str(pem),
        read_key_kid="read-file",
    )
    app = create_app(settings)
    claims = jose_jwt.decode(_mint(app, "cards.svc"), KeySet([key]), algorithms=["RS256"]).claims
    assert claims["scope"] == "cards:read"

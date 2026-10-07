"""The SQL-safe error log, measured through a REAL uvicorn server.

`tests/test_sql_safe_logging.py` proves the filter on records built by hand.
This file proves the property the work is for: when a driver error escapes a
handler of the real ``create_confirm_app`` / ``create_app`` stacks, the line
uvicorn writes to ``uvicorn.error`` carries no value the statement bound.

The server is real (`uvicorn.Server` on an ephemeral loopback port, a real HTTP
client over a real socket) and the capture handler formats like uvicorn's own
default (``DefaultFormatter``, ``%(levelprefix)s %(message)s``). The error is a
real asyncpg error from a real Postgres: a statement whose bound parameter is a
sentinel string cast to an integer, which asyncpg rejects with a message that
NAMES the value. That is the half ``hide_parameters`` does not reach, and it
means the unfiltered run below shows the sentinel even on an engine that hides
its parameters.

The sentinel is a module constant referred to by name on every raising line,
because a traceback frame prints its source line.
"""

import asyncio
import io
import logging
from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import httpx2
import pytest
import uvicorn
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core import log_safety
from postern_core.domain.verification import VerificationTier
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from uvicorn.logging import DefaultFormatter

import services.api.main as api_main
import services.confirm.main as confirm_main
from services.api.main import create_app
from services.api.settings import Settings
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.device_keys import approval_body, device_key, enrolled_store

PARAM_SENTINEL = "bf_uvicorn_leak_7731"
CUSTOMER = "cust_sqlsafe01"
CHALLENGE_ID = "chal_sqlsafe_001"
ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"

DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("sqlsafe-phone")

MESSAGE = "Exception in ASGI application"


@pytest.fixture
def _uvicorn_filters_restored(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Start each test with no sanitising record factory, put the previous one back after.

    (The name is kept from the design this replaced, a filter on uvicorn's two
    loggers; what is reset now is the process-wide record factory.)
    """
    previous = logging.getLogRecordFactory()
    logging.setLogRecordFactory(logging.LogRecord)
    monkeypatch.setattr(log_safety, "_installed_factory", None)
    yield
    logging.setLogRecordFactory(previous)


@asynccontextmanager
async def _captured_uvicorn_error_log() -> AsyncIterator[io.StringIO]:
    """What an operator's terminal would show for `uvicorn.error`."""
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(DefaultFormatter("%(levelprefix)s %(message)s", use_colors=False))
    log = logging.getLogger("uvicorn.error")
    previous_level = log.level
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    try:
        yield buffer
    finally:
        log.removeHandler(handler)
        log.setLevel(previous_level)


@asynccontextmanager
async def _serve(app: Any) -> AsyncIterator[str]:
    """`app` behind a real uvicorn server on an ephemeral loopback port."""
    config = uvicorn.Config(
        app, host="127.0.0.1", port=0, log_config=None, lifespan="off", access_log=False
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve())
    try:
        while not server.started:
            if task.done():
                task.result()
            await asyncio.sleep(0.01)
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await task


async def _failing_statement(session: AsyncSession) -> None:
    await session.execute(text("SELECT CAST(:p AS int)"), {"p": PARAM_SENTINEL})


# ---------------------------------------------------------------------------
# services/confirm: the approval callback, which re-raises on purpose.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture
async def confirm_stack(
    pg_url: str, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[tuple[Database, dict[str, Any]]]:
    """A pending challenge, its signed body, and a ``get_challenge`` that fails."""
    db = Database(pg_url, null_pool=True)
    async with db.sessionmaker() as session:
        await store.create_challenge(
            session,
            challenge_id=CHALLENGE_ID,
            customer_ref=CUSTOMER,
            tool_name="standing_orders.cancel",
            payload={"order_id": "so_340"},
            tier=VerificationTier.APP_APPROVAL,
        )
        await session.commit()
    body = await approval_body(db, CHALLENGE_ID, DEVICE_PRIVATE)

    async def failing_get_challenge(session: AsyncSession, challenge_id: str) -> Any:
        await _failing_statement(session)

    monkeypatch.setattr("services.confirm.callback.get_challenge", failing_get_challenge)
    try:
        yield db, body
    finally:
        async with db.sessionmaker() as cleanup:
            await cleanup.execute(
                text("DELETE FROM challenges WHERE challenge_id = :c"), {"c": CHALLENGE_ID}
            )
            await cleanup.commit()
        await db.close()


def _confirm_app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    settings = ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=enrolled_store(CUSTOMER, DEVICE_PUBLIC),
    )


async def _approve_over_the_wire(
    base_url: str, key_pair: RSAKeyPair, body: dict[str, Any]
) -> httpx2.Response:
    token = key_pair.create_token(
        subject=CUSTOMER, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    async with httpx2.AsyncClient(base_url=base_url) as client:
        return await client.post(
            f"/challenges/{CHALLENGE_ID}/approve",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )


async def _raised_rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as session:
        found = await session.execute(
            select(AuditEntry)
            .where(AuditEntry.customer_ref == CUSTOMER)
            .where(AuditEntry.outcome == "raised")
        )
        return list(found.scalars().all())


@pytest.mark.usefixtures("_uvicorn_filters_restored")
async def test_confirm_without_the_filter_the_driver_message_reaches_the_log(
    pg_url: str,
    key_pair: RSAKeyPair,
    confirm_stack: tuple[Database, dict[str, Any]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The red evidence: the leak is real in this harness."""
    _, body = confirm_stack
    monkeypatch.setattr(confirm_main, "install_sql_safe_logging", lambda: None)
    app = _confirm_app(pg_url, key_pair)
    async with _captured_uvicorn_error_log() as log, _serve(app) as base_url:
        response = await _approve_over_the_wire(base_url, key_pair, body)
    text_out = log.getvalue()
    assert response.status_code == 500
    assert MESSAGE in text_out
    assert PARAM_SENTINEL in text_out, text_out
    assert not getattr(logging.getLogRecordFactory(), "_postern_sql_safe_factory", False)


@pytest.mark.usefixtures("_uvicorn_filters_restored")
async def test_confirm_with_the_filter_nothing_a_statement_bound_reaches_the_log(
    pg_url: str,
    key_pair: RSAKeyPair,
    confirm_stack: tuple[Database, dict[str, Any]],
) -> None:
    db, body = confirm_stack
    app = _confirm_app(pg_url, key_pair)
    async with _captured_uvicorn_error_log() as log, _serve(app) as base_url:
        response = await _approve_over_the_wire(base_url, key_pair, body)
    text_out = log.getvalue()

    # The ESCAPING behaviour is unchanged: the exception still escapes the
    # handler, so uvicorn answers 500, and decision 0006's audit row exists.
    assert response.status_code == 500
    assert PARAM_SENTINEL not in response.text
    raised = await _raised_rows(db)
    assert raised, "no `raised` audit row: the approval did not fail the way this test assumes"

    assert MESSAGE in text_out
    assert PARAM_SENTINEL not in text_out, text_out
    assert "[parameters:" not in text_out
    assert "[message, SQL and parameters withheld]" in text_out
    assert "sqlalchemy.exc.DBAPIError" in text_out
    assert "asyncpg.exceptions.DataError" in text_out
    # Frames survive, so the failure is still locatable.
    assert "callback.py" in text_out
    assert "test_sql_safe_logging_uvicorn.py" in text_out


# ---------------------------------------------------------------------------
# services/api: one handler error.
# ---------------------------------------------------------------------------


def _api_app_with_a_failing_route(pg_url: str) -> Starlette:
    app = create_app(Settings.for_testing())

    async def boom(request: Request) -> PlainTextResponse:
        db = Database(pg_url, null_pool=True)
        try:
            async with db.sessionmaker() as session:
                await _failing_statement(session)
        finally:
            await db.close()
        return PlainTextResponse("unreachable")

    app.add_route("/boom", boom)
    return app


async def _get_boom(base_url: str) -> httpx2.Response:
    async with httpx2.AsyncClient(base_url=base_url) as client:
        return await client.get("/boom")


@pytest.mark.usefixtures("_uvicorn_filters_restored")
async def test_api_without_the_filter_the_driver_message_reaches_the_log(
    pg_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(api_main, "install_sql_safe_logging", lambda: None)
    app = _api_app_with_a_failing_route(pg_url)
    async with _captured_uvicorn_error_log() as log, _serve(app) as base_url:
        response = await _get_boom(base_url)
    assert response.status_code == 500
    assert MESSAGE in log.getvalue()
    assert PARAM_SENTINEL in log.getvalue(), log.getvalue()


@pytest.mark.usefixtures("_uvicorn_filters_restored")
async def test_api_with_the_filter_nothing_a_statement_bound_reaches_the_log(
    pg_url: str,
) -> None:
    app = _api_app_with_a_failing_route(pg_url)
    async with _captured_uvicorn_error_log() as log, _serve(app) as base_url:
        response = await _get_boom(base_url)
    text_out = log.getvalue()
    assert response.status_code == 500
    assert MESSAGE in text_out
    assert PARAM_SENTINEL not in text_out, text_out
    assert "[message, SQL and parameters withheld]" in text_out
    assert "asyncpg.exceptions.DataError" in text_out
    assert "test_sql_safe_logging_uvicorn.py" in text_out


# ---------------------------------------------------------------------------
# The composition roots install it.
# ---------------------------------------------------------------------------


def _wrappers() -> int:
    count = 0
    factory: object = logging.getLogRecordFactory()
    while factory is not None:
        if getattr(factory, "_postern_sql_safe_factory", False):
            count += 1
        factory = getattr(factory, "__wrapped__", None)
    return count


@pytest.mark.usefixtures("_uvicorn_filters_restored")
def test_create_app_installs_the_record_factory() -> None:
    create_app(Settings.for_testing())
    assert _wrappers() == 1


@pytest.mark.usefixtures("_uvicorn_filters_restored")
def test_create_confirm_app_installs_the_record_factory_once(
    pg_url: str, key_pair: RSAKeyPair
) -> None:
    _confirm_app(pg_url, key_pair)
    _confirm_app(pg_url, key_pair)
    assert _wrappers() == 1

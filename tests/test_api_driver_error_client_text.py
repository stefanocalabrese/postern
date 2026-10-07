"""A SQL driver error never reaches the MCP client's reply (golden, real stack).

THE LEAK, measured against the real `create_app`, a real HTTP `tools/call` and a
real Postgres: when an audit write failed, the client's reply carried the
driver's text WITH THE BOUND VALUE. An entry-write failure came back as HTTP 200
`result.content[0].text` = ``Error calling tool 'accounts.list': (sqlalchemy.
dialects.postgresql.asyncpg.Error) ... invalid input for query argument $1:
'<value>' ... [SQL: ...]``; a completion-write failure came back as a JSON-RPC
`error.message` carrying the same text. That reply lands in an AI vendor's chat
history. `hide_parameters` does not cover the worst case: a NOT NULL violation
puts ``DETAIL: Failing row contains (<the whole row>)`` into the message.

Two layers, each pinned by its own test:

* `FastMCP(mask_error_details=True)` (`services/api/server.py`): an exception a
  tool raises, other than a `ToolError`, reaches the client as
  ``Error calling tool 'x'``. Covers the ENTRY write, which fails inside the
  tool body.
* `AuditMiddleware`'s `_client_safe`: an exception that leaves the middleware
  with a driver error anywhere in its chain is replaced by ``ToolError
  ("internal error")``. Covers the COMPLETION write, which fails outside the
  tool body, and a wrapper whose own text interpolates the driver's.

Every failure is produced for real: the audit insert is wrapped to run a failing
statement through the app's own `Database`, so the exception is asyncpg's own,
carrying the sentinel in the place the real one would.

The sentinels are module constants referred to by NAME on every raising line.
"""

import io
import logging
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core import log_safety
from postern_core.identity import CustomerRef
from postern_core.store import audit as store_audit
from postern_core.store import consents
from postern_core.store.engine import Database
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.middleware.audit import INTERNAL_ERROR_TEXT
from services.api.tools.payments import CHALLENGE_NOT_FOUND
from tests.test_audit_reserve import (
    _app,
    _drive_lifespan,
    _settings,
    app_database,
    consented,
    token_for,
)

CUSTOMER = "cust_apidrv01"
PARAM_SENTINEL = "zzsentinel_api_4412"
ROW_SENTINEL = "zzsentinel_row_9051"
ENTRY_TOOL = "accounts.list"
STATUS_TOOL = "payments.get_payment_status"

#: What a client must never read, in any reply.
FORBIDDEN = ("[SQL:", "asyncpg", "parameters", "sqlalchemy", "Failing row", "DETAIL")

MASKED_ENTRY_TEXT = "Error calling tool 'accounts.list'"


@pytest.fixture(autouse=True)
def _only_create_app_installs_the_record_factory(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """A factory left by an earlier test would hide a `create_app` that stopped
    installing it, so every test here starts without one."""
    previous = logging.getLogRecordFactory()
    logging.setLogRecordFactory(logging.LogRecord)
    monkeypatch.setattr(log_safety, "_installed_factory", None)
    yield
    logging.setLogRecordFactory(previous)


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture
async def not_null_table(database: Database) -> AsyncIterator[None]:
    async with database.sessionmaker() as session:
        await session.execute(text("DROP TABLE IF EXISTS sqlsafe_api_nn"))
        await session.execute(text("CREATE TABLE sqlsafe_api_nn (a text, b text NOT NULL)"))
        await session.commit()
    yield
    async with database.sessionmaker() as session:
        await session.execute(text("DROP TABLE IF EXISTS sqlsafe_api_nn"))
        await session.commit()


async def _bound_value_error(session: AsyncSession) -> None:
    await session.execute(text("SELECT CAST(:p AS int)"), {"p": PARAM_SENTINEL})


async def _failing_row_error(session: AsyncSession) -> None:
    await session.execute(
        text("INSERT INTO sqlsafe_api_nn (a, b) VALUES (:a, NULL)"), {"a": ROW_SENTINEL}
    )


class _Wrapped(RuntimeError):
    """A non-driver exception whose own text interpolates the driver's."""


def _install(
    monkeypatch: pytest.MonkeyPatch,
    app: Any,
    *,
    fail_outcomes: set[str],
    statement: Callable[[AsyncSession], Any],
    wrap: bool = False,
) -> None:
    """Make `audit.append` fail, for real, on the named outcomes."""
    real = store_audit.append
    database: Database = app_database(app)

    async def failing(session: AsyncSession, **kwargs: Any) -> Any:
        if kwargs.get("outcome") in fail_outcomes:
            async with database.sessionmaker() as other:
                try:
                    await statement(other)
                except Exception as driver_error:
                    if wrap:
                        raise _Wrapped(f"audit failed: {driver_error}") from driver_error
                    raise
        return await real(session, **kwargs)

    monkeypatch.setattr(store_audit, "append", failing)


async def _tools_call(
    app: Any, token: str, tool: str, arguments: dict[str, Any]
) -> httpx2.Response:
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://t") as client:
        return await client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {token}",
                "Mcp-Method": "tools/call",
                "Mcp-Name": tool,
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool, "arguments": arguments},
            },
        )


def _assert_client_clean(response: httpx2.Response) -> None:
    body = response.text
    assert response.status_code == 200, body
    for sentinel in (PARAM_SENTINEL, ROW_SENTINEL):
        assert sentinel not in body, body
    for fragment in FORBIDDEN:
        assert fragment not in body, (fragment, body)


def _client_text(response: httpx2.Response) -> str:
    """The one human-readable string the reply carries, tool result or JSON-RPC error."""
    payload = response.json()
    if "error" in payload:
        return str(payload["error"]["message"])
    return str(payload["result"]["content"][0]["text"])


@pytest.fixture
async def stack(
    pg_url: str, database: Database, key_pair: RSAKeyPair, not_null_table: None
) -> AsyncIterator[tuple[Any, str]]:
    settings = _settings(
        pg_url,
        database_pool_size=5,
        database_max_overflow=5,
        database_pool_timeout_seconds=1.0,
        payments_enabled=True,
    )
    async with consented(database, CUSTOMER, "accounts", "payments"):
        app = _app(settings, key_pair)
        async with _drive_lifespan(app):
            yield app, token_for(key_pair, CUSTOMER)


# ---------------------------------------------------------------------------
# ENTRY write failure: inside the tool body, so FastMCP's masking is the layer.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("statement", [_bound_value_error, _failing_row_error])
async def test_an_entry_write_failure_reaches_the_client_as_the_masked_text(
    stack: tuple[Any, str], monkeypatch: pytest.MonkeyPatch, statement: Callable[..., Any]
) -> None:
    app, token = stack
    _install(monkeypatch, app, fail_outcomes={"reaching"}, statement=statement)

    response = await _tools_call(app, token, ENTRY_TOOL, {})

    _assert_client_clean(response)
    assert response.json()["result"]["isError"] is True
    assert _client_text(response) == MASKED_ENTRY_TEXT


# ---------------------------------------------------------------------------
# COMPLETION write failure: outside the tool body, so the middleware is the layer.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("statement", [_bound_value_error, _failing_row_error])
async def test_a_completion_write_failure_reaches_the_client_as_the_fixed_text(
    stack: tuple[Any, str], monkeypatch: pytest.MonkeyPatch, statement: Callable[..., Any]
) -> None:
    app, token = stack
    _install(monkeypatch, app, fail_outcomes={"returned"}, statement=statement)

    response = await _tools_call(app, token, ENTRY_TOOL, {})

    _assert_client_clean(response)
    assert _client_text(response) == INTERNAL_ERROR_TEXT


@pytest.mark.parametrize("statement", [_bound_value_error, _failing_row_error])
async def test_both_audit_writes_failing_still_leaks_nothing(
    stack: tuple[Any, str], monkeypatch: pytest.MonkeyPatch, statement: Callable[..., Any]
) -> None:
    app, token = stack
    _install(monkeypatch, app, fail_outcomes={"reaching", "raised"}, statement=statement)

    response = await _tools_call(app, token, ENTRY_TOOL, {})

    _assert_client_clean(response)
    assert _client_text(response) == MASKED_ENTRY_TEXT


async def test_a_wrapper_whose_text_interpolates_the_driver_error_is_replaced_by_chain(
    stack: tuple[Any, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The top-level exception is a plain `RuntimeError` subclass: only the
    chain (`__cause__`) says a driver error is under it."""
    app, token = stack
    _install(monkeypatch, app, fail_outcomes={"returned"}, statement=_bound_value_error, wrap=True)

    response = await _tools_call(app, token, ENTRY_TOOL, {})

    _assert_client_clean(response)
    assert _client_text(response) == INTERNAL_ERROR_TEXT


# ---------------------------------------------------------------------------
# Control: a deliberate ToolError still reaches the client, unchanged.
# ---------------------------------------------------------------------------


async def test_a_deliberate_tool_error_reaches_the_client_unchanged(
    stack: tuple[Any, str],
) -> None:
    app, token = stack

    response = await _tools_call(app, token, STATUS_TOOL, {"challenge_id": "chal_nope"})

    assert response.status_code == 200
    assert response.json()["result"]["isError"] is True
    assert _client_text(response) == CHALLENGE_NOT_FOUND


async def test_a_deliberate_tool_error_is_unchanged_even_when_the_completion_write_fails(
    stack: tuple[Any, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tool's own fixed refusal wins over the audit failure's text, as
    decision 0006 already says, and the audit failure's text is not added."""
    app, token = stack
    _install(monkeypatch, app, fail_outcomes={"raised"}, statement=_bound_value_error)

    response = await _tools_call(app, token, STATUS_TOOL, {"challenge_id": "chal_nope"})

    _assert_client_clean(response)
    assert _client_text(response) == CHALLENGE_NOT_FOUND


def test_the_server_is_built_with_mask_error_details() -> None:
    from services.api.server import build_server
    from services.api.settings import Settings

    server = build_server(Settings.for_testing(), lambda: CustomerRef(value=CUSTOMER), None)
    assert server._mask_error_details is True


# ---------------------------------------------------------------------------
# Logs: the whole process's output for a failed call, and each application
# site on its own with the record factory OFF.
# ---------------------------------------------------------------------------


@pytest.fixture
def every_log() -> Iterator[io.StringIO]:
    """A plain handler on root and on every logger that may have its own."""
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    targets = [logging.getLogger(n) for n in ("", "fastmcp", "mcp", "asyncio")]
    for target in targets:
        target.addHandler(handler)
    yield buffer
    for target in targets:
        target.removeHandler(handler)


def _assert_log_clean(captured: str) -> None:
    for sentinel in (PARAM_SENTINEL, ROW_SENTINEL):
        assert sentinel not in captured, captured
    for fragment in ("[SQL:", "[parameters:", "Failing row", "DETAIL"):
        assert fragment not in captured, (fragment, captured)


@pytest.mark.parametrize("statement", [_bound_value_error, _failing_row_error])
@pytest.mark.parametrize("outcomes", [{"reaching"}, {"returned"}, {"reaching", "raised"}])
async def test_nothing_a_statement_bound_reaches_any_log_of_a_failed_call(
    stack: tuple[Any, str],
    monkeypatch: pytest.MonkeyPatch,
    every_log: io.StringIO,
    statement: Callable[..., Any],
    outcomes: set[str],
) -> None:
    """The real net: `create_app` installed the record factory, and FastMCP's
    own `logger.exception` (its own handler) and the dispatcher's lines go
    through it."""
    app, token = stack
    _install(monkeypatch, app, fail_outcomes=outcomes, statement=statement)

    await _tools_call(app, token, ENTRY_TOOL, {})

    captured = every_log.getvalue()
    _assert_log_clean(captured)
    assert "write failed" in captured, captured


@pytest.mark.parametrize("statement", [_bound_value_error, _failing_row_error])
@pytest.mark.parametrize("outcomes", [{"reaching"}, {"returned"}, {"reaching", "raised"}])
async def test_the_audit_middleware_sites_do_not_rely_on_the_record_factory(
    stack: tuple[Any, str],
    monkeypatch: pytest.MonkeyPatch,
    statement: Callable[..., Any],
    outcomes: set[str],
) -> None:
    app, token = stack
    logging.setLogRecordFactory(logging.LogRecord)  # the net is off
    _install(monkeypatch, app, fail_outcomes=outcomes, statement=statement)
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    log = logging.getLogger("services.api.middleware.audit")
    log.addHandler(handler)
    try:
        await _tools_call(app, token, ENTRY_TOOL, {})
    finally:
        log.removeHandler(handler)

    _assert_log_clean(buffer.getvalue())
    assert "write failed" in buffer.getvalue()


@pytest.mark.parametrize("statement", [_bound_value_error, _failing_row_error])
async def test_the_consent_site_does_not_rely_on_the_record_factory(
    stack: tuple[Any, str],
    monkeypatch: pytest.MonkeyPatch,
    statement: Callable[..., Any],
) -> None:
    app, token = stack
    database: Database = app_database(app)

    async def failing_lookup(session: AsyncSession, customer: CustomerRef) -> set[str]:
        async with database.sessionmaker() as other:
            await statement(other)
        return set()

    monkeypatch.setattr(consents, "granted_domains", failing_lookup)
    logging.setLogRecordFactory(logging.LogRecord)  # the net is off
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    log = logging.getLogger("services.api.consent")
    log.addHandler(handler)
    try:
        response = await _tools_call(app, token, ENTRY_TOOL, {})
    finally:
        log.removeHandler(handler)

    _assert_log_clean(buffer.getvalue())
    assert "consent" in buffer.getvalue()
    _assert_client_clean(response)

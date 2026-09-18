"""The row written BEFORE the operator touches customer data.

`services/api/middleware/audit.py` used to write one row per tool call, after
`call_next`. `tests/test_request_deadline.py` measured what that cost: a call
whose backend had already served the customer's accounts, cancelled at the
edge deadline, left `audit_log` with zero rows. capo ruled on 2026-09-18 that
this table records customer data the operator TOUCHED, so the fix is a
durable write that happens first and fails closed.

WHAT THIS FILE PINS, and the split matters. `tests/test_request_deadline.py`
owns the two end-to-end measurements against a store that goes silent (the
entry write stalls and nothing is touched; the completion write stalls and
the entry row survives). Everything here is the shape of the row itself and
the rules around writing it, driven through the real middleware and a real
`BackendClient` over an in-process `Client(transport=server)` with no
network.

Those in-process calls carry NO access token -- `Client(transport=server)`
accepts no auth argument (CLAUDE.md's version traps) -- so every row below
has a NULL `customer_ref` and `customer_ref_absence_reason='no_access_token'`.
That is not an accident of the harness being ignored: it exercises
`ck_audit_log_customer_ref_xor_absence` on the entry row, which is a row
shape that constraint had never seen before this change.
"""

import asyncio
import logging

import httpx2
import pytest
import pytest_asyncio
from fastmcp import Client, FastMCP
from mcp.shared.exceptions import MCPError
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from postern_core.store.models import (
    ABSENCE_NO_ACCESS_TOKEN,
    AuditEntry,
)
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.main import create_app
from services.api.middleware import audit as audit_middleware
from services.api.middleware.audit import AuditMiddleware, record_data_touch
from services.api.settings import Settings

# The junk payload that exhausts the middleware's own redaction allowance,
# imported rather than re-derived: `tests/test_audit_middleware.py` owns the
# derivation and the reasoning behind the count, and a second copy here would
# be free to drift from `_IBAN_SCAN_BUDGET` without anything noticing.
from tests.test_audit_middleware import _EXHAUSTING_MEMO

# Nothing listens on port 1, so asyncpg's connect is refused immediately.
# Same address and same reason as `tests/test_consent_check_failure_mode.py`.
REFUSED_URL = "postgresql+asyncpg://postern:postern@127.0.0.1:1/postern"

CUSTOMER = CustomerRef(value="cust_7f3a")


def _minter(customer: CustomerRef, audience: str) -> str:
    """A real `TokenMinter` shape with none of the machinery: what is under
    test is when the request is made, not what it carries."""
    return "test-token"


class _Recorder:
    """Which backend paths were actually requested, in order.

    The decisive signal in this file, for the reason
    `tests/test_consent_check_failure_mode.py::RecordingBackend` gives: the
    JSON-RPC envelope cannot separate "the tool ran and reached the backend"
    from "the tool failed before it got there", and that separation is the
    property the entry write exists to create.
    """

    def __init__(self) -> None:
        self.paths: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(request.url.path)
        return httpx2.Response(200, json={"accounts": []})


def _server(audit_db: Database, backend: BackendClient) -> FastMCP:
    """A server with the audit middleware and four tools: one that makes a
    single backend request, one that makes two in sequence, one that makes
    two concurrently, and one that reaches no backend at all."""
    mcp = FastMCP(name="entry-row-test")
    mcp.add_middleware(AuditMiddleware(audit_db))

    @mcp.tool
    async def one_request(memo: str = "") -> str:
        await backend.get_json("/accounts", customer=CUSTOMER)
        return "ok"

    @mcp.tool
    async def two_requests_in_sequence() -> str:
        await backend.get_json("/accounts", customer=CUSTOMER)
        await backend.get_json("/cards", customer=CUSTOMER)
        return "ok"

    @mcp.tool
    async def two_requests_at_once() -> str:
        await asyncio.gather(
            backend.get_json("/accounts", customer=CUSTOMER),
            backend.get_json("/cards", customer=CUSTOMER),
        )
        return "ok"

    @mcp.tool
    async def no_request() -> str:
        return "ok"

    return mcp


@pytest_asyncio.fixture
async def clean_audit_log(database: Database) -> None:
    """`AuditMiddleware` commits through its own sessionmaker, so its rows
    survive the `session` fixture's rollback and would otherwise be visible
    to the next test in this file. Same reasoning as
    `tests/conftest.py::audit_server`."""
    async with database.sessionmaker() as s:
        await s.execute(delete(AuditEntry))
        await s.commit()


async def _rows(session: AsyncSession) -> list[AuditEntry]:
    result = await session.execute(select(AuditEntry).order_by(AuditEntry.id))
    return list(result.scalars().all())


def _backend(recorder: _Recorder, audit_db: Database) -> BackendClient:
    return BackendClient(
        "https://backend.test",
        _minter,
        transport=httpx2.MockTransport(recorder),
        before_backend_request=record_data_touch,
    )


async def test_a_tool_that_reaches_the_backend_writes_an_entry_row_first(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """The whole change in one row, with every field on it asserted.

    `reaching` comes first and `returned` second, they share a `call_id`,
    and the entry row carries the same tool name, the same arguments and the
    same subject as the completion row -- everything an investigator reads to
    know WHAT was touched, available before it was.

    The three fields that differ are the three that cannot be known yet:
    `detail` (nothing has gone wrong), `duration_ms` (the tool has not
    finished) and, on the completion row only, the outcome itself.
    `refusal_reason` is NULL on both. On the entry row that means "consent
    did NOT REFUSE this call", never "consent allowed it", and this file is
    where the distinction is sharpest: every tool `_server` registers is
    declared without `auth=`, so no consent check runs for any of them and
    the stronger reading would be false for all four. It is also false in
    production for one real tool -- `start_session` carries no `auth=`
    either (`services/api/tools/bootstrap.py:75`) and still reaches the
    backend. NULL covers all three of the states
    `AuditEntry.refusal_reason` documents, and "no check ran" is one of
    them.
    """
    recorder = _Recorder()
    async with Client(transport=_server(database, _backend(recorder, database))) as client:
        await client.call_tool("one_request", {"memo": "hello"})

    entry, completion = await _rows(session)
    assert recorder.paths == ["/accounts"]

    assert (entry.outcome, completion.outcome) == ("reaching", "returned")
    assert entry.call_id is not None
    assert entry.call_id == completion.call_id

    assert entry.tool_name == completion.tool_name == "one_request"
    assert entry.arguments == completion.arguments == {"memo": "hello"}
    assert entry.at == completion.at
    assert entry.customer_ref is None
    assert entry.customer_ref_absence_reason == ABSENCE_NO_ACCESS_TOKEN

    assert entry.detail is None
    assert entry.duration_ms is None, "a row written before the tool finished has no duration"
    assert entry.refusal_reason is None
    assert isinstance(completion.duration_ms, int)


async def test_a_tool_that_reaches_no_backend_writes_only_a_completion_row(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """One row, unchanged from before this feature existed.

    The entry row records a touch, not a call, so a tool that touches
    nothing produces none -- and a completion row with no partner reads as
    exactly that. This is the same shape a consent-denied call produces
    (`tests/test_audit_refusal_reason.py` pins that one, where the refusal
    itself is what has to stay legible).
    """
    recorder = _Recorder()
    async with Client(transport=_server(database, _backend(recorder, database))) as client:
        await client.call_tool("no_request")

    assert recorder.paths == []
    assert [(row.tool_name, row.outcome) for row in await _rows(session)] == [
        ("no_request", "returned")
    ]


async def test_two_sequential_backend_requests_write_one_entry_row(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """The guard that keeps the pairing usable once a tool makes more than
    one request.

    No façade function does today -- `facade/accounts.py:52` and `:57`,
    `facade/cards.py:80` and `facade/transactions.py:121` are one `get_json`
    each -- so without this the first multi-request tool (a
    `payments.create_payment` that looks a payee up before writing) would
    silently write N entry rows for one call and break the join, with no
    test failing. `_PendingEntry.record` holds the guard, not
    `BackendClient`, because "one tool call" is a concept only the
    middleware has.
    """
    recorder = _Recorder()
    async with Client(transport=_server(database, _backend(recorder, database))) as client:
        await client.call_tool("two_requests_in_sequence")

    assert recorder.paths == ["/accounts", "/cards"]
    assert [row.outcome for row in await _rows(session)] == ["reaching", "returned"]


async def test_two_concurrent_backend_requests_write_one_entry_row(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """The same guard against the case a bare boolean flag would miss.

    Two `get_json` calls in one `asyncio.gather` both reach the hook, and
    both would find `written` False across the `await` that writes the row.
    `_PendingEntry.lock` is what makes the second one wait and then see the
    first one's result instead of inserting a duplicate.
    """
    recorder = _Recorder()
    async with Client(transport=_server(database, _backend(recorder, database))) as client:
        await client.call_tool("two_requests_at_once")

    assert sorted(recorder.paths) == ["/accounts", "/cards"]
    assert [row.outcome for row in await _rows(session)] == ["reaching", "returned"]


async def test_an_entry_row_that_cannot_be_written_stops_the_call_before_the_backend(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """Fail closed, and the property that makes this better than what it
    replaced.

    The audit store is unreachable, so the entry write raises inside the
    façade hook and `get_json` never issues its request. Before this change
    the same outage let the tool run to completion and discovered the
    problem afterwards, which is how a call could touch real customer data
    and leave nothing behind (docs/decisions/0006-audit-write-failure.md is
    the policy; this is what it now buys).

    The tool call fails, which is the cost that record already states and
    does not hide: a store outage takes down read calls that would otherwise
    have succeeded.
    """
    unreachable = Database(REFUSED_URL)
    recorder = _Recorder()
    try:
        server = _server(unreachable, _backend(recorder, unreachable))
        async with Client(transport=server) as client:
            result = await client.call_tool("one_request", raise_on_error=False)
    finally:
        await unreachable.close()

    assert result.is_error is True
    assert recorder.paths == [], "customer data was reached on a call that could not be recorded"
    assert await _rows(session) == [], "the healthy store must not have been written to"


async def test_an_entry_write_failure_is_logged_for_the_operator(
    database: Database,
    session: AsyncSession,
    clean_audit_log: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The ERROR line is the only thing in the record that names this
    failure, which is why it is tested rather than trusted.

    `audit_log.detail` cannot do it: FastMCP wraps anything a tool body
    raises in `ToolError` before the middleware reads `type(exc).__name__`
    (`fastmcp/server/server.py:1555`), so a failed entry write records the
    same `detail='ToolError'` as a tool that raised on its own. The two
    completion-write failure paths each got a logging test when
    docs/decisions/0006-audit-write-failure.md was written
    (`tests/test_audit_middleware.py`); this is the third path's, and it
    matters more than either, because those two at least leave a row whose
    absence is informative.

    Both lines appear here, since the entry write and the completion write
    go to the same unreachable store. Asserting on the entry line's own
    wording is what proves an operator can tell them apart.
    """
    unreachable = Database(REFUSED_URL)
    recorder = _Recorder()
    caplog.set_level(logging.ERROR, logger=audit_middleware.logger.name)
    try:
        server = _server(unreachable, _backend(recorder, unreachable))
        async with Client(transport=server) as client:
            await client.call_tool("one_request", raise_on_error=False)
    finally:
        await unreachable.close()

    entry_lines = [
        record
        for record in caplog.records
        if record.levelno == logging.ERROR
        and record.name == audit_middleware.logger.name
        and "audit entry write failed" in record.getMessage()
    ]
    assert entry_lines, (
        "an entry write failed with no ERROR line: nothing in the audit record "
        "would distinguish it from an ordinary tool failure"
    )
    assert "one_request" in entry_lines[0].getMessage()
    assert entry_lines[0].exc_info is not None, "the line carries no traceback"
    assert isinstance(entry_lines[0].exc_info[1], OSError), (
        f"expected the store's own connection failure, got {entry_lines[0].exc_info[1]!r}"
    )
    assert recorder.paths == []


async def test_a_second_touch_after_a_failed_entry_write_fails_too(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """A write that never commits leaves `_PendingEntry.written` False, so
    the next touch in the same call retries and fails again rather than
    passing through on the strength of a row that does not exist.

    No shipping tool swallows that exception, so this builds its own: a
    read-before-write tool doing its own error handling is the realistic
    shape, and it is the one that would turn a missed guard into a backend
    request nothing recorded. Both attempts have to fail; one failure
    followed by `"reached"` would mean the second touch found the flag set
    by a write that never happened.
    """
    unreachable = Database(REFUSED_URL)
    recorder = _Recorder()
    backend = _backend(recorder, unreachable)
    attempts: list[str] = []

    mcp = FastMCP(name="entry-row-retry-test")
    mcp.add_middleware(AuditMiddleware(unreachable))

    @mcp.tool
    async def swallows_and_retries() -> str:
        for _ in range(2):
            try:
                await backend.get_json("/accounts", customer=CUSTOMER)
            except Exception as exc:
                attempts.append(type(exc).__name__)
            else:
                attempts.append("reached")
        return "done"

    try:
        async with Client(transport=mcp) as client:
            # `MCPError`, not a tool error, and the difference is this test's
            # own shape rather than the entry write's: the tool SWALLOWS both
            # failures and returns normally, so the middleware takes its
            # returned path, and that path's completion write is the one that
            # then fails against the same unreachable store. A raw store
            # exception escaping `on_call_tool` is the success-path behaviour
            # `docs/decisions/0006-audit-write-failure.md` documents, and
            # `raise_on_error=False` does not suppress it because it is a
            # protocol-level error rather than `isError: true`.
            with pytest.raises(MCPError):
                await client.call_tool("swallows_and_retries")
    finally:
        await unreachable.close()

    assert len(attempts) == 2, f"the tool did not attempt twice: {attempts}"
    assert "reached" not in attempts, (
        f"a second touch went through after an entry write that never committed: {attempts}"
    )
    assert recorder.paths == []
    assert await _rows(session) == []


async def test_the_entry_row_carries_the_measured_redaction_budget_not_a_default(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """`AuditEntry.redaction_budget_exhausted` is NOT NULL with a
    `server_default` of false, so an entry row that did not know the answer
    would assert one anyway -- a false statement on a regulator-facing table
    about a call that had not run.

    It does know. `on_call_tool` reads `RedactionScope.exhausted` after its
    `with redaction_budget()` block has closed, and nothing spends from that
    allowance afterwards, so the value is settled before the entry row is
    bound. Measured here rather than reasoned about: the same junk payload
    `tests/test_audit_middleware.py` uses to exhaust the allowance produces
    True on BOTH rows of one call.
    """
    recorder = _Recorder()
    async with Client(transport=_server(database, _backend(recorder, database))) as client:
        await client.call_tool("one_request", {"memo": _EXHAUSTING_MEMO})

    rows = await _rows(session)
    assert [row.outcome for row in rows] == ["reaching", "returned"]
    assert [row.redaction_budget_exhausted for row in rows] == [True, True]


async def test_the_entry_write_refuses_to_run_outside_a_tool_call() -> None:
    """`record_data_touch` raises rather than returning quietly when no call
    is in flight.

    Returning quietly is the tempting choice and is the wrong one: an empty
    `ContextVar` here means the audit middleware is not installed or its
    value did not reach this far, and in either case a backend request is
    about to be made that nothing can record -- which is precisely the
    condition this control exists to stop. The exception surfaces as the
    tool call's own failure.
    """
    with pytest.raises(RuntimeError, match="no audit entry is pending"):
        await record_data_touch()


def test_create_app_wires_the_entry_write_into_the_backend_client() -> None:
    """`BackendClient(before_backend_request=...)` is required but may be
    `None`: the façade unit tests in `tests/test_facade_client.py` build
    clients with no audit middleware behind them, and as of 2026-09-18 they
    are the only such callers -- `services/confirm/` is five modules and
    none of them imports `postern_core.facade` at all. So nothing in the
    type system distinguishes a composition root that passes the hook from
    one that passes `None`, and getting that wrong is a silent failure:
    every call served, nothing recorded first. The wiring is therefore
    asserted on the assembled app rather than trusted to the call site.

    Read through `app.state.backend_client`, the handle `create_app`
    deliberately exposes, for the same reason
    `test_backend_timeout_is_wired_from_settings_per_phase` reaches for it:
    nothing else holds the instance.
    """
    app = create_app(Settings.for_testing())
    assert app.state.backend_client._before_backend_request is record_data_touch

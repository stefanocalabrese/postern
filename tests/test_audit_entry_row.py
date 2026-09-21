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

ONE TEST BREAKS THAT RULE AND HAS TO. `start_session` is the only registered
tool with no consent check, and what its entry row's NULL `refusal_reason`
means is that no check RAN -- a claim that is only worth anything if the
check would have refused had one run. The in-process transport cannot show
that: with no token `create_app` installs no real check at all, and a real
one could not file its decision anyway, since `get_http_request()` raises
there. That test therefore goes over real HTTP with a real signed token,
reusing the harness `tests/test_audit_refusal_reason.py` already owns rather
than copying a third one.
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from fastmcp import Client, FastMCP
from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from mcp.shared.exceptions import MCPError
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from postern_core.store.models import (
    ABSENCE_NO_ACCESS_TOKEN,
    REFUSAL_DOMAIN_NOT_CONSENTED,
    AuditEntry,
)
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from services.api.main import create_app
from services.api.middleware import audit as audit_middleware
from services.api.middleware.audit import AuditMiddleware, record_data_touch
from services.api.settings import Settings

# The junk payload that exhausts the middleware's own redaction allowance,
# imported rather than re-derived: `tests/test_audit_middleware.py` owns the
# derivation and the reasoning behind the count, and a second copy here would
# be free to drift from `_IBAN_SCAN_BUDGET` without anything noticing.
from tests.test_audit_middleware import _EXHAUSTING_MEMO

# The real-HTTP harness, imported rather than copied a third time: it mints a
# token, builds the whole app through `create_app` with a mocked backend
# transport, and sends one `tools/call` per freshly built app (the lifespan
# closes the backend client, so a second call on the same app dies inside the
# tool). `tests/test_audit_refusal_reason.py` owns it and documents every one
# of those choices; what this file adds is a different question asked through
# it, not a different harness.
from tests.test_audit_refusal_reason import call, token_for

# Nothing listens on port 1, so asyncpg's connect is refused immediately.
# Same address and same reason as `tests/test_consent_check_failure_mode.py`.
REFUSED_URL = "postgresql+asyncpg://postern:postern@127.0.0.1:1/postern"

CUSTOMER = CustomerRef(value="cust_7f3a")

# How long `waits_then_requests` below waits before it reaches the backend,
# and the floor the assertion uses is half of it: the two instants being
# compared are both wall-clock readings taken on this machine, and the test
# asserts that they are FAR APART rather than pinning the sleep's own
# accuracy. A `reaching_at` copied from `at` -- the failure this test is
# written against -- differs by well under a millisecond, not by a tenth of a
# second.
_ARRIVAL_TO_TOUCH_DELAY = 0.2


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
    """A server with the audit middleware and five tools: one that makes a
    single backend request, one that makes two in sequence, one that makes
    two concurrently, one that reaches no backend at all, and one that waits
    a measurable while before reaching it."""
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

    @mcp.tool
    async def waits_then_requests() -> str:
        # The gap between a call ARRIVING and the operator REACHING for the
        # customer's data, made large enough to measure. In production it is
        # the consent lookup and whatever else runs first, bounded only by
        # `Settings.request_deadline_seconds`; here it is one sleep, because
        # the point is that the table records two different instants, not
        # how far apart they happen to be.
        await asyncio.sleep(_ARRIVAL_TO_TOUCH_DELAY)
        await backend.get_json("/accounts", customer=CUSTOMER)
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

    The fields that differ are the ones that cannot be known yet, plus the
    one only an entry row has: `detail` (nothing has gone wrong),
    `duration_ms` (the tool has not finished), the outcome itself, and
    `reaching_at`, which carries the instant this row's own write was about
    to be followed by a backend request and is therefore NULL on the
    completion row. `refusal_reason` is NULL on both. On the entry row that
    means "consent did NOT REFUSE this call", never "consent allowed it",
    and this file is where the distinction is sharpest: every tool `_server`
    registers is declared without `auth=`, so no consent check runs for any
    of them and the stronger reading would be false for all four. It is also
    false in production for one real tool -- `start_session` carries no
    `auth=` either (`services/api/tools/bootstrap.py`'s `start_session`) and
    still reaches the backend, which
    `test_the_ungated_tool_writes_an_entry_row_and_its_refusal_reason_is_null`
    at the bottom of this file now measures. NULL covers all three of the
    states `AuditEntry.refusal_reason` documents, and "no check ran" is one
    of them.
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
    # THE SHARED `at` SURVIVED A CHANGE THAT COULD HAVE ENDED IT, and the
    # assertion is here rather than deleted because of what it now means.
    # Until `reaching_at` existed, this equality was the whole reason the
    # table could not say when the operator reached the backend: both rows
    # carried the arrival instant and nothing carried the touch. The cheap
    # fix was to redefine this column per row shape, which would have made
    # this line false and made one NOT NULL column on a regulator-facing
    # table mean arrival on some rows and a touch on others. The touch got
    # its own column instead, so `at` still means exactly one thing on every
    # row, and the pair still shares the timestamp a reader uses to see they
    # belong to one call.
    assert entry.at == completion.at
    assert entry.customer_ref is None
    assert entry.customer_ref_absence_reason == ABSENCE_NO_ACCESS_TOKEN

    assert entry.detail is None
    assert entry.duration_ms is None, "a row written before the tool finished has no duration"
    assert entry.refusal_reason is None
    assert isinstance(completion.duration_ms, int)
    assert entry.reaching_at is not None
    assert entry.reaching_at >= entry.at
    assert completion.reaching_at is None, (
        "a completion row carries no touch instant: the entry row holds it, and "
        "the same fact on both rows would be free to disagree with itself"
    )


async def test_the_entry_row_records_when_the_backend_was_reached_not_when_the_call_arrived(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """The question this table could not answer until `reaching_at` existed.

    `at` is the ARRIVAL instant, on both of a call's rows: the middleware
    reads `context.timestamp` once and passes it to both writes. So the two
    rows shared one number, and the instant the operator actually reached
    for the customer's data was in none of them -- the gap between the two
    bounded only by `Settings.request_deadline_seconds`, since everything
    that runs before the first backend request (the consent lookup, argument
    validation, whatever a tool body does first) sits inside it.

    The tool here sleeps before its request, which is what makes this
    discriminating rather than merely green: a `reaching_at` copied from
    `at`, or an `at` reused as the touch instant, differs by microseconds
    against the tenth of a second asserted below.

    The inequality's direction is pinned in the sibling test above, with the
    caveat this file is downstream of: the entry row is written after the
    call arrived and before the request is issued, so the ORDER OF EVENTS
    puts the touch second, but both numbers are wall-clock readings and
    `AuditEntry.reaching_at` (models.py) grants that a clock step between
    them breaks the arithmetic. An `at` later than `reaching_at` in this
    table is therefore a clock artefact rather than an impossibility, and a
    failure of that assertion here would be measuring this machine's clock,
    not this code.
    """
    recorder = _Recorder()
    async with Client(transport=_server(database, _backend(recorder, database))) as client:
        await client.call_tool("waits_then_requests")

    entry, completion = await _rows(session)
    assert recorder.paths == ["/accounts"]
    assert (entry.outcome, completion.outcome) == ("reaching", "returned")
    assert entry.reaching_at is not None
    assert entry.reaching_at - entry.at >= timedelta(seconds=_ARRIVAL_TO_TOUCH_DELAY / 2), (
        f"the touch instant is indistinguishable from the arrival instant: "
        f"at={entry.at}, reaching_at={entry.reaching_at}"
    )
    assert completion.reaching_at is None


async def test_both_rows_of_one_call_name_the_same_oauth_client(
    database: Database,
    session: AsyncSession,
    clean_audit_log: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`client_id` on BOTH row shapes, carrying one value.

    The pairing is the property, not the presence. `AuditMiddleware
    .on_call_tool` reads `get_access_token()` ONCE and puts the derived id on
    the `_PendingEntry` that both writes read from, so the entry row written
    before the backend was reached and the completion row written after it
    name the same client by construction. Two separate reads would make the
    agreement depend on both landing in the same `ContextVar` context, and a
    pair that named two different callers for one `call_id` would be a
    regulator-facing table contradicting itself on the one question this
    column was added to answer.

    The token has to be monkeypatched here for the reason this file's module
    docstring gives: `Client(transport=server)` accepts no auth argument, so
    every other call in this file carries no token at all. That absence is
    the subject of the test immediately below, which is the other half of
    this one -- without it, a `client_id` that was always NULL would pass
    every pairing assertion here.

    `sub` is a real `CustomerRef` so the row satisfies
    `ck_audit_log_customer_ref_xor_absence`, and the client id is a
    CIMD-shaped URL rather than an opaque string, because that is the shape
    `AuditEntry.client_id`'s 512-character width was chosen for.
    """
    client_id = "https://claude.ai/.well-known/oauth-client-metadata"
    token = AccessToken(
        token="t",  # noqa: S106
        client_id=client_id,
        scopes=[],
        claims={"sub": CUSTOMER.value},
    )
    monkeypatch.setattr("services.api.middleware.audit.get_access_token", lambda: token)

    recorder = _Recorder()
    async with Client(transport=_server(database, _backend(recorder, database))) as client:
        await client.call_tool("one_request", {"memo": "hello"})

    entry, completion = await _rows(session)
    assert recorder.paths == ["/accounts"]
    assert (entry.outcome, completion.outcome) == ("reaching", "returned")
    assert entry.call_id == completion.call_id
    assert entry.client_id == client_id
    assert completion.client_id == client_id


async def test_a_call_with_no_access_token_names_no_client_on_either_row(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """NULL is a live answer on this column, not only a pre-migration one.

    `get_access_token()` returns None for every call over the in-process
    `Client(transport=server)` transport, which is a working path and not a
    degraded one, so `AuditEntry.client_id` is nullable rather than `NOT
    NULL`: the INSERT would otherwise fail, and under
    dev-docs/decisions/0006-audit-write-failure.md a failed audit write takes the
    tool call with it. The column would then fail closed on a transport the
    test suite above it runs entirely on.

    The absence is corroborated on the same rows rather than asserted alone.
    `customer_ref_absence_reason` reads `no_access_token` on both, which is
    the same fact arriving through `_customer_ref` instead of `_client_id`,
    and the two agree because one `get_access_token()` call feeds both --
    the equivalence `AuditEntry.client_id` documents and deliberately does
    not enforce with a CHECK constraint.
    """
    recorder = _Recorder()
    async with Client(transport=_server(database, _backend(recorder, database))) as client:
        await client.call_tool("one_request", {"memo": "hello"})

    entry, completion = await _rows(session)
    assert (entry.outcome, completion.outcome) == ("reaching", "returned")
    assert entry.client_id is None
    assert completion.client_id is None
    assert entry.customer_ref_absence_reason == ABSENCE_NO_ACCESS_TOKEN
    assert completion.customer_ref_absence_reason == ABSENCE_NO_ACCESS_TOKEN


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

    No façade function does today -- `facade/accounts.py`'s `list_accounts`
    and `get_balance`, `facade/cards.py`'s `list_cards` and
    `facade/transactions.py`'s `list_transactions` are one `get_json` each --
    so without this the first multi-request tool (a
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
    and leave nothing behind (dev-docs/decisions/0006-audit-write-failure.md is
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
    (`fastmcp/server/server.py::call_tool`), so a failed entry write records
    the same `detail='ToolError'` as a tool that raised on its own. The two
    completion-write failure paths each got a logging test when
    dev-docs/decisions/0006-audit-write-failure.md was written
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
            # `dev-docs/decisions/0006-audit-write-failure.md` documents, and
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


# -- The one registered tool with no consent check ---------------------------


@pytest.fixture(scope="session")
def key_pair() -> RSAKeyPair:
    """Session-scoped, like the identical fixture in
    `tests/test_audit_refusal_reason.py`: generating an RSA key pair is the
    slow part of the HTTP harness and nothing here depends on a fresh one."""
    return RSAKeyPair.generate()


# A customer with no `consents` row of any kind, and a different reference
# from `CUSTOMER` above, which other test modules seed. Consenting to nothing
# is the whole point: it is what makes the consent check REFUSE the gated
# tool in the same breath as the ungated one succeeds.
UNCONSENTED_CUSTOMER = "cust_4b2e"


async def test_the_ungated_tool_writes_an_entry_row_and_its_refusal_reason_is_null(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    session: AsyncSession,
) -> None:
    """`start_session` is the exception every claim about the entry row has
    to survive, and until this test nothing exercised it.

    It is the only one of the five registered tools declared without `auth=`
    (`services/api/tools/bootstrap.py`'s `start_session`; the other four
    carry `auth=check` on `services/api/tools/accounts.py`'s `accounts_list`
    and `accounts_get_balance`, `services/api/tools/transactions.py`'s
    `transactions_list` and `services/api/tools/cards.py`'s `cards_list`),
    and it reaches the operator's backend anyway, through
    `accounts_facade.list_accounts`. So it is the one
    ungated tool that writes an entry row -- and `services/api/middleware/audit.py` names
    it as the reason that row's NULL `refusal_reason` may only be read as
    "consent did not refuse this call", never "consent allowed it".

    THE SECOND CALL IS WHAT MAKES THE FIRST ONE MEAN ANYTHING. A NULL
    `refusal_reason` on a row is the same NULL whether no check ran or a
    check ran and allowed the call, so this test puts both tools in front of
    the same customer, in the same consent state, over the same harness:
    `cards.list` is REFUSED for want of consent and records
    `domain_not_consented`, while `start_session` is not refused, reaches
    the backend and writes its entry row. Had `start_session`'s NULL meant
    "the check allowed it", it would be an allowance for a customer whose
    very next call, to a gated tool, this same test watches being denied.

    Over real HTTP with a real signed token, not the in-process transport
    this file otherwise uses, and the reason is that the in-process path
    cannot produce the contrast at all. `create_app` only hands
    `build_server` a database to check consent against when real customer
    auth is configured, so without a token the gated tools get
    `_no_consent_required` and nothing is ever refused; and even with a real
    check installed, `get_http_request()` raises under that transport, so
    `services/api/consent.py`'s `_refuse` returns without filing and the row
    would read NULL whatever the check decided. Either way both halves of
    the comparison would be NULL for reasons that have nothing to do with
    which tool was called. `audit_server` is requested for its clear-the-
    table-before-and-after behaviour only (`tests/conftest.py`), exactly as
    `tests/test_audit_refusal_reason.py` requests it; the calls below go
    through an app `create_app` assembles.
    """
    token = token_for(key_pair, UNCONSENTED_CUSTOMER)
    await call(pg_url, key_pair, token, "start_session")
    await call(pg_url, key_pair, token, "cards.list")

    # The row SHAPE first, with its own message, because the unpack below
    # would otherwise be this test's real guard and would report a bare
    # `ValueError` when it fires. The regression this test exists against --
    # `cards.list` stops being refused -- produces four rows, not three: an
    # allowed `cards.list` runs, reaches the backend and writes its own
    # `reaching`/`returned` pair.
    rows = await _rows(session)
    shape = [(row.tool_name, row.outcome) for row in rows]
    assert shape == [
        ("start_session", "reaching"),
        ("start_session", "returned"),
        ("cards.list", "raised"),
    ], (
        "the ungated tool's NULL refusal_reason proves nothing unless the gated "
        f"tool was refused for this same customer; rows were {shape}"
    )
    entry, completion, refused = rows

    assert (entry.tool_name, entry.outcome) == ("start_session", "reaching")
    assert (completion.tool_name, completion.outcome) == ("start_session", "returned")
    assert entry.call_id is not None
    assert entry.call_id == completion.call_id
    assert entry.customer_ref == completion.customer_ref == UNCONSENTED_CUSTOMER
    assert entry.reaching_at is not None, "the ungated tool's touch instant is recorded too"
    assert entry.refusal_reason is None
    assert completion.refusal_reason is None

    assert (refused.tool_name, refused.outcome, refused.detail) == (
        "cards.list",
        "raised",
        "NotFoundError",
    )
    assert refused.refusal_reason == REFUSAL_DOMAIN_NOT_CONSENTED, (
        "the gated tool was refused but the reason was not recorded, so the "
        "row cannot say the refusal was about consent rather than a name "
        "nobody registered"
    )
    assert refused.reaching_at is None, "a refused call touches nothing"


# -- The window where the commit succeeds and the session exit raises --------
#
# `_PendingEntry.record` commits the row and sets `written` on the next line,
# INSIDE the session block. The class docstring in
# `services/api/middleware/audit.py` says why that placement is load-bearing
# and describes both failure shapes around it; until these two tests, only one
# of them was reachable from the suite
# (`test_a_second_touch_after_a_failed_entry_write_fails_too` covers the write
# that never commits). This is the other: `AsyncSession.__aexit__` closes the
# session and can raise on its own, AFTER the commit has already made the row
# durable.

_CLOSE_FAILURE = "session close failed after the commit succeeded"


class _StoreWhoseSessionCloseRaises(Database):
    """A store whose sessions commit for real and then raise on exit.

    Subclasses `Database` and takes the ENGINE the `database` fixture already
    built rather than calling `Database.__init__`, which would open a second
    engine against the same container that this class would then have to own
    and close. Everything `_PendingEntry` touches is `sessionmaker`, and the
    sessions it hands out are ordinary `AsyncSession` objects against that
    real engine: the INSERT and the COMMIT are real, which is the whole point
    -- the row has to be genuinely durable before the exception is raised, or
    the test would be about something else.

    `exits_that_raise` bounds how many session exits fail, because the two
    tests below need different shapes: one session for the entry write alone,
    or one failing entry write followed by a completion write that must
    succeed so the row it produces can be read.
    """

    def __init__(self, engine: AsyncEngine, *, exits_that_raise: int) -> None:
        self.engine = engine
        self.exits_left_to_raise = exits_that_raise
        store = self

        class _SessionThatRaisesOnClose(AsyncSession):
            async def __aexit__(self, type_: Any, value: Any, traceback: Any) -> None:
                # The real close FIRST, so this fails the way a genuine
                # close failure does -- after the session has done whatever
                # it does on exit -- rather than by skipping it.
                await super().__aexit__(type_, value, traceback)
                if store.exits_left_to_raise > 0:
                    store.exits_left_to_raise -= 1
                    raise RuntimeError(_CLOSE_FAILURE)

        self.sessionmaker = async_sessionmaker[AsyncSession](
            engine, expire_on_commit=False, class_=_SessionThatRaisesOnClose
        )


def _pending_entry_against(store: Database) -> audit_middleware._PendingEntry:
    """One call's entry row, bound directly rather than through a tool call.

    `AuditMiddleware.on_call_tool` builds this object and puts it on a
    `ContextVar` that only the façade hook reads, so a test driven through a
    tool cannot see the `written` flag at all -- and that flag is half of
    what the window below is about. The fields are the ones the middleware
    would have derived from a call with no access token, which is what every
    in-process call in this file produces.
    """
    return audit_middleware._PendingEntry(
        db=store,
        at=datetime.now(UTC),
        subject=audit_middleware._Subject(None, ABSENCE_NO_ACCESS_TOKEN),
        tool_name="one_request",
        arguments={},
        redaction_budget_exhausted=False,
        request_id=None,
        call_id=str(uuid.uuid4()),
        # None for the same reason the subject beside it is a
        # `no_access_token` absence: `_client_id` returns None whenever
        # `get_access_token()` does, and this helper stands in for a call
        # with no token.
        client_id=None,
    )


async def test_an_entry_write_that_commits_then_raises_leaves_the_row_and_the_flag(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """The window `written = True` is placed inside the session block for.

    The commit succeeds, the session exit then raises, and the exception
    reaches the caller -- so this first touch is stopped, exactly as a failed
    write would stop it. What must NOT happen is the second touch writing a
    second `reaching` row under the same `call_id`: the row it needs is
    already durable, and a pair of entry rows for one call is the pairing
    break the guard exists to prevent, arrived at through the guard.

    Set after the block instead -- the placement the middleware's class
    docstring warns about -- the flag would still be False here, and the
    second `record()` would insert again. Both halves are asserted for that
    reason: the flag, and the row count after touching twice.
    """
    store = _StoreWhoseSessionCloseRaises(database.engine, exits_that_raise=1)
    pending = _pending_entry_against(store)

    with pytest.raises(RuntimeError, match=_CLOSE_FAILURE):
        await pending.record()

    assert pending.written is True, (
        "the commit succeeded, so the flag must be set: a second toucher that "
        "finds it False writes a duplicate reaching row for one call"
    )
    assert [(row.outcome, row.call_id) for row in await _rows(session)] == [
        ("reaching", pending.call_id)
    ], "the row was committed before the exception and must be durable"

    # The second touch, which is what the flag is read for. It returns
    # quietly -- no exception, no write -- because the row it needed exists.
    await pending.record()
    assert [(row.outcome, row.call_id) for row in await _rows(session)] == [
        ("reaching", pending.call_id)
    ], "a second touch wrote a duplicate reaching row under the same call_id"


async def test_a_commit_that_then_raises_records_a_touch_that_never_happened(
    database: Database, session: AsyncSession, clean_audit_log: None
) -> None:
    """The same window driven through a real tool call, where nothing
    swallows the exception -- and the false positive that follows, made
    concrete.

    The entry row commits, the session exit raises, `get_json` therefore
    never issues its request, and the tool fails. The table ends up holding
    `reaching` + `raised` for a call that did not touch the customer's data
    at all. `OUTCOME_REACHING` in `postern_core/store/models.py` licenses
    exactly this direction -- a row claiming a touch a later failure
    prevented is a false positive an investigator can resolve against the
    backend's own logs, where the reverse leaves nothing to resolve -- and
    this is the shape that licence is written for, rather than a hypothetical
    one.

    `recorder.paths` is the decisive assertion: the JSON-RPC envelope reports
    a failed call either way, and only the backend transport can say whether
    the customer's data was reached.
    """
    store = _StoreWhoseSessionCloseRaises(database.engine, exits_that_raise=1)
    recorder = _Recorder()
    async with Client(transport=_server(store, _backend(recorder, store))) as client:
        result = await client.call_tool("one_request", raise_on_error=False)

    assert result.is_error is True
    assert recorder.paths == [], "the backend was reached after the entry write failed"

    entry, completion = await _rows(session)
    assert (entry.outcome, completion.outcome) == ("reaching", "raised")
    assert entry.call_id == completion.call_id
    assert entry.reaching_at is not None
    # `ToolError`, not `RuntimeError`: FastMCP wraps whatever a tool body
    # raises before this middleware reads the type
    # (`fastmcp/server/server.py::call_tool`), so nothing in the row names
    # the session close as the cause. The ERROR line
    # `test_an_entry_write_failure_is_logged_for_the_operator` pins is what
    # does.
    assert completion.detail == "ToolError"

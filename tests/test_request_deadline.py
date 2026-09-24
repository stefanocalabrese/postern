"""What a wall-clock deadline on the whole request does, and what it costs.

Two halves, and the second is the one worth reading.

THE CONTROL. `docs/verification/2026-09-17-query-stall-deadline.md` measured a
request against a store silent in BOTH directions as not returned at a
60-second cap, on the query path and on the `pool_pre_ping` path both, at
`command_timeout=1.0`. That is a cap and not a bound: whether either request
ever returns was not determined. `services/api/asgi/request_deadline.py` is
the edge deadline that record's last section named as one of three candidates.
The tests below prove it returns the request rather than merely looking like
it does -- the distinction that matters, because the obvious implementation
(`asyncio.wait_for`) does NOT, measured in this file.

THE COST. `dev-docs/decisions/0006-audit-write-failure.md` makes auditing
fail-closed, and `services/api/middleware/audit.py` is FastMCP middleware
running INSIDE the server, so the ASGI deadline is outside it and cancelling
the request cancels whichever audit write is in flight.

This file measured the worst version of that until 2026-09-18: with the only
audit write sitting after the tool, a cancelled call whose backend had
already served the customer's accounts left ZERO rows. The audit middleware
now commits an entry row before the first backend request, so the two tests
that pair here measure what replaced it --
`test_a_deadline_during_the_entry_write_never_reaches_the_backend` (the
store is silent, so nothing is touched) and
`test_a_deadline_after_the_backend_was_reached_leaves_a_durable_entry_row`
(the touch happened and the table says so, with no outcome recorded). The
remaining cost is the unpaired row, not the missing one.

Timings are small on purpose (`DEADLINE`, `COMMAND` below) so the gate does
not spend minutes proving a wait. Every bounded assertion carries a LOWER
bound as well as an upper one, the convention
`tests/test_store_query_stall_deadline.py` set: "it answered" also passes
against an answer that arrived for the wrong reason.

Cost, measured back to back on this tree by moving this file out of `tests/`
and running the gate again. The figures are pytest's own, so they measure the
`test` STEP and not the whole of `make ci`, which also runs lint, format,
mypy, import-linter and the lock check: 34.18s without this file (837
passed), 43.72s with it (857 passed). **+9.5 seconds on that step, +28%, zero
skips.** Most of that is deliberate waiting: three requests are expired at
`DEADLINE`, and one negative test spends 20x `UNIT_DEADLINE` establishing
that `asyncio.wait_for` does not return. The lower bound each one asserts is
what makes the answer evidence rather than a stopwatch reading. It shortens
by changing `DEADLINE`, at the price of that margin.
"""

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan
from mcp.types import REQUEST_TIMEOUT
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.auth.read_minter import ReadTokenMinter
from postern_core.auth.revocation import unchecked_revocation
from postern_core.facade.client import BackendClient
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ConsentRecord
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import QueuePool
from starlette.middleware import Middleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from services.api.asgi.header_validation import HeaderBodyValidation
from services.api.asgi.request_deadline import RequestDeadline
from services.api.main import create_app
from services.api.middleware.audit import AuditMiddleware, record_data_touch
from services.api.server import build_server, token_customer_resolver
from services.api.settings import Settings
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

# The harness these tests are built on, imported rather than re-declared:
# `SilentServer` is the TCP interposer that reproduces a path silent in both
# directions, `_Calls` posts real JSON-RPC over one app with one lifespan, and
# the rest is `create_app`'s assembly with a real signed token. Rebuilding any
# of it here would be a second, divergent copy of the exact shape this file
# needs to be faithful to.
from tests.test_consent_check_failure_mode import (
    AUDIENCE,
    CUSTOMER,
    GATED_TOOL,
    ISSUER,
    RecordingBackend,
    _seed,
    _settings,
)
from tests.test_store_query_stall_deadline import (
    RECOVERY,
    SilentServer,
    _Calls,
    _finished,
)

# The deadline the integration tests configure. Far below `Settings`'
# production 101.0s so the gate stays quick; the production number is derived
# in `services/api/settings.py` and is not a measurement.
DEADLINE = 1.5

# The store command timeout those same tests configure, well below `DEADLINE`
# so the stall is already past its own deadline by the time the edge fires.
COMMAND = 0.4

# The unit tests below drive a bare ASGI app, so they need no database and no
# Postgres; a tenth of a second is enough to separate "the deadline fired"
# from "the call returned".
UNIT_DEADLINE = 0.1


@pytest.fixture(scope="session")
def key_pair() -> RSAKeyPair:
    """Declared, not imported, for the reason
    `tests/test_store_query_stall_deadline.py` gives: a fixture imported by
    name and then taken as a parameter is an F811 redefinition."""
    return RSAKeyPair.generate()


@pytest_asyncio.fixture
async def silent_server(pg_url: str) -> AsyncIterator[SilentServer]:
    server = SilentServer(pg_url)
    await server.start()
    yield server
    await server.stop()


@pytest_asyncio.fixture
async def consent_session(database: Database) -> AsyncIterator[AsyncSession]:
    """Commits for real, then deletes its own rows -- and the audit rows too.

    Same reasoning as the fixture of this name in
    `tests/test_consent_check_failure_mode.py`: `tests/conftest.py`'s
    `session` binds to one externally-managed transaction whose `commit()`
    never reaches Postgres, so a consent row seeded through it is invisible to
    the connection the consent check opens inside the running app.

    `audit_log` is cleared at BOTH ends here, which that fixture does not do
    and `tests/conftest.py::audit_server` does for the same reason: the audit
    middleware commits through its own sessionmaker, so its rows are real and
    survive any rollback. A test in this file that counts rows must not be
    able to read a neighbour's, in either direction.
    """
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
        yield s
        await s.execute(delete(ConsentRecord))
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


# --------------------------------------------------------------------------
# The ASGI layer, with no database and no Postgres.
# --------------------------------------------------------------------------


async def _drive(app: ASGIApp, receive: Receive | None = None) -> tuple[list[Message], float]:
    """One POST through `app`, returning what it sent and how long it took."""
    scope: Scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"content-type", b"application/json")],
        "server": ("test", 80),
        "client": ("test", 1234),
    }
    pending: list[Message] = [{"type": "http.request", "body": b"{}", "more_body": False}]

    async def default_receive() -> Message:
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    started = time.monotonic()
    await app(scope, receive or default_receive, send)
    return sent, time.monotonic() - started


def _status(sent: list[Message]) -> int:
    return int(next(m["status"] for m in sent if m["type"] == "http.response.start"))


def _json(sent: list[Message]) -> dict[str, Any]:
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    result: dict[str, Any] = json.loads(raw)
    return result


def _fast(status: int = 200) -> ASGIApp:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": b'{"ok":true}'})

    return app


def _hangs(cleanup_blocks: bool = False) -> ASGIApp:
    """An app that never answers, optionally with cleanup that never finishes.

    `cleanup_blocks=True` is the asyncpg shape this control exists for:
    `command_timeout` fires, SQLAlchemy invalidates the connection through
    asyncpg's graceful `close()`, and that close awaits `cancel_sent_waiter`
    with no deadline of its own. Cancelling the request task delivers one
    `CancelledError` into the body; an `await` that runs afterwards, in a
    `finally`, suspends normally and is not interrupted again. So the
    cancellation itself never completes -- which is exactly what makes
    `asyncio.wait_for` unusable here, measured in
    `test_a_deadline_that_awaited_its_own_cancellation_would_not_return`.
    """

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await asyncio.Event().wait()
        finally:
            if cleanup_blocks:
                await asyncio.Event().wait()

    return app


async def test_a_request_that_finishes_inside_the_deadline_is_untouched() -> None:
    """The status and body are what prove "untouched".

    The timing bound here is deliberately NOT the `+ 1.0` the rest of this
    file uses. That convention belongs on assertions that already carry a
    LOWER bound, where the lower bound does the discriminating and the upper
    one only has to catch a hang. This test has no lower bound, so its upper
    bound is the only timing evidence it has, and `UNIT_DEADLINE + 1.0` would
    pass just as happily against a call that waited the deadline out.
    `UNIT_DEADLINE / 2` still tolerates a machine ten times slower than this
    one, where the call measures under 0.005s.
    """
    sent, elapsed = await _drive(RequestDeadline(_fast(), seconds=UNIT_DEADLINE))
    assert _status(sent) == 200
    assert _json(sent) == {"ok": True}
    assert elapsed < UNIT_DEADLINE / 2, f"took {elapsed:.3f}s -- the deadline was waited out"


@pytest.mark.parametrize("seconds", [0.0, -1.0])
def test_a_non_positive_deadline_is_refused_at_construction(seconds: float) -> None:
    """Zero is what an operator reaching for "turn this off" writes.

    `asyncio.wait(timeout=0)` returns immediately having done nothing, so a
    zero deadline expires every request before the app runs a line: the whole
    service would answer 504 and nothing else, from a setting whose obvious
    reading is the opposite. Refused at construction, which for
    `POSTERN_REQUEST_DEADLINE_SECONDS` means at startup rather than at the
    first customer request.
    """
    with pytest.raises(ValueError, match="must be positive"):
        RequestDeadline(_fast(), seconds=seconds)


async def test_a_request_that_never_answers_gets_a_504_at_the_deadline() -> None:
    """504, not 400 and not 500.

    This server is a gateway in the literal sense RFC 9110 uses: every tool
    call it serves is a request to the operator's backend over HTTP and to
    Postgres, and the case this fires on is one of those upstreams not
    answering. 400 would blame the client for a request that was well formed;
    500 would claim a fault in this process, which is the one place the fault
    is not.
    """
    sent, elapsed = await _drive(RequestDeadline(_hangs(), seconds=UNIT_DEADLINE))
    assert elapsed >= UNIT_DEADLINE, f"answered in {elapsed:.3f}s -- nothing was stalled"
    assert elapsed < UNIT_DEADLINE + 1.0, f"took {elapsed:.3f}s -- the deadline did not end it"
    assert _status(sent) == 504
    assert _json(sent)["error"]["code"] == REQUEST_TIMEOUT


async def test_the_expiry_body_is_a_json_rpc_envelope_with_a_null_id() -> None:
    """Null, and that is the cost of being outermost.

    `HeaderBodyValidation._reject` echoes the request id because it has
    already parsed the body to compare it against the headers. This
    middleware runs OUTSIDE that one, so the body has not been drained when
    it is installed and there is no parsed id to echo. A null id is what
    JSON-RPC uses when the id could not be determined.
    """
    sent, _ = await _drive(RequestDeadline(_hangs(), seconds=UNIT_DEADLINE))
    payload = _json(sent)
    assert payload["jsonrpc"] == "2.0"
    assert payload["id"] is None


async def test_a_deadline_that_awaited_its_own_cancellation_would_not_return() -> None:
    """The measurement that chose the implementation. Measured 2026-09-18.

    `asyncio.wait_for(task, seconds)` cancels the task and then AWAITS the
    cancellation before raising `TimeoutError`. Against a task whose cleanup
    blocks -- the asyncpg shape `_hangs(cleanup_blocks=True)` reproduces -- it
    therefore does not return at all. Measured directly: `wait_for` with a
    0.5s timeout had not returned at a 6.0s cap, twelve times the deadline,
    and `async with asyncio.timeout(0.5)` had not either. A deadline
    implemented on top of either would read as a control, pass a test that
    only asserted `TimeoutError` was raised eventually, and free nothing.

    This test asserts the negative directly rather than trusting that
    reasoning, because the whole point of the control is that it does not
    merely look right. The cap is 20x the deadline, which is evidence rather
    than a stopwatch; the 6.0s figure above is the by-hand measurement.

    Scope, so nobody reads this as covering more than it does: it pins
    `asyncio.wait_for` ONLY. A rewrite of the middleware onto `asyncio.timeout`
    passes this test untouched, because this test never constructs one. The
    test that would notice is
    `test_the_deadline_returns_even_when_the_cancellation_never_completes`,
    and it carries no upper bound on the whole call while this repository
    configures no pytest timeout, so that rewrite hangs the gate instead of
    failing it.
    """
    hung = asyncio.ensure_future(_hangs(cleanup_blocks=True)(_scope(), _never, _nowhere))
    bounded = asyncio.ensure_future(asyncio.wait_for(hung, UNIT_DEADLINE))
    done, _ = await asyncio.wait({bounded}, timeout=UNIT_DEADLINE * 20)
    bounded.cancel()
    hung.cancel()
    assert bounded not in done, (
        "asyncio.wait_for returned -- the blocking-cleanup shape did not reproduce, "
        "and this file's reason for not using it no longer holds"
    )


async def test_the_deadline_returns_even_when_the_cancellation_never_completes() -> None:
    """The control, against the same shape the test above defeats.

    This is the one claim that decides whether the middleware is a control or
    decoration: the inner task's cleanup blocks forever, so the cancellation
    this middleware requests never finishes, and the middleware must return
    the worker anyway. It does, because it never awaits that cancellation.

    The task is deliberately left running afterwards, which is the shape this
    test exists to hold: a cancellation that never completes. Against the real
    store, measured in
    `test_a_silent_store_is_bounded_at_the_deadline_and_does_not_accumulate`,
    it does complete shortly after the response -- but the middleware cannot
    know which of the two it has, which is why it waits for neither.
    """
    middleware = RequestDeadline(_hangs(cleanup_blocks=True), seconds=UNIT_DEADLINE)
    sent, elapsed = await _drive(middleware)
    assert _status(sent) == 504
    assert elapsed < UNIT_DEADLINE + 1.0, f"took {elapsed:.3f}s -- the cancellation was awaited"
    assert [task.done() for task in middleware.orphans] == [False], (
        "the orphan must still be running -- if it finished, this shape did not reproduce"
    )


async def test_a_response_already_begun_keeps_its_status_and_is_terminated() -> None:
    """Once `http.response.start` is on the wire the status cannot be changed.

    ASGI has no way to retract it, so the deadline cannot answer 504 here. It
    ends the response body instead: the client gets the status the inner app
    chose and a truncated body, which is the only honest thing available. The
    status is asserted to still be 200 precisely because a middleware that
    tried to send a second `http.response.start` would raise inside the
    server rather than produce one.
    """

    async def begins_then_hangs(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b'{"partial":', "more_body": True})
        await asyncio.Event().wait()

    sent, elapsed = await _drive(RequestDeadline(begins_then_hangs, seconds=UNIT_DEADLINE))
    assert _status(sent) == 200
    assert elapsed >= UNIT_DEADLINE
    assert [m["type"] for m in sent] == [
        "http.response.start",
        "http.response.body",
        "http.response.body",
    ]
    assert sent[-1] == {"type": "http.response.body", "body": b"", "more_body": False}


class _ParkingServer:
    """uvicorn's `send()`, reduced to the three lines that decide this case.

    `uvicorn/protocols/http/httptools_impl.py::send` (0.52.4, the version in
    this lockfile) is:

        async def send(self, message):
            if self.flow.write_paused and not self.disconnected:
                await self.flow.drain()
            if self.disconnected:
                return
            if not self.response_started:
                if message["type"] != "http.response.start":
                    raise RuntimeError(
                        f"Expected ASGI message 'http.response.start', "
                        f"but got '{message['type']}'."
                    )
                self.response_started = True

    The two facts that matter: the drain is a real suspension point, and
    `response_started` is set only AFTER it. So a send cancelled while parked
    in the drain leaves the server having seen nothing, and the next message
    it does process must still be a start. Reached in production by a large
    tool response to a client that has stopped reading, once the transport
    passes its 64KB high-water mark.

    Only the FIRST send parks here, so that a middleware which wrongly follows
    up with a body gets the RuntimeError promptly instead of parking too and
    hanging the gate. Everything a correct middleware does on this path is
    nothing, so the distinction costs it nothing.
    """

    def __init__(self) -> None:
        self.attempted: list[str] = []
        self.processed: list[str] = []
        self.response_started = False
        self._parked = False

    async def send(self, message: Message) -> None:
        self.attempted.append(str(message["type"]))
        if not self._parked:
            self._parked = True
            await asyncio.Event().wait()
        if not self.response_started:
            if message["type"] != "http.response.start":
                raise RuntimeError(
                    f"Expected ASGI message 'http.response.start', but got '{message['type']}'."
                )
            self.response_started = True
        self.processed.append(str(message["type"]))


async def test_a_start_the_server_never_took_is_not_followed_by_a_body() -> None:
    """The bug the first version of this middleware shipped with.

    `_Response.started` was set BEFORE `await send(message)`, so a start still
    suspended inside the server counted as delivered, and `_expire` followed
    it with an `http.response.body`. Against the real uvicorn contract that is
    `RuntimeError: Expected ASGI message 'http.response.start', but got
    'http.response.body'` raised inside the server: the client gets a 500 and
    a logged traceback instead of the truncated body this middleware promises.

    The fix is the `in_flight` state on `_Response`. While a hand-off is
    suspended, the server may or may not have taken it, the two cases want
    opposite actions, and the only action correct under both is neither. So
    the assertion here is that NOTHING follows the parked start.

    Moving the recording after the await, without `in_flight`, fails this test
    the other way round: the start would read as never sent and `_expire`
    would offer a second `http.response.start`.
    """
    server = _ParkingServer()

    async def starts_then_hangs(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await asyncio.Event().wait()

    async def receive() -> Message:
        return {"type": "http.request", "body": b"{}", "more_body": False}

    app = RequestDeadline(starts_then_hangs, seconds=UNIT_DEADLINE)
    await app(_scope(), receive, server.send)

    assert server.attempted == ["http.response.start"], (
        "the middleware sent something after a start the server had not taken"
    )
    assert server.processed == [], "the parked send must never have completed"


async def test_a_completed_response_is_never_terminated_a_second_time() -> None:
    """A finished response plus a task that has not returned yet.

    The body is already complete, so there is nothing to terminate and
    anything sent now is a protocol violation the server would reject. The
    middleware must send nothing at all on this branch.
    """

    async def answers_then_hangs(scope: Scope, receive: Receive, send: Send) -> None:
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b'{"ok":true}'})
        await asyncio.Event().wait()

    sent, _ = await _drive(RequestDeadline(answers_then_hangs, seconds=UNIT_DEADLINE))
    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"]
    assert _json(sent) == {"ok": True}


async def test_a_send_from_the_orphan_after_expiry_is_dropped() -> None:
    """The orphan outlives the response, and may still try to answer.

    Handing that message to the server would raise `Unexpected ASGI message
    'http.response.start' sent, after response already completed` inside
    uvicorn -- an error attributed to this request, on a connection that has
    already moved on. It is dropped instead.

    The app has to answer from a `finally`, and that is the whole difficulty.
    An earlier version of this test waited on an event and sent afterwards,
    which never reached the guard at all: `task.cancel()` cancelled the wait,
    so the sends were never attempted and the test passed with the guard
    deleted. Proven by mutation, which is also how the replacement below was
    checked. A `finally` reached by that same cancellation is a real
    post-expiry send, because asyncio delivers one `CancelledError` and an
    `await` that runs after it suspends normally.
    """

    async def answers_while_unwinding(scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await asyncio.Event().wait()
        finally:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b'{"late":true}'})

    sent, _ = await _drive(RequestDeadline(answers_while_unwinding, seconds=UNIT_DEADLINE))
    assert _status(sent) == 504
    # The orphan's `finally` runs after this call returned, so the drop can
    # only be observed once it has had the loop.
    await asyncio.sleep(0.05)
    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"], (
        "the orphan's own response reached the client after the 504"
    )
    assert _status(sent) == 504
    assert _json(sent)["error"]["code"] == REQUEST_TIMEOUT


async def test_a_cancelled_request_takes_the_inner_app_down_with_it() -> None:
    """A leak this control would otherwise have introduced by itself.

    Running the app in a child task means a cancellation delivered to the
    middleware's own call no longer reaches the app: a child does not inherit
    its parent's cancellation, so without the `except BaseException` branch
    the app would be left running with nothing able to cancel it. That is a
    leak caused by the control rather than by the silent path it exists for,
    which makes it worse than the problem.

    NOT a client disconnect, which is what an earlier version of this
    docstring claimed and what this test was mistakenly said to verify. It
    cancels the outer task by hand and goes nowhere near uvicorn. uvicorn does
    not cancel the ASGI task on disconnect at all: it sets
    `cycle.disconnected = True` and wakes a pending `receive()` with
    `http.disconnect` (`uvicorn/protocols/http/httptools_impl.py`'s
    `connection_lost`), and the only `cancel()` in any of its three HTTP
    protocol implementations in 0.52.4 is `timeout_keep_alive_task.cancel()`.
    The real sources are the graceful-shutdown timeout, which cancels every
    in-flight request task (`uvicorn/server.py`'s `shutdown`), and any
    enclosing cancellation scope. What this test verifies is the branch,
    which is what it was always doing.
    """
    middleware = RequestDeadline(_hangs(), seconds=100.0)
    outer = asyncio.ensure_future(_drive(middleware))
    await asyncio.sleep(0.05)
    inner = next(iter(middleware.orphans))

    outer.cancel()
    with pytest.raises(asyncio.CancelledError):
        await outer

    await asyncio.wait({inner}, timeout=1.0)
    assert inner.cancelled(), "a client disconnect must not leave the inner app running"


async def test_an_exception_from_the_inner_app_still_propagates() -> None:
    """Starlette's `ServerErrorMiddleware` sits outside every user middleware
    and is what turns an unhandled exception into a 500. Swallowing one here
    would replace that 500 with a hang until the deadline."""

    async def boom(scope: Scope, receive: Receive, send: Send) -> None:
        raise RuntimeError("inner")

    with pytest.raises(RuntimeError, match="inner"):
        await _drive(RequestDeadline(boom, seconds=UNIT_DEADLINE))


async def test_non_http_scopes_are_passed_straight_through() -> None:
    """The lifespan scope runs startup and shutdown and is not a request.

    Wrapping it would put an 88-second deadline on `create_app`'s own lifespan
    -- FastMCP's session manager, `backend.aclose()`, `db.close()` -- and
    would cancel a shutdown that took longer, which is not what this bounds.
    """
    seen: list[str] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(str(scope["type"]))

    await RequestDeadline(app, seconds=UNIT_DEADLINE)({"type": "lifespan"}, _never, _nowhere)
    assert seen == ["lifespan"]


async def test_the_deadline_covers_a_body_that_never_arrives() -> None:
    """Why this middleware is installed OUTSIDE `HeaderBodyValidation`.

    That middleware's `_drain` awaits `receive()` in a loop with no deadline
    of its own, buffering up to `max_body_bytes`. A client that opens a POST
    and then sends its body one byte at a time -- or never -- parks a worker
    there, before any deadline in this repository applies: the store timeouts
    bound Postgres, the httpx2 timeouts bound the backend, and neither is
    reached yet. Installed outermost, this deadline is the only thing that
    bounds it, which is measured here through the real `HeaderBodyValidation`
    rather than a stand-in.
    """
    stalled_body = asyncio.Event()
    seen: list[bytes] = []

    async def never_finishes_the_body() -> Message:
        await stalled_body.wait()
        return {"type": "http.disconnect"}

    async def downstream(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(b"reached")
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    app = RequestDeadline(
        HeaderBodyValidation(downstream, max_body_bytes=1024), seconds=UNIT_DEADLINE
    )
    sent, elapsed = await _drive(app, receive=never_finishes_the_body)
    stalled_body.set()
    assert _status(sent) == 504
    assert elapsed >= UNIT_DEADLINE
    assert seen == [], "the request never had a complete body; nothing downstream may have run"


def _scope() -> Scope:
    return {"type": "http", "method": "POST", "path": "/mcp", "headers": []}


async def _never() -> Message:
    await asyncio.Event().wait()
    return {"type": "http.disconnect"}


async def _nowhere(message: Message) -> None:
    return None


# --------------------------------------------------------------------------
# Composition: the value and the position the production app actually gets.
# --------------------------------------------------------------------------


def test_settings_carries_the_derived_default_and_reads_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """101.0 is not a preference and not a round number: it is the sum
    `services/api/settings.py` derives from the per-phase budgets already in
    this repository. A test pinning the literal is what makes a later change
    to it deliberate.

    Both routes to the value are pinned, and the second is the one that
    matters: production reads `from_env`, which carries its own `"101.0"`
    string literal in an `os.environ.get` default. Pinning only the dataclass
    field would let those two drift, with the gate green and every deployment
    on the stale number. Same shape as
    `tests/test_store_timeouts.py::test_default_store_timeouts_sum_to_the_
    stated_six_second_worst_case`, which pins the store budgets through
    `from_env` with the variables explicitly unset.
    """
    assert Settings.for_testing().request_deadline_seconds == 101.0

    monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
    monkeypatch.delenv("POSTERN_REQUEST_DEADLINE_SECONDS", raising=False)
    assert Settings.from_env().request_deadline_seconds == 101.0

    monkeypatch.setenv("POSTERN_REQUEST_DEADLINE_SECONDS", "12.5")
    assert Settings.from_env().request_deadline_seconds == 12.5


def test_create_app_installs_the_deadline_outside_header_validation() -> None:
    """Order, asserted on the real app rather than on the call site.

    Starlette wraps `user_middleware` in reverse, so the FIRST entry of the
    `middleware=[...]` list is the OUTERMOST
    (`starlette/applications.py::build_middleware_stack`). The deadline must
    be that entry: outermost is what makes it cover
    `HeaderBodyValidation._drain`, which is otherwise unbounded (see
    `test_the_deadline_covers_a_body_that_never_arrives`).
    """
    app = create_app(Settings.for_testing())
    # Keyed by name, not by the class object: `Middleware.cls` is typed as the
    # `_MiddlewareFactory` protocol, so mypy rejects both `__name__` on it and
    # an identity check against a concrete class. The identity check is made
    # separately below, through a name mypy will let it compare.
    names = [getattr(m.cls, "__name__", "") for m in app.user_middleware]
    positions = {name: index for index, name in enumerate(names)}
    assert positions["RequestDeadline"] < positions["HeaderBodyValidation"], (
        f"the deadline must be the outer of the two, got {names}"
    )
    deadline = app.user_middleware[positions["RequestDeadline"]]
    installed: object = deadline.cls
    assert installed is RequestDeadline, "a different class is registered under that name"
    assert deadline.kwargs["seconds"] == Settings.for_testing().request_deadline_seconds


# --------------------------------------------------------------------------
# Against a real Postgres, a real token, and a path that goes silent.
# --------------------------------------------------------------------------


def _deadline_app(
    consent_db: Database,
    audit_db: Database,
    key_pair: RSAKeyPair,
    backend_handler: Callable[[httpx2.Request], httpx2.Response],
    settings: Settings,
    seconds: float,
) -> StarletteWithLifespan:
    """`create_app`'s assembly plus the middleware under test.

    Mirrors `tests/test_consent_check_failure_mode.py::_app` -- same
    `build_server`, same `AuditMiddleware`, same `http_app` and
    `HeaderBodyValidation` -- with consent and audit on separate databases so
    a stall can be attributed to one of them, and with `RequestDeadline` first
    in the middleware list exactly as `create_app` installs it.

    `create_app` itself is deliberately not called: it wires
    `_close_resources_after_fastmcp_shutdown`, so leaving the lifespan closes
    the backend client and calls `db.close()` -- and `engine.dispose()`
    against a path that is silent in both directions is itself an unbounded
    wait, which would hang teardown for the exact reason these tests exist.
    `test_create_app_installs_the_deadline_outside_header_validation` covers
    the real composition root separately, where no store is involved.
    """
    backend = BackendClient(
        settings.backend_base_url,
        ReadTokenMinter(
            InternalTokenMinter(
                issuer=settings.read_token_issuer,
                key_source=GeneratedKeySource(kid=settings.read_key_kid),
            ),
            # This file measures deadlines, not ZT-7, and builds its own
            # server rather than `create_app`'s, so no `RevocationMiddleware`
            # publishes a decision for the minter's default provider to read.
            revocation_decision=unchecked_revocation,
        ),
        transport=httpx2.MockTransport(backend_handler),
        # Wired exactly as `create_app` wires it
        # (`test_create_app_wires_the_entry_write_into_the_backend_client`
        # pins that). Without it this app reaches the backend with no entry
        # row, and the two tests below would measure an assembly production
        # does not run.
        before_backend_request=record_data_touch,
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    server = build_server(
        settings, token_customer_resolver, backend, db=consent_db, auth_override=verifier
    )
    server.add_middleware(AuditMiddleware(audit_db))
    return server.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        middleware=[
            Middleware(RequestDeadline, seconds=seconds),
            Middleware(
                HeaderBodyValidation,
                strict=settings.strict_headers,
                max_body_bytes=settings.max_body_bytes,
            ),
        ],
    )


def _token(key_pair: RSAKeyPair) -> str:
    return key_pair.create_token(subject=CUSTOMER, issuer=ISSUER, audience=AUDIENCE)


async def _rows(database: Database) -> list[AuditEntry]:
    async with database.sessionmaker() as s:
        result = await s.execute(select(AuditEntry).order_by(AuditEntry.id))
        return list(result.scalars().all())


def _deadline_middleware(app: StarletteWithLifespan) -> RequestDeadline:
    """The live `RequestDeadline` instance inside a built middleware stack.

    Starlette constructs user middleware itself, so nothing at the call site
    holds a reference to the instance. The stack is a chain of wrappers each
    holding the next as `.app`, so walking it is how a test reads the orphan
    set the middleware deliberately exposes. `middleware_stack` is built on
    the app's first call, so this only works after a request has run.
    """
    node: object = app.middleware_stack
    while node is not None and not isinstance(node, RequestDeadline):
        node = getattr(node, "app", None)
    assert isinstance(node, RequestDeadline), "the deadline middleware is not in the stack"
    return node


async def test_a_silent_store_is_bounded_at_the_deadline_and_does_not_accumulate(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    silent_server: SilentServer,
) -> None:
    """The residual case from `docs/verification/2026-09-17-query-stall-deadline.md`,
    and four things measured about it on 2026-09-18.

    The reproduction is the one that record used and that
    `tests/test_store_query_stall_deadline.py::test_a_silent_path_still_hangs_
    the_request_past_every_deadline` pins: the consent SELECT is forwarded
    upstream and its answer is held, `command_timeout` fires on time, and the
    invalidation that follows hits asyncpg's undeadlined close. There, the
    request had not returned at a 60-second cap. Here:

    1. IT RETURNS, at the deadline, with a status and a body.
    2. THE ORPHAN FINISHES ON ITS OWN, after the response. The middleware does
       not wait for it, which is what makes (1) true at all; against this
       particular shape the cancellation does eventually complete. Against a
       shape whose cleanup blocks it does not, which is the unit test
       `test_the_deadline_returns_even_when_the_cancellation_never_completes`
       and is why the implementation may never await it.
    3. THE POOL CHECKOUT COMES BACK. `checkedout() == 0` once the orphan has
       finished. This contradicts the reasoning written before it was
       measured -- the expectation was that the orphan would hold its checkout
       and that enough of these would exhaust the pool -- so that cost is not
       claimed anywhere. What is NOT established is the ordering: this test
       waits for the orphan before reading the pool, so it cannot say whether
       the checkout came back before the response or only as the orphan
       unwound, and it passes either way. Nor is `checkedin()` asserted, so
       "back in the pool" as opposed to "discarded" is not pinned either.
    4. A SECOND REQUEST, WITH THE PATH STILL SILENT, IS ALSO BOUNDED. This is
       the blast-radius claim: expired requests do not pile up, and the pool
       is at zero again afterwards.

    Each expired request does leave one more inbound connection at the store,
    and that IS asserted here rather than merely noted: 2 after the first
    request, 3 after the second, which is asyncpg's out-of-band cancel
    connection opening into the same silence. Whether those sockets are ever
    closed was not determined.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    silent_server.trigger = b"consents"
    stalled = Database(silent_server.url(pg_url), command_timeout_seconds=COMMAND)
    backend = RecordingBackend()
    try:
        app = _deadline_app(stalled, database, key_pair, backend, _settings(pg_url), DEADLINE)
        async with _Calls(app, _token(key_pair)) as calls:
            started = time.monotonic()
            response = await _finished(calls.start(), DEADLINE + RECOVERY)
            waited = time.monotonic() - started

            assert waited >= DEADLINE, f"answered in {waited:.2f}s -- the stall did not reproduce"
            assert waited < DEADLINE + 3.0, f"took {waited:.2f}s -- the deadline did not end it"
            assert response.status_code == 504
            assert json.loads(response.text)["error"]["code"] == REQUEST_TIMEOUT
            assert backend.paths == [], "no customer data may move while consent is unanswered"
            assert silent_server.connections == 2, (
                "one pooled connection plus asyncpg's out-of-band cancel connection, "
                f"got {silent_server.connections}"
            )

            # Bounded, so a cancellation that never completes fails this test
            # loudly instead of hanging the gate. An already-empty set is the
            # same finding arriving sooner: the callback discards a task when
            # it finishes.
            orphans = set(_deadline_middleware(app).orphans)
            if orphans:
                await asyncio.wait(orphans, timeout=RECOVERY)
            assert all(task.done() for task in orphans), (
                "the orphaned request task never finished -- the connection it holds is leaked"
            )

            pool = stalled.engine.pool
            assert isinstance(pool, QueuePool)
            assert pool.checkedout() == 0, (
                f"the pool did not get its checkout back: {pool.status()}"
            )

            second_started = time.monotonic()
            second = await _finished(calls.start(), DEADLINE + RECOVERY)
            second_waited = time.monotonic() - second_started

            assert second.status_code == 504, "a second call against the same silence must answer"
            assert second_waited >= DEADLINE, f"answered in {second_waited:.2f}s -- not stalled"
            assert second_waited < DEADLINE + 3.0, f"took {second_waited:.2f}s -- it accumulated"
            assert pool.checkedout() == 0, f"the pool accumulated a checkout: {pool.status()}"
            assert silent_server.connections == 3, (
                "each expired request leaves one more cancel connection in the silence, "
                f"got {silent_server.connections}"
            )

            silent_server.resume()
    finally:
        await asyncio.wait_for(stalled.close(), RECOVERY)


async def test_a_deadline_during_the_entry_write_never_reaches_the_backend(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    silent_server: SilentServer,
) -> None:
    """The audit store is silent, so no customer data moves at all.

    This test measured the opposite outcome until 2026-09-18, and the old
    result is worth keeping in view: with the only audit write sitting AFTER
    `call_next`, consent answered, the tool ran, the operator's backend
    served `/accounts`, the deadline then cancelled the write, and
    `audit_log` held zero rows -- a call that happened against a real
    customer's data with no trace in it. `services/api/middleware/audit.py`
    now commits an entry row BEFORE the first backend request, and that write
    fails closed like every other one, so the same silence stops the call
    instead of following it.

    `b"audit_log"` still selects the first audit statement on the connection,
    which is now the entry INSERT's own `Parse`. What changed is what that
    costs: `backend.paths` is EMPTY, where the same line used to read
    `["/accounts"]`.

    Zero rows, and here that is the truthful table rather than a gap in it:
    nothing was touched, so there is nothing to record. The rows that could
    not be written are the entry row (cancelled mid-write, one `AuditEntry`
    in one uncommitted transaction) and the completion row (the tool's own
    failure, whose write goes to the same silence).
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    silent_server.trigger = b"audit_log"
    stalled_audit = Database(silent_server.url(pg_url), command_timeout_seconds=COMMAND)
    backend = RecordingBackend()
    try:
        app = _deadline_app(database, stalled_audit, key_pair, backend, _settings(pg_url), DEADLINE)
        async with _Calls(app, _token(key_pair)) as calls:
            started = time.monotonic()
            response = await _finished(calls.start(), DEADLINE + RECOVERY)
            waited = time.monotonic() - started

            assert waited >= DEADLINE, f"answered in {waited:.2f}s -- the stall did not reproduce"
            assert response.status_code == 504
            assert backend.paths == [], (
                "the entry write must fail closed BEFORE any customer data is reached"
            )
            assert await _rows(database) == [], (
                "an audit row survived the cancellation -- re-read the middleware docstring"
            )

            silent_server.resume()
    finally:
        await asyncio.wait_for(stalled_audit.close(), RECOVERY)


async def test_a_deadline_after_the_backend_was_reached_leaves_a_durable_entry_row(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    silent_server: SilentServer,
) -> None:
    """The shape this whole change exists for: the operator touched customer
    data, the request was then cancelled, and the table still says so.

    The silence is moved off the entry write and onto the COMPLETION write,
    which is the only remaining arrangement in which the old bug's
    precondition survives: consent answers, the entry row commits, the tool
    runs, `/accounts` is served, and the request then hangs in the write that
    would have recorded the outcome. The deadline cancels that write exactly
    as it did before -- nothing here makes a cancelled write survive.

    Selecting WHICH write goes silent is done with a parameter value rather
    than with statement text, because both writes run the same INSERT:
    `b"returned"` is carried in the completion row's own `Bind` and appears
    in no earlier packet on this connection (the entry row binds
    `b"reaching"`, and the INSERT text names no outcome at all). If that ever
    stopped holding, this test fails at the row assertion below rather than
    passing for the wrong reason.

    One row, `outcome='reaching'`, committed in its own transaction before
    the first backend request and therefore not the cancelled one. What the
    table then says is exactly true and no more: this call reached for this
    customer's data under this tool name, and no outcome was ever recorded
    for it. `duration_ms` is NULL on that row because no tool duration
    exists for it, and `call_id` is the key a reader pairs it on -- here
    finding nothing, which IS the finding.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    silent_server.trigger = b"returned"
    stalled_audit = Database(silent_server.url(pg_url), command_timeout_seconds=COMMAND)
    backend = RecordingBackend()
    try:
        app = _deadline_app(database, stalled_audit, key_pair, backend, _settings(pg_url), DEADLINE)
        async with _Calls(app, _token(key_pair)) as calls:
            started = time.monotonic()
            response = await _finished(calls.start(), DEADLINE + RECOVERY)
            waited = time.monotonic() - started

            assert waited >= DEADLINE, f"answered in {waited:.2f}s -- the stall did not reproduce"
            assert response.status_code == 504
            assert backend.paths == ["/accounts"], (
                "the tool body must have run: this test is about a call that HAPPENED"
            )

            rows = await _rows(database)
            assert [(row.tool_name, row.outcome) for row in rows] == [(GATED_TOOL, "reaching")], (
                "the entry row did not survive the cancellation that took the completion row"
            )
            assert rows[0].call_id is not None, "an entry row with nothing to pair it on"
            assert rows[0].duration_ms is None, "an entry row cannot carry a tool duration"
            assert rows[0].refusal_reason is None, "the entry row is written after consent allowed"

            silent_server.resume()
    finally:
        await asyncio.wait_for(stalled_audit.close(), RECOVERY)


async def test_control_the_same_call_against_a_healthy_store_is_audited(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
) -> None:
    """The control for the two tests above, and the proof the deadline is
    inert on a working request: the same app, the same deadline, a store that
    answers -- two rows, one backend call, HTTP 200.

    Two rows and not one since 2026-09-18, in the order they were written:
    `reaching`, committed before `/accounts` was requested, and `returned`
    after the tool answered. They carry the same `call_id`, which is what a
    reader pairs them on, and it is not NULL -- an unpaired `reaching` row is
    the finding in the test above, so this control has to establish that a
    healthy call does NOT leave one."""
    await _seed(consent_session, CUSTOMER, "accounts")
    backend = RecordingBackend()
    app = _deadline_app(database, database, key_pair, backend, _settings(pg_url), DEADLINE)
    async with _Calls(app, _token(key_pair)) as calls:
        started = time.monotonic()
        response = await _finished(calls.start(), DEADLINE + RECOVERY)
        waited = time.monotonic() - started

    assert waited < DEADLINE, f"took {waited:.2f}s -- a healthy call must not near the deadline"
    assert response.status_code == 200
    assert json.loads(response.text)["result"]["isError"] is False
    assert backend.paths == ["/accounts"]
    rows = await _rows(database)
    assert [row.tool_name for row in rows] == [GATED_TOOL, GATED_TOOL]
    assert [row.outcome for row in rows] == ["reaching", "returned"]
    assert rows[0].call_id is not None and rows[0].call_id == rows[1].call_id, (
        "the two rows of one call must be joinable"
    )

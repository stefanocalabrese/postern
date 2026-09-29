"""A wall-clock deadline on the whole HTTP request (ASGI, outermost).

WHY THIS EXISTS. Every other deadline in this service is a deadline on a
socket that eventually says something. `services/api/settings.py` splits the
backend HTTP budget by phase, and
`packages/postern-core/src/postern_core/store/engine.py` puts asyncpg's
`timeout`, `command_timeout` and SQLAlchemy's `pool_timeout` on every database
operation. All of them bound a store or a backend that answers, resets or
refuses. None bounds a path that goes SILENT IN BOTH DIRECTIONS, because there
is no event for them to fire on: `command_timeout` does expire on schedule,
but SQLAlchemy then invalidates the connection through asyncpg's graceful
`close()`, whose first act is `await self.cancel_sent_waiter` with no deadline
on that await (`asyncpg/protocol/protocol.pyx:602-613`), and that waiter is
resolved only by a SECOND connection opened to the same silent address
(`asyncpg/connect_utils.py::_cancel`).

`docs/verification/2026-09-17-query-stall-deadline.md` measured that end to
end through a real HTTP request with `command_timeout=1.0`, on the query path
and on the `pool_pre_ping` path both: neither had returned within the
60-second cap the measurement used. That is a cap and not a bound -- whether
either request ever returns was not determined. In a real deployment something
upstream (Istio, an ingress, the client giving up) would cut it off; none of
that is configured in this repository and this repository does not know those
values. This middleware is the server bounding its own request regardless of
what the edge does, which is the third of the three candidates that record's
last section listed, chosen on 2026-09-18.

WHAT IT ACTUALLY FREES, measured 2026-09-18 against the silent-path
reproduction in
`tests/test_request_deadline.py::test_a_silent_store_is_bounded_at_the_
deadline_and_does_not_accumulate`, and recorded here because the reasoning
written before the measurement was wrong in the optimistic direction's
favour: the expectation was that the orphan would keep its pool checkout and
that enough of these would exhaust the pool. It does not. The request returns
at the deadline with a status; the orphaned task then finishes on its own,
after the response; once it has, `QueuePool.checkedout()` reads 0; and a
second request against the same silence is bounded identically and leaves the
pool at zero again. So against THIS shape the cancellation does eventually
complete, and expired requests do not pile up.

The ORDER of those last two is not pinned and is not claimed here. The test
waits for the orphan before reading the pool, so it cannot tell whether the
checkout came back before the response or after the orphan unwound; the
by-hand probe that suggested the former is not in the gate. What is pinned is
the state after the orphan completes, which is what decides blast radius.

That is a property of this shape, not of the mechanism: against a task whose
cleanup blocks, the cancellation never completes and the orphan runs for as
long as the block lasts (`test_the_deadline_returns_even_when_the_
cancellation_never_completes`). The middleware is correct either way
precisely because it never waits to find out which one it has.

Each expired request leaves one additional inbound connection at the store:
the interposer counted 2 after the first and 3 after the second, which is
asyncpg's out-of-band cancel connection opening into the same silence. That
count is asserted, not merely observed. Whether those sockets are ever closed
was not determined.

WHAT IT DOES NOT DO, stated plainly because this part reads as safe and is
not:

  - **It still cancels an audit write, and can leave a call with no
    OUTCOME recorded.** `dev-docs/decisions/0006-audit-write-failure.md` makes
    auditing fail-closed, and `services/api/middleware/audit.py` is FastMCP
    middleware running INSIDE the server, so this middleware is outside it
    and cancelling the request cancels whichever audit write is in flight --
    one `AuditEntry` in one transaction that is never committed, not a
    partial row.

    What that costs changed on 2026-09-18, and this bullet was rewritten with
    it. Before, the only audit write happened AFTER the tool: the backend was
    reached, the cancellation took the write, and `audit_log` held ZERO rows
    for a call that had already served real customer data. That is no longer
    what happens, because the audit middleware now commits an entry row
    (`outcome='reaching'`) before the first backend request and fails the
    call closed if it cannot. Measured in
    `tests/test_request_deadline.py`: with the audit store silent, the entry
    write is what stalls and `/accounts` is never requested
    (`test_a_deadline_during_the_entry_write_never_reaches_the_backend`);
    with the store silent only for the completion write, the backend IS
    reached and the entry row survives the cancellation
    (`test_a_deadline_after_the_backend_was_reached_leaves_a_durable_entry_
    row`).

    The residual is a real one and is smaller: a cancelled call can leave a
    `reaching` row with no partner, so the table says the operator touched
    this customer's data and no outcome was ever recorded. That is a true
    statement about a call that happened rather than silence about one.

  - **It does not make the service responsive.** See the deadline value in
    `services/api/settings.py`: 105.0 seconds is longer than any consumer AI
    client will wait. This control exists to return the WORKER, not to give
    the caller a timely answer.

WHY NOT `asyncio.wait_for` / `asyncio.timeout`. Both cancel the inner task and
then AWAIT the cancellation before raising `TimeoutError`. The shape this
middleware exists for is precisely one whose cleanup blocks: asyncio delivers
one `CancelledError` into the running coroutine, and an `await` that runs
afterwards in a `finally` suspends normally rather than being interrupted
again, so the cancellation never completes and the caller never gets control
back. Measured 2026-09-18: against a coroutine whose `finally` awaits an event
that is never set, `asyncio.wait_for(task, 0.5)` had not returned at a
6.0-second cap, twelve times its own timeout, and `async with
asyncio.timeout(0.5)` had not either. Both would have passed a test that only
asserted `TimeoutError` eventually; both free nothing.

Only the `wait_for` half of that is pinned, by
`tests/test_request_deadline.py::test_a_deadline_that_awaited_its_own_
cancellation_would_not_return`. A rewrite onto `asyncio.timeout` passes that
test untouched, because it never constructs one; what would catch it is
`test_the_deadline_returns_even_when_the_cancellation_never_completes`, and
that test carries no upper bound on the whole call and this repository
configures no pytest timeout. So that particular rewrite HANGS the gate
rather than failing it. Loud either way, but a hang is a worse signal than a
red test, and anyone shortening this module should know which of the two they
are relying on.

So this waits with `asyncio.wait`, requests cancellation, and never awaits
that cancellation. It is not free of awaits: `_expire`'s own sends can park
in the server's flow control for as long as the peer takes, so "returns at
the deadline" is a claim about not waiting on the INNER TASK, not a bound on
this function. Nothing here bounds a server that will not take a 200-byte
error body. The deliberate consequence of not awaiting is an orphaned task
that outlives the response -- by a fraction of a second against the measured
store shape, for as long as the block lasts against one that does not unwind.
That is the trade, and it is the right way round: the alternative to leaking a
task is leaking a worker.

Cancellation delivered to THIS call still has to reach the child, which is
what the `except BaseException` in `__call__` is for; its comment records
which cancellations are real and which one an earlier version of it wrongly
claimed.

WHY OUTERMOST. `services/api/main.py` installs this as the first entry of
`http_app(middleware=[...])`, which Starlette wraps in reverse, so the first
entry is the outermost (`starlette/applications.py::build_middleware_stack`).
That puts it outside `HeaderBodyValidation`, whose `_drain` awaits `receive()`
in a loop with no deadline of its own while it buffers up to `max_body_bytes`:
a client that opens a POST and sends its body one byte at a time parks a
worker there, before any store or backend timeout is reachable. Outermost is
the only position that bounds that too
(`tests/test_request_deadline.py::test_the_deadline_covers_a_body_that_never_
arrives`). The cost of the position is that the request body has not been
parsed yet, so there is no JSON-RPC `id` to echo in the error envelope and it
carries `null` -- which is what JSON-RPC uses when the id could not be
determined.
"""

import asyncio
import json
from dataclasses import dataclass

from mcp.types import REQUEST_TIMEOUT
from starlette.types import ASGIApp, Message, Receive, Scope, Send


@dataclass
class _Response:
    """What the server has actually TAKEN from the inner app, and whether a
    hand-off is still in flight.

    Three states, not two, and the third one is where the first version of
    this was wrong. `started` used to be set BEFORE `await send(message)`, on
    the reasoning that over-approximating was safe in one direction. It is
    not, because a send can be cancelled while suspended INSIDE the server:
    `uvicorn/protocols/http/httptools_impl.py::send` (0.52.4) opens with
    `if self.flow.write_paused and not self.disconnected: await
    self.flow.drain()` and sets its own `response_started` only after that
    await returns. Cancel the request while that drain is parked -- a large
    tool response to a client that has stopped reading, past the 64KB
    high-water mark, is enough -- and the server never saw the start while
    this middleware believed it had, so `_expire` would follow it with an
    `http.response.body` and the server would raise `RuntimeError: Expected
    ASGI message 'http.response.start', but got 'http.response.body'`. The
    client gets a 500 and a logged traceback in place of the truncated body
    this middleware promises.

    Moving the recording after the await alone does not fix it, it moves the
    failure: the start would then be unrecorded even when the server DID take
    it, and `_expire` would send a second `http.response.start`. Neither
    answer is safe while a send is suspended, because from out here the two
    cases are indistinguishable. So `in_flight` names that third state and
    `_expire` sends nothing in it, which is the only action that is correct
    under both readings.

    WHICH HALF CARRIES THE GUARANTEE: `in_flight`, on its own. The post-await
    recording of `started` and `complete` is defence in depth, and NOTHING IN
    THE SUITE PINS IT -- measured 2026-09-18 by mutation, moving the recording
    back before the await while keeping `in_flight` passes all 20 tests in
    `tests/test_request_deadline.py`. That is expected rather than a gap in
    the tests: `_expire` consults `started` only on the branch where
    `in_flight` is already zero, and with no send suspended the two orderings
    cannot disagree. Stated here so a later reader does not delete
    `in_flight` believing the recording order covers them: deleting the gate
    in `_expire` fails exactly one test
    (`test_a_start_the_server_never_took_is_not_followed_by_a_body`, measured
    the same way), and deleting the ordering fails none. The ordering is kept
    anyway, because `started` and `complete` meaning "the server took this"
    rather than "we offered it" is what makes the branch logic in `_expire`
    readable at all.
    """

    in_flight: int = 0
    started: bool = False
    complete: bool = False
    expired: bool = False


class RequestDeadline:
    def __init__(self, app: ASGIApp, *, seconds: float) -> None:
        """`seconds` is a wall-clock bound on the whole request, from the
        moment this middleware is entered to the moment the inner app returns.

        `services/api/settings.py::Settings.request_deadline_seconds` derives
        the production value from the per-phase budgets already configured in
        this repository and explains why it is as large as it is. Nothing here
        picks a number; a caller that passes one small enough to cut a
        legitimate request will cut legitimate requests.

        Zero and negative are REFUSED, at construction, because the obvious
        reading of them is the opposite of what they would do. An operator
        reaching for "turn this off" writes
        `POSTERN_REQUEST_DEADLINE_SECONDS=0`, and `asyncio.wait(timeout=0)`
        returns immediately with nothing done: every request would expire
        before the app ran a single line, so the whole service would answer
        504 and nothing else. Failing at startup with a `ValueError` naming
        the value is the same shape `POSTERN_BACKEND_BASE_URL` already has --
        loud, at boot, rather than at the first customer request. There is
        deliberately no off switch: this middleware is installed
        unconditionally, and a deployment that wants a looser bound raises the
        number rather than disabling the control.

        WHERE "at boot" actually is, because it is not `create_app`. Starlette
        builds its middleware stack lazily, inside `Starlette.__call__` (`if
        self.middleware_stack is None: self.middleware_stack =
        self.build_middleware_stack()`), so nothing constructs this class
        until the app is first CALLED. Verified 2026-09-18:
        `create_app(Settings(..., request_deadline_seconds=0.0))` returns an
        app with `middleware_stack is None` and raises nothing; the
        `ValueError` arrives on the first `__call__`. Under a server that
        supports lifespan -- uvicorn by default -- that first call is the
        `lifespan` scope, dispatched before any connection is accepted, so
        the process still fails before it can serve a request and the
        paragraph above holds as shipped.

        Two consequences a reader should have. Under `--lifespan off`, or a
        server with no lifespan support, the first call is a REQUEST instead:
        the failure moves to request time and every request 500s, which is
        louder than a 504 for every request but much later than boot. And
        nothing in the suite pins that boot path -- the test for this is a
        unit test on the class, not on the assembled app -- so this paragraph
        is a description of a verified behaviour, not a guarded one.
        """
        if seconds <= 0:
            raise ValueError(
                f"request deadline must be positive, got {seconds!r}; "
                "a zero or negative deadline expires every request before it runs"
            )
        self.app = app
        self.seconds = seconds
        # Public and held on the instance, for two reasons. asyncio keeps only
        # a weak reference to a running task, so a task nothing else refers to
        # can be garbage-collected mid-flight; and an orphan is the one piece
        # of state this middleware leaves behind, so it should be inspectable
        # rather than invisible (`tests/test_request_deadline.py` reads it both
        # to prove a cancellation genuinely did not complete and to wait for
        # one that does).
        #
        # This set can grow without bound, under the one condition where the
        # cancellation never completes (a blocking cleanup -- see the module
        # docstring; against the measured store shape the orphans discard
        # themselves within a fraction of a second). It is bounded by nothing
        # here on purpose: dropping the reference would not end the task, it
        # would only hide it.
        self.orphans: set[asyncio.Task[None]] = set()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # `lifespan` and `websocket` scopes are not requests. Wrapping the
        # lifespan in particular would put this deadline on FastMCP's session
        # manager startup and on `_close_resources_after_fastmcp_shutdown`'s
        # `backend.aclose()` / `db.close()`, and cancel a shutdown that took
        # longer than one request is allowed to.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response = _Response()
        task = asyncio.ensure_future(self.app(scope, receive, _guard(send, response)))
        self.orphans.add(task)
        task.add_done_callback(self.orphans.discard)

        try:
            done, _ = await asyncio.wait({task}, timeout=self.seconds)
        except BaseException:
            # Running the app in a CHILD task means a cancellation delivered
            # to THIS call no longer reaches it: a child does not inherit its
            # parent's cancellation. Without this branch, any outer
            # cancellation would return here and leave the app running with
            # nothing left to ever cancel it -- a leak introduced by the
            # control rather than by the condition it exists for.
            #
            # NOT a client disconnect, which is what an earlier version of
            # this comment claimed. uvicorn does not cancel the ASGI task on
            # disconnect: it sets `cycle.disconnected = True` and wakes a
            # pending `receive()` with `http.disconnect`
            # (`uvicorn/protocols/http/httptools_impl.py::connection_lost`),
            # and the only `cancel()` in any of the three HTTP protocol
            # implementations in 0.52.4 is `timeout_keep_alive_task.cancel()`.
            # The real sources are uvicorn's graceful-shutdown timeout, which
            # cancels every in-flight request task (`uvicorn/server.py`'s
            # `shutdown`), and any enclosing cancellation scope -- a task
            # group, a test harness, a future middleware -- whose whole
            # contract is that it propagates.
            # Cancelled, not awaited, for the same reason the deadline path
            # does not await it. `BaseException` because `CancelledError` is
            # one.
            task.cancel()
            raise
        if task in done:
            # Re-raises whatever the inner app raised, so Starlette's
            # `ServerErrorMiddleware` -- which sits outside every user
            # middleware -- still turns an unhandled exception into a 500
            # exactly as it did before this middleware existed.
            task.result()
            return

        # No `await` between `asyncio.wait` returning and this assignment, so
        # on a single-threaded event loop the inner task cannot interleave and
        # slip a message past the guard in between. Everything it sends from
        # here on is dropped, including the response it may still be about to
        # produce: this request has already been answered.
        response.expired = True
        task.cancel()
        await _expire(response, send, self.seconds)


def _guard(send: Send, response: _Response) -> Send:
    async def guarded(message: Message) -> None:
        if response.expired:
            return
        response.in_flight += 1
        try:
            await send(message)
        finally:
            response.in_flight -= 1
        # Recorded only once `send` has RETURNED, so both flags mean "the
        # server took this", never "we offered it". A send that is cancelled
        # while suspended inside the server records nothing and leaves
        # `in_flight` back at zero -- which would read as "nothing happened"
        # and is why `_expire` has to consult `in_flight` while it is still
        # non-zero, i.e. before the cancelled send has unwound. See
        # `_Response` for the failure this ordering exists to prevent.
        if message["type"] == "http.response.start":
            response.started = True
        elif message["type"] == "http.response.body" and not message.get("more_body", False):
            response.complete = True

    return guarded


async def _expire(response: _Response, send: Send, seconds: float) -> None:
    """Answer the expired request, in whichever of four states it is in.

    ASGI has no way to retract an `http.response.start`, so the status is only
    this middleware's to choose while the server has taken nothing. All four
    branches are covered in `tests/test_request_deadline.py`.

    Every branch is decided from state read before this function's first
    `await`, which matters: `__call__` has already cancelled the inner task,
    so the first suspension here lets that cancellation unwind and drop
    `in_flight` back to zero. The decision must be made against the state as
    it was at the moment of expiry, not as it becomes while answering.
    """
    if response.in_flight:
        # A hand-off to the server is suspended right now, and it is about to
        # be cancelled where it stands. Whether the server had already taken
        # that message is not knowable from here, and the two possibilities
        # want opposite actions, so the only safe one is neither: send
        # nothing. What the client gets is then the server's own handling of
        # an app that returned without finishing -- for uvicorn, a 500 if no
        # start was processed and a closed transport if one was
        # (`uvicorn/protocols/http/httptools_impl.py::run_asgi`) -- which is
        # worse than a truncated body and better than a RuntimeError raised
        # inside the server.
        return
    if response.complete:
        # The response is already fully on the wire and the task is merely
        # still running -- a hang after the answer, not before it. There is
        # nothing to send, and anything sent here would be rejected.
        return
    if response.started:
        # Status and headers are gone; only the body is still open. Ending it
        # hands the client a truncated response, which is the honest signal
        # available: the alternative is holding the connection open for the
        # same unbounded time this exists to stop.
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        return
    # 504, not 400 and not 500. RFC 9110: a gateway "did not receive a timely
    # response from an upstream server". That is literally this case -- every
    # tool call is a request to the operator's backend over HTTP and to
    # Postgres, and the condition is one of those not answering. 400 would
    # blame a client whose request was well formed; 500 would claim a fault in
    # this process, which is the one place the fault is not. `ToolError` could
    # not have produced any of them: FastMCP 4 returns it as
    # `CallToolResult(is_error=True)` inside an HTTP 200, which is why this is
    # ASGI middleware at all (dev-docs/decisions/0002-header-validation.md).
    #
    # The body is a JSON-RPC error envelope because that is what the client
    # parses, with `mcp.types.REQUEST_TIMEOUT` (-32001, verified against mcp
    # 2.2.0 in this lockfile) rather than an invented code. `id` is null: see
    # the module docstring on what being outermost costs.
    raw = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": REQUEST_TIMEOUT,
                "message": "Request deadline exceeded",
                "data": f"the server bounded this request at {seconds:g}s",
            },
        }
    ).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 504,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": raw})

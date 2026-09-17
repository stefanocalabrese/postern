"""What a query the store stops answering does to a request. Measured 2026-09-17.

`tests/test_consent_check_failure_mode.py` measured the store being
UNREACHABLE: a refused connection raises in ~0.0s, a blackholed connect after
60 seconds (asyncpg's `connect(timeout=60)` default). It was explicit that it
had NOT measured the shape where the handshake SUCCEEDS and the stall happens
later, during query execution, and said there might be no deadline there at
all. That shape is this file, measured on both sides of the commit that
changed the answer.

BEFORE (`c7b884f`): no deadline existed. Both reproductions below were capped
by hand at 120 seconds and returned nothing at all. `pool_pre_ping=True` --
the liveness check that exists to notice an unusable pooled connection -- hung
in the same place (45s cap, no response, no replacement connection opened).
The only bounded wait was SQLAlchemy's default `QueuePool` checkout timeout,
30 seconds, which applied to the 16th concurrent request and beyond: 15
concurrent calls hung indefinitely and the 16th was refused at 30.07s. In
production's shape, where `create_app` gives consent and audit ONE `Database`
and therefore one 15-connection pool, that was 60.06s and the audit row was
lost to the same pool timeout.

AFTER (`61934d1`, "bound every wait on the way to Postgres"): the common case
is bounded, and one case is not.

  BOUNDED. A query stalled against a server that is still reachable -- the
  lock case below, and the realistic one: a slow store, a long transaction, a
  hot row -- now fails at `command_timeout`. Measured 3.09s at the production
  default of 3.0s, 1.06s at 1.0s, both with `isError: true`. Sixteen
  concurrent calls against a stalled store now ALL answer, in 3.45s total,
  where before fifteen of them never answered at all.

  NOT BOUNDED. A path that goes silent in BOTH directions still hangs the
  request with no deadline of any kind. `command_timeout` fires on time, but
  SQLAlchemy then invalidates the connection through asyncpg's graceful
  `close()`, whose first act is to await `cancel_sent_waiter` with no
  deadline; that waiter resolves only when a SECOND connection, opened to the
  same silent address to carry Postgres's out-of-band cancel, finishes.
  `61934d1`'s own constructor docstring names this and measures it at 20s
  through `AsyncSession.execute`. Measured here end to end through a real
  request, with `command_timeout=1.0`: STILL NOT RETURNED AT 60 SECONDS, on
  two separate paths -- the query itself, and the `pool_pre_ping` health check
  on a recycled connection. The interposer counted two connections in both,
  which is the cancel connection opening into the same silence.

So the honest summary of the current state: a store that answers, resets or
refuses is bounded by 61934d1's numbers; a store that silently drops packets
is bounded by the kernel, not by this codebase, and a request against one
never returns. Which shape a real outage takes is not something this file can
decide -- a blackholing firewall, a failed-over primary and a dropped route
all produce the silent one.

What the caller gets, in both eras and every bounded case, is HTTP 200 with
`isError: true` and `Unknown tool: 'accounts.list'`: a `TimeoutError` from the
store reaches FastMCP's `_evaluate_check`, which catches every `Exception` and
denies. That text is a false statement about a tool that exists, for a
customer who consented to it, and it is byte-identical to a mistyped tool
name. Bounding the wait did not change it.

The caps here are one second or so, because the gate should not spend minutes
proving a wait; the two-minute measurements are in
`docs/verification/2026-09-17-query-stall-deadline.md`. Every unbounded probe
below then RELEASES the stall and asserts the very same request completes,
which is what keeps a short probe from being a statement about a slow machine,
and every bounded one asserts a LOWER bound as well as an upper one, because
"it raised" also passes against a sixty-second wait.

These tests assert what IS. No remedy is applied here and none is chosen: the
residual case belongs to whoever owns `61934d1`.
"""

import asyncio
import json
import time
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlsplit

import httpx2
import pytest
import pytest_asyncio
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan
from postern_core.store.engine import Database
from postern_core.store.models import ConsentRecord
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.pool import QueuePool

# Imported, not re-declared: this is the harness
# `tests/test_consent_check_failure_mode.py` built for exactly this question.
# `_app` is `create_app`'s assembly with a separate audit database, and
# `RecordingBackend` is what answers "did any customer data move?" when the
# HTTP envelope cannot -- a denial and a successful call are both 200.
from tests.test_consent_check_failure_mode import (
    _META,
    CUSTOMER,
    GATED_TOOL,
    RecordingBackend,
    _app,
    _seed,
    _settings,
    _token,
)

# The command timeout these tests configure. Well under `Settings`'
# production 3.0s so the gate stays quick, and small enough that a probe of
# three times its length is still about a second.
COMMAND = 0.4

# How long an unbounded stall is watched before it is called hung: 3x
# COMMAND, so a probe that finds the request still running has already
# outlived the deadline that was supposed to end it. Not a measurement --
# the measurement is 60 seconds, in the record.
PROBE = 3 * COMMAND

# Generous, and never the measured quantity: these bound how long a test
# waits for a call to finish AFTER the stall is released, so a wedged harness
# fails instead of hanging `make ci`.
RECOVERY = 10.0


@pytest.fixture(scope="session")
def key_pair() -> RSAKeyPair:
    """Declared here rather than imported from the module above: a fixture
    imported by name and then taken as a parameter is a redefinition ruff
    rejects (F811), and silencing that reads worse than four lines."""
    return RSAKeyPair.generate()


@pytest_asyncio.fixture
async def consent_session(database: Database) -> AsyncIterator[AsyncSession]:
    """Commits for real, then deletes its own rows.

    Same reasoning and same shape as the fixture of this name in
    `tests/test_consent_check_failure_mode.py`: `tests/conftest.py`'s
    `session` binds to one externally-managed transaction whose `commit()`
    never reaches Postgres, so a row seeded through it is invisible to the
    independent connection the consent check opens inside the running app.
    """
    async with database.sessionmaker() as s:
        yield s
        await s.execute(delete(ConsentRecord))
        await s.commit()


def _headers(token: str, name: str) -> dict[str, str]:
    """The three mandatory headers plus auth, as `_rpc` sends them.

    `MCP-Protocol-Version` is load-bearing rather than decorative: it is what
    makes a `tools/call` trigger the MCP SDK's internal `tools/list` pass, so
    the consent check runs on the busy path (five evaluations) rather than the
    quiet one.
    """
    return {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
        "MCP-Protocol-Version": "2026-07-28",
    }


def _body(name: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": {}, "_meta": _META},
    }


def _is_error(response: httpx2.Response) -> bool:
    payload = json.loads(response.text)
    assert "error" not in payload, payload
    return bool(payload["result"]["isError"])


def _text(response: httpx2.Response) -> str:
    payload = json.loads(response.text)
    return str(payload["result"]["content"][0]["text"])


class _Calls:
    """Concurrent `tools/call` posts through ONE app, ONE client, ONE lifespan.

    `tests/test_consent_check_failure_mode.py::_rpc` posts once and awaits it,
    which cannot express either half of this file: a call that is started and
    deliberately not awaited, and several calls in flight at once against one
    pool. Entering the lifespan once and reusing one client is also the shape
    production has -- a request does not get its own app.
    """

    def __init__(self, app: StarletteWithLifespan, token: str) -> None:
        self._app = app
        self._token = token

    async def __aenter__(self) -> "_Calls":
        self._client = httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=self._app), base_url="http://t", timeout=None
        )
        await self._client.__aenter__()
        self._lifespan = self._app.router.lifespan_context(self._app)
        await self._lifespan.__aenter__()
        self._tasks: list[asyncio.Task[httpx2.Response]] = []
        return self

    async def __aexit__(self, *exc: object) -> None:
        for task in self._tasks:
            task.cancel()
        # Cancelled, never awaited. Cancelling a stalled query is itself
        # unbounded, and for the same reason the silent-path tests below
        # measure: the cancellation rides a second connection into the same
        # silence. Measured before 61934d1, and unchanged by it: a
        # cancellation that had still not completed 20 seconds after
        # `task.cancel()`. A test that awaited its own cancellations would
        # hang for the reason it exists to document.
        await self._lifespan.__aexit__(None, None, None)
        await self._client.__aexit__(None, None, None)

    def start(self, name: str = GATED_TOOL) -> asyncio.Task[httpx2.Response]:
        task = asyncio.ensure_future(
            self._client.post("/mcp", headers=_headers(self._token, name), json=_body(name))
        )
        self._tasks.append(task)
        return task


async def _still_running(task: asyncio.Task[httpx2.Response], seconds: float) -> bool:
    done, _ = await asyncio.wait({task}, timeout=seconds)
    return task not in done


async def _finished(task: asyncio.Task[httpx2.Response], seconds: float) -> httpx2.Response:
    done, _ = await asyncio.wait({task}, timeout=seconds)
    assert task in done, f"the call did not finish within {seconds}s"
    return task.result()


class LockedTable:
    """A real Postgres that accepts the query and does not answer it.

    The most faithful reproduction available without breaking a database on
    purpose: no interposer, no fake, no patched driver. A second session takes
    `ACCESS EXCLUSIVE` on `consents`, so the consent check's own SELECT
    completes its handshake, reaches the server, is parsed, and then waits --
    which is what "accepted the connection and stopped answering mid-query"
    looks like from the client socket.

    This is the REACHABLE stall: the server is healthy and would answer if the
    lock went away, which is what `release()` proves, and it is also why
    asyncpg's cancel request gets an answer here. That is exactly the
    difference between this class and `SilentServer` below, and after
    `61934d1` the two no longer behave the same: this one is bounded by
    `command_timeout`, that one is not bounded at all.

    Measured on this very container, and the reason the wait is unbounded
    server-side: `statement_timeout=0`, `lock_timeout=0`,
    `idle_in_transaction_session_timeout=0`. Nothing on the server gives up
    either; every deadline that now exists is the client's.
    """

    def __init__(self, url: str) -> None:
        self._db = Database(url)

    async def hold(self, table: str) -> None:
        self._conn = await self._db.engine.connect()
        await self._conn.execute(text(f"LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE"))

    async def release(self) -> None:
        await self._conn.rollback()
        await self._conn.close()
        await self._db.close()


class SilentServer:
    """A TCP interposer that forwards the handshake and then swallows answers.

    The other honest way to build this shape, and the one that covers what a
    lock cannot: a path that will NEVER deliver an answer. It is a plain byte
    pump in both directions until it goes silent; everything asyncpg needs --
    startup, authentication, parameter status, type introspection, the
    pre-ping -- crosses it normally, so the stall is unambiguously after a
    complete, working connection.

    Silence HOLDS the server's bytes rather than discarding them, so
    `resume()` delivers them and the stalled request completes. That is what
    lets a short probe prove a block instead of merely reporting that a second
    passed.

    Two ways to go silent, one per test below:
      - `trigger`: the first client packet containing these bytes is forwarded
        upstream and the answer to it is held. The mid-query stall -- Postgres
        executed the query and the result never came back.
      - `silence()`: everything from now on, which is how a POOLED
        connection's pre-ping is stalled. A different moment in the request,
        and measured separately because a fix could easily cover one and not
        the other.

    Because silence applies to the whole interposer and not to one socket, the
    second connection asyncpg opens to carry Postgres's out-of-band cancel
    also lands in it -- which is not an artefact of the harness but the exact
    production shape of a blackholing network path, and the reason the request
    never returns.

    The one caveat, stated rather than hidden: the trigger matches per TCP
    read, so a query split across segments could slip past it. The statements
    here are a few hundred bytes and arrive whole; a test that failed to stall
    would fail loudly at its first assertion rather than pass.
    """

    def __init__(self, upstream_url: str) -> None:
        parts = urlsplit(upstream_url)
        self._host = parts.hostname or "127.0.0.1"
        self._port = parts.port or 5432
        self.trigger: bytes | None = None
        self._silent = asyncio.Event()
        self._resumed = asyncio.Event()
        self.held_bytes = 0
        self.connections = 0
        self.port = 0

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = int(self._server.sockets[0].getsockname()[1])

    async def stop(self) -> None:
        self.resume()
        self._server.close()
        try:
            await asyncio.wait_for(self._server.wait_closed(), 5.0)
        except TimeoutError:
            # Teardown must not hang a run; a socket still open here cannot
            # change an assertion that has already been made.
            pass

    def url(self, upstream_url: str) -> str:
        parts = urlsplit(upstream_url)
        return (
            f"{parts.scheme}://{parts.username}:{parts.password}@127.0.0.1:{self.port}{parts.path}"
        )

    def silence(self) -> None:
        self._silent.set()

    def resume(self) -> None:
        self._resumed.set()

    async def _handle(self, client: asyncio.StreamReader, to_client: asyncio.StreamWriter) -> None:
        self.connections += 1
        upstream, to_upstream = await asyncio.open_connection(self._host, self._port)

        async def forward_up() -> None:
            while True:
                data = await client.read(65536)
                if not data:
                    return
                if self.trigger is not None and self.trigger in data:
                    self._silent.set()
                to_upstream.write(data)
                await to_upstream.drain()

        async def forward_down() -> None:
            held: list[bytes] = []
            while True:
                data = await upstream.read(65536)
                if not data:
                    return
                if self._silent.is_set():
                    held.append(data)
                    self.held_bytes += len(data)
                    await self._resumed.wait()
                    for chunk in held:
                        to_client.write(chunk)
                    held.clear()
                    self._silent.clear()
                    await to_client.drain()
                    continue
                to_client.write(data)
                await to_client.drain()

        # FIRST_COMPLETED, then close BOTH sides. Waiting for both directions
        # to finish deadlocks teardown instead: `engine.dispose()` sends
        # Terminate, Postgres closes its end, the downstream pump returns --
        # and the upstream pump is still parked in `client.read()`, so the
        # socket back to asyncpg is never closed and `close()` waits on a
        # connection-lost that cannot arrive. Found exactly that way, as a
        # 10-second teardown hang with nothing to do with the measurement.
        pumps = [asyncio.ensure_future(forward_up()), asyncio.ensure_future(forward_down())]
        try:
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for pump in pumps:
                pump.cancel()
            to_client.close()
            to_upstream.close()


@pytest_asyncio.fixture
async def silent_server(pg_url: str) -> AsyncIterator[SilentServer]:
    server = SilentServer(pg_url)
    await server.start()
    yield server
    await server.stop()


async def test_a_query_stalled_by_a_reachable_server_now_fails_at_the_command_timeout(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
) -> None:
    """The case `61934d1` fixed, measured end to end through a request.

    Before it, this exact call returned nothing at a 120-second cap. Now the
    stalled SELECT is abandoned at `command_timeout` and the request is
    answered. Both bounds are asserted: the lower one because "it raised"
    passes just as well against a wait of a minute, the upper one because the
    number is the point.

    At the production default of 3.0s the same call was measured at 3.09s.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    lock = LockedTable(pg_url)
    await lock.hold("consents")
    stalled = Database(pg_url, command_timeout_seconds=COMMAND)
    backend = RecordingBackend()
    try:
        app = _app(stalled, database, key_pair, backend, _settings(pg_url))
        async with _Calls(app, _token(key_pair)) as calls:
            started = time.monotonic()
            response = await _finished(calls.start(), RECOVERY)
            waited = time.monotonic() - started

        assert waited >= COMMAND, f"answered in {waited:.2f}s -- it cannot have waited on the query"
        assert waited < COMMAND + 2.0, f"took {waited:.2f}s -- the command timeout did not end it"
        assert response.status_code == 200
        assert _is_error(response) is True
        assert _text(response) == f"Unknown tool: '{GATED_TOOL}'"
        assert backend.paths == [], "a denied call must not reach the backend"
    finally:
        await lock.release()
        await asyncio.wait_for(stalled.close(), RECOVERY)


async def test_a_silent_path_still_hangs_the_request_past_every_deadline(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    silent_server: SilentServer,
) -> None:
    """The case `61934d1` does NOT fix, and its own docstring says so.

    Same stalled query, but the path back is gone rather than merely slow.
    `command_timeout` fires on time and the request still does not return: the
    connection is invalidated through asyncpg's graceful `close()`, which
    awaits `cancel_sent_waiter` with no deadline, and that waiter is resolved
    only by a second connection opened to the same silent address.

    The probe below is three times the command timeout, so a call still
    running at that point has already outlived the deadline meant to end it.
    Measured by hand at a 60-second cap with `command_timeout=1.0`: no
    response, backend never reached, two connections counted by the
    interposer. The release-and-complete half is the control -- the held bytes
    are handed over and this same request finishes -- so the hang is the
    silence and not the harness.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    silent_server.trigger = b"consents"
    stalled = Database(silent_server.url(pg_url), command_timeout_seconds=COMMAND)
    backend = RecordingBackend()
    try:
        app = _app(stalled, database, key_pair, backend, _settings(pg_url))
        async with _Calls(app, _token(key_pair)) as calls:
            call = calls.start()
            assert await _still_running(call, PROBE), (
                f"the call answered within {PROBE}s -- something now bounds this path"
            )
            assert silent_server.held_bytes > 0, "the interposer must be holding a real answer"
            assert backend.paths == [], "no customer data may move while consent is unanswered"

            silent_server.resume()
            recovered = await _finished(call, RECOVERY)

        # DENIED, not served -- and that is the sharpest evidence in this
        # file. The held bytes are the answer to the consent SELECT, so
        # before `61934d1` this same line got `isError: false` and a backend
        # call: the query was still pending and the answer arrived late. Now
        # the deadline has already fired by the time the silence lifts, so
        # what comes back is the denial it produced. The request was
        # therefore NOT waiting on the query during that probe. It was
        # waiting on the invalidation that follows the timeout, which is the
        # undeadlined close, which is the finding.
        assert _is_error(recovered) is True
        assert _text(recovered) == f"Unknown tool: '{GATED_TOOL}'"
        assert backend.paths == [], "the tool body must not have run"
    finally:
        await asyncio.wait_for(stalled.close(), RECOVERY)


async def test_a_silent_path_hangs_the_pool_pre_ping_health_check_too(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    silent_server: SilentServer,
) -> None:
    """The second unbounded path, and the one easiest to miss.

    `pool_pre_ping=True` runs a liveness check before handing over a recycled
    connection -- exactly the situation a stalled store creates. The first call
    here is this file's other control: it crosses the interposer, answers
    normally, and leaves a live connection pooled. Only then does the path go
    silent, so the next request stalls at CHECKOUT rather than in the query.

    `61934d1` gives the ping a `command_timeout` like any other statement, and
    that is not enough: the timeout fires and the invalidation that follows
    hits the same undeadlined close. Measured by hand at a 60-second cap with
    `command_timeout=1.0`: no response. A fix that covered the query and not
    this would look complete from the outside.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    stalled = Database(silent_server.url(pg_url), command_timeout_seconds=COMMAND)
    backend = RecordingBackend()
    try:
        app = _app(stalled, database, key_pair, backend, _settings(pg_url))
        async with _Calls(app, _token(key_pair)) as calls:
            warm = await _finished(calls.start(), RECOVERY)
            assert _is_error(warm) is False, "the interposer must be transparent when it forwards"
            pool = stalled.engine.pool
            assert isinstance(pool, QueuePool)
            assert pool.checkedin() == 1, "a live connection must be left pooled"

            silent_server.silence()
            call = calls.start()
            assert await _still_running(call, PROBE), (
                f"the call answered within {PROBE}s -- the pre-ping is now bounded"
            )
            assert backend.paths == ["/accounts"], "the second call must not have run its body"

            silent_server.resume()
            recovered = await _finished(call, RECOVERY)

        # Denied, for the same reason as the test above: the ping's own
        # `command_timeout` had already expired while the request was still
        # hanging, so lifting the silence delivers a refusal rather than the
        # tool's answer. The backend path list is unchanged from the warm
        # call, which is how that reads on the wire.
        assert _is_error(recovered) is True
        assert backend.paths == ["/accounts"]
    finally:
        await asyncio.wait_for(stalled.close(), RECOVERY)


async def test_sixteen_concurrent_calls_against_a_reachable_stall_all_answer_now(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
) -> None:
    """What `61934d1` bought, in the one number that decides blast radius.

    The pool is 5 connections plus 10 overflow, so 15 concurrent calls can be
    parked in it at once. Before the fix that is exactly what happened: 15
    hung with no deadline and the 16th was refused after 30.07 seconds by the
    pool's own checkout timeout (60.06s in production's shape, where consent
    and audit share one `Database`, with the audit row lost). Every one of
    them now answers -- measured at 3.45s for all 16 at the production default.

    The answers are still wrong, in the way this file's docstring describes:
    sixteen `Unknown tool` denials for a tool that exists. Bounded is not the
    same as truthful, and only the first was fixed.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    lock = LockedTable(pg_url)
    await lock.hold("consents")
    stalled = Database(pg_url, command_timeout_seconds=COMMAND)
    backend = RecordingBackend()
    try:
        app = _app(stalled, database, key_pair, backend, _settings(pg_url))
        async with _Calls(app, _token(key_pair)) as calls:
            started = time.monotonic()
            tasks = [calls.start() for _ in range(16)]
            done, _ = await asyncio.wait(tasks, timeout=RECOVERY)
            waited = time.monotonic() - started

            assert len(done) == 16, f"only {len(done)}/16 answered within {RECOVERY}s"
            assert waited >= COMMAND, f"all 16 answered in {waited:.2f}s -- nothing was stalled"
            for task in tasks:
                assert _is_error(task.result()) is True
            assert backend.paths == [], "no denied call may reach the backend"
    finally:
        await lock.release()
        await asyncio.wait_for(stalled.close(), RECOVERY)


async def test_the_production_database_carries_all_three_deadlines(
    pg_url: str,
) -> None:
    """Read off a live connection, not off `Settings`: the values that arrive.

    Before `61934d1` this same reading was
    `ConnectionConfiguration(command_timeout=None, ...)` with a pool timeout
    of SQLAlchemy's default 30.0 -- which is how "no deadline at all" was
    established in the first place. Asserting the driver's view rather than
    the constructor's arguments is deliberate: the URL query string silently
    hands asyncpg a string it cannot add to a float, so a value that is
    "configured" is not necessarily a value that applies.
    """
    db = Database(pg_url)
    try:
        pool = db.engine.pool
        assert isinstance(pool, QueuePool)
        assert pool.size() == 5
        assert pool._max_overflow == 10
        assert pool._timeout == 1.0
        assert pool._pre_ping is True

        async with db.engine.connect() as conn:
            raw = await conn.get_raw_connection()
            driver = raw.driver_connection
            assert driver is not None
            assert driver._config.command_timeout == 3.0
    finally:
        await db.close()

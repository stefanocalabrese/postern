"""Every wait on the way to Postgres, bounded and measured.

`Database` built its engine with no `connect_args` at all before this file
existed, which left two unbounded waits under a policy that fails closed on
both of them (`docs/decisions/0006-audit-write-failure.md`): connecting fell
back to asyncpg's `connect(timeout=60)` default, and a statement that stalled
after the connection was up had no deadline of any kind -- no
`command_timeout`, no `statement_timeout`. The second one is what these tests
are mostly about, because it was the one nobody had ever measured.

Every timing assertion here has BOTH bounds. The lower bound is what
separates a deadline that actually fired from a fast failure for an unrelated
reason: the URL query-string form of these same timeouts (recorded in
`tests/test_consent_check_failure_mode.py`'s module docstring) hands asyncpg
the string "1.0" and dies in 0.0s with a `TypeError`, which satisfies any
assertion that only checks "it raised". The upper bound is what separates the
configured value from the 60-second driver default that was there before.

What is NOT covered, measured rather than assumed: a socket that goes silent
in both directions mid-statement and also swallows the out-of-band cancel
connection. `command_timeout` fires on time at the driver (1.00s at
`command_timeout=1.0`, against a TCP proxy that relays until told to stop),
but SQLAlchemy then invalidates the connection through asyncpg's graceful
`close(timeout=2)`, which begins with `await self.cancel_sent_waiter` and
applies no deadline to that await (`asyncpg/protocol/protocol.pyx:602-613`);
the waiter resolves only when a second connection to the same dead address
completes (`asyncpg/connect_utils.py:1255-1281`, `loop.create_connection`
with no timeout). Measured through `AsyncSession.execute`: still running 20
seconds later. `Database.__init__`'s docstring says the same thing; no test
here asserts a bound that does not exist.
"""

import asyncio
import time
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any, cast

import pytest
import pytest_asyncio
from postern_core.store.engine import Database
from sqlalchemy import event, text
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.pool import ConnectionPoolEntry, QueuePool

from services.api.main import create_app
from services.api.settings import Settings


class _NoConnect(Exception):
    """Raised from a `do_connect` listener to read the driver's parameters
    without opening a socket."""


async def _driver_connect_kwargs(db: Database) -> dict[str, Any]:
    """The kwargs SQLAlchemy is about to call `asyncpg.connect` with.

    `do_connect` fires with the final, merged parameters, which is the only
    place a `connect_args` mistake is visible before the driver acts on it:
    the value's TYPE matters as much as the number, since the query-string
    form reaches asyncpg as a string and fails arithmetic rather than timing
    anything out.
    """
    captured: dict[str, Any] = {}

    @event.listens_for(db.engine.sync_engine, "do_connect")
    def _capture(
        dialect: Dialect,
        conn_rec: ConnectionPoolEntry,
        cargs: tuple[Any, ...],
        cparams: dict[str, Any],
    ) -> None:
        captured.update(cparams)
        raise _NoConnect

    with pytest.raises(_NoConnect):
        async with db.engine.connect():
            pass
    return captured


@pytest_asyncio.fixture
async def blackhole_port() -> AsyncIterator[int]:
    """A TCP listener that completes the handshake and then never speaks.

    The honest "store is up, store is silent" shape: a refused connection
    raises at once and proves nothing about a timeout, while this lets
    asyncpg finish connecting at the socket level and then wait for a server
    greeting that never arrives. Same fixture shape as
    `tests/test_consent_check_failure_mode.py`, which measures the same wait
    through the whole ASGI stack rather than at the constructor.
    """
    stop = asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await stop.wait()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port: int = server.sockets[0].getsockname()[1]
    yield port
    stop.set()
    server.close()
    await server.wait_closed()


async def test_database_hands_asyncpg_both_driver_timeouts() -> None:
    db = Database(
        "postgresql+asyncpg://u:p@localhost:5432/x",
        connect_timeout_seconds=1.5,
        command_timeout_seconds=2.5,
    )
    kwargs = await _driver_connect_kwargs(db)
    assert kwargs["timeout"] == 1.5
    assert kwargs["command_timeout"] == 2.5
    assert isinstance(kwargs["command_timeout"], float), "a string here disables the deadline"
    await db.close()


async def test_database_defaults_are_the_production_values_not_no_timeout() -> None:
    """A default of "unset" would leave every construction that does not pass
    these -- `tests/conftest.py`'s fixture, every test below, anything a later
    task writes -- on the 60-second driver default the change was about.
    """
    db = Database("postgresql+asyncpg://u:p@localhost:5432/x")
    kwargs = await _driver_connect_kwargs(db)
    assert kwargs["timeout"] == 2.0
    assert kwargs["command_timeout"] == 3.0
    pool = db.engine.pool
    assert isinstance(pool, QueuePool)
    assert pool._timeout == 1.0, "SQLAlchemy's own default here is 30s, three times the budget"
    await db.close()


async def test_a_null_pool_keeps_the_driver_timeouts_and_drops_the_pool_one() -> None:
    """`pool_timeout` is a QueuePool argument, and `create_async_engine`
    rejects the whole call with `TypeError: Invalid argument(s)
    'pool_timeout'` when the pool class cannot take it (measured against
    SQLAlchemy 2.0.52). NullPool opens a connection per checkout and queues
    nothing, so there is no wait to bound -- but the connect and command
    deadlines still have to reach the driver on that path, which is the one
    `tests/conftest.py` builds every database-backed test on.
    """
    db = Database(
        "postgresql+asyncpg://u:p@localhost:5432/x",
        null_pool=True,
        command_timeout_seconds=4.0,
    )
    kwargs = await _driver_connect_kwargs(db)
    assert kwargs["timeout"] == 2.0
    assert kwargs["command_timeout"] == 4.0
    await db.close()


async def test_a_command_timeout_ends_a_query_that_stalls_after_the_connection_is_up(
    pg_url: str,
) -> None:
    """The half nothing in this repository had ever bounded.

    The connection is fully established and authenticated -- this engine ran
    the control below against the same container -- and then the server
    accepts a statement and does not answer for 30 seconds. Before
    `command_timeout`, the call waited all 30, and would have waited 30
    minutes the same way: asyncpg applies no deadline to a statement unless
    one is configured (`asyncpg/protocol/protocol.pyx:715-722`).

    `pg_sleep` is the stall, rather than a cut network path, because it is
    the failure shape this trade is actually about: a store that is alive and
    answering, just later than the budget allows. That is the call this
    deadline converts from slow to failed, and the module docstring records
    which stall shape has no bound at all.
    """
    db = Database(pg_url, command_timeout_seconds=1.0)
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        async with db.sessionmaker() as session:
            await session.execute(text("SELECT pg_sleep(30)"))
    elapsed = time.monotonic() - started
    await db.close()

    assert elapsed >= 1.0, f"failed in {elapsed:.2f}s -- it cannot have waited on the statement"
    assert elapsed < 5.0, f"took {elapsed:.2f}s -- the 1.0s command timeout did not end it"


async def test_the_default_command_timeout_leaves_a_normal_query_alone(pg_url: str) -> None:
    """The control. A deadline that also breaks working queries is not a
    deadline, and every other assertion in this file is about a query that
    was supposed to fail, so nothing else here would notice.
    """
    db = Database(pg_url)
    async with db.sessionmaker() as session:
        assert (await session.execute(text("SELECT 1"))).scalar_one() == 1
    await db.close()


async def test_the_connect_timeout_is_reachable_through_the_constructor(
    blackhole_port: int,
) -> None:
    """Replacing `Database.engine` after construction was the only way to
    reach this before, which is what `tests/test_consent_check_failure_mode.py`
    used to do. 1.0s rather than the 2.0s default so the wait is
    distinguishable from CI noise in both directions.

    `TimeoutError` arrives undisguised: `asyncio.TimeoutError` is not a DBAPI
    error, so SQLAlchemy's exception wrapping does not apply to it (measured
    -- the mro is `TimeoutError, OSError, Exception`). The elapsed bounds
    below are still what carry the proof, since a `TimeoutError` raised in
    0.0s would be some other timeout entirely.
    """
    db = Database(
        f"postgresql+asyncpg://postern:postern@127.0.0.1:{blackhole_port}/postern",
        connect_timeout_seconds=1.0,
    )
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        async with db.sessionmaker() as session:
            await session.execute(text("SELECT 1"))
    elapsed = time.monotonic() - started
    await db.close()

    assert elapsed >= 1.0, f"failed in {elapsed:.2f}s -- it cannot have waited on the socket"
    assert elapsed < 5.0, f"took {elapsed:.2f}s -- that is the driver's 60s default, not ours"


async def test_create_app_wires_the_store_timeouts_from_settings() -> None:
    """The single production construction, `services/api/main.py`'s `db =
    Database(...)`, read back off `app.state.postern_database` -- the handle
    `create_app` already exposes for exactly this kind of proof.
    """
    settings = replace(
        Settings.for_testing(),
        database_connect_timeout_seconds=1.25,
        database_command_timeout_seconds=2.75,
        database_pool_timeout_seconds=0.5,
    )
    db = cast(Database, create_app(settings).state.postern_database)
    pool = db.engine.pool
    assert isinstance(pool, QueuePool)
    assert pool._timeout == 0.5
    kwargs = await _driver_connect_kwargs(db)
    assert kwargs["timeout"] == 1.25
    assert kwargs["command_timeout"] == 2.75


def test_default_store_timeouts_sum_to_the_stated_six_second_worst_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The number `Database.__init__` and `services/api/main.py` both state,
    pinned from the environment rather than from the dataclass defaults, so
    the three variables are proven reachable at the same time.

    Six seconds is one database operation on a checkout that has to open a
    connection: pool wait, connect, statement. It is a unit, not a per-call
    total -- a checkout that reuses a pooled connection pays the pre-ping
    instead of the connect, and a call whose consent lookup keeps raising
    pays the unit once per check evaluation, because only a successful
    lookup is cached. `Database.__init__` does both pieces of that
    arithmetic.
    """
    monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
    for var in (
        "POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS",
        "POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS",
        "POSTERN_DATABASE_POOL_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)
    settings = Settings.from_env()
    worst_case_total = (
        settings.database_pool_timeout_seconds
        + settings.database_connect_timeout_seconds
        + settings.database_command_timeout_seconds
    )
    assert worst_case_total == 6.0


def test_the_store_timeouts_are_individually_configurable_by_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
    monkeypatch.setenv("POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS", "0.5")
    monkeypatch.setenv("POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS", "7.5")
    monkeypatch.setenv("POSTERN_DATABASE_POOL_TIMEOUT_SECONDS", "0.25")
    settings = Settings.from_env()
    assert settings.database_connect_timeout_seconds == 0.5
    assert settings.database_command_timeout_seconds == 7.5
    assert settings.database_pool_timeout_seconds == 0.25

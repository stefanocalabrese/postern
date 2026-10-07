"""The startup check of the clock skew between confirm and Postgres.

Tier-2 `auth_time` is compared with the challenge's `created_at` (stamped by
Postgres `statement_timestamp()`) with a 30 s allowance, so a confirm clock that
lags the database by more than about 30 s refuses legitimate approvals. The check
only WARNS and never blocks startup. Two layers: the pure function with an
injected clock and an injected database-time callable, and the confirm app's
lifespan against a real Postgres and against an unreachable one.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime, tzinfo
from typing import Any, cast

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.store.engine import Database
from sqlalchemy.engine import make_url
from starlette.applications import Starlette
from starlette.types import Message

from services.confirm import database_clock
from services.confirm.database_clock import (
    DATABASE_CLOCK_SKEW_WARN_SECONDS,
    check_database_clock,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings

NOW = 1_800_000_000.0
SENTINEL = "sentinel-secret-in-exception-text"


def _db_time(seconds: float) -> datetime:
    return datetime.fromtimestamp(seconds, tz=UTC)


def _fetch_returning(value: object) -> Callable[[], Awaitable[object]]:
    async def fetch() -> object:
        return value

    return fetch


def _records(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.levelno >= logging.WARNING and r.name == database_clock.logger.name
    ]


async def _run(
    caplog: pytest.LogCaptureFixture,
    fetch: Callable[[], Awaitable[object]],
    *,
    clock: Callable[[], float] = lambda: NOW,
    timeout_seconds: float = 1.0,
) -> float | None:
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        return await check_database_clock(
            cast(Callable[[], Awaitable[datetime]], fetch),
            clock=clock,
            timeout_seconds=timeout_seconds,
        )


def test_the_tolerance_is_five_seconds() -> None:
    assert DATABASE_CLOCK_SKEW_WARN_SECONDS == 5.0


@pytest.mark.parametrize("skew", [0.0, 4.9, -4.9, 5.0])
async def test_a_skew_within_tolerance_logs_no_warning(
    caplog: pytest.LogCaptureFixture, skew: float
) -> None:
    result = await _run(caplog, _fetch_returning(_db_time(NOW + skew)))
    assert result == pytest.approx(skew, abs=1e-3)
    assert _records(caplog) == []


@pytest.mark.parametrize(
    ("skew", "text", "direction", "consequence"),
    [
        (5.1, "+5.1", "ahead of", "may be refused"),
        (-5.1, "-5.1", "behind", "freshness window is widened"),
        (400.0, "+400.0", "ahead of", "may be refused"),
    ],
)
async def test_a_skew_beyond_tolerance_warns_with_the_signed_value_and_the_window(
    caplog: pytest.LogCaptureFixture, skew: float, text: str, direction: str, consequence: str
) -> None:
    result = await _run(caplog, _fetch_returning(_db_time(NOW + skew)))
    assert result == pytest.approx(skew, abs=1e-3)
    records = _records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    message = records[0].getMessage()
    assert text in message
    assert "30" in message
    assert f"database {direction} confirm" in message
    assert consequence in message
    other = "freshness window is widened" if skew > 0 else "may be refused"
    assert other not in message


async def test_a_slow_query_does_not_create_a_false_skew(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The query takes 8 s on the injected clock and the database read its clock in
    the middle of it, so a perfectly synchronised pair must measure zero."""
    now = [NOW]

    async def fetch() -> datetime:
        now[0] += 4.0
        answer = _db_time(now[0])
        now[0] += 4.0
        return answer

    result = await _run(caplog, fetch, clock=lambda: now[0])
    assert result == pytest.approx(0.0, abs=1e-3)
    assert _records(caplog) == []


async def test_a_real_skew_is_measured_from_the_midpoint(
    caplog: pytest.LogCaptureFixture,
) -> None:
    now = [NOW]

    async def fetch() -> datetime:
        now[0] += 1.0
        answer = _db_time(now[0] + 10.0)
        now[0] += 1.0
        return answer

    result = await _run(caplog, fetch, clock=lambda: now[0])
    assert result == pytest.approx(10.0, abs=1e-3)
    assert len(_records(caplog)) == 1


def _assert_unmeasured(caplog: pytest.LogCaptureFixture, kind: str | None) -> None:
    records = _records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    message = records[0].getMessage()
    assert "could not be measured" in message
    assert SENTINEL not in message
    assert SENTINEL not in caplog.text
    if kind is not None:
        assert kind in message


async def test_a_raising_query_warns_with_the_exception_type_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def fetch() -> datetime:
        raise ConnectionRefusedError(f"postgresql://user:{SENTINEL}@db/postern")

    assert await _run(caplog, fetch) is None
    _assert_unmeasured(caplog, "ConnectionRefusedError")
    assert all(r.exc_info is None for r in caplog.records)


async def test_a_query_that_outlasts_the_timeout_warns_and_returns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def fetch() -> datetime:
        await asyncio.sleep(30)
        return _db_time(NOW)

    started = time.monotonic()
    assert await _run(caplog, fetch, timeout_seconds=0.05) is None
    assert time.monotonic() - started < 2.0
    _assert_unmeasured(caplog, None)


@pytest.mark.parametrize("value", [datetime(2027, 1, 1, 12, 0, 0), "2027-01-01", None, 12345])
async def test_a_naive_datetime_or_a_non_datetime_warns_and_does_not_raise(
    caplog: pytest.LogCaptureFixture, value: object
) -> None:
    assert await _run(caplog, _fetch_returning(value)) is None
    _assert_unmeasured(caplog, None)


# ---------------------------------------------------------------------------
# App level: the lifespan runs the check, and only the lifespan.
# ---------------------------------------------------------------------------


def _app(database_url: str) -> Starlette:
    settings = dataclasses.replace(ConfirmSettings.for_testing(), database_url=database_url)
    verifier = JWTVerifier(
        public_key=RSAKeyPair.generate().public_key,
        issuer="https://app.test.invalid",
        audience="postern-confirm",
    )
    return create_confirm_app(
        settings, assertion_verifier=verifier, device_key_store=no_enrolled_devices()
    )


async def test_building_the_app_runs_no_database_query(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        _app("postgresql+asyncpg://nobody:nopass@127.0.0.1:1/none")
    assert [r for r in caplog.records if r.name == database_clock.logger.name] == []


async def test_the_lifespan_warns_once_when_confirm_lags_postgres_by_sixty_seconds(
    pg_url: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    real = time.time
    monkeypatch.setattr(database_clock, "_wall_clock", lambda: real() - 60.0)
    app = _app(pg_url)
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        async with app.router.lifespan_context(app):
            pass
    records = _records(caplog)
    assert len(records) == 1
    assert "+60." in records[0].getMessage() or "+59." in records[0].getMessage()


async def test_the_lifespan_on_a_synchronised_clock_logs_no_warning(
    pg_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(pg_url)
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        async with app.router.lifespan_context(app):
            pass
    assert _records(caplog) == []


async def test_the_lifespan_with_an_unreachable_database_starts_fast_with_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app("postgresql+asyncpg://nobody:nopass@127.0.0.1:1/none")
    started = time.monotonic()
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        async with asyncio.timeout(5):
            async with app.router.lifespan_context(app):
                pass
    assert time.monotonic() - started < 3.0
    _assert_unmeasured(caplog, None)
    assert "nopass" not in caplog.text


async def test_the_lifespan_with_a_database_that_never_answers_is_bounded(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A listener that accepts and stays silent: asyncpg's own connect timeout is 2 s
    by default, so only the module's 1.5 s total bound makes this finish inside 2 s."""

    async def hold(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(30)

    server = await asyncio.start_server(hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        app = _app(f"postgresql+asyncpg://nobody:nopass@127.0.0.1:{port}/none")
        started = time.monotonic()
        with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
            async with asyncio.timeout(5):
                async with app.router.lifespan_context(app):
                    pass
        assert time.monotonic() - started < 2.0
        _assert_unmeasured(caplog, None)
    finally:
        server.close()


# ---------------------------------------------------------------------------
# Answers that look aware and are not, or that raise when asked.
# ---------------------------------------------------------------------------


class _NoOffset(tzinfo):
    def utcoffset(self, dt: datetime | None) -> None:
        return None

    def tzname(self, dt: datetime | None) -> None:
        return None

    def dst(self, dt: datetime | None) -> None:
        return None


class _RaisingOffset(tzinfo):
    def utcoffset(self, dt: datetime | None) -> None:
        raise RuntimeError(SENTINEL)

    def tzname(self, dt: datetime | None) -> None:
        return None

    def dst(self, dt: datetime | None) -> None:
        return None


async def test_a_tzinfo_with_no_offset_warns_and_does_not_raise(
    caplog: pytest.LogCaptureFixture,
) -> None:
    value = datetime(2027, 1, 1, tzinfo=_NoOffset())
    assert value.tzinfo is not None
    assert await _run(caplog, _fetch_returning(value)) is None
    _assert_unmeasured(caplog, "not an aware datetime")


async def test_a_tzinfo_whose_offset_raises_warns_with_the_type_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    value = datetime(2027, 1, 1, tzinfo=_RaisingOffset())
    assert await _run(caplog, _fetch_returning(value)) is None
    _assert_unmeasured(caplog, "RuntimeError")


# ---------------------------------------------------------------------------
# `run_database_clock_check` against a fake `Database`: connect, bound, cancel.
# ---------------------------------------------------------------------------


class _Result:
    def __init__(self, value: object) -> None:
        self._value = value

    def scalar_one(self) -> object:
        return self._value


class _Connection:
    def __init__(self, execute: Callable[[], Awaitable[object]]) -> None:
        self._execute = execute

    async def execute(self, statement: object) -> _Result:
        return _Result(await self._execute())


class _Engine:
    def __init__(
        self, execute: Callable[[], Awaitable[object]], connect_error: Exception | None
    ) -> None:
        self._execute = execute
        self._connect_error = connect_error

    @contextlib.asynccontextmanager
    async def connect(self) -> AsyncIterator[_Connection]:
        if self._connect_error is not None:
            raise self._connect_error
        yield _Connection(self._execute)


class _FakeDatabase:
    def __init__(
        self, execute: Callable[[], Awaitable[object]], connect_error: Exception | None = None
    ) -> None:
        self.engine = _Engine(execute, connect_error)


def _fake(
    execute: Callable[[], Awaitable[object]], connect_error: Exception | None = None
) -> Database:
    return cast(Database, _FakeDatabase(execute, connect_error))


async def test_a_connect_error_warns_with_the_type_only(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def execute() -> object:
        return _db_time(NOW)

    database = _fake(execute, OSError(f"postgresql://user:{SENTINEL}@db/postern"))
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        await database_clock.run_database_clock_check(database)
    _assert_unmeasured(caplog, "OSError")


async def test_a_raising_tzinfo_through_the_run_path_warns_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async def execute() -> object:
        return datetime(2027, 1, 1, tzinfo=_RaisingOffset())

    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        await database_clock.run_database_clock_check(_fake(execute))
    _assert_unmeasured(caplog, "RuntimeError")


async def test_the_total_bound_does_not_wait_for_the_cancellation_cleanup(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The query stalls and its cancellation cleanup takes 3 s, as SQLAlchemy's
    does against a stalled asyncpg connection. Startup must still return in under
    2 s, and the one warning is the 'could not be measured' one."""
    cleaned = asyncio.Event()

    async def execute() -> object:
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await asyncio.sleep(3)
            cleaned.set()
            raise
        return None

    started = time.monotonic()
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        await database_clock.run_database_clock_check(_fake(execute))
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, elapsed
    _assert_unmeasured(caplog, None)
    assert not cleaned.is_set()
    assert len(database_clock._ABANDONED) == 1
    await asyncio.wait_for(asyncio.gather(*database_clock._ABANDONED, return_exceptions=True), 6)
    # The abandoned task was cancelled a second time while it cleaned up, which is
    # the point: nobody waits for it, and it still ends and leaves the set.
    assert database_clock._ABANDONED == set()


async def test_an_outer_cancellation_reaches_the_check_and_is_not_swallowed() -> None:
    cancelled = asyncio.Event()

    async def execute() -> object:
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            cancelled.set()
            raise
        return None

    task = asyncio.ensure_future(database_clock.run_database_clock_check(_fake(execute)))
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.wait_for(cancelled.wait(), 1)


# ---------------------------------------------------------------------------
# Through the ASGI lifespan protocol, so the whole middleware stack is in the path.
# ---------------------------------------------------------------------------


async def _drive_lifespan(app: Starlette, *, cap_seconds: float = 8.0) -> tuple[float, list[str]]:
    """Run startup and shutdown through ``app(scope, receive, send)`` and return the
    seconds until startup finished and the message types sent. An app that never
    answers the startup message fails here after `cap_seconds`."""
    inbox: asyncio.Queue[Message] = asyncio.Queue()
    sent: list[str] = []
    started = asyncio.Event()
    await inbox.put({"type": "lifespan.startup"})

    async def send(message: Message) -> None:
        sent.append(message["type"])
        if message["type"].startswith("lifespan.startup"):
            started.set()

    scope: Any = {"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}
    runner = asyncio.create_task(app(scope, inbox.get, send))
    begun = time.monotonic()
    try:
        await asyncio.wait_for(started.wait(), cap_seconds)
        elapsed = time.monotonic() - begun
        await inbox.put({"type": "lifespan.shutdown"})
        await asyncio.wait_for(runner, cap_seconds)
    finally:
        runner.cancel()
    return elapsed, sent


async def test_asgi_lifespan_warns_once_when_confirm_lags_postgres(
    pg_url: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    real = time.time
    monkeypatch.setattr(database_clock, "_wall_clock", lambda: real() - 60.0)
    app = _app(pg_url)
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        _, sent = await _drive_lifespan(app)
    assert "lifespan.startup.complete" in sent
    records = _records(caplog)
    assert len(records) == 1
    assert "database ahead of confirm" in records[0].getMessage()


async def test_asgi_lifespan_with_an_unreachable_database_completes_with_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app("postgresql+asyncpg://nobody:nopass@127.0.0.1:1/none")
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        elapsed, sent = await _drive_lifespan(app)
    assert "lifespan.startup.complete" in sent
    assert elapsed < 2.0
    _assert_unmeasured(caplog, None)


async def test_asgi_lifespan_with_a_silent_database_completes_inside_two_seconds(
    caplog: pytest.LogCaptureFixture,
) -> None:
    release = asyncio.Event()

    async def hold(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await release.wait()
        writer.close()

    server = await asyncio.start_server(hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        app = _app(f"postgresql+asyncpg://nobody:nopass@127.0.0.1:{port}/none")
        with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
            elapsed, sent = await _drive_lifespan(app)
        assert "lifespan.startup.complete" in sent
        assert elapsed < 2.0, elapsed
        _assert_unmeasured(caplog, None)
    finally:
        release.set()
        server.close()
        await asyncio.gather(*database_clock._ABANDONED, return_exceptions=True)


async def test_asgi_lifespan_completes_when_the_database_stalls_mid_query(
    pg_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A TCP proxy in front of the real Postgres forwards until the statement_timestamp
    query and then goes silent both ways, and holds every later connection (the
    out-of-band cancel included) open without answering. With `asyncio.wait_for`
    around the check, startup did not complete within 60 s."""
    upstream = make_url(pg_url)
    release = asyncio.Event()
    stalled = asyncio.Event()
    connections = 0

    async def pipe(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, upstream_side: bool
    ) -> None:
        try:
            while not stalled.is_set():
                data = await reader.read(65536)
                if not data:
                    return
                if upstream_side and b"statement_timestamp" in data:
                    stalled.set()
                    return
                if stalled.is_set():
                    return
                writer.write(data)
                await writer.drain()
        except OSError:
            return

    async def handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
        nonlocal connections
        connections += 1
        if connections > 1:
            await release.wait()
            client_w.close()
            return
        server_r, server_w = await asyncio.open_connection(upstream.host, upstream.port)
        await asyncio.gather(
            pipe(client_r, server_w, upstream_side=True),
            pipe(server_r, client_w, upstream_side=False),
        )
        await release.wait()
        server_w.close()
        client_w.close()

    proxy = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = proxy.sockets[0].getsockname()[1]
    url = upstream.set(host="127.0.0.1", port=port).render_as_string(hide_password=False)
    try:
        app = _app(url)
        with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
            elapsed, sent = await _drive_lifespan(app)
        assert stalled.is_set(), "the proxy never saw the query, so nothing stalled"
        assert "lifespan.startup.complete" in sent
        assert elapsed < 2.0, elapsed
        _assert_unmeasured(caplog, None)
    finally:
        release.set()
        proxy.close()
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(
                asyncio.gather(*database_clock._ABANDONED, return_exceptions=True), 5
            )

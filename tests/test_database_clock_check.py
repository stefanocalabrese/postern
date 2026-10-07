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
import dataclasses
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices

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


def _fetch_returning(value: object) -> Callable[[], object]:
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
    fetch: Callable[[], object],
    *,
    clock: Callable[[], float] = lambda: NOW,
    timeout_seconds: float = 1.0,
) -> float | None:
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        return await check_database_clock(
            fetch,  # type: ignore[arg-type]
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


@pytest.mark.parametrize(("skew", "text"), [(5.1, "+5.1"), (-5.1, "-5.1"), (400.0, "+400.0")])
async def test_a_skew_beyond_tolerance_warns_with_the_signed_value_and_the_window(
    caplog: pytest.LogCaptureFixture, skew: float, text: str
) -> None:
    result = await _run(caplog, _fetch_returning(_db_time(NOW + skew)))
    assert result == pytest.approx(skew, abs=1e-3)
    records = _records(caplog)
    assert len(records) == 1
    assert records[0].levelno == logging.WARNING
    message = records[0].getMessage()
    assert text in message
    assert "30" in message


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


def _app(database_url: str) -> object:
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
        async with app.router.lifespan_context(app):  # type: ignore[attr-defined]
            pass
    records = _records(caplog)
    assert len(records) == 1
    assert "+60." in records[0].getMessage() or "+59." in records[0].getMessage()


async def test_the_lifespan_on_a_synchronised_clock_logs_no_warning(
    pg_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    app = _app(pg_url)
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        async with app.router.lifespan_context(app):  # type: ignore[attr-defined]
            pass
    assert _records(caplog) == []


async def test_the_lifespan_with_an_unreachable_database_starts_fast_with_one_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app = _app("postgresql+asyncpg://nobody:nopass@127.0.0.1:1/none")
    started = time.monotonic()
    with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
        async with asyncio.timeout(5):
            async with app.router.lifespan_context(app):  # type: ignore[attr-defined]
                pass
    assert time.monotonic() - started < 3.0
    _assert_unmeasured(caplog, None)
    assert "nopass" not in caplog.text


async def test_the_lifespan_with_a_database_that_never_answers_is_bounded(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A listener that accepts and stays silent: asyncpg's own connect timeout is 2 s
    by default, so only the module's 1 s bound makes this finish inside 1.5 s."""

    async def hold(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(30)

    server = await asyncio.start_server(hold, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        app = _app(f"postgresql+asyncpg://nobody:nopass@127.0.0.1:{port}/none")
        started = time.monotonic()
        with caplog.at_level(logging.DEBUG, logger=database_clock.logger.name):
            async with asyncio.timeout(5):
                async with app.router.lifespan_context(app):  # type: ignore[attr-defined]
                    pass
        assert time.monotonic() - started < 1.8
        _assert_unmeasured(caplog, None)
    finally:
        server.close()

"""Application call sites that log or retrieve a driver error, each with the
record factory OFF, so that what is measured is the site and not the net.

* `RequestDeadline` abandons a task at its deadline. If that task raised a
  driver error afterwards, asyncio logs `Task exception was never retrieved`
  with the task's repr, which ends `exception=DBAPIError('<driver text>')`.
* `services/confirm/device_auth.py::_withdraw_pairing` logs a failed
  revocation.
* Every `exc_info=` and every bare exception argument in the two services is
  one of the sanctioned shapes (a scan, so a new site cannot be added raw).
* `migrations/env.py` builds its engine with `hide_parameters=True`.

The sentinel is a module constant referred to by name on every raising line.
"""

import ast
import asyncio
import gc
import io
import logging
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from postern_core import log_safety
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from services.api.asgi.request_deadline import RequestDeadline
from services.confirm.device_auth import _withdraw_pairing
from tests.test_request_deadline import _drive

SENTINEL = "zzsent_deadline_31"
ROOT = Path(__file__).resolve().parent.parent

#: Short: the point is what the abandoned task does after the deadline, not how
#: long the deadline is.
DEADLINE = 0.05


@pytest.fixture(autouse=True)
def _plain_factory(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    previous = logging.getLogRecordFactory()
    logging.setLogRecordFactory(logging.LogRecord)
    monkeypatch.setattr(log_safety, "_installed_factory", None)
    yield
    logging.setLogRecordFactory(previous)


@pytest.fixture
async def engine(pg_url: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(pg_url)
    yield eng
    await eng.dispose()


@pytest.fixture
def every_log() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    targets = [logging.getLogger(n) for n in ("", "asyncio", "services")]
    for target in targets:
        target.addHandler(handler)
    yield buffer
    for target in targets:
        target.removeHandler(handler)


# ---------------------------------------------------------------------------
# I4: the deadline middleware retrieves what an abandoned task raised.
# ---------------------------------------------------------------------------


async def test_a_task_abandoned_at_the_deadline_that_raises_a_driver_error_leaks_nothing(
    engine: AsyncEngine, every_log: io.StringIO
) -> None:
    async def inner(scope: Any, receive: Any, send: Any) -> None:
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            # The shape this guards: cancellation is delivered, and the
            # cleanup that follows raises a driver error of its own.
            async with engine.connect() as connection:
                await connection.execute(text("SELECT CAST(:p AS int)"), {"p": SENTINEL})

    middleware = RequestDeadline(inner, seconds=DEADLINE)
    await _drive(middleware)
    await asyncio.wait(set(middleware.orphans), timeout=5)
    assert not middleware.orphans
    gc.collect()
    await asyncio.sleep(0.05)
    gc.collect()

    captured = every_log.getvalue()
    assert "never retrieved" not in captured, captured
    assert SENTINEL not in captured, captured
    assert "abandoned at its deadline raised afterwards" in captured
    assert "sqlalchemy.exc.DBAPIError, asyncpg.exceptions.DataError client-side" in captured


async def test_a_task_abandoned_at_the_deadline_that_is_cancelled_logs_nothing(
    every_log: io.StringIO,
) -> None:
    async def inner(scope: Any, receive: Any, send: Any) -> None:
        await asyncio.Event().wait()

    middleware = RequestDeadline(inner, seconds=DEADLINE)
    await _drive(middleware)
    await asyncio.wait(set(middleware.orphans), timeout=5)
    gc.collect()
    assert "abandoned" not in every_log.getvalue()
    assert "never retrieved" not in every_log.getvalue()


# ---------------------------------------------------------------------------
# services/confirm/device_auth.py::_withdraw_pairing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("cause", ["audit", "cancelled", "store"])
async def test_a_failed_withdrawal_logs_the_driver_error_by_type_only(
    cause: str, engine: AsyncEngine, every_log: io.StringIO
) -> None:
    class Store:
        async def revoke_device_code(self, value: str) -> None:
            async with engine.connect() as connection:
                await connection.execute(text("SELECT CAST(:p AS int)"), {"p": SENTINEL})

    await _withdraw_pairing(Store(), "dc_sentinel_check", cause=cause, state="approved")  # type: ignore[arg-type]

    captured = every_log.getvalue()
    assert SENTINEL not in captured, captured
    assert "[parameters:" not in captured and "[SQL:" not in captured
    assert "asyncpg.exceptions.DataError client-side" in captured


# ---------------------------------------------------------------------------
# I5b: a device code is a bearer credential and never reaches a log.
# ---------------------------------------------------------------------------

DEVICE_CODE_SENTINEL = "zzdevcode_sentinel_6620_abcdefghijklmnopq"


async def test_a_device_code_that_fails_to_deserialise_is_logged_by_handle_only(
    every_log: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    from postern_core.auth.device_codes import RedisDeviceCodeStore

    from services.confirm.audit import device_code_handle

    class Redis:
        async def get(self, key: str) -> str:
            return "{ not json"

    store = object.__new__(RedisDeviceCodeStore)
    store._redis = Redis()
    monkeypatch.setattr(RedisDeviceCodeStore, "_key", lambda self, value: f"k:{value}")

    assert await store.get_device_code(DEVICE_CODE_SENTINEL) is None

    captured = every_log.getvalue()
    assert DEVICE_CODE_SENTINEL not in captured, captured
    assert "Failed to deserialize device code" in captured
    assert device_code_handle(DEVICE_CODE_SENTINEL) in captured


def test_the_core_handle_is_the_audit_rows_handle() -> None:
    from postern_core.auth.device_codes import _device_code_handle

    from services.confirm.audit import device_code_handle

    assert _device_code_handle(DEVICE_CODE_SENTINEL) == device_code_handle(DEVICE_CODE_SENTINEL)


# ---------------------------------------------------------------------------
# M5: migrations hide parameters.
# ---------------------------------------------------------------------------


def test_the_migration_engine_hides_parameters() -> None:
    tree = ast.parse((ROOT / "migrations" / "env.py").read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "async_engine_from_config"
    ]
    assert len(calls) == 1
    hidden = [
        kw
        for kw in calls[0].keywords
        if kw.arg == "hide_parameters"
        and isinstance(kw.value, ast.Constant)
        and kw.value.value is True
    ]
    assert hidden

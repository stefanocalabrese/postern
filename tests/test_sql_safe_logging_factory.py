"""The process-wide log record factory (`postern_core.log_safety`).

A filter on uvicorn's two loggers was the first design. It missed every record
that another logger's own handler writes (`fastmcp.server.server`,
`propagate = False`), every `exc_info=` call in the application's own loggers,
and every `%s` of an exception in a record's arguments. The factory sanitises a
record when it is CREATED, so no logger, handler or propagation setting is
between a driver error and the sanitiser.

Every test here runs against REAL loggers with a plain `StreamHandler`, and
against a real asyncpg error from a real Postgres: a bound parameter carrying a
sentinel (asyncpg's own message names it) and a unique violation whose DETAIL
carries two more. Sentinels are module constants referred to by name on every
raising line, since a traceback frame prints its source line.
"""

import asyncio
import gc
import io
import logging
from collections.abc import AsyncIterator, Iterator
from typing import Any

import pytest
from postern_core import log_safety
from postern_core.log_safety import install_sql_safe_logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from tests.test_sql_safe_logging import (
    ALL_SENTINELS,
    UNIQUE_SENTINEL_A,
    _param_error,
    _unique_error,
)

LOGGERS = [
    "services.api.middleware.audit",
    "services.api.consent",
    "fastmcp.server.server",
    "mcp.shared.jsonrpc_dispatcher",
    "sqlalchemy.pool",
    "asyncio",
    "uvicorn.error",
    "",
]


@pytest.fixture
def plain_factory(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """No sanitising factory installed: the state before `install_sql_safe_logging`."""
    previous = logging.getLogRecordFactory()
    logging.setLogRecordFactory(logging.LogRecord)
    monkeypatch.setattr(log_safety, "_installed_factory", None)
    yield
    logging.setLogRecordFactory(previous)


@pytest.fixture
def installed(plain_factory: None) -> None:
    install_sql_safe_logging()


@pytest.fixture
async def engine(pg_url: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(pg_url)
    yield eng
    await eng.dispose()


class _Capture:
    """A plain `StreamHandler` on the named logger AND another on root."""

    def __init__(self, name: str) -> None:
        self.logger = logging.getLogger(name)
        self.own = io.StringIO()
        self.root = io.StringIO()
        self._own_handler = logging.StreamHandler(self.own)
        self._root_handler = logging.StreamHandler(self.root)
        fmt = logging.Formatter("%(name)s %(levelname)s %(message)s")
        self._own_handler.setFormatter(fmt)
        self._root_handler.setFormatter(fmt)
        self._propagate = self.logger.propagate
        self._level = self.logger.level

    def __enter__(self) -> "_Capture":
        self.logger.addHandler(self._own_handler)
        logging.getLogger().addHandler(self._root_handler)
        self.logger.setLevel(logging.DEBUG)
        return self

    def __exit__(self, *exc: object) -> None:
        self.logger.removeHandler(self._own_handler)
        logging.getLogger().removeHandler(self._root_handler)
        self.logger.propagate = self._propagate
        self.logger.setLevel(self._level)

    @property
    def everything(self) -> str:
        return self.own.getvalue() + "\n" + self.root.getvalue()


def _assert_clean(captured: _Capture) -> None:
    for sentinel in ALL_SENTINELS:
        assert sentinel not in captured.everything, (sentinel, captured.everything)


@pytest.fixture(params=["param", "unique"])
async def driver_error(request: pytest.FixtureRequest, engine: AsyncEngine) -> Exception:
    if request.param == "param":
        return await _param_error(engine)
    return await _unique_error(engine)


# ---------------------------------------------------------------------------
# The harness is real: with no factory the leak is there, on every logger.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", LOGGERS)
@pytest.mark.usefixtures("plain_factory")
async def test_without_the_factory_every_logger_leaks(name: str, engine: AsyncEngine) -> None:
    error = await _unique_error(engine)
    with _Capture(name) as captured:
        logging.getLogger(name).error("boom", exc_info=error)
    assert UNIQUE_SENTINEL_A in captured.everything


# ---------------------------------------------------------------------------
# exc_info, args, msg: on every logger, own handler and root handler both.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", LOGGERS)
@pytest.mark.usefixtures("installed")
def test_exc_info_is_sanitised_on_every_logger(name: str, driver_error: Exception) -> None:
    log = logging.getLogger(name)
    with _Capture(name) as captured:
        if name == "fastmcp.server.server":
            log.propagate = False  # its real configuration: own handler only
        try:
            raise driver_error
        except Exception:
            log.exception("Error calling tool 'x'")
        log.error("explicit", exc_info=driver_error)
    _assert_clean(captured)
    assert "withheld" in captured.own.getvalue()
    assert "Error calling tool 'x'" in captured.own.getvalue()


@pytest.mark.parametrize("name", LOGGERS)
@pytest.mark.usefixtures("installed")
def test_an_exception_in_the_arguments_is_replaced(name: str, driver_error: Exception) -> None:
    log = logging.getLogger(name)
    with _Capture(name) as captured:
        log.error("audit write failed: %s", driver_error)
        log.error("audit write failed: %r", driver_error)
        log.error("nested %s", (driver_error,))
        log.error("%(e)s", {"e": driver_error})
    _assert_clean(captured)
    assert "sqlalchemy.exc." in captured.own.getvalue()


@pytest.mark.usefixtures("installed")
def test_an_exception_as_the_message_is_replaced(driver_error: Exception) -> None:
    with _Capture("services.api.consent") as captured:
        logging.getLogger("services.api.consent").error(driver_error)
    _assert_clean(captured)
    assert "sqlalchemy.exc." in captured.own.getvalue()


@pytest.mark.usefixtures("installed")
def test_a_wrapper_exception_whose_chain_holds_a_driver_error_is_replaced(
    driver_error: Exception,
) -> None:
    try:
        raise RuntimeError(f"wrapped: {driver_error}") from driver_error
    except RuntimeError as wrapper:
        with _Capture("services.api.consent") as captured:
            logging.getLogger("services.api.consent").error("failed: %s", wrapper)
    _assert_clean(captured)


@pytest.mark.usefixtures("installed")
async def test_asyncio_task_exception_never_retrieved_is_sanitised(engine: AsyncEngine) -> None:
    """asyncio puts the task's repr, which ends `exception=DBAPIError('<text>')`,
    in the MESSAGE: text, not an exception object."""
    loop = asyncio.get_running_loop()
    seen: list[Any] = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(None)  # asyncio's own default handler logs it

    async def boom() -> None:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT CAST(:p AS int)"), {"p": ALL_SENTINELS[0]})

    with _Capture("asyncio") as captured:
        task = asyncio.ensure_future(boom())
        await asyncio.wait({task})
        del task
        gc.collect()
        await asyncio.sleep(0)
    loop.set_exception_handler(previous)
    assert not seen
    _assert_clean(captured)
    assert "Task exception was never retrieved" in captured.own.getvalue()


@pytest.mark.usefixtures("installed")
def test_a_non_sql_exception_is_untouched_byte_for_byte() -> None:
    def render() -> str:
        buffer = io.StringIO()
        handler = logging.StreamHandler(buffer)
        handler.setFormatter(logging.Formatter("%(message)s"))
        log = logging.getLogger("services.api.consent")
        log.addHandler(handler)
        try:
            try:
                raise KeyError("inner detail")
            except KeyError as inner:
                raise ValueError("outer detail") from inner
        except ValueError as outer:
            log.error("plain %s %s", "x", outer, exc_info=outer)
        finally:
            log.removeHandler(handler)
        return buffer.getvalue()

    with_factory = render()
    logging.setLogRecordFactory(logging.LogRecord)
    without_factory = render()
    assert with_factory == without_factory
    assert "outer detail" in with_factory and "inner detail" in with_factory


class _CountingList(list[Any]):
    """A list that counts how many items anything iterates out of it."""

    iterated = 0

    def __iter__(self) -> Iterator[Any]:
        for item in super().__iter__():
            type(self).iterated += 1
            yield item


def _record(arg: Any) -> logging.LogRecord:
    return logging.getLogRecordFactory()("n", logging.ERROR, __file__, 1, "m %s", (arg,), None)


def _first_arg(arg: Any) -> Any:
    """The first record argument, after the factory ran, untyped for indexing."""
    args: Any = _record(arg).args
    return args[0]


@pytest.mark.usefixtures("installed")
def test_a_huge_container_argument_is_scanned_only_up_to_the_cap(
    driver_error: Exception,
) -> None:
    """1,000,000 items cost 60 ms per record before the cap. Counted, not timed."""
    items = _CountingList([0] * 1_000_000)
    _CountingList.iterated = 0
    record = _record(items)
    assert _CountingList.iterated <= log_safety._MAX_ITEMS
    assert record.args == (items,)

    # An exception inside the first `_MAX_ITEMS` items is replaced...
    inside = _CountingList([0] * 999 + [driver_error] + [0] * 5000)
    replaced = _first_arg(inside)
    assert all(not isinstance(item, BaseException) for item in replaced)
    assert "sqlalchemy.exc." in replaced[999]
    assert len(replaced) == len(inside)

    # ...and one past it is NOT: the documented residual, pinned so it is not
    # mistaken for coverage.
    beyond = _CountingList([0] * log_safety._MAX_ITEMS + [driver_error])
    assert _first_arg(beyond)[-1] is driver_error


@pytest.mark.usefixtures("installed")
def test_the_depth_the_scrub_reaches_is_one_container_and_no_more(
    driver_error: Exception,
) -> None:
    """Pins `_scrub_value`'s documented reach. `[[e]]` and a set are NOT covered."""
    assert isinstance(_first_arg(driver_error), str)
    for one_container in ([driver_error], (driver_error,)):
        scrubbed = _first_arg(one_container)
        assert driver_error not in scrubbed
    # A lone mapping argument becomes `record.args` itself (logging's own rule).
    mapping_record = _record({"k": driver_error})
    assert isinstance(mapping_record.args, dict)
    assert isinstance(mapping_record.args["k"], str)
    assert _first_arg([[driver_error]])[0][0] is driver_error
    assert _first_arg({driver_error}) == {driver_error}


@pytest.mark.usefixtures("installed")
def test_a_plain_record_is_not_modified() -> None:
    factory = logging.getLogRecordFactory()
    record = factory("n", logging.INFO, __file__, 1, "msg %s", ("a",), None)
    assert record.getMessage() == "msg a"
    assert record.exc_info is None and record.exc_text is None
    assert record.args == ("a",)


# ---------------------------------------------------------------------------
# Install: idempotent, chained, never raising.
# ---------------------------------------------------------------------------


def _depth(factory: Any) -> int:
    count = 0
    while factory is not None:
        if getattr(factory, "_postern_sql_safe_factory", False):
            count += 1
        factory = getattr(factory, "__wrapped__", None)
    return count


@pytest.mark.usefixtures("plain_factory")
def test_install_wraps_exactly_once_however_often_it_runs() -> None:
    for _ in range(3):
        install_sql_safe_logging()
    assert _depth(logging.getLogRecordFactory()) == 1


@pytest.mark.usefixtures("plain_factory")
def test_a_previously_installed_custom_factory_still_runs() -> None:
    original = logging.getLogRecordFactory()

    def custom(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = original(*args, **kwargs)
        record.tenant = "t-1"
        return record

    logging.setLogRecordFactory(custom)
    install_sql_safe_logging()
    install_sql_safe_logging()
    record = logging.getLogRecordFactory()("n", logging.INFO, __file__, 1, "m", (), None)
    assert record.tenant == "t-1"  # type: ignore[attr-defined]
    assert _depth(logging.getLogRecordFactory()) == 1


@pytest.mark.usefixtures("installed")
def test_a_dict_config_after_the_install_leaves_the_factory_sanitising(
    driver_error: Exception,
) -> None:
    import logging.config

    saved_handlers = list(logging.getLogger().handlers)
    # `disable_existing_loggers: True` disables every logger that exists, for the
    # rest of the process: put each flag back, or this test silences every other
    # test's logger (it did, and `tests/test_audit_reserve.py` failed for it).
    saved_disabled = {
        name: logger.disabled
        for name, logger in logging.root.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})
    try:
        assert _depth(logging.getLogRecordFactory()) == 1
        with _Capture("services.api.consent") as captured:
            logging.getLogger("services.api.consent").disabled = False
            logging.getLogger("services.api.consent").error("x", exc_info=driver_error)
        _assert_clean(captured)
        assert "withheld" in captured.own.getvalue()
    finally:
        logging.getLogger().handlers[:] = saved_handlers
        for name, logger in logging.root.manager.loggerDict.items():
            if isinstance(logger, logging.Logger):
                logger.disabled = saved_disabled.get(name, False)


@pytest.mark.usefixtures("plain_factory")
def test_install_pins_the_sqlalchemy_loggers_that_write_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("sqlalchemy.engine", "sqlalchemy.pool"):
        monkeypatch.setattr(logging.getLogger(name), "level", logging.DEBUG)
    install_sql_safe_logging()
    assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING
    assert logging.getLogger("sqlalchemy.pool").level == logging.WARNING


@pytest.mark.usefixtures("installed")
def test_the_factory_never_raises_when_sanitising_itself_fails(
    driver_error: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Hostile(Exception):
        def __str__(self) -> str:
            raise RuntimeError(UNIQUE_SENTINEL_A)

        def __repr__(self) -> str:
            raise RuntimeError(UNIQUE_SENTINEL_A)

    def broken(exc: BaseException) -> Any:
        raise RuntimeError(UNIQUE_SENTINEL_A)

    monkeypatch.setattr(log_safety, "_chain", broken)
    with _Capture("services.api.consent") as captured:
        log = logging.getLogger("services.api.consent")
        log.error("x %s", Hostile(UNIQUE_SENTINEL_A))
        log.error("y", exc_info=driver_error)
    _assert_clean(captured)

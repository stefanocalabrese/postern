"""The log filter that keeps SQL, bound parameters and driver messages out of
uncaught-error logs (`postern_core.log_safety`).

WHY IT EXISTS, measured: when a SQL driver error escapes an ASGI handler,
uvicorn logs ``Exception in ASGI application`` with the whole exception chain.
SQLAlchemy's ``DBAPIError`` text carries ``[SQL: ...]`` and ``[parameters:
(...)]`` (customer refs, assertion ``jti`` values, signatures), and the
asyncpg message under it can carry values of its own (a unique violation's
``DETAIL Key (a, b)=(x, y) already exists``). The approval callback re-raises
on purpose (decision 0006), so the fix is to make the LOG safe.

The sentinels below are held in module constants and referred to by NAME in
every call, because a traceback frame prints its source line: a literal on the
raising line would appear in the output as code, and these tests assert that
the VALUE appears nowhere.

The filter is proven here on an engine WITHOUT ``hide_parameters``, so what
passes is the filter alone; ``tests/test_sql_safe_logging_uvicorn.py`` proves
the whole stack through a real uvicorn server.
"""

import io
import logging
import signal
from collections.abc import AsyncIterator, Iterator
from contextlib import contextmanager

import anyio
import asyncpg  # type: ignore[import-untyped]
import pytest
from postern_core.log_safety import (
    SqlSafeExceptionFilter,
    chain_holds_driver_error,
    describe_exception,
    exc_info_for_log,
)
from postern_core.store.engine import Database
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

PARAM_SENTINEL = "bf_param_leak_7731"
UNIQUE_SENTINEL_A = "bf_unique_a_leak_7731"
UNIQUE_SENTINEL_B = "bf_unique_b_leak_7731"
MESSAGE_SENTINEL = "bf_message_leak_7731"
NUL_SENTINEL = "bf_nul_leak_7731\x00tail"

ALL_SENTINELS = (
    PARAM_SENTINEL,
    UNIQUE_SENTINEL_A,
    UNIQUE_SENTINEL_B,
    MESSAGE_SENTINEL,
    "bf_nul_leak_7731",
)

WITHHELD = "[message, SQL and parameters withheld]"


def _logger(*, with_filter: bool = True) -> tuple[logging.Logger, io.StringIO]:
    """A private logger rendering like uvicorn's default formatter."""
    log = logging.Logger("sqlsafe.unit")
    log.propagate = False
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    log.addHandler(handler)
    if with_filter:
        log.addFilter(SqlSafeExceptionFilter())
    return log, buffer


def _render(exc: BaseException, *, with_filter: bool = True) -> str:
    log, buffer = _logger(with_filter=with_filter)
    log.error("Exception in ASGI application", exc_info=exc)
    return buffer.getvalue()


@pytest.fixture(autouse=True)
def _plain_record_factory() -> Iterator[None]:
    """These tests measure `SqlSafeExceptionFilter` and the unfiltered baseline on
    private loggers; a record factory installed by an earlier test (any `create_app`)
    would sanitise the baseline too, so none is installed here. Put back after."""
    previous = logging.getLogRecordFactory()
    logging.setLogRecordFactory(logging.LogRecord)
    yield
    logging.setLogRecordFactory(previous)


@pytest.fixture
async def engine(pg_url: str) -> AsyncIterator[AsyncEngine]:
    """An engine WITHOUT ``hide_parameters``: the filter has to do it alone."""
    eng = create_async_engine(pg_url)
    assert eng.sync_engine.hide_parameters is False
    yield eng
    await eng.dispose()


async def _param_error(engine: AsyncEngine) -> Exception:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT CAST(:p AS int)"), {"p": PARAM_SENTINEL})
    except Exception as exc:
        return exc
    raise AssertionError("the statement was expected to fail")


async def _nul_error(engine: AsyncEngine) -> Exception:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT CAST(:p AS text)"), {"p": NUL_SENTINEL})
    except Exception as exc:
        return exc
    raise AssertionError("the statement was expected to fail")


async def _unique_error(engine: AsyncEngine) -> Exception:
    try:
        async with engine.begin() as conn:
            await conn.execute(text("DROP TABLE IF EXISTS sqlsafe_uniq"))
            await conn.execute(text("CREATE TABLE sqlsafe_uniq (a text, b text, UNIQUE (a, b))"))
        async with engine.connect() as conn:
            insert = text("INSERT INTO sqlsafe_uniq (a, b) VALUES (:a, :b)")
            values = {"a": UNIQUE_SENTINEL_A, "b": UNIQUE_SENTINEL_B}
            await conn.execute(insert, values)
            await conn.execute(insert, values)
    except Exception as exc:
        return exc
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("DROP TABLE IF EXISTS sqlsafe_uniq"))
    raise AssertionError("the second insert was expected to fail")


def _assert_clean(rendered: str) -> None:
    for sentinel in ALL_SENTINELS:
        assert sentinel not in rendered, sentinel


# ---------------------------------------------------------------------------
# The harness is real: without the filter, the leak is there.
# ---------------------------------------------------------------------------


async def test_without_the_filter_the_parameters_and_the_driver_message_leak(
    engine: AsyncEngine,
) -> None:
    exc = await _param_error(engine)
    rendered = _render(exc, with_filter=False)
    assert "[parameters:" in rendered
    assert PARAM_SENTINEL in rendered

    unique = await _unique_error(engine)
    unique_rendered = _render(unique, with_filter=False)
    assert UNIQUE_SENTINEL_A in unique_rendered


# ---------------------------------------------------------------------------
# What the filter renders.
# ---------------------------------------------------------------------------


async def test_a_bound_parameter_error_keeps_frames_types_and_sqlstate_only(
    engine: AsyncEngine,
) -> None:
    exc = await _param_error(engine)
    assert isinstance(exc, DBAPIError)
    sqlstate = exc.orig.sqlstate  # type: ignore[union-attr]
    # Raised by asyncpg while ENCODING the parameter: no server was involved, and
    # the class attribute below says 22000 anyway.
    assert sqlstate == "22000"
    assert "sqlstate" not in vars(exc.orig.__cause__)  # type: ignore[union-attr]

    rendered = _render(exc)

    _assert_clean(rendered)
    assert "Exception in ASGI application" in rendered
    assert "sqlalchemy.exc.DBAPIError" in rendered
    assert "asyncpg.exceptions.DataError" in rendered
    assert "client-side" in rendered
    assert "22000" not in rendered
    assert "sqlstate=" not in rendered
    assert WITHHELD in rendered
    assert "test_sql_safe_logging.py" in rendered  # a traceback frame of this file
    assert "[SQL:" not in rendered
    assert "[parameters:" not in rendered


async def test_a_unique_violation_detail_does_not_reach_the_log(engine: AsyncEngine) -> None:
    exc = await _unique_error(engine)
    assert isinstance(exc, DBAPIError)
    assert exc.orig.sqlstate == "23505"  # type: ignore[union-attr]

    rendered = _render(exc)

    _assert_clean(rendered)
    assert "sqlstate=23505" in rendered
    assert "asyncpg.exceptions.UniqueViolationError" in rendered
    assert "already exists" not in rendered
    assert "duplicate key" not in rendered


async def test_an_invalid_byte_sequence_does_not_reach_the_log(engine: AsyncEngine) -> None:
    exc = await _nul_error(engine)
    rendered = _render(exc)

    _assert_clean(rendered)
    # What Postgres really answers for a NUL in a text parameter.
    assert "sqlstate=22021" in rendered, rendered
    assert "invalid byte sequence" not in rendered


async def test_the_sanitised_text_is_what_a_real_formatter_renders(engine: AsyncEngine) -> None:
    exc = await _param_error(engine)
    record = logging.LogRecord(
        "t", logging.ERROR, __file__, 1, "msg", None, (type(exc), exc, exc.__traceback__)
    )
    assert SqlSafeExceptionFilter().filter(record) is True
    assert record.exc_info is None
    assert record.exc_text is not None
    assert WITHHELD in record.exc_text
    formatted = logging.Formatter("%(message)s").format(record)
    assert formatted == "msg\n" + record.exc_text
    _assert_clean(formatted)


# ---------------------------------------------------------------------------
# Chains.
# ---------------------------------------------------------------------------


async def test_a_wrapper_raised_from_a_driver_error_is_sanitised(engine: AsyncEngine) -> None:
    cause = await _param_error(engine)
    try:
        raise RuntimeError(MESSAGE_SENTINEL) from cause
    except RuntimeError as wrapper:
        rendered = _render(wrapper)
    _assert_clean(rendered)
    assert "RuntimeError" in rendered
    assert "sqlalchemy.exc.DBAPIError" in rendered


async def test_an_implicit_context_driver_error_is_sanitised(engine: AsyncEngine) -> None:
    try:
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT CAST(:p AS int)"), {"p": PARAM_SENTINEL})
        except Exception:
            raise RuntimeError(MESSAGE_SENTINEL)  # noqa: B904 - implicit __context__ is the case
    except RuntimeError as wrapper:
        assert wrapper.__cause__ is None
        assert wrapper.__context__ is not None
        rendered = _render(wrapper)
    _assert_clean(rendered)
    assert "sqlalchemy.exc.DBAPIError" in rendered


async def test_a_cyclic_chain_terminates_and_is_sanitised(engine: AsyncEngine) -> None:
    exc = await _param_error(engine)
    other = RuntimeError(MESSAGE_SENTINEL)
    other.__context__ = exc
    exc.__context__ = other
    rendered = _render(other)
    _assert_clean(rendered)
    assert "sqlalchemy.exc.DBAPIError" in rendered


async def test_a_deep_chain_with_the_driver_error_at_the_root_is_sanitised(
    engine: AsyncEngine,
) -> None:
    current: BaseException = await _param_error(engine)
    for _ in range(30):
        try:
            raise ValueError(MESSAGE_SENTINEL) from current
        except ValueError as err:
            current = err
    rendered = _render(current)
    _assert_clean(rendered)
    assert "sqlalchemy.exc.DBAPIError" in rendered


@contextmanager
def _time_bound(seconds: int) -> Iterator[None]:
    """Fail the test, rather than hang the run, if the body does not finish.

    A regression here (the bound ignored) used to hang the suite for about 19
    minutes inside `traceback`'s rendering of a 400-deep chain.
    """

    def on_alarm(signum: int, frame: object) -> None:
        raise TimeoutError(f"did not finish within {seconds}s")

    previous = signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def test_a_chain_deeper_than_the_bound_is_withheld_whole() -> None:
    """Past the bound the tail is unknown, and unknown is treated as SQL."""
    current: BaseException = ValueError(MESSAGE_SENTINEL)
    with _time_bound(30):
        for _ in range(400):
            try:
                raise ValueError(MESSAGE_SENTINEL) from current
            except ValueError as err:
                current = err
        # NOT rendered through a logger: if the bound were ignored, logging's
        # own formatting of a 400-deep chain is what hung the suite, and its
        # `handleError` formats the TimeoutError again. The record is inspected
        # instead, so a regression fails here, fast.
        record = logging.LogRecord(
            "t", logging.ERROR, __file__, 1, "msg", None, (type(current), current, None)
        )
        SqlSafeExceptionFilter().filter(record)
        assert chain_holds_driver_error(current) is True
    assert record.exc_info is None
    assert record.exc_text is not None
    _assert_clean(record.exc_text)
    assert WITHHELD in record.exc_text


def test_a_bare_asyncpg_exception_without_the_sqlalchemy_wrapper_is_sanitised() -> None:
    bare = asyncpg.exceptions.UniqueViolationError(
        f"duplicate key value violates unique constraint, Key (a)=({MESSAGE_SENTINEL})"
    )
    rendered = _render(bare)
    _assert_clean(rendered)
    assert "asyncpg.exceptions.UniqueViolationError" in rendered
    # Built in the client: the class says 23505, no server said it.
    assert "client-side" in rendered
    assert "23505" not in rendered

    try:
        raise RuntimeError("wrapper") from bare
    except RuntimeError as wrapper:
        wrapped = _render(wrapper)
    _assert_clean(wrapped)
    assert "asyncpg.exceptions.UniqueViolationError" in wrapped


async def test_an_exception_whose_str_raises_does_not_break_the_filter(
    engine: AsyncEngine,
) -> None:
    class Hostile(Exception):
        def __str__(self) -> str:
            raise RuntimeError(MESSAGE_SENTINEL)

        def __repr__(self) -> str:
            raise RuntimeError(MESSAGE_SENTINEL)

    cause = await _param_error(engine)
    try:
        raise Hostile(MESSAGE_SENTINEL) from cause
    except Hostile as hostile:
        rendered = _render(hostile)
    _assert_clean(rendered)
    assert "Hostile" in rendered
    assert "sqlalchemy.exc.DBAPIError" in rendered


def test_a_hostile_attribute_falls_back_to_type_names_only() -> None:
    class Hostile(asyncpg.exceptions.PostgresError):  # type: ignore[misc]
        @property
        def sqlstate(self) -> str:
            raise RuntimeError(MESSAGE_SENTINEL)

    rendered = _render(Hostile(MESSAGE_SENTINEL))
    _assert_clean(rendered)
    assert "Hostile" in rendered


# ---------------------------------------------------------------------------
# Exception groups: a task group wraps what its children raised.
# ---------------------------------------------------------------------------


async def test_an_exception_group_holding_a_driver_error_is_sanitised(
    engine: AsyncEngine,
) -> None:
    inner = await _param_error(engine)
    group = ExceptionGroup("tg", [inner])
    rendered = _render(group)
    _assert_clean(rendered)
    assert "sqlalchemy.exc.DBAPIError" in rendered
    assert chain_holds_driver_error(group) is True


async def test_a_nested_base_exception_group_is_sanitised(engine: AsyncEngine) -> None:
    inner = await _param_error(engine)
    nested = BaseExceptionGroup("outer", [KeyboardInterrupt(), ExceptionGroup("mid", [inner])])
    rendered = _render(nested)
    _assert_clean(rendered)
    assert "sqlalchemy.exc.DBAPIError" in rendered


async def test_a_real_anyio_task_group_leaks_nothing(engine: AsyncEngine) -> None:
    driver_error = await _param_error(engine)

    async def child() -> None:
        raise driver_error

    caught: BaseExceptionGroup[Exception] | None = None
    try:
        async with anyio.create_task_group() as group:
            group.start_soon(child)
    except BaseExceptionGroup as raised:
        caught = raised
    assert caught is not None
    rendered = _render(caught)
    _assert_clean(rendered)
    assert "sqlalchemy.exc.DBAPIError" in rendered
    assert WITHHELD in rendered


def test_a_non_sql_exception_group_is_left_alone() -> None:
    group = ExceptionGroup("tg", [ValueError("plain detail")])
    assert _render(group) == _render(group, with_filter=False)
    assert chain_holds_driver_error(group) is False


# ---------------------------------------------------------------------------
# What the SQLSTATE position can say.
# ---------------------------------------------------------------------------


def test_a_value_bearing_sqlstate_is_never_printed() -> None:
    forged = asyncpg.exceptions.UniqueViolationError("m")
    forged.sqlstate = f"23505'{MESSAGE_SENTINEL}"
    rendered = _render(forged)
    _assert_clean(rendered)
    assert "23505'" not in rendered
    assert "client-side" in rendered


def test_a_sqlstate_set_only_on_the_wrapped_orig_is_read() -> None:
    orig = Exception(MESSAGE_SENTINEL)
    orig.sqlstate = "40001"  # type: ignore[attr-defined]
    wrapper = DBAPIError("SELECT 1", None, orig)
    rendered = _render(wrapper)
    _assert_clean(rendered)
    assert "sqlalchemy.exc.DBAPIError sqlstate=40001" in rendered


def test_a_wrong_length_or_lowercase_sqlstate_on_the_orig_is_not_printed() -> None:
    for bad in ("4000", "400011", "4000a", "40 01"):
        orig = Exception(MESSAGE_SENTINEL)
        orig.sqlstate = bad  # type: ignore[attr-defined]
        rendered = _render(DBAPIError("SELECT 1", None, orig))
        assert "sqlstate=" not in rendered, bad


async def test_describe_exception_is_type_and_sqlstate_only(engine: AsyncEngine) -> None:
    client_side = await _param_error(engine)
    described = describe_exception(client_side)
    assert described == ("sqlalchemy.exc.DBAPIError, asyncpg.exceptions.DataError client-side")
    server_side = await _unique_error(engine)
    assert describe_exception(server_side) == (
        "sqlalchemy.exc.IntegrityError, asyncpg.exceptions.UniqueViolationError sqlstate=23505"
    )
    for text_out in (described, describe_exception(server_side)):
        _assert_clean(text_out)


def test_describe_exception_never_raises_and_names_a_plain_exception_by_type() -> None:
    class Hostile(Exception):
        def __str__(self) -> str:
            raise RuntimeError(MESSAGE_SENTINEL)

    assert describe_exception(Hostile(MESSAGE_SENTINEL)).endswith("Hostile")
    assert describe_exception(None) == "<no exception>"


def test_exc_info_for_log_keeps_ordinary_exceptions_and_drops_driver_errors() -> None:
    plain = ValueError("plain")
    assert exc_info_for_log(plain) is plain
    assert exc_info_for_log(None) is None
    assert exc_info_for_log(asyncpg.exceptions.DataError("m")) is None


# ---------------------------------------------------------------------------
# What it leaves alone.
# ---------------------------------------------------------------------------


def _raise_non_sql() -> ValueError:
    try:
        try:
            raise KeyError("inner detail")
        except KeyError as inner:
            raise ValueError("outer detail") from inner
    except ValueError as outer:
        return outer


def test_a_non_sql_exception_renders_byte_identically_to_no_filter() -> None:
    exc = _raise_non_sql()
    assert _render(exc) == _render(exc, with_filter=False)
    assert "outer detail" in _render(exc)
    assert "inner detail" in _render(exc)


def test_a_record_without_exc_info_is_untouched() -> None:
    log, buffer = _logger()
    log.error("plain %s", "line")
    assert buffer.getvalue() == "ERROR: plain line\n"


def test_the_filter_never_drops_a_record() -> None:
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "msg", None, None)
    assert SqlSafeExceptionFilter().filter(record) is True


# ---------------------------------------------------------------------------
# The engines hide parameters themselves.
# ---------------------------------------------------------------------------


async def test_both_database_engines_hide_parameters_and_say_so(pg_url: str) -> None:
    db = Database(pg_url, audit_reserve_size=1)
    try:
        assert db.audit_reserve is not None
        assert db.engine.sync_engine.hide_parameters is True
        assert db.audit_reserve.sync_engine.hide_parameters is True
        for engine in (db.engine, db.audit_reserve):
            exc = await _param_error(engine)
            assert isinstance(exc, DBAPIError)
            assert "hidden" in str(exc)
            assert "[SQL parameters hidden due to hide_parameters=True]" in str(exc)
            assert "[parameters:" not in str(exc)
            # NOT asserted: that the sentinel is absent. Measured: asyncpg's own
            # message ("invalid input for query argument $1: 'value' ...") names
            # the value, and hide_parameters does not touch it. That is the
            # half the log filter exists for.
    finally:
        await db.close()


async def test_a_null_pool_database_hides_parameters_too(pg_url: str) -> None:
    db = Database(pg_url, null_pool=True)
    try:
        assert db.engine.sync_engine.hide_parameters is True
    finally:
        await db.close()

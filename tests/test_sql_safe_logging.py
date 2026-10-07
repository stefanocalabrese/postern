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
import re
from collections.abc import AsyncIterator, Iterator

import asyncpg  # type: ignore[import-untyped]
import pytest
from postern_core.log_safety import (
    SqlSafeExceptionFilter,
    install_sql_safe_logging,
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
    assert sqlstate == "22000"

    rendered = _render(exc)

    _assert_clean(rendered)
    assert "Exception in ASGI application" in rendered
    assert "sqlalchemy.exc.DBAPIError" in rendered
    assert "asyncpg.exceptions.DataError" in rendered
    assert "22000" in rendered
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
    assert "23505" in rendered
    assert "asyncpg.exceptions.UniqueViolationError" in rendered
    assert "already exists" not in rendered
    assert "duplicate key" not in rendered


async def test_an_invalid_byte_sequence_does_not_reach_the_log(engine: AsyncEngine) -> None:
    exc = await _nul_error(engine)
    rendered = _render(exc)

    _assert_clean(rendered)
    # What Postgres really answers for a NUL in a text parameter.
    assert re.search(r"\b22021\b", rendered), rendered
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


def test_a_chain_deeper_than_the_bound_is_withheld_whole() -> None:
    """Past the bound the tail is unknown, and unknown is treated as SQL."""
    current: BaseException = ValueError(MESSAGE_SENTINEL)
    for _ in range(400):
        try:
            raise ValueError(MESSAGE_SENTINEL) from current
        except ValueError as err:
            current = err
    rendered = _render(current)
    _assert_clean(rendered)
    assert WITHHELD in rendered


def test_a_bare_asyncpg_exception_without_the_sqlalchemy_wrapper_is_sanitised() -> None:
    bare = asyncpg.exceptions.UniqueViolationError(
        f"duplicate key value violates unique constraint, Key (a)=({MESSAGE_SENTINEL})"
    )
    rendered = _render(bare)
    _assert_clean(rendered)
    assert "asyncpg.exceptions.UniqueViolationError" in rendered
    assert "23505" in rendered  # the class attribute, readable without a message

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
# Install.
# ---------------------------------------------------------------------------


@pytest.fixture
def _clean_uvicorn_filters() -> Iterator[None]:
    names = ("uvicorn.error", "uvicorn")
    saved = {n: list(logging.getLogger(n).filters) for n in names}
    for n in names:
        logging.getLogger(n).filters[:] = []
    yield
    for n in names:
        logging.getLogger(n).filters[:] = saved[n]


@pytest.mark.usefixtures("_clean_uvicorn_filters")
def test_install_attaches_exactly_one_filter_per_logger_however_often_it_runs() -> None:
    for _ in range(3):
        install_sql_safe_logging()
    for name in ("uvicorn.error", "uvicorn"):
        mine = [f for f in logging.getLogger(name).filters if isinstance(f, SqlSafeExceptionFilter)]
        assert len(mine) == 1, name


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

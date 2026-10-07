# ruff: noqa: F811
"""How far the log record factory reaches (`postern_core.log_safety`).

The factory used to scan ONE container level of a record's arguments. Measured
leaks, each now covered and pinned here with a real asyncpg error (a bound
parameter carrying a sentinel, and a unique violation whose DETAIL carries two
more), rendered by a plain `StreamHandler` on a named logger and on root:

* an exception nested deeper (`[[e]]`), in a set or frozenset, or held by a
  dataclass, a plain object, a `__slots__` object or a namespace;
* `extra={"err": e}` rendered by a custom formatter;
* `logging.makeLogRecord`, which builds a record without `Logger._log`;
* `warnings.warn` text of a SQLAlchemy warning, which `captureWarnings` routes
  through the `py.warnings` logger.

What stays uncovered is pinned too, so it is not mistaken for coverage: an
exception past the node budget or the depth cap, and a wrapper whose own text
embeds the driver's.

The sentinels are module constants referred to by name, as in the sibling files.
"""

import dataclasses
import io
import logging
import subprocess
import sys
import types
import warnings
from collections import deque
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from postern_core import log_safety
from postern_core.log_safety import install_sql_safe_logging
from sqlalchemy.exc import SAWarning

from tests.test_sql_safe_logging import ALL_SENTINELS, UNIQUE_SENTINEL_A
from tests.test_sql_safe_logging_factory import (  # noqa: F401  (fixtures)
    _Capture,
    _CountingList,
    driver_error,
    engine,
    installed,
    plain_factory,
)

ROOT = Path(__file__).resolve().parent.parent
#: The most items any scan may pull out of containers per record. A literal, not
#: `log_safety._MAX_NODES`: a test that reads the limit from the module it tests
#: passes whatever the limit is set to.
ABSOLUTE_BUDGET = 5000
LOG = "services.api.consent"


@dataclasses.dataclass
class _Wrapper:
    err: BaseException


class _Plain:
    def __init__(self, err: BaseException) -> None:
        self.err = err

    def __repr__(self) -> str:
        return f"_Plain({self.err!r})"


class _Slotted:
    __slots__ = ("err", "other")

    def __init__(self, err: BaseException) -> None:
        self.err = err
        self.other = 1

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.err!r})"


class _SlottedChild(_Slotted):
    __slots__ = ("more",)


class _Holder:
    """Defines a `__dict__` holding a list that holds the exception."""

    def __init__(self, err: BaseException) -> None:
        self.items = [err]

    def __repr__(self) -> str:
        return f"_Holder({self.items!r})"


SHAPES: dict[str, Callable[[Any], Any]] = {
    "nested list": lambda e: [[e]],
    "list in tuple": lambda e: ((e,),),
    "dict in list in dict": lambda e: {"k": [{"j": e}]},
    "dict key": lambda e: {e: 1},
    "set": lambda e: {e},
    "frozenset": lambda e: frozenset({e}),
    "deque": lambda e: deque([e]),
    "dataclass": lambda e: _Wrapper(e),
    "plain object": lambda e: _Plain(e),
    "slots object": lambda e: _Slotted(e),
    "slots in a subclass": lambda e: _SlottedChild(e),
    "object holding a list": lambda e: _Holder(e),
    "namespace": lambda e: types.SimpleNamespace(err=e),
    "wrapper in a list in a list": lambda e: [[_Plain(e)]],
    "wrapper exception holding it in args": lambda e: RuntimeError("outer", e),
}


def _rendered(log: logging.Logger, value: Any) -> str:
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    try:
        log.error("value: %s", value)
        log.error("repr: %r", value)
    finally:
        log.removeHandler(handler)
    return buffer.getvalue()


def _clean(text: str) -> None:
    for sentinel in ALL_SENTINELS:
        assert sentinel not in text, (sentinel, text)


# ---------------------------------------------------------------------------
# (1) (2) (3): deeper nesting, sets, wrapper objects.
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("installed")
@pytest.mark.parametrize("name", [LOG, ""])
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_a_driver_error_in_every_shape_is_withheld(
    shape: str, name: str, driver_error: Exception
) -> None:
    log = logging.getLogger(name)
    with _Capture(name) as captured:
        log.error("value: %s", SHAPES[shape](driver_error))
        log.error("repr: %r", SHAPES[shape](driver_error))
    _clean(captured.everything)
    assert "sqlalchemy.exc." in captured.own.getvalue()


@pytest.mark.usefixtures("installed")
def test_an_object_holding_one_is_named_by_type_and_says_so(driver_error: Exception) -> None:
    out = _rendered(logging.getLogger(LOG), _Wrapper(driver_error))
    assert "<_Wrapper holding a driver error:" in out
    assert "sqlalchemy.exc." in out


@pytest.mark.usefixtures("installed")
def test_the_same_shapes_without_the_factory_do_leak(driver_error: Exception) -> None:
    """The harness is real: a plain factory renders the sentinel in these shapes."""
    logging.setLogRecordFactory(logging.LogRecord)
    leaks = [
        shape
        for shape in ("nested list", "set", "dataclass", "slots object")
        if any(
            sentinel in _rendered(logging.getLogger(LOG), SHAPES[shape](driver_error))
            for sentinel in ALL_SENTINELS
        )
    ]
    assert leaks == ["nested list", "set", "dataclass", "slots object"]


@pytest.mark.usefixtures("installed")
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_non_sql_exceptions_in_the_same_shapes_are_untouched_byte_for_byte(shape: str) -> None:
    error = ValueError("plain detail")
    value = SHAPES[shape](error)
    log = logging.getLogger(LOG)
    with_factory = _rendered(log, value)
    logging.setLogRecordFactory(logging.LogRecord)
    without_factory = _rendered(log, value)
    assert with_factory == without_factory
    assert "plain detail" in with_factory


@pytest.mark.usefixtures("installed")
def test_a_shared_exception_in_two_places_is_withheld_in_both(driver_error: Exception) -> None:
    inner = [driver_error]
    out = _rendered(logging.getLogger(LOG), [driver_error, inner, [inner], (inner, inner)])
    _clean(out)


@pytest.mark.usefixtures("installed")
def test_a_self_referential_structure_terminates(driver_error: Exception) -> None:
    cyclic: list[Any] = [driver_error]
    cyclic.append(cyclic)
    mapping: dict[str, Any] = {"e": driver_error}
    mapping["self"] = mapping
    obj = _Plain(driver_error)
    obj.err = [driver_error, obj]  # type: ignore[assignment]
    for value in (cyclic, mapping, obj):
        _clean(_rendered(logging.getLogger(LOG), value))
    plain: list[Any] = []
    plain.append(plain)
    assert _first_arg(plain) is plain  # nothing found, nothing rebuilt


def _record(arg: Any) -> logging.LogRecord:
    return logging.getLogRecordFactory()("n", logging.ERROR, __file__, 1, "m %s", (arg,), None)


def _first_arg(arg: Any) -> Any:
    args: Any = _record(arg).args
    return args[0]


def _second_arg(arg: Any) -> Any:
    """`LogRecord.__init__` itself calls `isinstance(args[0], Mapping)`, which reads
    a hostile object's `__class__`: stdlib code, not ours. A second argument
    keeps the object out of that call."""
    record = logging.getLogRecordFactory()("n", logging.ERROR, __file__, 1, "%s %s", (0, arg), None)
    args: Any = record.args
    return args[1]


# ---------------------------------------------------------------------------
# The budget, the depth cap and the residuals they leave.
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("installed")
def test_a_million_element_nested_list_is_scanned_within_the_node_budget() -> None:
    inner = _CountingList([0] * 1_000_000)
    outer = _CountingList([inner, _CountingList([0] * 1_000_000)])
    _CountingList.iterated = 0
    record = _record(outer)
    assert _CountingList.iterated <= ABSOLUTE_BUDGET
    assert record.args == (outer,)


@pytest.mark.usefixtures("installed")
def test_an_exception_inside_the_budget_is_found_and_one_past_it_is_not(
    driver_error: Exception,
) -> None:
    budget = ABSOLUTE_BUDGET
    inside = _CountingList([0] * 500 + [driver_error] + [0] * (2 * budget))
    replaced = _first_arg(inside)
    assert "sqlalchemy.exc." in replaced[500]
    assert len(replaced) == len(inside)
    # The documented residual, pinned so it is not read as coverage.
    beyond = _CountingList([0] * (2 * budget) + [driver_error])
    assert _first_arg(beyond)[-1] is driver_error


@pytest.mark.usefixtures("installed")
def test_an_unlimited_budget_would_be_visible(driver_error: Exception) -> None:
    """The budget is a number, not an accident: it is bounded and small."""
    assert 1 <= log_safety._MAX_NODES <= ABSOLUTE_BUDGET
    assert 1 <= log_safety._MAX_DEPTH <= 50


@pytest.mark.usefixtures("installed")
def test_an_exception_past_the_depth_cap_is_not_scanned(driver_error: Exception) -> None:
    def nest(levels: int) -> Any:
        value: Any = [driver_error]
        for _ in range(levels):
            value = [value]
        return value

    shallow = _first_arg(nest(log_safety._MAX_DEPTH - 4))
    node = shallow
    while isinstance(node, list):
        node = node[0]
    assert isinstance(node, str)

    deep = nest(log_safety._MAX_DEPTH + 5)
    result = _first_arg(deep)
    node = result
    while isinstance(node, list):
        node = node[0]
    assert node is driver_error  # the residual


@pytest.mark.usefixtures("installed")
def test_a_wrapper_whose_own_text_embeds_the_drivers_is_the_documented_residual(
    driver_error: Exception,
) -> None:
    wrapped = RuntimeError(f"wrapped: {driver_error}")  # not chained, not holding the object
    out = _rendered(logging.getLogger(LOG), wrapped)
    assert any(sentinel in out for sentinel in ALL_SENTINELS)


# ---------------------------------------------------------------------------
# Hostile objects: no user code runs while scanning.
# ---------------------------------------------------------------------------

CALLS: list[str] = []


class _Hostile:
    def __getattribute__(self, name: str) -> Any:
        CALLS.append(f"getattribute {name}")
        raise RuntimeError(UNIQUE_SENTINEL_A)

    def __getattr__(self, name: str) -> Any:
        CALLS.append(f"getattr {name}")
        raise AttributeError(name)

    def __repr__(self) -> str:
        CALLS.append("repr")
        raise RuntimeError(UNIQUE_SENTINEL_A)

    def __str__(self) -> str:
        CALLS.append("str")
        raise RuntimeError(UNIQUE_SENTINEL_A)

    def __iter__(self) -> Iterator[Any]:
        CALLS.append("iter")
        raise RuntimeError(UNIQUE_SENTINEL_A)

    def __len__(self) -> int:
        CALLS.append("len")
        raise RuntimeError(UNIQUE_SENTINEL_A)

    def __eq__(self, other: object) -> bool:
        CALLS.append("eq")
        raise RuntimeError(UNIQUE_SENTINEL_A)

    def __hash__(self) -> int:
        CALLS.append("hash")
        raise RuntimeError(UNIQUE_SENTINEL_A)


@pytest.mark.usefixtures("installed")
def test_hostile_objects_do_not_run_user_code_while_scanning(driver_error: Exception) -> None:
    CALLS.clear()
    plain = _Hostile()
    assert _second_arg(plain) is plain
    assert _first_arg([plain, (plain,)])  # no raise
    holding = _Hostile()
    object.__setattr__(holding, "err", driver_error)
    replaced = _second_arg(holding)
    assert isinstance(replaced, str) and "holding a driver error" in replaced
    assert CALLS == []


@pytest.mark.usefixtures("installed")
def test_a_hostile_object_inside_a_container_next_to_an_exception(
    driver_error: Exception,
) -> None:
    CALLS.clear()
    result = _first_arg([_Hostile(), driver_error])
    assert isinstance(result[1], str)
    assert CALLS == []


# ---------------------------------------------------------------------------
# (6) extras.
# ---------------------------------------------------------------------------


class _ExtraFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return f"{record.getMessage()} | err={getattr(record, 'err', None)}"


def _extra_output(extra: dict[str, Any]) -> str:
    log = logging.getLogger(LOG)
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(_ExtraFormatter())
    log.addHandler(handler)
    root_buffer = io.StringIO()
    root_handler = logging.StreamHandler(root_buffer)
    root_handler.setFormatter(_ExtraFormatter())
    logging.getLogger().addHandler(root_handler)
    previous = log.level
    log.setLevel(logging.DEBUG)
    try:
        log.error("with extra", extra=extra)
    finally:
        log.setLevel(previous)
        log.removeHandler(handler)
        logging.getLogger().removeHandler(root_handler)
    return buffer.getvalue() + root_buffer.getvalue()


@pytest.mark.usefixtures("installed")
@pytest.mark.parametrize("shape", ["direct", "list", "dataclass"])
def test_an_exception_in_extra_is_withheld(shape: str, driver_error: Exception) -> None:
    value = {
        "direct": driver_error,
        "list": [driver_error],
        "dataclass": _Wrapper(driver_error),
    }[shape]
    out = _extra_output({"err": value})
    _clean(out)
    assert "sqlalchemy.exc." in out


@pytest.mark.usefixtures("installed")
def test_a_non_sql_exception_in_extra_is_untouched() -> None:
    error = ValueError("plain detail")
    log = logging.getLogger(LOG)
    seen: list[logging.LogRecord] = []

    class Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record)

    grab = Grab()
    log.addHandler(grab)
    try:
        log.error("x", extra={"err": error})
    finally:
        log.removeHandler(grab)
    assert seen[0].err is error  # type: ignore[attr-defined]


@pytest.mark.usefixtures("plain_factory")
def test_without_the_wrap_extra_leaks(driver_error: Exception) -> None:
    original = _unwrapped(logging.Logger.makeRecord)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(logging.Logger, "makeRecord", original)
        out = _extra_output({"err": driver_error})
    assert any(sentinel in out for sentinel in ALL_SENTINELS)


def _unwrapped(function: Any) -> Any:
    while hasattr(function, "__wrapped__"):
        function = function.__wrapped__
    return function


# ---------------------------------------------------------------------------
# (7) makeLogRecord.
# ---------------------------------------------------------------------------


def _from_dict(driver: Exception, **more: Any) -> logging.LogRecord:
    fields: dict[str, Any] = {
        "name": LOG,
        "levelno": logging.ERROR,
        "levelname": "ERROR",
        "msg": "from a dict: %s",
        "args": (driver,),
        "exc_info": (type(driver), driver, driver.__traceback__),
    }
    fields.update(more)
    return logging.makeLogRecord(fields)


@pytest.mark.usefixtures("installed")
def test_make_log_record_is_sanitised(driver_error: Exception) -> None:
    record = _from_dict(driver_error, err=[driver_error])
    out = logging.Formatter("%(message)s | %(err)s").format(record)
    _clean(out)
    assert "sqlalchemy.exc." in out
    assert "withheld" in out


@pytest.mark.usefixtures("installed")
def test_make_log_record_leaves_a_plain_record_alone() -> None:
    record = logging.makeLogRecord({"msg": "m %s", "args": ("a",), "extra_x": 1})
    assert record.getMessage() == "m a" and record.extra_x == 1  # type: ignore[attr-defined]


@pytest.mark.usefixtures("plain_factory")
def test_without_the_wrap_make_log_record_leaks(driver_error: Exception) -> None:
    original = _unwrapped(logging.makeLogRecord)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(logging, "makeLogRecord", original)
        record = _from_dict(driver_error)
        out = logging.Formatter("%(message)s").format(record)
    assert any(sentinel in out for sentinel in ALL_SENTINELS)


# ---------------------------------------------------------------------------
# (8) warnings.
# ---------------------------------------------------------------------------

SA_SENTINEL = "bf_sawarn_leak_7731"


def _warning_output(message: Warning | str, category: type[Warning]) -> str:
    log = logging.getLogger("py.warnings")
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    handler.setFormatter(logging.Formatter("%(message)s"))
    log.addHandler(handler)
    previous = log.propagate
    log.propagate = False
    try:
        log_safety._showwarning(message, category, "somewhere_file", 7)
    finally:
        log.removeHandler(handler)
        log.propagate = previous
    return buffer.getvalue()


def test_a_sqlalchemy_warning_text_is_withheld_and_the_category_is_named() -> None:
    message = SAWarning(f"SELECT {SA_SENTINEL} FROM t")  # noqa: S608
    out = _warning_output(message, SAWarning)
    assert SA_SENTINEL not in out
    assert "SAWarning" in out and "message withheld" in out
    assert "somewhere_file:7" in out


def test_a_sqlalchemy_subclass_and_deprecation_category_are_withheld_too() -> None:
    from sqlalchemy.exc import SADeprecationWarning

    class Mine(SAWarning):
        pass

    for category in (Mine, SADeprecationWarning):
        out = _warning_output(category(SA_SENTINEL), category)
        assert SA_SENTINEL not in out and "message withheld" in out


def test_another_warning_is_logged_with_its_text() -> None:
    out = _warning_output(UserWarning("plain text"), UserWarning)
    assert "UserWarning: plain text" in out and "withheld" not in out


def _run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, this repo's own source
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_install_routes_warn_through_logging_once_and_withholds_sqlalchemy_text() -> None:
    result = _run(
        "import logging, sys, warnings\n"
        "import postern_core.log_safety as ls\n"
        "from sqlalchemy.exc import SAWarning\n"
        "before = warnings.showwarning\n"
        "ls.install_sql_safe_logging()\n"
        "first = warnings.showwarning\n"
        "ls.install_sql_safe_logging()\n"
        "assert warnings.showwarning is first and first is ls._showwarning\n"
        "assert first is not before\n"
        f"warnings.warn(SAWarning('SELECT {SA_SENTINEL}'))\n"
        "warnings.warn('plain warning text')\n"
        "print('done', file=sys.stdout)\n"
    )
    assert result.returncode == 0, result.stderr
    assert SA_SENTINEL not in result.stderr + result.stdout
    assert "message withheld" in result.stderr
    assert "plain warning text" in result.stderr


def test_without_install_a_sqlalchemy_warning_prints_its_text_to_stderr() -> None:
    """The harness is real: with no install the text reaches stderr."""
    result = _run(
        "import warnings\nfrom sqlalchemy.exc import SAWarning\n"
        f"warnings.warn(SAWarning('SELECT {SA_SENTINEL}'))\n"
    )
    assert SA_SENTINEL in result.stderr


def test_the_suite_does_not_capture_warnings_in_process() -> None:
    """tests/conftest.py turns the capture off in the pytest process only."""
    assert warnings.showwarning is not log_safety._showwarning


# ---------------------------------------------------------------------------
# Install: one wrapper each, a custom factory still runs.
# ---------------------------------------------------------------------------


def _depth(function: Any) -> int:
    count = 0
    while function is not None:
        if getattr(function, "_postern_sql_safe_factory", False):
            count += 1
        function = getattr(function, "__wrapped__", None)
    return count


@pytest.fixture
def fresh_hooks(monkeypatch: pytest.MonkeyPatch, plain_factory: None) -> None:
    monkeypatch.setattr(logging.Logger, "makeRecord", _unwrapped(logging.Logger.makeRecord))
    monkeypatch.setattr(logging, "makeLogRecord", _unwrapped(logging.makeLogRecord))


@pytest.mark.usefixtures("fresh_hooks")
def test_install_wraps_each_hook_exactly_once() -> None:
    for _ in range(3):
        install_sql_safe_logging()
    assert _depth(logging.getLogRecordFactory()) == 1
    assert _depth(logging.Logger.makeRecord) == 1
    assert _depth(logging.makeLogRecord) == 1


@pytest.mark.usefixtures("fresh_hooks")
def test_a_custom_factory_installed_earlier_still_runs_and_extras_still_work() -> None:
    original = logging.getLogRecordFactory()

    def custom(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = original(*args, **kwargs)
        record.tenant = "t-1"
        return record

    logging.setLogRecordFactory(custom)
    install_sql_safe_logging()
    install_sql_safe_logging()
    log = logging.getLogger(LOG)
    seen: list[logging.LogRecord] = []

    class Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record)

    grab = Grab()
    log.addHandler(grab)
    try:
        log.error("m", extra={"k": "v"})
    finally:
        log.removeHandler(grab)
    assert seen[0].tenant == "t-1"  # type: ignore[attr-defined]
    assert seen[0].k == "v"  # type: ignore[attr-defined]
    assert _depth(logging.getLogRecordFactory()) == 1


# ---------------------------------------------------------------------------
# When the scan itself fails, nothing is trusted.
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("installed")
def test_a_failing_scan_withholds_every_non_plain_argument_and_extra(
    driver_error: Exception, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(value: Any) -> Any:
        raise RuntimeError(UNIQUE_SENTINEL_A)

    monkeypatch.setattr(log_safety, "_scan", broken)
    wrapper = _Wrapper(driver_error)
    with _Capture(LOG) as captured:
        logging.getLogger(LOG).error("args: %s %s %s", "plain", [driver_error], wrapper)
    _clean(captured.everything)
    assert "plain" in captured.own.getvalue()
    assert "<list withheld>" in captured.own.getvalue()
    assert "<_Wrapper withheld>" in captured.own.getvalue()
    extra_out = _extra_output({"err": [driver_error], "n": 1})
    _clean(extra_out)
    assert "<list withheld>" in extra_out


# ---------------------------------------------------------------------------
# `_children` reads at most `limit` items of a container, not the whole of it:
# the cap is what keeps a 1,000,000-key dict or a 1,000,000-argument exception
# from costing a record its time and memory.
# ---------------------------------------------------------------------------


def test_an_exception_with_a_huge_args_tuple_yields_at_most_the_limit() -> None:
    huge = ValueError(*range(100_000))
    assert len(log_safety._children(huge, 7)) == 7
    assert len(log_safety._children(huge, 0)) == 0


def test_a_huge_dict_is_read_only_up_to_the_limit() -> None:
    """Counted by allocation: reading every item builds a list of them all, a
    capped read builds a handful. The dict is built before tracing starts."""
    import tracemalloc

    huge = {index: index for index in range(300_000)}
    tracemalloc.start()
    try:
        children = log_safety._children(huge, 5)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert children == [0, 0, 1, 1, 2]
    assert peak < 20_000, f"a capped read of a dict allocated {peak} bytes"

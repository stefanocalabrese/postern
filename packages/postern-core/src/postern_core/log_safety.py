"""Keep SQL, bound parameters and driver messages out of every log record.

THE LEAK, measured. A SQL driver error carries values in four places:

* SQLAlchemy's ``DBAPIError`` / ``StatementError`` text: ``[SQL: ...]`` and
  ``[parameters: (...)]`` (customer refs, assertion ``jti`` values, signatures,
  scrubbed arguments);
* the translated adapter error and the asyncpg exception under it, whose
  message names the offending value (``invalid input for query argument $1:
  'x'``, a unique violation's ``Key (a, b)=(x, y) already exists``);
* a constraint violation's ``DETAIL: Failing row contains (...)``, which is the
  whole row and is in ``str(exc)`` even with parameters hidden;
* the rows SQLAlchemy's ``sqlalchemy.engine`` logger writes at DEBUG.

It reaches a log through ``exc_info=`` on a record, through ``%s`` of the
exception in a record's arguments, and through frameworks that log an exception
on their own logger (uvicorn's ``Exception in ASGI application``, FastMCP's
``Error calling tool``, ``mcp``'s dispatcher, asyncio's ``Task exception was
never retrieved``). The first design here was a filter on uvicorn's two loggers;
the measured exposure was wider than those two, and a logger's filter does not
see a record that another logger's own handler (``propagate = False``) writes.

So the net is a PROCESS-WIDE LOG RECORD FACTORY. `install_sql_safe_logging`
wraps ``logging.getLogRecordFactory()``, and a record created through
``Logger._log``, on any logger and handler, is sanitised when it is created, in
the shapes below and no others:

* an ``exc_info`` whose exception chain holds a driver error is replaced by the
  traceback FRAMES of the outermost exception (file, line and source line, so a
  failure is still locatable) plus one line per exception in the chain: its
  dotted type, a qualifier (below) and a literal saying what was withheld;
* an exception in ``record.args`` (or ``record.msg``) whose chain holds a driver
  error is replaced by `describe_exception`'s text, wherever it sits inside the
  arguments within the scan's bounds (`_scrub_value`): nested to any depth up to
  `_MAX_DEPTH` in tuples, lists, sets, frozensets, deques and dicts (keys and
  values); held in the ``__dict__`` or ``__slots__`` of any object that is not a
  builtin (a dataclass, a namespace, a plain wrapper), which is then replaced
  whole by ``<Type holding a driver error: ...>``; or in the ``args`` of a
  non-driver exception (``RuntimeError("outer", e)``). At most `_MAX_NODES`
  items are charged to one scan;
* an exception in a record attribute set by ``extra=`` (`Logger.makeRecord` is
  wrapped), the same scan on each extra's value;
* a record built by ``logging.makeLogRecord`` (wrapped), which skips the factory
  and the arguments of which come straight from a dict: the same sanitising and
  the same scan of every attribute;
* ``warnings.warn``: `install_warning_capture` turns on ``captureWarnings`` so
  warning text goes through the ``py.warnings`` logger (and so the factory), and
  installs `_showwarning`, which withholds the message of any warning whose
  category is a SQLAlchemy one (``SAWarning`` and its subclasses, the
  deprecation categories): SQLAlchemy builds that text and some of it embeds
  statements. The category, file and line are kept;
* the ``repr`` of a driver error that asyncio embeds in the MESSAGE of ``Task
  exception was never retrieved``;
* everything else is left alone, byte for byte.

THE SCAN. Iterative, with an explicit stack: nothing recurses on the data. A
node budget (`_MAX_NODES`) charges every item pulled out of a container and a
depth cap (`_MAX_DEPTH`) stops descent, so a 1,000,000-element list in any
nesting costs at most the budget; each node is visited once (shared nodes and
cycles terminate, and a node reached from two parents taints both). It enters
an unknown object only through ``object.__getattribute__`` of ``__dict__`` and
``type.__getattribute__`` of ``__slots__``, and tells types apart with
``type(x)``, never ``isinstance``, which reads the object's own ``__class__``:
no ``__str__``, ``__repr__``, ``__getattr__``, ``__getattribute__``,
``__iter__`` or ``__eq__`` of an unknown object runs. Only a structure that
holds a driver error is rebuilt (recursively, bounded by the depth cap); a
record without one is returned as it came, so the cost for an ordinary record
is one pass over its arguments.

NOT COVERED, each measured to leak, and each pinned by a test so it is not
mistaken for coverage: an exception beyond the node budget or the depth cap;
a non-chained wrapper whose own message embeds the driver's text
(``RuntimeError(f"x {e}")`` raised outside the handler: nothing links it to the
driver error and matching on SQL keywords is not attempted); ``str(e)`` or an
f-string built at the call site (the rule for a developer is to log
`describe_exception(e)` instead; `tests/test_log_call_scan.py` enforces it); a
non-dict ``Mapping`` (not entered); a record made by ``Logger.handle`` or a
``LogRecord(...)`` constructed by hand; an attribute that a custom record
factory adds after ours; a handler that reads an exception from a custom
attribute after a custom factory replaced ours without chaining; any exception
recorded outside logging (an OpenTelemetry exporter, a Sentry-style SDK:
`tests/test_no_exception_exporters.py` fails if one is added).

The chain walk follows ``__cause__``, ``__context__`` and the ``.exceptions`` of
any ``BaseExceptionGroup`` (an ``asyncio.TaskGroup`` or anyio task group wraps
what its children raised), with cycle protection and a bound of `_MAX_CHAIN`
exceptions. Past the bound the tail is unknown and unknown is treated as SQL.

THE QUALIFIER, and what it can honestly say. An asyncpg exception that carries
``sqlstate`` in its INSTANCE dictionary came from the server: it prints
``sqlstate=XXXXX`` (accepted only if it is exactly five characters of
``[0-9A-Z]``). One without it was raised in the client (asyncpg's ``DataError``
"invalid input for query argument" is raised while encoding a parameter, before
anything is sent) and prints ``client-side``: its class carries a SQLSTATE
attribute, which would read as a server error that never happened. SQLAlchemy's
wrapper copies the value onto its own exception whatever its origin, so a
wrapper defers to the asyncpg exception under it.

Nothing here reads ``str(exc)``, ``repr(exc)``, ``exc.args`` of a driver error,
``exc.statement``, ``exc.params`` or the text of ``exc.orig``. The factory never
raises: if sanitising fails it falls back to type names only (every non-leaf
argument is withheld by type), then to one constant line.

`logging.Formatter.format` uses ``record.exc_text`` when it is set and renders
``exc_info`` only otherwise, so setting the text and clearing ``exc_info`` is
the supported way to replace a rendering, for every handler downstream.

WHAT WOULD REMOVE IT: code that calls ``logging.setLogRecordFactory`` AFTER the
app is built with a factory that does not chain to the previous one, or that
puts back ``Logger.makeRecord``, ``logging.makeLogRecord`` or
``warnings.showwarning``. The factory does not depend on uvicorn's loggers or
on any logging config, so ``dictConfig`` (which removes handlers, not factories)
and any ASGI server keep it. What it cannot see is an exception recorded outside
logging or text already built into a message string with an f-string.
"""

import logging
import re
import traceback
import types
import warnings
from collections import deque
from collections.abc import Iterator, Mapping
from itertools import islice
from types import TracebackType
from typing import Any, Final

from sqlalchemy.exc import SAWarning, StatementError

__all__ = [
    "SqlSafeExceptionFilter",
    "chain_holds_driver_error",
    "describe_exception",
    "exc_info_for_log",
    "install_sql_safe_logging",
    "install_warning_capture",
    "sanitise_record",
]

#: How many exceptions of one chain the walk will visit. A chain that is longer
#: is treated as SQL: the unvisited tail is unknown, and unknown is withheld.
_MAX_CHAIN: Final[int] = 100

_SQLSTATE: Final[re.Pattern[str]] = re.compile(r"[0-9A-Z]{5}")

_WITHHELD: Final[str] = "[message, SQL and parameters withheld]"

_LAST_RESORT: Final[str] = "<exception rendering withheld: it could not be sanitised>"

_MARKER: Final[str] = "_postern_sql_safe_factory"

#: SQLAlchemy loggers that write statement results (rows at DEBUG) or
#: connection events; pinned so that an operator's `--log-level debug` does not
#: turn on a log of result rows, which `hide_parameters` does not cover.
_PINNED_LOGGERS: Final[tuple[str, ...]] = ("sqlalchemy.engine", "sqlalchemy.pool")

_installed_factory: Any = None


def _chain(exc: BaseException) -> tuple[list[BaseException], bool]:
    """The exceptions reachable through ``__cause__``, ``__context__`` and groups.

    Outermost first, each exception once (cycles are cut by identity), bounded
    at `_MAX_CHAIN`. The flag says the bound was hit.
    """
    seen: set[int] = set()
    ordered: list[BaseException] = []
    pending: list[BaseException] = [exc]
    while pending:
        current = pending.pop(0)
        if id(current) in seen:
            continue
        if len(ordered) >= _MAX_CHAIN:
            return ordered, True
        seen.add(id(current))
        ordered.append(current)
        for nxt in (current.__cause__, current.__context__):
            if nxt is not None and id(nxt) not in seen:
                pending.append(nxt)
        if isinstance(current, BaseExceptionGroup):
            for member in current.exceptions:
                if id(member) not in seen:
                    pending.append(member)
    return ordered, False


def _is_asyncpg(exc: BaseException) -> bool:
    for cls in type(exc).__mro__:
        module = getattr(cls, "__module__", "") or ""
        if module == "asyncpg" or module.startswith("asyncpg."):
            return True
    return False


def _is_sql(exc: BaseException) -> bool:
    return isinstance(exc, StatementError) or _is_asyncpg(exc)


def chain_holds_driver_error(exc: BaseException) -> bool:
    """True when ``exc`` or anything in its chain is a SQL driver error.

    Also True for a chain longer than the walk's bound, and when the walk
    itself fails: both are unknowns, and an unknown is not allowed through.
    """
    try:
        chain, hit_bound = _chain(exc)
        return hit_bound or any(_is_sql(item) for item in chain)
    except Exception:  # noqa: BLE001 - unknown is treated as SQL
        return True


def _type_name(exc: BaseException) -> str:
    cls = type(exc)
    return f"{cls.__module__}.{cls.__qualname__}"


def _read(holder: object, attribute: str) -> object:
    """``getattr`` that answers None for an attribute that raises."""
    try:
        return getattr(holder, attribute, None)
    except Exception:  # noqa: BLE001 - a hostile property must not break logging
        return None


def _instance_sqlstate(holder: object) -> str | None:
    """A well-formed SQLSTATE held in the INSTANCE dictionary, else None.

    Not ``getattr``: asyncpg's exception classes carry ``sqlstate`` as a class
    attribute, which exists whether or not a server was ever involved.
    """
    try:
        attributes = vars(holder)
    except TypeError:
        return None
    for name in ("sqlstate", "pgcode"):
        value = attributes.get(name)
        if isinstance(value, str) and _SQLSTATE.fullmatch(value):
            return value
    return None


def _qualifier(exc: BaseException) -> str | None:
    try:
        if _is_asyncpg(exc):
            state = _instance_sqlstate(exc)
            return f"sqlstate={state}" if state is not None else "client-side"
        for holder in (exc, _read(exc, "orig")):
            if holder is None:
                continue
            cause = _read(holder, "__cause__")
            if isinstance(cause, BaseException) and _is_asyncpg(cause):
                return None  # the asyncpg line below says it
            state = _instance_sqlstate(holder)
            if state is not None:
                return f"sqlstate={state}"
    except Exception:  # noqa: BLE001
        return None
    return None


def _facts(exc: BaseException) -> str:
    try:
        name = _type_name(exc)
    except Exception:  # noqa: BLE001
        name = "<unnamed exception type>"
    qualifier = _qualifier(exc)
    return name if qualifier is None else f"{name} {qualifier}"


def describe_exception(exc: BaseException | None) -> str:
    """The exception's dotted type and, for each driver error under it, its
    type and SQLSTATE (or ``client-side``). No message, no arguments.

    What application code logs in place of ``%s`` of an exception or
    ``exc_info=`` where the exception may be a driver error. Never raises.
    """
    if exc is None:
        return "<no exception>"
    try:
        chain, hit_bound = _chain(exc)
        parts = [_facts(exc)]
        parts.extend(_facts(item) for item in chain[1:] if _is_sql(item))
        if hit_bound:
            parts.append(f"chain longer than {_MAX_CHAIN}, the rest withheld")
        return ", ".join(parts)
    except Exception:  # noqa: BLE001
        try:
            return _type_name(exc)
        except Exception:  # noqa: BLE001
            return "<exception>"


def exc_info_for_log(exc: BaseException | None) -> BaseException | None:
    """``exc`` for a log call's ``exc_info=``, or None when it holds a driver error.

    Keeps the traceback of an ordinary failure in the log and drops the one
    that would render a driver's message. The record factory sanitises the
    second kind anyway; this is the call site not relying on it.
    """
    if exc is None or chain_holds_driver_error(exc):
        return None
    return exc


def _frames(tb: TracebackType | None) -> str:
    if tb is None:
        return ""
    try:
        return "".join(traceback.format_tb(tb))
    except Exception:  # noqa: BLE001
        return ""


def _sanitised(exc: BaseException, tb: TracebackType | None, truncated: bool) -> str:
    chain, hit_bound = _chain(exc)
    lines = [f"{_facts(item)} {_WITHHELD}" for item in chain]
    if truncated or hit_bound:
        lines.append(f"... exception chain longer than {_MAX_CHAIN}, the rest {_WITHHELD}")
    frames = _frames(tb if tb is not None else exc.__traceback__)
    header = "Traceback (most recent call last), frames only:\n"
    return header + frames + "Exception chain, outermost first:\n" + "\n".join(lines)


def _type_names_only(exc: BaseException) -> str:
    try:
        chain, _ = _chain(exc)
        return "Exception chain, outermost first:\n" + "\n".join(
            f"{_type_name(item)} {_WITHHELD}" for item in chain
        )
    except Exception:  # noqa: BLE001
        return _LAST_RESORT


#: The node budget of one scan. Every item pulled out of any container while
#: scanning a record's arguments is charged one, so a 1,000,000-element list, in
#: any nesting, costs at most this many steps a record (it was 60 ms a record
#: with no limit). An exception beyond the budget is NOT scanned: that is the
#: residual, documented rather than closed because nothing in this repository
#: logs a structure that size.
_MAX_NODES: Final[int] = 2000

#: How deep the scan descends. An exception nested deeper is not scanned.
_MAX_DEPTH: Final[int] = 20

#: Argument types that cannot hold an exception: the factory's fast path and the
#: scan both stop at them. Looked up by exact `type()`, never `isinstance`,
#: because `isinstance` falls back to the object's own `__class__`, which is
#: user code on a hostile object.
_LEAF_TYPES: Final[frozenset[type]] = frozenset({str, int, float, bool, bytes, complex, type(None)})

#: Never entered: code and modules are not a logged value, and entering a bound
#: method or a function would walk into whatever its owner references.
_OPAQUE_TYPES: Final[tuple[type, ...]] = (
    type,
    types.ModuleType,
    types.FunctionType,
    types.BuiltinFunctionType,
    types.MethodType,
    types.CodeType,
    types.FrameType,
    types.TracebackType,
    property,
)

_SEQUENCE_TYPES: Final[tuple[type, ...]] = (tuple, list, set, frozenset, deque)


def _slot_values(obj: object) -> Iterator[Any]:
    """The values of the ``__slots__`` of ``obj``, through no overridable hook."""
    for cls in type(obj).__mro__:
        try:
            slots = type.__getattribute__(cls, "__dict__").get("__slots__", ())
        except Exception:  # noqa: BLE001, S112
            continue
        for name in (slots,) if isinstance(slots, str) else slots:
            if not isinstance(name, str) or name in {"__dict__", "__weakref__"}:
                continue
            if name.startswith("__") and not name.endswith("__"):
                name = f"_{cls.__name__.lstrip('_')}{name}"
            try:
                yield object.__getattribute__(obj, name)
            except Exception:  # noqa: BLE001, S112 - an unset slot
                continue


def _field_values(obj: object) -> list[Any]:
    """The attribute values of an unknown object: its ``__dict__`` and slots.

    ``object.__getattribute__`` and ``type.__getattribute__`` bypass the
    object's own ``__getattribute__`` and ``__getattr__``; ``__str__`` and
    ``__repr__`` are never called.
    """
    values: list[Any] = []
    try:
        attributes = object.__getattribute__(obj, "__dict__")
        if type(attributes) is dict:
            values.extend(dict.values(attributes))
    except Exception:  # noqa: BLE001, S110 - no __dict__
        pass
    values.extend(_slot_values(obj))
    return values


def _children(node: Any, limit: int) -> list[Any]:
    """What ``node`` holds, at most ``limit`` items (a dict: keys and values)."""
    kind = type(node)
    if kind in _LEAF_TYPES or issubclass(kind, _OPAQUE_TYPES):
        return []
    if issubclass(kind, BaseException):
        try:
            args = BaseException.args.__get__(node)  # type: ignore[attr-defined]
            return list(islice(args, limit))
        except Exception:  # noqa: BLE001
            return []
    if issubclass(kind, _SEQUENCE_TYPES):
        return list(islice(node, limit))
    if issubclass(kind, dict):
        flat: list[Any] = []
        for key, item in islice(dict.items(node), limit):
            flat.append(key)
            flat.append(item)
        return flat[:limit]
    if getattr(kind, "__module__", "") == "builtins" or issubclass(kind, Mapping):
        return []
    return _field_values(node)[:limit]


def _scan(root: Any) -> tuple[dict[int, str], set[int]] | None:
    """Find every driver error reachable from ``root`` inside the budget.

    Iterative, with an explicit stack. None when there is none, which is the
    usual answer and means nothing is rebuilt. Otherwise ``(texts, hits)``: for
    every node ON A PATH to a driver error, the text to show if that node has to
    be replaced whole, and the ids of the driver errors themselves. Every edge
    is recorded, so a node shared by two parents, or inside a cycle, taints all
    of them.
    """
    budget = _MAX_NODES
    parents: dict[int, list[int]] = {}
    hits: dict[int, str] = {}
    seen: set[int] = set()
    stack: list[tuple[Any, int, int]] = [(root, -1, 0)]
    while stack:
        node, parent, depth = stack.pop()
        kind = type(node)
        if kind in _LEAF_TYPES:
            continue
        node_id = id(node)
        if parent >= 0:
            parents.setdefault(node_id, []).append(parent)
        if node_id in seen:
            continue
        seen.add(node_id)
        if issubclass(kind, BaseException) and chain_holds_driver_error(node):
            hits[node_id] = describe_exception(node)
            continue
        if depth >= _MAX_DEPTH or budget <= 0:
            continue
        children = _children(node, budget)
        budget -= len(children)
        stack.extend((child, node_id, depth + 1) for child in children)
    if not hits:
        return None
    texts = dict(hits)
    pending = list(hits)
    while pending:
        current = pending.pop()
        for parent in parents.get(current, ()):
            if parent not in texts:
                texts[parent] = texts[current]
                pending.append(parent)
    return texts, set(hits)


def _holding(value: Any, text: str) -> str:
    return f"<{type(value).__qualname__} holding a driver error: {text}>"


def _rebuild(node: Any, texts: dict[int, str], hits: set[int], memo: dict[int, Any]) -> Any:
    """``node`` with each driver error replaced, rebuilding only what holds one.

    Recursion is bounded by `_MAX_DEPTH`: only nodes the scan reached on a path
    to a driver error are entered, and the scan stopped at that depth.
    """
    node_id = id(node)
    text = texts.get(node_id)
    if text is None:
        return node
    if node_id in hits:
        return text
    if node_id in memo:
        return memo[node_id]
    kind = type(node)
    if issubclass(kind, list):
        rebuilt_list: list[Any] = []
        memo[node_id] = rebuilt_list
        rebuilt_list.extend(_rebuild(item, texts, hits, memo) for item in node)
        return rebuilt_list
    if issubclass(kind, dict):
        rebuilt_dict: dict[Any, Any] = {}
        memo[node_id] = rebuilt_dict
        for key, item in dict.items(node):
            rebuilt_dict[_rebuild(key, texts, hits, memo)] = _rebuild(item, texts, hits, memo)
        return rebuilt_dict
    result: Any
    if issubclass(kind, tuple):
        result = tuple(_rebuild(item, texts, hits, memo) for item in node)
    elif issubclass(kind, frozenset):
        result = frozenset(_rebuild(item, texts, hits, memo) for item in node)
    elif issubclass(kind, set):
        result = {_rebuild(item, texts, hits, memo) for item in node}
    elif issubclass(kind, deque):
        result = [_rebuild(item, texts, hits, memo) for item in node]
    else:
        result = _holding(node, text)
    memo[node_id] = result
    return result


def _scrub_value(value: Any) -> Any:
    """``value`` with every driver error reachable inside the budget replaced.

    Reaches an exception that is the value; one inside any nesting of tuples,
    lists, sets, frozensets, deques and dicts (keys and values); one held by an
    object's ``__dict__`` or ``__slots__`` (the object is replaced by ``<Type
    holding a driver error: ...>``); one inside a non-driver exception's
    ``args``. At most `_MAX_NODES` items are charged and `_MAX_DEPTH` levels
    descended. Returns the same object when nothing changed.
    """
    found = _scan(value)
    if found is None:
        return value
    texts, hits = found
    return _rebuild(value, texts, hits, {})


def _withhold_every_exception(record: logging.LogRecord) -> None:
    """The conservative rendering: type names only, for every exception."""
    info = record.exc_info
    if isinstance(info, tuple) and len(info) == 3 and info[1] is not None:
        record.exc_text = _type_names_only(info[1])
        record.exc_info = None
    if isinstance(record.msg, BaseException):
        record.msg = _type_name(record.msg)
    if record.args:
        record.args = _type_only_args(record.args)


def _type_only_args(args: Any) -> Any:
    # The fallback for a record whose sanitising raised, so it trusts nothing: an
    # exception becomes its type name and any other argument that is not a plain
    # string or number becomes its type, whole. Runs only after a failure.
    def one(value: Any) -> Any:
        if type(value) in _LEAF_TYPES:
            return value
        if isinstance(value, BaseException):
            return _type_name(value)
        return f"<{type(value).__qualname__} withheld>"

    if isinstance(args, Mapping):
        return {key: one(item) for key, item in args.items()}
    if isinstance(args, tuple):
        return tuple(one(item) for item in args)
    return args


def _scrub_reprs(message: str, chain: list[BaseException]) -> str:
    """``message`` with the ``repr`` of any driver error in ``chain`` replaced.

    asyncio's ``Task exception was never retrieved`` puts the task's repr in
    the MESSAGE, and that repr ends ``exception=DBAPIError('<the driver's
    text>')``: text, not an exception object, so the argument scrub cannot see
    it. ``repr`` is read here only to find that text, never emitted.
    """
    for item in chain:
        if not _is_sql(item):
            continue
        rendered = _repr_or_none(item)
        if rendered and rendered in message:
            message = message.replace(rendered, f"<{describe_exception(item)}>")
    return message


def _repr_or_none(exc: BaseException) -> str | None:
    try:
        return repr(exc)
    except Exception:  # noqa: BLE001 - a hostile repr must not break logging
        return None


def sanitise_record(record: logging.LogRecord) -> None:
    """Rewrite ``record`` in place so that no driver error text can reach a handler."""
    try:
        info = record.exc_info
        if isinstance(info, tuple) and len(info) == 3 and info[1] is not None:
            exc = info[1]
            chain, hit_bound = _chain(exc)
            if hit_bound or any(_is_sql(item) for item in chain):
                if isinstance(record.msg, str):
                    record.msg = _scrub_reprs(record.msg, chain)
                record.exc_text = _sanitised(exc, info[2], hit_bound)
                record.exc_info = None
        if type(record.msg) is not str:
            record.msg = _scrub_value(record.msg)
        args = record.args
        if args:
            scrubbed = _scrub_value(args)
            if scrubbed is not args:
                record.args = scrubbed
    except Exception:  # noqa: BLE001 - sanitising must never raise
        try:
            _withhold_every_exception(record)
        except Exception:  # noqa: BLE001
            record.exc_info = None
            record.exc_text = _LAST_RESORT
            record.msg = "<log record withheld>"
            record.args = ()


def _scrub_attributes(record: logging.LogRecord, names: Any) -> None:
    """Scan the record attributes called ``names`` (``extra=`` keys, dict keys).

    A value that is, or holds, a driver error is replaced by its description;
    one the scan cannot handle is replaced by its type name. Never raises.
    """
    try:
        attributes = record.__dict__
        for name in list(names):
            value = attributes.get(name)
            if type(value) in _LEAF_TYPES:
                continue
            try:
                scrubbed = _scrub_value(value)
            except Exception:  # noqa: BLE001 - trust nothing after a failure
                scrubbed = f"<{type(value).__qualname__} withheld>"
            if scrubbed is not value:
                attributes[name] = scrubbed
    except Exception:  # noqa: BLE001, S110
        pass


class SqlSafeExceptionFilter(logging.Filter):
    """`sanitise_record` as a `logging.Filter`, for a handler or logger that
    wants it directly. Never drops a record."""

    def filter(self, record: logging.LogRecord) -> bool:
        sanitise_record(record)
        return True


def _wrap(inner: Any) -> Any:
    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record: logging.LogRecord = inner(*args, **kwargs)
        # The common record has no exception, and arguments that are plain
        # strings and numbers: leave it after one pass over those arguments.
        if record.exc_info is None and type(record.msg) is str:
            record_args = record.args
            if not record_args:
                return record
            if type(record_args) is tuple:
                for item in record_args:
                    if type(item) not in _LEAF_TYPES:
                        break
                else:
                    return record
        sanitise_record(record)
        return record

    setattr(factory, _MARKER, True)
    factory.__wrapped__ = inner  # type: ignore[attr-defined]
    return factory


def _wrap_make_record(inner: Any) -> Any:
    """`Logger.makeRecord`, then a scan of the attributes ``extra=`` set.

    The factory cannot see them: `Logger.makeRecord` writes ``extra`` into the
    record's ``__dict__`` AFTER the factory returns.
    """

    def make_record(
        self: logging.Logger,
        name: str,
        level: int,
        fn: str,
        lno: int,
        msg: object,
        args: Any,
        exc_info: Any,
        func: str | None = None,
        extra: Any = None,
        sinfo: str | None = None,
    ) -> logging.LogRecord:
        record: logging.LogRecord = inner(
            self, name, level, fn, lno, msg, args, exc_info, func, extra, sinfo
        )
        if extra:
            _scrub_attributes(record, extra)
        return record

    setattr(make_record, _MARKER, True)
    make_record.__wrapped__ = inner  # type: ignore[attr-defined]
    return make_record


def _wrap_make_log_record(inner: Any) -> Any:
    """`logging.makeLogRecord`, which fills a record from a dict and bypasses
    `Logger._log`: the record gets the same sanitising and attribute scan."""

    def make_log_record(dictionary: Any) -> logging.LogRecord:
        record: logging.LogRecord = inner(dictionary)
        sanitise_record(record)
        _scrub_attributes(record, dictionary)
        return record

    setattr(make_log_record, _MARKER, True)
    make_log_record.__wrapped__ = inner  # type: ignore[attr-defined]
    return make_log_record


def _is_sqlalchemy_category(category: type) -> bool:
    return issubclass(category, SAWarning) or (
        getattr(category, "__module__", "") or ""
    ).startswith("sqlalchemy")


def _showwarning(
    message: Warning | str,
    category: type[Warning],
    filename: str,
    lineno: int,
    file: Any = None,
    line: str | None = None,
) -> None:
    """``warnings.showwarning`` that logs through ``py.warnings``, like
    `logging.captureWarnings`, and withholds a SQLAlchemy warning's message.

    SQLAlchemy builds that text, and some of it embeds statements. The category,
    file and line are kept. Another warning keeps its text: it cannot be known
    to hold a driver's, and a warning is not an exception.
    """
    if file is not None:
        # An explicit stream is the caller's own: the stdlib behaviour.
        original = getattr(logging, "_warnings_showwarning", None)
        if original is not None:
            original(message, category, filename, lineno, file, line)
        return
    try:
        if _is_sqlalchemy_category(category):
            text = f"{filename}:{lineno}: {category.__qualname__}: message withheld\n"
        else:
            text = warnings.formatwarning(message, category, filename, lineno, line)
    except Exception:  # noqa: BLE001 - logging a warning must not raise
        text = "a warning was raised: message withheld\n"
    # Unlike `logging._showwarning`, no `NullHandler` is added when nothing is
    # configured: a handler found stops `logging.lastResort`, and with no root
    # handler (uvicorn configures its own loggers only) the warning would then
    # vanish, the READ-key-generated-in-process warning included. With none,
    # `lastResort` prints the message to stderr, as the stdlib hook did.
    logging.getLogger("py.warnings").warning("%s", text)


def install_warning_capture() -> None:
    """Route ``warnings.warn`` through the ``py.warnings`` logger, once.

    Calls ``logging.captureWarnings(True)`` and then puts `_showwarning` in
    ``warnings.showwarning``. Idempotent. A process that never installs it
    prints warnings to stderr as before, SAWarning text included.
    """
    logging.captureWarnings(True)
    if warnings.showwarning is not _showwarning:
        warnings.showwarning = _showwarning


def install_sql_safe_logging() -> None:
    """Make every log record in this process safe, once.

    Idempotent: the tests build many apps in one process and each calls this.
    A record factory installed earlier keeps running (this one wraps it).
    Also wraps ``Logger.makeRecord`` (``extra=``) and ``logging.makeLogRecord``,
    turns on warning capture (`install_warning_capture`), and pins
    ``sqlalchemy.engine`` and ``sqlalchemy.pool`` at WARNING.
    """
    global _installed_factory
    current = logging.getLogRecordFactory()
    if not (current is _installed_factory and getattr(current, _MARKER, False)):
        _installed_factory = _wrap(current)
        logging.setLogRecordFactory(_installed_factory)
    if not getattr(logging.Logger.makeRecord, _MARKER, False):
        logging.Logger.makeRecord = _wrap_make_record(logging.Logger.makeRecord)  # type: ignore[method-assign]
    if not getattr(logging.makeLogRecord, _MARKER, False):
        logging.makeLogRecord = _wrap_make_log_record(logging.makeLogRecord)
    install_warning_capture()
    for name in _PINNED_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)


def pin_http_client_loggers() -> None:
    """Hold ``httpx2`` and ``httpcore2`` at WARNING, whatever the root logger says.

    The operator's backend's response is text neither service may log. ``httpx2``
    writes ``HTTP Request: POST <url> "HTTP/1.1 500 <reason phrase>"`` at INFO,
    and ``httpcore2`` writes every response header at DEBUG, so a deployment that
    lowers the root logger to debug a problem would start logging the backend's
    reason phrase and headers. Dormant at the default root level (WARNING), live
    the moment an operator lowers it. Neither logger emits anything at WARNING or
    above on the paths these services use. Called by both ``create_app`` and
    ``create_confirm_app``; idempotent.
    """
    for name in ("httpx2", "httpcore2"):
        logging.getLogger(name).setLevel(logging.WARNING)

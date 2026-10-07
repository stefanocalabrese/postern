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
  error is replaced by `describe_exception`'s text, and so is one inside ONE
  tuple, list or mapping that is itself an argument (`_scrub_value`; at most
  `_MAX_ITEMS` items per container are scanned);
* the ``repr`` of a driver error that asyncio embeds in the MESSAGE of ``Task
  exception was never retrieved``;
* everything else is left alone, byte for byte.

NOT COVERED, each measured to leak: an exception nested two containers deep
(``[[e]]``), in a set, in a dataclass or other wrapper object, or past the
`_MAX_ITEMS`th item; a non-chained wrapper whose own text embeds the driver's;
``str(e)`` or an f-string built at the call site (the rule for a developer is
to log `describe_exception(e)` instead; `tests/test_log_call_scan.py` enforces
it); ``extra=`` rendered by a custom formatter; ``logging.makeLogRecord``, which
bypasses the factory; ``warnings.warn``.

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

Nothing here reads ``str(exc)``, ``repr(exc)``, ``exc.args``, ``exc.statement``,
``exc.params`` or the text of ``exc.orig``. The factory never raises: if
sanitising fails it falls back to type names only, then to one constant line.

`logging.Formatter.format` uses ``record.exc_text`` when it is set and renders
``exc_info`` only otherwise, so setting the text and clearing ``exc_info`` is
the supported way to replace a rendering, for every handler downstream.

WHAT WOULD REMOVE IT: code that calls ``logging.setLogRecordFactory`` AFTER the
app is built with a factory that does not chain to the previous one. The
factory does not depend on uvicorn's loggers or on any logging config, so
``dictConfig`` (which removes handlers, not factories) and any ASGI server keep
it. What it cannot see is an exception recorded outside logging (an
OpenTelemetry ``record_exception``, a Sentry-style SDK) or text already built
into a message string with an f-string.
"""

import logging
import re
import traceback
from collections.abc import Mapping
from itertools import islice
from types import TracebackType
from typing import Any, Final

from sqlalchemy.exc import StatementError

__all__ = [
    "SqlSafeExceptionFilter",
    "chain_holds_driver_error",
    "describe_exception",
    "exc_info_for_log",
    "install_sql_safe_logging",
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


#: How many items of one container `_scrub_value` looks at. A 1,000,000-element
#: list passed as a log argument cost 60 ms per record before this cap, on every
#: record, with no limit. An exception beyond the first `_MAX_ITEMS` items of a
#: container is NOT scanned: that is the residual, and it is documented rather
#: than closed because nothing in this repository logs a container that size.
_MAX_ITEMS: Final[int] = 1000


def _scrub_value(value: Any, depth: int = 0) -> Any:
    """``value`` with a driver-error exception replaced by its description.

    Called on a record's ``args`` (depth 0). What it reaches: an exception that
    is an argument (depth 1), and an exception inside ONE tuple, list or mapping
    that is itself an argument (depth 2). A container inside that container
    (depth 2 holding another) is not entered, so ``[[e]]`` is not covered; nor
    are sets, dataclasses or other wrapper objects. At most `_MAX_ITEMS` items
    of any one container are scanned. Returns the same object when nothing
    changed.
    """
    if isinstance(value, BaseException):
        return describe_exception(value) if chain_holds_driver_error(value) else value
    if depth >= 2:
        return value
    if isinstance(value, tuple | list):
        head = list(islice(value, _MAX_ITEMS))
        scrubbed = [_scrub_value(item, depth + 1) for item in head]
        if all(a is b for a, b in zip(scrubbed, head, strict=True)):
            return value
        rebuilt = [*scrubbed, *islice(value, _MAX_ITEMS, None)]
        return rebuilt if isinstance(value, list) else tuple(rebuilt)
    if isinstance(value, Mapping):
        replaced: dict[Any, Any] = {}
        for key, item in islice(value.items(), _MAX_ITEMS):
            scrubbed_item = _scrub_value(item, depth + 1)
            if scrubbed_item is not item:
                replaced[key] = scrubbed_item
        if not replaced:
            return value
        merged = dict(value)
        merged.update(replaced)
        return merged
    return value


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
    # NOT capped, unlike `_scrub_value`: this is the fallback for a record whose
    # sanitising raised, and a cap would leave an exception past it raw. It runs
    # only after a failure, never on the ordinary path.
    def one(value: Any) -> Any:
        return _type_name(value) if isinstance(value, BaseException) else value

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


_CONTAINERS: Final[tuple[type, ...]] = (BaseException, tuple, list, dict)


def _may_hold_exception(args: Any) -> bool:
    """Cheap pre-check: plain strings and numbers are the usual arguments.

    CAPPED at `_MAX_ITEMS`, like `_scrub_value` which it guards: a sole mapping
    argument of 1,000,000 items cost 41 ms a record here before the cap, and an
    item past the cap is one `_scrub_value` would not look at either.
    """
    items = args.values() if isinstance(args, dict) else args
    return any(isinstance(item, _CONTAINERS) for item in islice(items, _MAX_ITEMS))


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
        if isinstance(record.msg, BaseException):
            record.msg = _scrub_value(record.msg)
        args = record.args
        if args and _may_hold_exception(args):
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
        if record.exc_info is None and not isinstance(record.msg, BaseException):
            record_args = record.args
            if not record_args:
                return record
            if type(record_args) is tuple:
                for item in record_args:
                    if isinstance(item, _CONTAINERS):
                        break
                else:
                    return record
        sanitise_record(record)
        return record

    setattr(factory, _MARKER, True)
    factory.__wrapped__ = inner  # type: ignore[attr-defined]
    return factory


def install_sql_safe_logging() -> None:
    """Make every log record in this process safe, once.

    Idempotent: the tests build many apps in one process and each calls this.
    A record factory installed earlier keeps running (this one wraps it).
    Also pins ``sqlalchemy.engine`` and ``sqlalchemy.pool`` at WARNING.
    """
    global _installed_factory
    current = logging.getLogRecordFactory()
    if not (current is _installed_factory and getattr(current, _MARKER, False)):
        _installed_factory = _wrap(current)
        logging.setLogRecordFactory(_installed_factory)
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

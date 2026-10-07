"""Keep SQL, bound parameters and driver messages out of uncaught-error logs.

THE LEAK, measured through a real uvicorn server. When an exception escapes an
ASGI handler, uvicorn logs ``Exception in ASGI application`` on
``uvicorn.error`` with the whole exception chain rendered by
``traceback.format_exception``. For a SQL driver error that chain is:

* SQLAlchemy's ``DBAPIError`` / ``StatementError`` text, which carries
  ``[SQL: ...]`` and ``[parameters: (...)]``: customer refs, assertion ``jti``
  values, signatures, scrubbed arguments;
* the translated adapter error and the asyncpg exception under it, whose message
  can carry values of its own (a unique violation's ``DETAIL Key (a, b)=(x, y)
  already exists``, an invalid byte sequence's offending byte).

The approval callback re-raises such an error on purpose after it has written
its audit row (decision 0006, which fails the request closed) and
``tests/test_audit_reserve.py`` pins the escaping CLASS, so the fix is not to
catch or wrap it. It is to make the LOG safe, process-wide, because the same
exposure exists for every handler in both services.

TWO HALVES. ``Database`` builds both its engines with ``hide_parameters=True``,
so SQLAlchemy prints ``[SQL parameters hidden due to hide_parameters=True]``.
This filter is the half that does not depend on SQLAlchemy's text at all: for a
record whose exception chain holds a ``sqlalchemy.exc.StatementError`` (which
includes every ``DBAPIError``) or an asyncpg exception, it replaces the
rendering with the traceback FRAMES of the outermost exception (file, line and
source line, so a failure is still locatable) followed by one line per
exception in the chain: its dotted type name, its SQLSTATE where it has one, and
a literal saying what was withheld. It never reads ``str(exc)``, ``repr(exc)``,
``exc.args``, ``exc.statement``, ``exc.params`` or the text of ``exc.orig``.

A SQLSTATE is read only if it is exactly five characters of ``[0-9A-Z]``. It is
a class of failure (``23505`` unique violation, ``22021`` invalid byte
sequence), carries no value, and is what an operator needs to find the statement
in Postgres' own log, which is where the driver's message text lives now.

A record with no such exception is left untouched, byte for byte. The filter
never raises and never drops a record: if sanitising itself fails it falls back
to type names only, and if that fails to one constant line.

`logging.Formatter.format` uses ``record.exc_text`` when it is already set and
renders ``exc_info`` only otherwise, so setting the text and clearing
``exc_info`` is the supported way to replace a rendering; every handler that
formats the record afterwards sees the same safe text.

WHERE IT ATTACHES. A logger's filters apply to records logged ON that logger
and not to records that propagate up to it. uvicorn logs this one on
``uvicorn.error``; ``uvicorn`` is covered as well for a record logged there
directly. Starlette's ``ServerErrorMiddleware`` re-raises and does not log, so
there is no third logger. Both composition roots call
`install_sql_safe_logging` at app construction; because uvicorn applies its own
logging config before it imports the application, the filter survives that
config. A deployment that REPLACES uvicorn's logging config afterwards (a custom
``dictConfig`` or ``--log-config`` that rebuilds the ``uvicorn.error`` logger)
loses it unless it calls `install_sql_safe_logging` again after that config.
"""

import logging
import re
import traceback
from types import TracebackType
from typing import Final

from sqlalchemy.exc import StatementError

__all__ = ["SqlSafeExceptionFilter", "install_sql_safe_logging"]

#: The loggers an uncaught ASGI error is written on.
_LOGGERS: Final[tuple[str, ...]] = ("uvicorn.error", "uvicorn")

#: How many exceptions of one chain the walk will visit. A chain that is longer
#: is treated as SQL: the unvisited tail is unknown, and unknown is withheld.
_MAX_CHAIN: Final[int] = 100

_SQLSTATE: Final[re.Pattern[str]] = re.compile(r"[0-9A-Z]{5}")

_WITHHELD: Final[str] = "[message, SQL and parameters withheld]"

_LAST_RESORT: Final[str] = "<exception rendering withheld: it could not be sanitised>"

_MARKER: Final[str] = "_postern_sql_safe_filter"

ExcInfo = tuple[type[BaseException], BaseException, TracebackType | None]


def _chain(exc: BaseException) -> tuple[list[BaseException], bool]:
    """The exceptions reachable through ``__cause__`` and ``__context__``.

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
    return ordered, False


def _is_sql(exc: BaseException) -> bool:
    if isinstance(exc, StatementError):
        return True
    for cls in type(exc).__mro__:
        module = getattr(cls, "__module__", "") or ""
        if module == "asyncpg" or module.startswith("asyncpg."):
            return True
    return False


def _type_name(exc: BaseException) -> str:
    cls = type(exc)
    return f"{cls.__module__}.{cls.__qualname__}"


def _read(holder: object, attribute: str) -> object:
    """``getattr`` that answers None for an attribute that raises."""
    try:
        return getattr(holder, attribute, None)
    except Exception:  # noqa: BLE001 - a hostile property must not break logging
        return None


def _sqlstate(exc: BaseException) -> str | None:
    """A SQLSTATE the exception, or the driver error it wraps, carries."""
    for holder in (exc, _read(exc, "orig")):
        if holder is None:
            continue
        for attribute in ("sqlstate", "pgcode"):
            value = _read(holder, attribute)
            if isinstance(value, str) and _SQLSTATE.fullmatch(value):
                return value
    return None


def _line(exc: BaseException) -> str:
    try:
        name = _type_name(exc)
    except Exception:  # noqa: BLE001
        name = "<unnamed exception type>"
    try:
        state = _sqlstate(exc)
    except Exception:  # noqa: BLE001
        state = None
    parts = [name]
    if state is not None:
        parts.append(f"sqlstate={state}")
    parts.append(_WITHHELD)
    return " ".join(parts)


def _frames(tb: TracebackType | None) -> str:
    if tb is None:
        return ""
    try:
        return "".join(traceback.format_tb(tb))
    except Exception:  # noqa: BLE001
        return ""


def _sanitised(exc: BaseException, tb: TracebackType | None, truncated: bool) -> str:
    chain, hit_bound = _chain(exc)
    lines = [_line(item) for item in chain]
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


class SqlSafeExceptionFilter(logging.Filter):
    """Replace the exception rendering of a record whose chain holds a SQL error."""

    _postern_sql_safe_filter = True

    def filter(self, record: logging.LogRecord) -> bool:
        info = record.exc_info
        if not isinstance(info, tuple) or len(info) != 3 or info[1] is None:
            return True
        exc = info[1]
        try:
            chain, hit_bound = _chain(exc)
            if not hit_bound and not any(_is_sql(item) for item in chain):
                return True
            text = _sanitised(exc, info[2], hit_bound)
        except Exception:  # noqa: BLE001 - this filter must never raise
            text = _type_names_only(exc)
        record.exc_info = None
        record.exc_text = text
        return True


def install_sql_safe_logging() -> None:
    """Attach `SqlSafeExceptionFilter` to uvicorn's error loggers, once.

    Idempotent: the tests build many apps in one process and each calls this.
    """
    for name in _LOGGERS:
        target = logging.getLogger(name)
        if not any(getattr(f, _MARKER, False) for f in target.filters):
            target.addFilter(SqlSafeExceptionFilter())

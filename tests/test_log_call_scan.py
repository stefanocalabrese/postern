"""A scan, by `ast`, for log calls that could carry a driver error's text.

The record factory (`postern_core.log_safety`) is the net. This scan is the
plan: a log call inside `services/` or `packages/` must not hand an exception to
the logger raw. What it treats as a log call:

* `<logger>.<debug|info|warning|warn|error|exception|critical|fatal|log>(...)`,
  where a receiver is a logger when ANY of these holds: its last name contains
  `log`; it is a `getLogger(...)` call (`logging.getLogger(__name__).error(e)`);
  or, by DATAFLOW, it is a name or attribute (`sink`, `self._audit`) assigned
  anywhere in the module from `logging.getLogger(...)`, `getLogger(...)`,
  `logging.Logger(...)`, `structlog.get_logger()` / `get_logger()`, from
  `.getChild(...)` / `.bind(...)` of a logger, or from another such name
  (`out = sink`, in any order);
* `getattr(<logger>, "error")(...)`;
* a name imported `from logging import error as report`, called as `report(...)`;
* `warnings.warn(...)`, `print(...)` and `sys.stderr.write(...)` /
  `sys.stdout.write(...)`.

What it flags in such a call:

* any argument, or keyword value, that mentions an identifier bound by an
  enclosing `except ... as X`, unless the mention sits inside a call to
  `describe_exception`, `exc_info_for_log`, `type` or `_exception_name` (so `%s` of the exception,
  an f-string holding it, `str(X)`, `exc_info=X`, `**{"exc_info": X}` and a
  tuple or list holding it are all flagged);
* `exc_info=True`, any other truthy constant (`exc_info=1`), and
  `exc_info=sys.exc_info()`, any `exc_info()` call inside an argument
  (`logger.error("x %s", sys.exc_info()[1])`), and `.exception(...)`, which
  implies it, because all of them render whatever exception is being handled;
* a call to `traceback.format_exc`, `format_exception`, `format_exception_only`,
  `format_tb` or `print_exc` anywhere in the arguments, bound name or not;
* nothing else. Arguments that merely mention a name which is not an exception
  are not looked at.

TAINT. A name assigned from the handled exception, or from a name that holds it
(`saved = e`, `saved = e.args`, `pair, other = e, 1`, `b = a`), is treated as the
exception from there to the end of the enclosing function (the module counts as
one), until it is assigned from something else. An assignment through
`describe_exception`, `exc_info_for_log`, `type` or `_exception_name` does not
taint.

THE SCAN IS STILL HEURISTIC, and says so. It looks at names and assignments, not
at types, so it misses a logger that arrives as a parameter or an attribute
under a name without `log` that no assignment in the module explains
(`def f(out): out.error(e)`), an exception carried in a container built earlier
(`items.append(e)` then `logger.error("%s", items)`), taint through a call
(`saved = wrap(e)` is flagged, but a helper that stores `e` elsewhere is not
followed), taint across functions, and any call routed through a helper that
logs on the caller's behalf. `str(e)` and f-strings are flagged here and are
the one shape the record factory cannot fix. It is a net for the shapes this
codebase writes, not a proof that no handled exception reaches a log.

THE ALLOWLIST below is explicit and every entry says why it is safe: the
exception can never be a SQL driver error (a parse error, a Redis or Vault
error, a JSON error) or the call is a deliberate use of the raw exception whose
type this repository controls. Each entry is keyed on the source text of the
call itself (`ast.unparse`), not on its function, so a NEW unsafe call inside
an allowlisted function is flagged, and editing a listed call re-opens its
review. The key also carries the type of the `except` clause the call sits in
(`ast.unparse(handler.type)`), because an entry is safe only for the exception
that clause catches: widening `except DeviceCodeStoreContended` to `except
Exception` makes the call unlisted and its entry stale. The flagged set and
the allowlist must be EQUAL: a flagged call that is not listed fails, and a
listed call that is no longer flagged (deleted or rewritten) fails too, so the list cannot rot.
"""

import ast
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
)
#: `_exception_name` (services/confirm/callback.py) returns a type name, or the
#: `kind` a BackendTransportError carries (a class name such as `ReadTimeout`).
SAFE_CALLS = frozenset({"describe_exception", "exc_info_for_log", "type", "_exception_name"})
TRACEBACK_TEXT = frozenset(
    {"format_exc", "format_exception", "format_exception_only", "format_tb", "print_exc"}
)

#: (path, enclosing function, rule, unparsed call, the innermost enclosing
#: `except` clause's type as source text: `DeviceCodeStoreContended`,
#: `(A, B)`, `<bare>`, or `<none>` outside any handler). The type is in the key
#: because an entry's safety rests on WHICH exception it catches.
Key = tuple[str, str, str, str, str]
Found = tuple[str, str, str, str, str, int]  # a Key and the line number

_ARG = "raw exception argument"
_SRC = "packages/postern-core/src/postern_core"

#: key -> (how many identical calls, why they are safe).
ALLOWLIST: dict[Key, tuple[int, str]] = {
    (
        f"{_SRC}/auth/redis_preflight.py",
        "check_eviction_policy",
        _ARG,
        "logger.warning('Redis maxmemory-policy cannot be verified (CONFIG was refused: %s). "
        "The ZT-7 revocation sets carry no TTL, so check by hand that the instance runs "
        "maxmemory-policy noeviction; an evicting policy can silently drop revocations.', exc)",
        "ResponseError",
    ): (1, "a redis ResponseError for CONFIG; no SQL"),
    (
        f"{_SRC}/auth/revocation.py",
        "revoke_session",
        "exc_info=<current exception>",
        "logger.warning('session revocation prune failed; the revoke stands', exc_info=True)",
        "Exception",
    ): (2, "a prune failure against Redis; no SQL (two sites, identical text)"),
    (
        f"{_SRC}/auth/revoke_cli.py",
        "_run",
        _ARG,
        "print(f'prune-sessions failed: {exc}', file=err or sys.stderr)",
        "RevocationStoreUnavailable",
    ): (1, "the operator CLI's own terminal; a Redis error from a prune, no SQL, no client"),
    (
        f"{_SRC}/store/audit.py",
        "append_with_reserve",
        _ARG,
        "logger.warning('the connection pool is at its ceiling; writing this audit row on "
        "the reserve connection instead: %s', saturated)",
        "sa_exc.TimeoutError",
    ): (
        1,
        "sqlalchemy.exc.TimeoutError, the pool's 'QueuePool limit' sentence; it is not a "
        "StatementError and holds no statement",
    ),
    (
        "services/confirm/callback.py",
        "_approve",
        _ARG,
        "logger.warning('challenge approve: %r: the backend refused the write: tool=%s "
        "status=%d', challenge_id, updated.tool_name, exc.status)",
        "BackendWriteError",
    ): (1, "logs `exc.status`, the numeric HTTP status of a BackendWriteError; no text"),
    (
        "services/confirm/device_auth.py",
        "_exchange",
        _ARG,
        "logger.warning('device grant: %s; refusing to mint', exc)",
        "RefreshSessionStoreFull",
    ): (1, "RefreshSessionStoreFull, a fixed sentence this repository writes"),
    (
        "services/confirm/device_auth.py",
        "device_authorization",
        _ARG,
        "logger.warning('device authorization refused: %s', exc)",
        "DeviceCodeStoreContended",
    ): (1, "DeviceCodeStoreContended, whose text is a fixed sentence this repository writes"),
    (
        "services/confirm/device_auth.py",
        "device_authorization",
        _ARG,
        "logger.warning('device authorization refused: the device code store holds %d codes, "
        "its cap', exc.held)",
        "DeviceCodeStoreFull",
    ): (1, "DeviceCodeStoreFull `exc.held`, an int"),
}


def _terminal_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


#: Calls whose result is a logger.
_LOGGER_SOURCES = frozenset({"getlogger", "get_logger"})

#: Methods that return another logger from a logger.
_LOGGER_DERIVERS = frozenset({"getchild", "bind", "new", "unbind", "with_name"})


def _is_logger_like(node: ast.expr, known: frozenset[str] = frozenset()) -> bool:
    """A receiver that is a logger: named like one, a `getLogger(...)` call, or
    (by dataflow) a name or attribute assigned from a logger source anywhere in
    the module (`known`, from `_logger_names`)."""
    if isinstance(node, ast.Call):
        terminal = _terminal_name(node.func).lower()
        if terminal in _LOGGER_SOURCES:
            return True
        if terminal == "logger" and ast.unparse(node.func) == "logging.Logger":
            return True
        return (
            terminal in _LOGGER_DERIVERS
            and isinstance(node.func, ast.Attribute)
            and _is_logger_like(node.func.value, known)
        )
    if isinstance(node, ast.Name | ast.Attribute) and ast.unparse(node) in known:
        return True
    return "log" in _terminal_name(node).lower()


def _assignment_targets(node: ast.AST) -> list[ast.expr]:
    if isinstance(node, ast.Assign):
        return list(node.targets)
    if isinstance(node, ast.AnnAssign) and node.value is not None:
        return [node.target]
    return []


def _logger_names(tree: ast.AST) -> frozenset[str]:
    """Names and attributes (`sink`, `self._audit`) assigned, anywhere in the
    module, from a logger source, or from another such name. A fixed point, so
    `out = sink` after `sink = logging.getLogger(...)` is found in any order."""
    known: set[str] = set()
    while True:
        before = len(known)
        for node in ast.walk(tree):
            value = getattr(node, "value", None)
            if value is None or not isinstance(value, ast.expr):
                continue
            targets = _assignment_targets(node)
            if targets and _is_logger_like(value, frozenset(known)):
                known.update(
                    ast.unparse(t) for t in targets if isinstance(t, ast.Name | ast.Attribute)
                )
        if len(known) == before:
            return frozenset(known)


def _log_method(
    node: ast.Call, aliases: dict[str, str], known: frozenset[str] = frozenset()
) -> str | None:
    """The logging method this call is, or ``None`` if it is not a log call."""
    func = node.func
    if isinstance(func, ast.Attribute):
        if func.attr in LOG_METHODS and _is_logger_like(func.value, known):
            return func.attr
        if func.attr == "warn" and _terminal_name(func.value) == "warnings":
            return "warn"
        if func.attr == "write" and ast.unparse(func.value) in {"sys.stderr", "sys.stdout"}:
            return "write"
        return None
    if isinstance(func, ast.Name):
        if func.id == "print":
            return "print"
        return aliases.get(func.id)
    if (
        isinstance(func, ast.Call)
        and _terminal_name(func.func) == "getattr"
        and len(func.args) >= 2
        and isinstance(func.args[1], ast.Constant)
        and func.args[1].value in LOG_METHODS
        and _is_logger_like(func.args[0], known)
    ):
        return str(func.args[1].value)
    return None


def _mentions(node: ast.AST, bound: frozenset[str]) -> bool:
    """True if ``node`` mentions a bound name outside a safe call."""
    if isinstance(node, ast.Call) and _terminal_name(node.func) in SAFE_CALLS:
        return False
    if isinstance(node, ast.Name):
        return node.id in bound
    return any(_mentions(child, bound) for child in ast.iter_child_nodes(node))


def _has_traceback_text(node: ast.AST) -> bool:
    return any(
        isinstance(sub, ast.Call) and _terminal_name(sub.func) in TRACEBACK_TEXT
        for sub in ast.walk(node)
    )


def _renders_current_exception(value: ast.expr) -> bool:
    """`exc_info=` with a truthy constant or `sys.exc_info()`."""
    if isinstance(value, ast.Constant):
        return bool(value.value)
    return isinstance(value, ast.Call) and _terminal_name(value.func) == "exc_info"


def _calls_exc_info(node: ast.AST) -> bool:
    """A `sys.exc_info()` / `exc_info()` call anywhere inside ``node``: the
    exception being handled, wherever the call sits in the argument."""
    return any(
        isinstance(sub, ast.Call) and _terminal_name(sub.func) == "exc_info"
        for sub in ast.walk(node)
    )


class _Scan(ast.NodeVisitor):
    def __init__(
        self, path: str, aliases: dict[str, str], known: frozenset[str] = frozenset()
    ) -> None:
        self.path = path
        self.aliases = aliases
        self.known = known
        self.bound: list[str] = []
        # Names that hold the handled exception or something taken from it
        # (`saved = e`), one set per function, the module being the first.
        self.tainted: list[set[str]] = [set()]
        self.functions: list[str] = []
        # The `except` clauses enclosing the node being visited, one list per
        # function, the module being the first.
        self.handlers: list[list[str]] = [[]]
        self.found: list[Found] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node.name)
        self.tainted.append(set())
        self.handlers.append([])
        self.generic_visit(node)
        self.handlers.pop()
        self.tainted.pop()
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bound.append(node.name)
        self.handlers[-1].append(ast.unparse(node.type) if node.type else "<bare>")
        self.generic_visit(node)
        self.handlers[-1].pop()
        if node.name:
            self.bound.pop()

    def _names(self) -> frozenset[str]:
        return frozenset(self.bound) | frozenset(self.tainted[-1])

    def _assigned(self, node: ast.Assign | ast.AnnAssign) -> None:
        """Track `saved = e`: a name assigned from the exception, or from a name
        that holds it, holds it too, until it is assigned something else."""
        value = node.value
        if value is None:
            return
        taints = bool(self._names()) and _mentions(value, self._names())
        for target in _assignment_targets(node):
            for name in ast.walk(target):
                if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store):
                    if taints:
                        self.tainted[-1].add(name.id)
                    else:
                        self.tainted[-1].discard(name.id)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        self._assigned(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        self._assigned(node)

    def visit_Call(self, node: ast.Call) -> None:
        method = _log_method(node, self.aliases, self.known)
        if method is not None:
            self._check(node, method)
        self.generic_visit(node)

    def _flag(self, rule: str, node: ast.Call) -> None:
        function = self.functions[-1] if self.functions else "<module>"
        handler = self.handlers[-1][-1] if self.handlers[-1] else "<none>"
        self.found.append((self.path, function, rule, ast.unparse(node), handler, node.lineno))

    def _check(self, node: ast.Call, method: str) -> None:
        bound = self._names()
        if method == "exception":
            self._flag("exception()", node)
        values = [*node.args, *(kw.value for kw in node.keywords)]
        if bound and any(_mentions(value, bound) for value in values):
            self._flag(_ARG, node)
        if any(_has_traceback_text(value) for value in values):
            self._flag("traceback text", node)
        # One flag, whichever of the two shapes (or both) is present: the
        # keyword with a truthy value, or any `exc_info()` call anywhere in an
        # argument (`logger.error("x %s", sys.exc_info()[1])`).
        if any(
            kw.arg == "exc_info" and _renders_current_exception(kw.value) for kw in node.keywords
        ) or any(_calls_exc_info(value) for value in values):
            self._flag("exc_info=<current exception>", node)


def _logging_aliases(tree: ast.AST) -> dict[str, str]:
    """`from logging import error as report` gives ``{"report": "error"}``."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "logging":
            for item in node.names:
                if item.name in LOG_METHODS:
                    aliases[item.asname or item.name] = item.name
    return aliases


def violations(source: str, path: str) -> list[Found]:
    tree = ast.parse(source)
    scan = _Scan(path, _logging_aliases(tree), _logger_names(tree))
    scan.visit(tree)
    return scan.found


def _counted(found: list[Found]) -> Counter[Key]:
    return Counter(
        (path, func, rule, call, handler) for path, func, rule, call, handler, _ in found
    )


def unlisted(found: Counter[Key], allowlist: dict[Key, tuple[int, str]]) -> list[Key]:
    """Flagged calls beyond what the allowlist grants."""
    return sorted(key for key, count in found.items() if count > allowlist.get(key, (0, ""))[0])


def stale(found: Counter[Key], allowlist: dict[Key, tuple[int, str]]) -> list[Key]:
    """Allowlisted calls that are no longer flagged, or flagged fewer times."""
    return sorted(key for key, (count, _) in allowlist.items() if found.get(key, 0) != count)


def _scanned_files() -> list[Path]:
    return [
        *sorted((ROOT / "services").rglob("*.py")),
        *sorted((ROOT / "packages").glob("*/src/**/*.py")),
    ]


def _all_violations() -> list[Found]:
    found: list[Found] = []
    for path in _scanned_files():
        relative = str(path.relative_to(ROOT))
        found.extend(violations(path.read_text(), relative))
    return found


def test_the_flagged_set_equals_the_allowlist_no_call_is_unlisted() -> None:
    found = _counted(_all_violations())
    assert not unlisted(found, ALLOWLIST), "\n".join(map(str, unlisted(found, ALLOWLIST)))


def test_the_flagged_set_equals_the_allowlist_no_entry_is_stale() -> None:
    found = _counted(_all_violations())
    assert not stale(found, ALLOWLIST), "\n".join(map(str, stale(found, ALLOWLIST)))


# ---------------------------------------------------------------------------
# The equality check itself: a second unsafe call in a listed function is
# flagged, and deleting one of two listed calls is stale.
# ---------------------------------------------------------------------------

_LISTED_MODULE = (
    "def f():\n"
    "    try:\n"
    "        pass\n"
    "    except Exception as e:\n"
    "        logger.error('a %s', e.status)\n"
)
_SYNTHETIC_PATH = "synthetic.py"


def _allowlist_for(source: str, *, count: int = 1) -> dict[Key, tuple[int, str]]:
    return {key: (count, "test") for key in _counted(violations(source, _SYNTHETIC_PATH))}


def test_a_new_unsafe_call_in_an_allowlisted_function_is_flagged() -> None:
    allowlist = _allowlist_for(_LISTED_MODULE)
    grown = _LISTED_MODULE + "        logger.error('leak %s', str(e))\n"
    found = _counted(violations(grown, _SYNTHETIC_PATH))
    assert unlisted(found, allowlist) == [
        (_SYNTHETIC_PATH, "f", _ARG, "logger.error('leak %s', str(e))", "Exception")
    ]


def test_a_second_identical_call_in_an_allowlisted_function_is_flagged() -> None:
    allowlist = _allowlist_for(_LISTED_MODULE)
    found = _counted(
        violations(_LISTED_MODULE + "        logger.error('a %s', e.status)\n", "synthetic.py")
    )
    assert unlisted(found, allowlist), "the count must be equal, not at-least"


def test_deleting_one_of_two_allowlisted_calls_is_stale() -> None:
    two = _LISTED_MODULE + "        logger.error('b %s', e.status)\n"
    allowlist = _allowlist_for(two)
    one = _counted(violations(_LISTED_MODULE, _SYNTHETIC_PATH))
    assert stale(one, allowlist) == [
        (_SYNTHETIC_PATH, "f", _ARG, "logger.error('b %s', e.status)", "Exception")
    ]


def test_deleting_one_of_two_identical_allowlisted_calls_is_stale() -> None:
    two = _LISTED_MODULE + "        logger.error('a %s', e.status)\n"
    allowlist = _allowlist_for(two, count=2)
    one = _counted(violations(_LISTED_MODULE, _SYNTHETIC_PATH))
    assert stale(one, allowlist)


# An entry's safety rests on WHICH exception its handler catches (a fixed
# sentence this repository wrote), so the handler's type is part of the key:
# widening `except DeviceCodeStoreContended` to `except Exception` re-opens it.
_NARROW = (
    "def f():\n"
    "    try:\n"
    "        pass\n"
    "    except DeviceCodeStoreContended as e:\n"
    "        logger.error('a %s', e)\n"
)


def test_widening_the_except_type_of_a_listed_call_is_unlisted_and_stale() -> None:
    allowlist = _allowlist_for(_NARROW)
    widened = _NARROW.replace("DeviceCodeStoreContended", "Exception")
    found = _counted(violations(widened, _SYNTHETIC_PATH))
    assert unlisted(found, allowlist), "the widened handler must re-open the entry"
    assert stale(found, allowlist), "the narrow entry no longer matches anything"


def test_the_same_call_under_the_same_except_type_stays_listed() -> None:
    allowlist = _allowlist_for(_NARROW)
    found = _counted(violations(_NARROW, _SYNTHETIC_PATH))
    assert not unlisted(found, allowlist)
    assert not stale(found, allowlist)


def test_a_tuple_of_except_types_is_keyed_whole() -> None:
    two = _NARROW.replace("DeviceCodeStoreContended", "(A, B)")
    allowlist = _allowlist_for(two)
    widened = two.replace("(A, B)", "(A, B, Exception)")
    assert unlisted(_counted(violations(widened, _SYNTHETIC_PATH)), allowlist)


# ---------------------------------------------------------------------------
# The scan itself: each shape it exists for is flagged, each sanctioned one is not.
# ---------------------------------------------------------------------------


def _handled(call: str, *, bind: bool = True, header: str = "") -> str:
    """A `try`/`except` whose handler body is ``call``."""
    clause = "except Exception as e:" if bind else "except Exception:"
    return f"{header}try:\n    pass\n{clause}\n    {call}\n"


SYNTHETIC_FLAGGED = {
    "percent-s of the exception": _handled('logger.error("x %s", e)'),
    "str() of the exception": _handled('logger.error("x %s", str(e))'),
    "f-string": _handled('logger.warning(f"x {e}")'),
    "exception()": _handled('logger.exception("x")', bind=False),
    "exc_info=True": _handled('logger.warning("x", exc_info=True)', bind=False),
    "exc_info=1": _handled('logger.warning("x", exc_info=1)', bind=False),
    "exc_info=sys.exc_info()": _handled('logger.warning("x", exc_info=sys.exc_info())', bind=False),
    "positional sys.exc_info()[1]": _handled('logger.error("x %s", sys.exc_info()[1])', bind=False),
    "positional exc_info()": _handled('logger.error("x %s", exc_info())', bind=False),
    "f-string of sys.exc_info()": _handled('logger.error(f"x {sys.exc_info()}")', bind=False),
    "exc_info=name": _handled('logger.error("x", exc_info=e)'),
    "starred dict": _handled('logger.error("x", **{"exc_info": e})'),
    "tuple argument": _handled('logger.error("x %s", (1, e))'),
    "self.logger": _handled('self.logger.error("x %s", e)'),
    "log()": _handled('logger.log(40, "x %s", e)'),
    "getattr(logger, name)(...)": _handled('getattr(logger, "error")("x %s", e)'),
    "from logging import error as report": _handled(
        'report("x %s", e)', header="from logging import error as report\n"
    ),
    "logging.getLogger(...).error(...)": _handled('logging.getLogger(__name__).error("x %s", e)'),
    "traceback.format_exc()": _handled('logger.error("x %s", traceback.format_exc())', bind=False),
    "format_exception passed to logger": _handled("logger.error(traceback.format_exception(e))"),
    "print(e, file=sys.stderr)": _handled("print(e, file=sys.stderr)"),
    "print(traceback.format_exc())": _handled("print(traceback.format_exc())", bind=False),
    "sys.stderr.write": _handled("sys.stderr.write(str(e))"),
    "warnings.warn(str(e))": _handled("warnings.warn(str(e))"),
    # A logger known by where it came from, not by its name.
    "sink bound from logging.getLogger": _handled(
        'sink.error("x %s", e)', header="sink = logging.getLogger(__name__)\n"
    ),
    "sink bound from a bare getLogger": _handled(
        'sink.error("x %s", e)', header="sink = getLogger(__name__)\n"
    ),
    "sink bound from logging.Logger": _handled(
        'sink.error("x %s", e)', header='sink = logging.Logger("a")\n'
    ),
    "sink bound from structlog.get_logger": _handled(
        'sink.error("x %s", e)', header="sink = structlog.get_logger()\n"
    ),
    "annotated sink": _handled(
        'sink.error("x %s", e)', header="sink: logging.Logger = logging.getLogger('a')\n"
    ),
    "self attribute bound in another method": (
        "class A:\n"
        "    def __init__(self):\n"
        '        self._audit = logging.getLogger("a")\n'
        "    def run(self):\n"
        "        try:\n"
        "            pass\n"
        "        except Exception as e:\n"
        '            self._audit.error("x", e)\n'
    ),
    "child logger": _handled(
        'sink.error("x %s", e)', header='sink = logging.getLogger("a").getChild("b")\n'
    ),
    "logger alias": _handled(
        'out.error("x %s", e)', header="out = logger\nlogger = logging.getLogger('a')\n"
    ),
    "alias of a sink": _handled(
        'out.error("x %s", e)', header="sink = logging.getLogger('a')\nout = sink\n"
    ),
    "bound structlog logger": _handled(
        'sink.error("x %s", e)',
        header="base = structlog.get_logger()\nsink = base.bind(a=1)\n",
    ),
    "module-level logging.error": _handled('logging.error("x %s", e)'),
    # Taint: the exception copied to another name.
    "alias of the exception": (
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as e:\n"
        "        saved = e\n"
        '    logger.error("x %s", saved)\n'
    ),
    "alias inside the handler": _handled('saved = e\n    logger.error("x %s", saved)'),
    "args of the exception": _handled('saved = e.args\n    logger.error("x %s", saved)'),
    "tuple unpack": _handled('pair, other = e, 1\n    logger.error("x %s", pair)'),
    "alias of an alias": _handled('a = e\n    b = a\n    logger.error("x %s", b)'),
    "alias and a sink together": _handled(
        'saved = e\n    sink.error("x %s", saved)', header="sink = logging.getLogger('a')\n"
    ),
}

SYNTHETIC_CLEAN = {
    "describe_exception": _handled('logger.error("x %s", describe_exception(e))'),
    "type name": _handled('logger.error("x %s", type(e).__name__)'),
    "exc_info_for_log": _handled('logger.error("x", exc_info=exc_info_for_log(e))'),
    "exc_info=False": _handled('logger.error("x", exc_info=False)', bind=False),
    "a name that merely contains exc_info": _handled(
        'logger.error("x %s", exc_info_label)', bind=False
    ),
    "not an exception": 'value = 1\nlogger.error("x %s", value)\n',
    "not a logger": _handled("results.append(e)"),
    "print of a non-exception": _handled('print("done", file=out)'),
    "warnings.warn of a fixed sentence": _handled('warnings.warn("fixed")'),
    "sink that is not a logger": _handled('sink.error("x %s", e)', header="sink = make_sink()\n"),
    "a call on a name never bound to a logger": _handled('sink.error("x %s", e)'),
    "alias scrubbed through describe_exception": _handled(
        'saved = describe_exception(e)\n    logger.error("x %s", saved)'
    ),
    "alias to a type name": _handled('saved = type(e)\n    logger.error("x %s", saved)'),
    "taint does not cross functions": (
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as e:\n"
        "        saved = e\n"
        "def g(saved):\n"
        '    logger.error("x %s", saved)\n'
    ),
    "an alias that is reassigned is no longer the exception": _handled(
        'saved = e\n    saved = 1\n    logger.error("x %s", saved)'
    ),
    "a name assigned from something unrelated": (
        "saved = 1\ntry:\n    pass\nexcept Exception as e:\n    other = e\n"
        'logger.error("x %s", saved)\n'
    ),
}


@pytest.mark.parametrize("name", sorted(SYNTHETIC_FLAGGED))
def test_the_scan_flags(name: str) -> None:
    assert violations(SYNTHETIC_FLAGGED[name], "synthetic.py"), name


@pytest.mark.parametrize("name", sorted(SYNTHETIC_CLEAN))
def test_the_scan_passes(name: str) -> None:
    assert not violations(SYNTHETIC_CLEAN[name], "synthetic.py"), name

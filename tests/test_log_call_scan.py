"""A scan, by `ast`, for log calls that could carry a driver error's text.

The record factory (`postern_core.log_safety`) is the net. This scan is the
plan: a log call inside `services/` or `packages/` must not hand an exception to
the logger raw. What it treats as a log call:

* `<something named like a logger>.<debug|info|warning|warn|error|exception|
  critical|fatal|log>(...)`, where "named like a logger" means the receiver's
  last name contains `log`, or the receiver is a `getLogger(...)` call
  (`logging.getLogger(__name__).error(e)`);
* `getattr(<logger>, "error")(...)`;
* a name imported `from logging import error as report`, called as `report(...)`;
* `warnings.warn(...)`, `print(...)` and `sys.stderr.write(...)` /
  `sys.stdout.write(...)`.

What it flags in such a call:

* any argument, or keyword value, that mentions an identifier bound by an
  enclosing `except ... as X`, unless the mention sits inside a call to
  `describe_exception`, `exc_info_for_log` or `type` (so `%s` of the exception,
  an f-string holding it, `str(X)`, `exc_info=X`, `**{"exc_info": X}` and a
  tuple or list holding it are all flagged);
* `exc_info=True`, any other truthy constant (`exc_info=1`), and
  `exc_info=sys.exc_info()`, and `.exception(...)`, which implies it, because
  all of them render whatever exception is being handled;
* a call to `traceback.format_exc`, `format_exception`, `format_exception_only`,
  `format_tb` or `print_exc` anywhere in the arguments, bound name or not;
* nothing else. Arguments that merely mention a name which is not an exception
  are not looked at.

THE SCAN IS HEURISTIC, and says so. It looks at names, not at types, so it
misses a logger whose receiver is not named with `log` (`self.audit.error(e)`,
`out = logger; out.error(e)`), an exception copied to another name before the
call (`saved = e` then `logger.error("%s", saved)`), an exception carried in a
container built earlier, and any call routed through a helper that logs on the
caller's behalf. It is a net for the shapes this codebase writes, not a proof
that no handled exception reaches a log.

THE ALLOWLIST below is explicit and every entry says why it is safe: the
exception can never be a SQL driver error (a parse error, a Redis or Vault
error, a JSON error) or the call is a deliberate use of the raw exception whose
type this repository controls. Each entry is keyed on the source text of the
call itself (`ast.unparse`), not on its function, so a NEW unsafe call inside
an allowlisted function is flagged, and editing a listed call re-opens its
review. The flagged set and the allowlist must be EQUAL: a flagged call that is
not listed fails, and a listed call that is no longer flagged (deleted or
rewritten) fails too, so the list cannot rot.
"""

import ast
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
)
SAFE_CALLS = frozenset({"describe_exception", "exc_info_for_log", "type"})
TRACEBACK_TEXT = frozenset(
    {"format_exc", "format_exception", "format_exception_only", "format_tb", "print_exc"}
)

Key = tuple[str, str, str, str]  # (path, enclosing function, rule, unparsed call)

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
    ): (1, "a redis ResponseError for CONFIG; no SQL"),
    (
        f"{_SRC}/auth/revocation.py",
        "revoke_session",
        "exc_info=<current exception>",
        "logger.warning('session revocation prune failed; the revoke stands', exc_info=True)",
    ): (2, "a prune failure against Redis; no SQL (two sites, identical text)"),
    (
        f"{_SRC}/auth/revoke_cli.py",
        "_run",
        _ARG,
        "print(f'prune-sessions failed: {exc}', file=err or sys.stderr)",
    ): (1, "the operator CLI's own terminal; a Redis error from a prune, no SQL, no client"),
    (
        f"{_SRC}/store/audit.py",
        "append_with_reserve",
        _ARG,
        "logger.warning('the connection pool is at its ceiling; writing this audit row on "
        "the reserve connection instead: %s', saturated)",
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
    ): (1, "logs `exc.status`, the numeric HTTP status of a BackendWriteError; no text"),
    (
        "services/confirm/device_auth.py",
        "_exchange",
        _ARG,
        "logger.warning('device grant: %s; refusing to mint', exc)",
    ): (1, "RefreshSessionStoreFull, a fixed sentence this repository writes"),
    (
        "services/confirm/device_auth.py",
        "device_authorization",
        _ARG,
        "logger.warning('device authorization refused: %s', exc)",
    ): (1, "DeviceCodeStoreContended, whose text is a fixed sentence this repository writes"),
    (
        "services/confirm/device_auth.py",
        "device_authorization",
        _ARG,
        "logger.warning('device authorization refused: the device code store holds %d codes, "
        "its cap', exc.held)",
    ): (1, "DeviceCodeStoreFull `exc.held`, an int"),
}


def _terminal_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _is_logger_like(node: ast.expr) -> bool:
    """A receiver named like a logger, or a `getLogger(...)` call."""
    if isinstance(node, ast.Call):
        return "getlogger" in _terminal_name(node.func).lower()
    return "log" in _terminal_name(node).lower()


def _log_method(node: ast.Call, aliases: dict[str, str]) -> str | None:
    """The logging method this call is, or ``None`` if it is not a log call."""
    func = node.func
    if isinstance(func, ast.Attribute):
        if func.attr in LOG_METHODS and _is_logger_like(func.value):
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
        and _is_logger_like(func.args[0])
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


class _Scan(ast.NodeVisitor):
    def __init__(self, path: str, aliases: dict[str, str]) -> None:
        self.path = path
        self.aliases = aliases
        self.bound: list[str] = []
        self.functions: list[str] = []
        self.found: list[tuple[str, str, str, str, int]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name:
            self.bound.append(node.name)
        self.generic_visit(node)
        if node.name:
            self.bound.pop()

    def visit_Call(self, node: ast.Call) -> None:
        method = _log_method(node, self.aliases)
        if method is not None:
            self._check(node, method)
        self.generic_visit(node)

    def _flag(self, rule: str, node: ast.Call) -> None:
        function = self.functions[-1] if self.functions else "<module>"
        self.found.append((self.path, function, rule, ast.unparse(node), node.lineno))

    def _check(self, node: ast.Call, method: str) -> None:
        bound = frozenset(self.bound)
        if method == "exception":
            self._flag("exception()", node)
        values = [*node.args, *(kw.value for kw in node.keywords)]
        if bound and any(_mentions(value, bound) for value in values):
            self._flag(_ARG, node)
        if any(_has_traceback_text(value) for value in values):
            self._flag("traceback text", node)
        if any(
            kw.arg == "exc_info" and _renders_current_exception(kw.value) for kw in node.keywords
        ):
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


def violations(source: str, path: str) -> list[tuple[str, str, str, str, int]]:
    tree = ast.parse(source)
    scan = _Scan(path, _logging_aliases(tree))
    scan.visit(tree)
    return scan.found


def _counted(found: list[tuple[str, str, str, str, int]]) -> Counter[Key]:
    return Counter((path, function, rule, call) for path, function, rule, call, _ in found)


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


def _all_violations() -> list[tuple[str, str, str, str, int]]:
    found: list[tuple[str, str, str, str, int]] = []
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
        (_SYNTHETIC_PATH, "f", _ARG, "logger.error('leak %s', str(e))")
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
    assert stale(one, allowlist) == [(_SYNTHETIC_PATH, "f", _ARG, "logger.error('b %s', e.status)")]


def test_deleting_one_of_two_identical_allowlisted_calls_is_stale() -> None:
    two = _LISTED_MODULE + "        logger.error('a %s', e.status)\n"
    allowlist = _allowlist_for(two, count=2)
    one = _counted(violations(_LISTED_MODULE, _SYNTHETIC_PATH))
    assert stale(one, allowlist)


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
}

SYNTHETIC_CLEAN = {
    "describe_exception": _handled('logger.error("x %s", describe_exception(e))'),
    "type name": _handled('logger.error("x %s", type(e).__name__)'),
    "exc_info_for_log": _handled('logger.error("x", exc_info=exc_info_for_log(e))'),
    "exc_info=False": _handled('logger.error("x", exc_info=False)', bind=False),
    "not an exception": 'value = 1\nlogger.error("x %s", value)\n',
    "not a logger": _handled("results.append(e)"),
    "print of a non-exception": _handled('print("done", file=out)'),
    "warnings.warn of a fixed sentence": _handled('warnings.warn("fixed")'),
}


@pytest.mark.parametrize("name", sorted(SYNTHETIC_FLAGGED))
def test_the_scan_flags(name: str) -> None:
    assert violations(SYNTHETIC_FLAGGED[name], "synthetic.py"), name


@pytest.mark.parametrize("name", sorted(SYNTHETIC_CLEAN))
def test_the_scan_passes(name: str) -> None:
    assert not violations(SYNTHETIC_CLEAN[name], "synthetic.py"), name

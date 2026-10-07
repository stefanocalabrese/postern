"""A scan, by `ast`, for log calls that could carry a driver error's text.

The record factory (`postern_core.log_safety`) is the net. This scan is the
plan: a log call inside `services/` or `packages/` must not hand an exception to
the logger raw. What it flags, for a call `<something named like a logger>.
<debug|info|warning|warn|error|exception|critical|fatal|log>(...)`:

* any argument, or keyword value, that mentions an identifier bound by an
  enclosing `except ... as X`, unless the mention sits inside a call to
  `describe_exception`, `exc_info_for_log` or `type` (so `%s` of the exception,
  an f-string holding it, `str(X)`, `exc_info=X`, `**{"exc_info": X}` and a
  tuple or list holding it are all flagged);
* `exc_info=True`, and `.exception(...)`, which implies it, because both render
  whatever exception is being handled;
* nothing else. Arguments that merely mention a name which is not an exception
  are not looked at.

THE ALLOWLIST below is explicit and every entry says why it is safe: the
exception can never be a SQL driver error (a parse error, a Redis or Vault
error, a JSON error) or the call is a deliberate use of the raw exception whose
type this repository controls. A site that is not listed fails the test, and a
listed site that disappears fails it too, so the list cannot rot.
"""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "fatal", "log"}
)
SAFE_CALLS = frozenset({"describe_exception", "exc_info_for_log", "type"})

#: (relative path, enclosing function, rule) -> why it is safe.
_ARG = "raw exception argument"
ALLOWLIST: dict[tuple[str, str, str], str] = {
    ("services/confirm/callback.py", "_approve", _ARG): (
        "logs `exc.status`, the numeric HTTP status of a BackendWriteError; no text"
    ),
    ("services/confirm/device_auth.py", "device_authorization", _ARG): (
        "DeviceCodeStoreFull `exc.held` (an int) and DeviceCodeStoreContended, whose "
        "text is a fixed sentence this repository writes"
    ),
    ("services/confirm/device_auth.py", "_exchange", _ARG): (
        "RefreshSessionStoreFull, a fixed sentence this repository writes"
    ),
    (
        "packages/postern-core/src/postern_core/auth/redis_preflight.py",
        "check_eviction_policy",
        _ARG,
    ): ("a redis ResponseError for CONFIG; no SQL"),
    (
        "packages/postern-core/src/postern_core/auth/revocation.py",
        "revoke_session",
        "exc_info=True",
    ): ("a prune failure against Redis; no SQL (two sites)"),
    ("packages/postern-core/src/postern_core/store/audit.py", "append_with_reserve", _ARG): (
        "sqlalchemy.exc.TimeoutError, the pool's 'QueuePool limit' sentence; it is not a "
        "StatementError and holds no statement"
    ),
}


def _terminal_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


def _is_log_call(node: ast.Call) -> bool:
    func = node.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr in LOG_METHODS
        and "log" in _terminal_name(func.value).lower()
    )


def _mentions(node: ast.AST, bound: frozenset[str]) -> bool:
    """True if ``node`` mentions a bound name outside a safe call."""
    if isinstance(node, ast.Call) and _terminal_name(node.func) in SAFE_CALLS:
        return False
    if isinstance(node, ast.Name):
        return node.id in bound
    return any(_mentions(child, bound) for child in ast.iter_child_nodes(node))


class _Scan(ast.NodeVisitor):
    def __init__(self, path: str) -> None:
        self.path = path
        self.bound: list[str] = []
        self.functions: list[str] = []
        self.handlers = 0
        self.found: list[tuple[str, str, str, int]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node.name)
        self.generic_visit(node)
        self.functions.pop()

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.handlers += 1
        if node.name:
            self.bound.append(node.name)
        self.generic_visit(node)
        if node.name:
            self.bound.pop()
        self.handlers -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if _is_log_call(node):
            self._check(node)
        self.generic_visit(node)

    def _flag(self, rule: str, node: ast.AST) -> None:
        function = self.functions[-1] if self.functions else "<module>"
        self.found.append((self.path, function, rule, getattr(node, "lineno", 0)))

    def _check(self, node: ast.Call) -> None:
        assert isinstance(node.func, ast.Attribute)
        bound = frozenset(self.bound)
        if node.func.attr == "exception":
            self._flag("exception()", node)
        values = [*node.args, *(kw.value for kw in node.keywords)]
        if bound and any(_mentions(value, bound) for value in values):
            self._flag("raw exception argument", node)
        for kw in node.keywords:
            if (
                kw.arg == "exc_info"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
            ):
                self._flag("exc_info=True", node)


def violations(source: str, path: str) -> list[tuple[str, str, str, int]]:
    scan = _Scan(path)
    scan.visit(ast.parse(source))
    return scan.found


def _scanned_files() -> list[Path]:
    return [
        *sorted((ROOT / "services").rglob("*.py")),
        *sorted((ROOT / "packages").glob("*/src/**/*.py")),
    ]


def _all_violations() -> list[tuple[str, str, str, int]]:
    found: list[tuple[str, str, str, int]] = []
    for path in _scanned_files():
        relative = str(path.relative_to(ROOT))
        found.extend(violations(path.read_text(), relative))
    return found


def test_every_log_call_that_could_hold_a_driver_error_is_sanctioned() -> None:
    unlisted = [
        f"{path}:{line} in {function}: {rule}"
        for path, function, rule, line in _all_violations()
        if (path, function, rule) not in ALLOWLIST
    ]
    assert not unlisted, "\n".join(unlisted)


def test_every_allowlisted_site_still_exists() -> None:
    present = {(path, function, rule) for path, function, rule, _ in _all_violations()}
    stale = sorted(set(ALLOWLIST) - present)
    assert not stale, stale


# ---------------------------------------------------------------------------
# The scan itself: each shape it exists for is flagged, each sanctioned one is not.
# ---------------------------------------------------------------------------


def _handled(call: str, *, bind: bool = True) -> str:
    """A `try`/`except` whose handler body is ``call``."""
    header = "except Exception as e:" if bind else "except Exception:"
    return f"try:\n    pass\n{header}\n    {call}\n"


SYNTHETIC_FLAGGED = {
    "percent-s of the exception": _handled('logger.error("x %s", e)'),
    "str() of the exception": _handled('logger.error("x %s", str(e))'),
    "f-string": _handled('logger.warning(f"x {e}")'),
    "exception()": _handled('logger.exception("x")', bind=False),
    "exc_info=True": _handled('logger.warning("x", exc_info=True)', bind=False),
    "exc_info=name": _handled('logger.error("x", exc_info=e)'),
    "starred dict": _handled('logger.error("x", **{"exc_info": e})'),
    "tuple argument": _handled('logger.error("x %s", (1, e))'),
    "self.logger": _handled('self.logger.error("x %s", e)'),
    "log()": _handled('logger.log(40, "x %s", e)'),
}

SYNTHETIC_CLEAN = {
    "describe_exception": _handled('logger.error("x %s", describe_exception(e))'),
    "type name": _handled('logger.error("x %s", type(e).__name__)'),
    "exc_info_for_log": _handled('logger.error("x", exc_info=exc_info_for_log(e))'),
    "not an exception": 'value = 1\nlogger.error("x %s", value)\n',
    "not a logger": _handled("results.append(e)"),
}


@pytest.mark.parametrize("name", sorted(SYNTHETIC_FLAGGED))
def test_the_scan_flags(name: str) -> None:
    assert violations(SYNTHETIC_FLAGGED[name], "synthetic.py"), name


@pytest.mark.parametrize("name", sorted(SYNTHETIC_CLEAN))
def test_the_scan_passes(name: str) -> None:
    assert not violations(SYNTHETIC_CLEAN[name], "synthetic.py"), name

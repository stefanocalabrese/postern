"""``POSTERN_REDIS_URL`` is read in one place, and a blank value is unset everywhere.

``postern_core.config.redis_url_from_env`` strips and returns ``None`` for a
blank value, the convention that module's header states for every variable.
Until it existed the variable was read in eight places with three behaviours:
``" "`` was truthy at the store factories, which then built a Redis store with
a one-space URL, and falsy only where someone had added ``.strip()``. The
table below drives every call site with the same blank values.
"""

from __future__ import annotations

import ast
import io
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from postern_core.auth.device_codes import create_device_code_store
from postern_core.auth.refresh_sessions import create_refresh_session_store
from postern_core.auth.revocation import create_revocation_store
from postern_core.auth.revoke_cli import main as revoke_main
from postern_core.config import redis_url_from_env
from postern_core.risk.session import create_session_store

from services.confirm.customer_rate_limit import create_customer_rate_limit_store

BLANKS = ["", " ", " \t\n"]

FACTORIES: list[Callable[[], Any]] = [
    create_device_code_store,
    create_refresh_session_store,
    create_revocation_store,
    create_session_store,
    create_customer_rate_limit_store,
]


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)


class TestTheReader:
    def test_unset_is_none(self) -> None:
        assert redis_url_from_env() is None

    @pytest.mark.parametrize("blank", BLANKS)
    def test_blank_is_none(self, monkeypatch: pytest.MonkeyPatch, blank: str) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", blank)
        assert redis_url_from_env() is None

    def test_a_value_is_returned_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "  redis://cache:6379/1 \n")
        assert redis_url_from_env() == "redis://cache:6379/1"


class TestEveryCallSiteAgrees:
    @pytest.mark.parametrize("blank", BLANKS)
    @pytest.mark.parametrize("factory", FACTORIES, ids=lambda f: f.__name__)
    def test_a_blank_url_selects_the_in_memory_backend(
        self, monkeypatch: pytest.MonkeyPatch, factory: Callable[[], Any], blank: str
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", blank)
        assert type(factory()).__name__.startswith("InMemory")

    @pytest.mark.parametrize("factory", FACTORIES, ids=lambda f: f.__name__)
    def test_a_url_selects_redis(
        self, monkeypatch: pytest.MonkeyPatch, factory: Callable[[], Any]
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", " redis://127.0.0.1:6379/0 ")
        assert type(factory()).__name__.startswith("Redis")

    @pytest.mark.parametrize("blank", BLANKS)
    def test_the_revoke_cli_refuses_a_blank_url(
        self, monkeypatch: pytest.MonkeyPatch, blank: str
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", blank)
        err = io.StringIO()
        assert revoke_main(["list"], out=io.StringIO(), err=err) == 1
        assert "POSTERN_REDIS_URL is not set" in err.getvalue()


ROOT = Path(__file__).resolve().parent.parent
SCANNED = ("packages", "services", "stub", "tools")
READER = Path("packages/postern-core/src/postern_core/config.py")


VARIABLE = "POSTERN_REDIS_URL"
CONSTANT = "REDIS_URL_ENV"
_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)


def _names_environ(node: ast.expr) -> bool:
    """``environ``, ``os.environ`` or any ``<x>.environ``."""
    return (isinstance(node, ast.Name) and node.id == "environ") or (
        isinstance(node, ast.Attribute) and node.attr == "environ"
    )


def _names_getenv(node: ast.expr) -> bool:
    return (isinstance(node, ast.Name) and node.id in {"getenv", "getenvb"}) or (
        isinstance(node, ast.Attribute) and node.attr in {"getenv", "getenvb"}
    )


def _own_nodes(scope: ast.AST) -> Iterator[ast.AST]:
    """Every node of ``scope`` outside the functions nested in it."""
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPES):
            stack.extend(ast.iter_child_nodes(node))


def _tainted(node: ast.expr | None, names: set[str]) -> bool:
    """The variable's name: the literal, the constant, or a name bound to either."""
    if isinstance(node, ast.Constant):
        return node.value == VARIABLE
    if isinstance(node, ast.Name):
        return node.id == CONSTANT or node.id in names
    if isinstance(node, ast.Attribute):
        return node.attr == CONSTANT
    return False


def _bound_names(scope: ast.AST, inherited: set[str]) -> set[str]:
    """``inherited`` plus every name this scope binds to a tainted value, to a fixpoint."""
    names = set(inherited)
    while True:
        before = len(names)
        for node in _own_nodes(scope):
            targets: list[ast.expr] = []
            value: ast.expr | None = None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign | ast.NamedExpr):
                targets, value = [node.target], node.value
            if _tainted(value, names):
                names.update(t.id for t in targets if isinstance(t, ast.Name))
        if len(names) == before:
            return names


def _reads(scope: ast.AST, inherited: set[str]) -> Iterator[int]:
    """Line numbers of every environment read of the variable in ``scope`` and below."""
    names = _bound_names(scope, inherited)
    for node in _own_nodes(scope):
        if isinstance(node, _SCOPES):
            yield from _reads(node, names)
        elif isinstance(node, ast.Call):
            func = node.func
            accessor = _names_getenv(func) or (
                isinstance(func, ast.Attribute) and _names_environ(func.value)
            )
            arguments = [*node.args, *(k.value for k in node.keywords)]
            if accessor and any(_tainted(a, names) for a in arguments):
                yield node.lineno
        elif isinstance(node, ast.Subscript):
            if _names_environ(node.value) and _tainted(node.slice, names):
                yield node.lineno


def _offenders(root: Path) -> tuple[int, list[str]]:
    """``(files scanned, offending reads)`` under ``root``'s scanned directories.

    An ``ast`` walk, not a line scan: a read split across lines, a read
    through ``REDIS_URL_ENV`` imported or as an attribute, and a read through
    a variable bound to either name in the same scope (or an enclosing one)
    are all found, and a docstring or comment naming the variable beside the
    word ``environ`` is not.
    """
    scanned = 0
    offenders: list[str] = []
    for base in SCANNED:
        for path in (root / base).rglob("*.py"):
            scanned += 1
            if path == root / READER:
                continue
            tree = ast.parse(path.read_text(), filename=str(path))
            offenders.extend(f"{path.relative_to(root)}:{n}" for n in sorted(_reads(tree, set())))
    return scanned, offenders


def test_no_module_reads_the_variable_except_the_one_reader() -> None:
    """A raw read in a module under ``packages``, ``services``, ``stub`` or ``tools``."""
    scanned, offenders = _offenders(ROOT)
    assert scanned > 0
    assert offenders == []


OFFENDING = {
    "split across lines": """
import os

def url():
    return os.environ.get(
        "POSTERN_REDIS_URL",
        "",
    )
""",
    "the constant, imported": """
import os
from postern_core.config import REDIS_URL_ENV

def url():
    return os.getenv(
        REDIS_URL_ENV
    )
""",
    "the constant, as an attribute": """
import os
from postern_core import config

def url():
    return os.environ[
        config.REDIS_URL_ENV
    ]
""",
    "a variable assigned from the literal": """
import os

def url():
    name = "POSTERN_REDIS_URL"
    other = name
    return os.environ.get(
        other
    )
""",
    "a variable assigned from the constant": """
from os import environ
from postern_core.config import REDIS_URL_ENV

def url():
    key: str = REDIS_URL_ENV
    return environ.get(key, "")
""",
}

INNOCENT = """
import os

def url():
    "Reads POSTERN_REDIS_URL through redis_url_from_env, never environ."
    name = "POSTERN_REDIS_URL"
    return os.environ.get("POSTERN_OTHER"), name
"""


@pytest.mark.parametrize("source", OFFENDING.values(), ids=OFFENDING.keys())
def test_the_scan_bites_on_a_copy_of_the_tree(tmp_path: Path, source: str) -> None:
    """A copy of the real reader and one real module, plus one offending module."""
    (tmp_path / READER).parent.mkdir(parents=True)
    (tmp_path / READER).write_text((ROOT / READER).read_text())
    (tmp_path / "services").mkdir()
    (tmp_path / "services" / "main.py").write_text((ROOT / "services/confirm/main.py").read_text())
    (tmp_path / "services" / "innocent.py").write_text(INNOCENT)
    assert _offenders(tmp_path) == (3, [])
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "drift.py").write_text(source)
    scanned, offenders = _offenders(tmp_path)
    assert scanned == 4
    assert [entry.split(":")[0] for entry in offenders] == ["tools/drift.py"]

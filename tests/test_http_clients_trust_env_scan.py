"""Every ``httpx2`` client built outside ``tests/`` passes ``trust_env=False``.

Scanned: ``services/``, ``packages/``, ``tools/``, ``stub/`` and ``migrations/``.

The per-client behaviour is measured in ``tests/test_http_clients_ignore_proxy_env.py``.
This is the net for a client added later: a construction that leaves the default
(``trust_env=True``) sends its requests, bearer token included, through whatever
``HTTP_PROXY`` names. Proxy environment variables are ignored; egress is routed by
the network, not by the environment.

``ALLOWLIST`` names clients built by code this repository does not own and cannot
change. It is empty: fastmcp's JWT verifier builds its own client only when none is
passed, and both verifiers here pass one.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
#: The transports are scanned too: a transport builds its own SSL context from its own
#: `trust_env`, so `AsyncHTTPTransport()` handed to a `trust_env=False` client re-opens it.
CLIENT_NAMES = {"AsyncClient", "Client", "AsyncHTTPTransport", "HTTPTransport"}
HTTP_MODULES = {"httpx", "httpx2"}
ALLOWLIST: frozenset[str] = frozenset()

#: Every directory of Python this repository ships or runs outside `tests/`.
#: `tools/`, `stub/` and `migrations/` build no client today: they are listed so
#: that the first one anyone adds is held to the same rule.
SCANNED = ("services", "packages", "tools", "stub", "migrations")


def _scanned_files() -> list[Path]:
    return [
        path
        for top in SCANNED
        for path in sorted((ROOT / top).rglob("*.py"))
        if ".venv" not in path.parts
    ]


def _bindings(tree: ast.AST) -> tuple[set[str], dict[str, str], set[str], set[str]]:
    """Names this module binds to an httpx module, a client class, or `functools.partial`."""
    modules: set[str] = set()
    classes: dict[str, str] = {}
    partial_names: set[str] = set()
    functools_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in HTTP_MODULES:
                    modules.add(alias.asname or alias.name)
                if alias.name == "functools":
                    functools_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if node.module in HTTP_MODULES and alias.name in CLIENT_NAMES:
                    classes[alias.asname or alias.name] = alias.name
                if node.module == "functools" and alias.name == "partial":
                    partial_names.add(alias.asname or alias.name)
    return modules, classes, partial_names, functools_names


def _client_constructions(source: str) -> list[ast.Call]:
    """Calls that build an httpx client or transport, directly or through `partial`.

    A name counts only when this module imported it from `httpx`/`httpx2`, under
    whatever alias, so `fastmcp.Client` (a transport-taking class, not an HTTP
    client) is not flagged.
    """
    tree = ast.parse(source)
    modules, classes, partial_names, functools_names = _bindings(tree)

    def is_client(node: ast.expr) -> bool:
        if isinstance(node, ast.Attribute):
            return (
                isinstance(node.value, ast.Name)
                and node.value.id in modules
                and node.attr in CLIENT_NAMES
            )
        return isinstance(node, ast.Name) and node.id in classes

    def is_partial(node: ast.expr) -> bool:
        if isinstance(node, ast.Attribute):
            return (
                isinstance(node.value, ast.Name)
                and node.value.id in functools_names
                and node.attr == "partial"
            )
        return isinstance(node, ast.Name) and node.id in partial_names

    calls: list[ast.Call] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if is_client(node.func) or (
            is_partial(node.func) and node.args and is_client(node.args[0])
        ):
            calls.append(node)
    return calls


def _violations(source: str, label: str) -> list[str]:
    bad = []
    for call in _client_constructions(source):
        flag = next((k for k in call.keywords if k.arg == "trust_env"), None)
        ok = flag is not None and isinstance(flag.value, ast.Constant) and flag.value.value is False
        where = f"{label}@{call.lineno}"
        if not ok and where not in ALLOWLIST:
            bad.append(where)
    return bad


def test_every_production_http_client_sets_trust_env_false() -> None:
    files = _scanned_files()
    assert files
    constructed = 0
    violations: list[str] = []
    for path in files:
        source = path.read_text()
        label = str(path.relative_to(ROOT))
        constructed += len(_client_constructions(source))
        violations += _violations(source, label)
    # Five today: write, facade, vault and the two JWKS verifier clients.
    assert constructed >= 5, constructed
    assert violations == []


def test_the_scan_sees_a_client_without_the_flag() -> None:
    assert _violations("import httpx2\nhttpx2.AsyncClient(timeout=1)\n", "x.py") == ["x.py@2"]
    assert _violations("import httpx2\nhttpx2.Client(trust_env=True)\n", "x.py") == ["x.py@2"]
    assert _violations("from httpx2 import AsyncClient\nAsyncClient()\n", "x.py") == ["x.py@2"]
    assert _violations("import httpx2\nhttpx2.AsyncClient(trust_env=False)\n", "x.py") == []


def test_the_scan_covers_tools_stub_and_migrations_and_finds_no_unlisted_client() -> None:
    files = _scanned_files()
    covered = {path.relative_to(ROOT).parts[0] for path in files}
    assert covered == set(SCANNED), covered
    for top in ("tools", "stub", "migrations"):
        in_top = [path for path in files if path.relative_to(ROOT).parts[0] == top]
        assert in_top, top
        for path in in_top:
            source = path.read_text()
            assert _violations(source, str(path.relative_to(ROOT))) == [], path


def test_a_client_added_under_tools_stub_or_migrations_would_be_flagged() -> None:
    for top in ("tools", "stub", "migrations"):
        label = f"{top}/new_module.py"
        assert _violations("import httpx2\nhttpx2.AsyncClient()\n", label) == [f"{label}@2"]


def test_the_scan_follows_aliases_partials_and_transports() -> None:
    """Each evasion the first version of this scan missed, one synthetic case apiece."""
    flagged = {
        "module alias": "import httpx2 as h\nh.AsyncClient()\n",
        "class alias": "from httpx2 import AsyncClient as AC\nAC()\n",
        "partial": (
            "import functools\nimport httpx2\nfunctools.partial(httpx2.AsyncClient, timeout=1)()\n"
        ),
        "partial alias module": (
            "import functools as ft\nimport httpx2\nft.partial(httpx2.AsyncClient)()\n"
        ),
        "partial alias name": (
            "from functools import partial as p\nfrom httpx2 import AsyncClient\np(AsyncClient)()\n"
        ),
        "async transport": "import httpx2\nhttpx2.AsyncHTTPTransport()\n",
        "sync transport": "import httpx2\nhttpx2.HTTPTransport(retries=1)\n",
        "transport class alias": "from httpx2 import HTTPTransport as T\nT()\n",
        "httpx module": "import httpx\nhttpx.AsyncClient()\n",
    }
    for case, source in flagged.items():
        assert _violations(source, "x.py"), case


def test_the_scan_accepts_the_same_shapes_when_they_set_the_flag() -> None:
    clean = [
        "import httpx2 as h\nh.AsyncClient(trust_env=False)\n",
        "from httpx2 import AsyncClient as AC\nAC(trust_env=False)\n",
        "import functools\nimport httpx2\n"
        "functools.partial(httpx2.AsyncClient, trust_env=False)()\n",
        "import httpx2\nhttpx2.AsyncHTTPTransport(trust_env=False)\n",
        "import httpx2\nhttpx2.HTTPTransport(trust_env=False)\n",
    ]
    for source in clean:
        assert _violations(source, "x.py") == [], source


def test_a_client_class_that_is_not_httpx_is_not_flagged() -> None:
    assert _violations("from fastmcp import Client\nClient(object())\n", "x.py") == []
    assert _violations("import other\nother.AsyncClient()\n", "x.py") == []
    assert _violations("import functools\nfunctools.partial(print, 1)()\n", "x.py") == []

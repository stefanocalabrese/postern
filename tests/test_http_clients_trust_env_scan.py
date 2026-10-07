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
CLIENT_NAMES = {"AsyncClient", "Client"}
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


def _client_constructions(source: str) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name not in CLIENT_NAMES:
            continue
        # `httpx2.AsyncClient(...)` or a bare imported name; `fastmcp.Client` takes
        # a transport, not a URL, and is not an HTTP client.
        if isinstance(func, ast.Attribute) and not (
            isinstance(func.value, ast.Name) and func.value.id in {"httpx", "httpx2"}
        ):
            continue
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

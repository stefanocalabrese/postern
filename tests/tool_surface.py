"""Build the tool surface that ``tool-surface.json`` records.

WHY THIS FILE EXISTS AT ALL. CLAUDE.md's hard rule on tool definitions has two
clauses, and the module seam only satisfies the first by itself: discovery is
static config in the repo, AND the tool surface must be possible to diff between
deploys. A seam that adds tools from installed distributions makes the second
clause harder, not easier, because ``git diff`` on this repository no longer
shows the whole surface. ``tool-surface.json`` is the answer: it is regenerated
from the ASSEMBLED SERVER, checked in, and gated, so a module that adds, renames
or re-gates a tool shows up as a reviewable diff naming the tool, its module,
its consent domain, its annotations, its parameters and -- for a write
operation -- the backend audience, path, method and verification tier it routes.

WHY IT LIVES UNDER ``tests`` AND NOT UNDER ``services`` OR ``postern_core``.
It has to read both halves: `services/api/server.py` for what actually
registered, and `services/confirm/execute.py` for the write routing. A module
under ``services`` that imported both would break `.importlinter`'s first two
contracts, and one under ``postern_core`` would make the shared library import
the services. ``tests`` is the one place in this tree that legitimately sees
everything, and it is inside ``make ci``'s mypy and ruff runs, which ``tools/``
is not. `tools/write_tool_surface.py` is a five-line CLI over this module.

THE READ SURFACE COMES FROM THE SERVER, NOT FROM THE DECLARATIONS, and that
ordering is the control. Reading the declarations would record what modules
SAID; reading `fastmcp.FastMCP.list_tools` records what a client can actually
call. `surface` then asserts the two agree, so a tool that registered without a
declaration -- the shape a module could use to slip past both this gate and the
golden masking gate -- fails the build instead of appearing nowhere.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx2
from fastmcp import FastMCP
from fastmcp.tools import FunctionTool
from postern_core.facade.client import BackendClient, StubTokenMinter
from postern_core.modules.read import ReadModule, ReadTool, load_read_modules

from services.api.server import build_server
from services.api.settings import Settings
from services.api.tools import BUILTIN_READ_MODULES
from services.confirm.execute import build_write_operations
from tests.conftest import TEST_CUSTOMER

#: The checked-in golden file, at the repository root where a reviewer trips
#: over it rather than in a tools directory where they would not.
SURFACE_PATH = Path(__file__).resolve().parents[1] / "tool-surface.json"


def _server() -> FastMCP:
    """A server assembled the production way, over a backend nothing calls.

    No `db`, so consent resolves through `services/api/server.py`'s
    `_no_consent_required` stand-in: this function lists tools and calls none,
    and a real `postern_core.store.engine.Database` would make regenerating the
    golden file need Docker. The consent DOMAIN each tool declares is recorded
    from the declaration, which is the reviewable fact; whether the check object
    was the Postgres one or the stand-in is a property of the deployment, not of
    the surface.
    """
    backend = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(lambda request: httpx2.Response(404, json={})),
        before_backend_request=None,
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


def declared_read_tools() -> dict[str, tuple[ReadModule, ReadTool]]:
    """Every read tool the built-ins and installed modules declare.

    Built the same way `services/api/server.py`'s `_read_modules` builds it, so
    that a disagreement between this and the server is a disagreement about
    REGISTRATION and never about which modules were considered.
    """
    modules = BUILTIN_READ_MODULES + load_read_modules()
    return {tool.name: (module, tool) for module in modules for tool in module.tools}


def _parameters(tool: FunctionTool) -> dict[str, Any]:
    """The parameter names and which are required, off the real JSON schema.

    NAMES AND REQUIREDNESS, NOT THE WHOLE SCHEMA, on purpose. The full schema
    carries pydantic's rendering of every constraint, which churns on a pydantic
    or FastMCP upgrade and would make this file's diff unreadable exactly when
    someone needs to read it. A parameter appearing, disappearing or becoming
    optional is the change a reviewer has to see; that a `Field(le=365)` bound
    serialises differently is not.
    """
    schema = tool.parameters
    properties = schema.get("properties", {})
    return {
        "parameters": sorted(properties),
        "required": sorted(schema.get("required", [])),
    }


async def read_surface() -> list[dict[str, Any]]:
    """What a client can call, with the module that declared each tool.

    Raises:
        AssertionError: if a registered tool has no declaration, or a declared
            tool did not register. Both directions matter: the first is a tool
            outside every gate that reads declarations, and the second is a
            module whose tools silently did not arrive.
    """
    declared = declared_read_tools()
    registered = {tool.name: tool for tool in await _server().list_tools()}

    undeclared = sorted(set(registered) - set(declared))
    assert not undeclared, (
        f"registered tools with no module declaration: {undeclared}. Every tool "
        "reaches the server through a ReadModule; one that did not is outside the "
        "consent domain, the surface file and anything else that reads declarations."
    )
    unregistered = sorted(set(declared) - set(registered))
    assert not unregistered, (
        f"declared tools that did not register: {unregistered}. A module declared "
        "them and the assembled server does not serve them."
    )

    rows: list[dict[str, Any]] = []
    for name, tool in registered.items():
        assert isinstance(tool, FunctionTool), f"{name} is not a FunctionTool"
        module, declaration = declared[name]
        annotations = tool.annotations
        assert annotations is not None, f"{name} carries no annotations"
        rows.append(
            {
                "module": module.name,
                "name": name,
                "consent_domain": declaration.consent_domain,
                "read_only_hint": annotations.read_only_hint,
                "open_world_hint": annotations.open_world_hint,
                **_parameters(tool),
            }
        )
    return sorted(rows, key=lambda row: (row["module"], row["name"]))


def write_surface() -> list[dict[str, Any]]:
    """Every write operation this repository routes, built-in and installed."""
    rows = [
        {"module": _module_of(name), **operation.as_dict()}
        for name, operation in build_write_operations().items()
    ]
    return sorted(rows, key=lambda row: (row["module"], row["tool_name"]))


def _module_of(tool_name: str) -> str:
    """Which write module routes a tool name.

    ``"(built-in)"`` for the three `services/confirm/execute.py` still carries.
    Parentheses rather than a bare word so the value cannot be confused with a
    module name an installed distribution could also claim.
    """
    from postern_core.modules.write import load_write_modules

    for module in load_write_modules():
        if any(operation.tool_name == tool_name for operation in module.operations):
            return module.name
    return "(built-in)"


async def surface() -> dict[str, Any]:
    return {"read_tools": await read_surface(), "write_operations": write_surface()}


async def surface_json() -> str:
    """The golden file's exact bytes.

    ``indent=2`` and a trailing newline, because the value of this file is the
    diff: one JSON object per line would make a module addition a single
    unreadable changed line. ``sort_keys`` is deliberately OFF -- the key order
    inside a row is the order a reader wants (module, name, gate, then schema),
    and the rows themselves are sorted by `read_surface` and `write_surface`.
    """
    return json.dumps(await surface(), indent=2) + "\n"

"""The §6.2 and A3 controls expressed as tests.

lint-imports enforces the static boundary. These assert the runtime shape:
no write capability exists in the tool surface at all.
"""

import inspect
import typing

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.tools import FunctionTool
from postern_core.domain.masking import MaskedIban, MaskedPan
from postern_core.facade import accounts, cards, transactions
from postern_core.facade.client import BackendClient, StubTokenMinter

from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER

FORBIDDEN_NAME_PARTS = ("execute", "submit", "create_payment", "transfer", "pay")


@pytest.fixture
def server() -> FastMCP:
    backend = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json={"accounts": []})),
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


async def test_no_tool_name_suggests_execution(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        names = [t.name for t in await client.list_tools()]
    for name in names:
        assert not any(part in name.lower() for part in FORBIDDEN_NAME_PARTS), name


async def test_every_registered_tool_is_annotated_read_only(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        tools = await client.list_tools()
    assert tools, "expected tools to be registered"
    for tool in tools:
        assert tool.annotations is not None, tool.name
        # `.readOnlyHint` is a deprecated camelCase alias (fires a
        # DeprecationWarning on access); `read_only_hint` is the real field
        # (Task 8 correction 3, confirmed against `mcp.types.ToolAnnotations`
        # 4.0.3: `model_fields` has `read_only_hint`, not `readOnlyHint`).
        assert tool.annotations.read_only_hint is True, tool.name


def test_the_facade_exposes_no_write_helpers() -> None:
    for module in (accounts, transactions, cards):
        for name, _obj in inspect.getmembers(module, inspect.iscoroutinefunction):
            assert not name.startswith(("create_", "update_", "delete_", "post_")), (
                f"{module.__name__}.{name}"
            )


def test_the_api_service_does_not_import_the_confirm_service() -> None:
    import services.api.server as api_server

    module = inspect.getmodule(api_server)
    assert module is not None
    source = inspect.getsource(module)
    assert "services.confirm" not in source


async def test_no_tool_parameter_accepts_a_masked_type(server: FastMCP) -> None:
    """A parameter typed MaskedPan or MaskedIban would accept an
    already-masked value as an input identifier, which handoff §6.5
    forbids. Return annotations may use these types; parameters may not."""
    for tool in await server.list_tools():
        # `FastMCP.list_tools()` is typed to return the base `Tool`, which
        # has no `.fn`; every tool this server registers is a plain
        # `@mcp.tool`-decorated function, i.e. a `FunctionTool`, which does.
        assert isinstance(tool, FunctionTool), f"{tool.name} is not a FunctionTool"
        hints = typing.get_type_hints(tool.fn, include_extras=True)
        for param_name, hint in hints.items():
            if param_name == "return":
                continue
            assert hint != MaskedPan, f"{tool.name}.{param_name} accepts MaskedPan"
            assert hint != MaskedIban, f"{tool.name}.{param_name} accepts MaskedIban"

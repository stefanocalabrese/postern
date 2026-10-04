"""The §6.2 and A3 controls expressed as tests.

lint-imports enforces the static boundary. These assert the runtime shape:
no write capability exists in the tool surface at all.
"""

import inspect
import typing
from collections.abc import AsyncIterator

import httpx2
import pytest
import pytest_asyncio
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.tools import FunctionTool
from postern_core.domain.masking import MaskedIban, MaskedPan
from postern_core.facade import accounts, cards, payments, transactions
from postern_core.facade.client import BackendClient, StubTokenMinter
from postern_core.payments import PRODUCER_TOOL_NAMES

from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures.payments_http import offline_runtime

FORBIDDEN_HELPER_PREFIXES = (
    "create_",
    "update_",
    "delete_",
    "post_",
    "execute_",
    "submit_",
)
FORBIDDEN_NAME_PARTS = ("execute", "submit", "create_payment", "transfer", "pay")


@pytest.fixture
def server() -> FastMCP:
    backend = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json={"accounts": []})),
        before_backend_request=None,
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
    for module in (accounts, transactions, cards, payments):
        for name, obj in inspect.getmembers(module, inspect.isfunction):
            if obj.__module__ != module.__name__:
                continue
            assert not name.startswith(FORBIDDEN_HELPER_PREFIXES), f"{module.__name__}.{name}"


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


def test_the_payments_facade_is_one_read() -> None:
    """Decision 0022: one function and no write helper."""
    names = [name for name, _ in inspect.getmembers(payments, inspect.iscoroutinefunction)]
    assert names == ["get_payee"]


# --- A3 with POSTERN_PAYMENTS_ENABLED on: an allowlist, not a blocklist ---------

#: The whole flag-on surface. Five reads and exactly the two producer tools.
FLAG_ON_TOOLS = {
    "start_session",
    "accounts.list",
    "accounts.get_balance",
    "transactions.list",
    "cards.list",
    *PRODUCER_TOOL_NAMES,
}


@pytest_asyncio.fixture
async def flag_on_server() -> AsyncIterator[FastMCP]:
    """`local_provider.list_tools` is read rather than `list_tools`: the
    producer's tools are consent-gated and there is no token here, so the
    server's own listing would hide exactly the tools under test."""
    runtime = offline_runtime()
    backend = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(lambda r: httpx2.Response(200, json={"accounts": []})),
        before_backend_request=None,
    )
    yield build_server(
        Settings.for_testing(),
        resolver=lambda: TEST_CUSTOMER,
        backend=backend,
        payments=runtime,
    )
    await runtime.db.close()


async def test_with_the_flag_on_exactly_the_two_producer_tools_are_added(
    flag_on_server: FastMCP,
) -> None:
    names = {tool.name for tool in await flag_on_server.local_provider.list_tools()}
    assert names == FLAG_ON_TOOLS


async def test_with_the_flag_on_every_other_tool_is_still_read_only(
    flag_on_server: FastMCP,
) -> None:
    for tool in await flag_on_server.local_provider.list_tools():
        if tool.name in PRODUCER_TOOL_NAMES:
            continue
        assert tool.annotations is not None, tool.name
        assert tool.annotations.read_only_hint is True, tool.name


async def test_the_producer_tools_carry_the_specified_annotations(
    flag_on_server: FastMCP,
) -> None:
    tools = {tool.name: tool for tool in await flag_on_server.local_provider.list_tools()}
    for name in PRODUCER_TOOL_NAMES:
        annotations = tools[name].annotations
        assert annotations is not None, name
        assert (
            annotations.read_only_hint,
            annotations.destructive_hint,
            annotations.idempotent_hint,
            annotations.open_world_hint,
        ) == (False, False, True, False), name


async def test_with_the_flag_on_no_other_tool_name_suggests_execution(
    flag_on_server: FastMCP,
) -> None:
    names = {tool.name for tool in await flag_on_server.local_provider.list_tools()}
    for name in names - set(PRODUCER_TOOL_NAMES):
        assert not any(part in name.lower() for part in ("pay", "execute", "submit", "transfer"))
    for name in PRODUCER_TOOL_NAMES:
        assert not any(part in name for part in ("execute", "submit", "transfer")), name


async def test_with_the_flag_on_no_parameter_accepts_a_masked_type(
    flag_on_server: FastMCP,
) -> None:
    for tool in await flag_on_server.local_provider.list_tools():
        assert isinstance(tool, FunctionTool), f"{tool.name} is not a FunctionTool"
        hints = typing.get_type_hints(tool.fn, include_extras=True)
        for param_name, hint in hints.items():
            if param_name == "return":
                continue
            assert hint != MaskedPan, f"{tool.name}.{param_name} accepts MaskedPan"
            assert hint != MaskedIban, f"{tool.name}.{param_name} accepts MaskedIban"


async def test_the_producer_tools_are_consent_gated_even_without_customer_auth(
    flag_on_server: FastMCP,
) -> None:
    """`build_server` got no `db` here, so every read tool has the no-auth
    stand-in. The producer's tools must not: they carry the real check, and a
    caller with no token is shown neither."""
    tools = {tool.name: tool for tool in await flag_on_server.local_provider.list_tools()}
    for name in PRODUCER_TOOL_NAMES:
        assert tools[name].auth is not None, name
    async with Client(transport=flag_on_server) as client:
        listed = {tool.name for tool in await client.list_tools()}
    assert listed.isdisjoint(PRODUCER_TOOL_NAMES)

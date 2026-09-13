"""`accounts.list` and `accounts.get_balance` (Task 8).

FastMCP 4.0.3's structured-content shape was measured empirically rather
than assumed (see the commit message / task report): a tool returning
`list[Model]` wraps the list under a `"result"` key; a tool returning a
single `Model` is *not* wrapped, `structured_content` is the model's own
fields. Both forms appear below, matching what was measured.
"""

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from postern_core.facade.client import BackendClient, StubTokenMinter

from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures import backend_responses as fx

ROUTES = {"/accounts": fx.ACCOUNTS, "/accounts/acc_7f3a/balance": fx.BALANCE}


def _handler(request: httpx2.Request) -> httpx2.Response:
    body = ROUTES.get(request.url.path)
    return httpx2.Response(200, json=body) if body else httpx2.Response(404, json={})


@pytest.fixture
def client_and_server() -> FastMCP:
    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(_handler)
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


async def test_accounts_list_returns_masked_ibans(client_and_server: FastMCP) -> None:
    async with Client(transport=client_and_server) as client:
        result = await client.call_tool("accounts.list", {})
    assert result.structured_content is not None
    ibans = [a["iban"] for a in result.structured_content["result"]]
    assert ibans == ["ES•• •••• 1332", "ES•• •••• 1119"]


async def test_accounts_list_returns_refs_not_backend_ids(client_and_server: FastMCP) -> None:
    async with Client(transport=client_and_server) as client:
        result = await client.call_tool("accounts.list", {})
    assert result.structured_content is not None
    assert [a["ref"] for a in result.structured_content["result"]] == ["acc_7f3a", "acc_9b21"]


async def test_get_balance_carries_currency_and_as_of(client_and_server: FastMCP) -> None:
    async with Client(transport=client_and_server) as client:
        result = await client.call_tool("accounts.get_balance", {"account_ref": "acc_7f3a"})
    balance = result.structured_content
    assert balance is not None
    assert balance["amount"] == {"amount": "1200.50", "currency": "EUR"}
    assert balance["as_of"].startswith("2026-09-12T10:00:00")
    assert balance["account_ref"] == "acc_7f3a"


async def test_tools_take_no_customer_argument(client_and_server: FastMCP) -> None:
    """The token is the identity (handoff §6.2)."""
    async with Client(transport=client_and_server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    for name in ("accounts.list", "accounts.get_balance"):
        properties = tools[name].input_schema.get("properties", {})
        assert "user_id" not in properties
        assert "customer_id" not in properties
        assert "customer_ref" not in properties


async def test_read_tools_are_annotated_read_only(client_and_server: FastMCP) -> None:
    async with Client(transport=client_and_server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    assert tools["accounts.list"].annotations is not None
    assert tools["accounts.list"].annotations.read_only_hint is True
    assert tools["accounts.get_balance"].annotations is not None
    assert tools["accounts.get_balance"].annotations.read_only_hint is True


async def test_get_balance_rejects_a_masked_value_as_the_ref(client_and_server: FastMCP) -> None:
    """`Ref`'s pattern (`^[a-z]{3}_[A-Za-z0-9]{1,32}$`) rejects a masked IBAN
    outright, before any request reaches the backend: this is what stops a
    value the model copied out of a previous tool result -- a mask, not a
    ref -- being fed back in as a lookup identifier.
    """
    async with Client(transport=client_and_server) as client:
        result = await client.call_tool(
            "accounts.get_balance", {"account_ref": "ES•• •••• 1332"}, raise_on_error=False
        )
    assert result.is_error is True

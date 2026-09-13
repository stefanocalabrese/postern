"""`accounts.list` and `accounts.get_balance` (Task 8).

FastMCP 4.0.3's structured-content shape was measured empirically rather
than assumed (see the commit message / task report): a tool returning
`list[Model]` wraps the list under a `"result"` key; a tool returning a
single `Model` is *not* wrapped, `structured_content` is the model's own
fields. Both forms appear below, matching what was measured.
"""

import json
import logging

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


async def test_accounts_list_validation_error_does_not_leak_the_raw_iban(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A backend that sends an IBAN-shaped value failing the mod-97 checksum
    (plausible: a transposed-digit bug on the backend side) raises
    `pydantic.ValidationError` while `list_accounts` constructs `Account`.
    Left uncaught, FastMCP's own dispatcher logs that error's structured
    `.errors()` output -- which carries the raw value regardless of
    `hide_input_in_errors` -- via `logger.warning` on the `fastmcp` logger.
    `fastmcp.utilities.logging.configure_logging` sets `fastmcp.propagate =
    False`, so a plain root-logger `caplog` capture misses it; this asserts
    against `caplog.set_level(logging.DEBUG, logger="fastmcp")` specifically.

    Real failure captured while building this test, with
    `packages/postern-core/src/postern_core/facade/accounts.py` reverted to
    construct `Account(...)` directly (no `build_model`) -- the test fails
    before it even reaches its own assertions, because the uncaught
    `pydantic.ValidationError` surfaces as a protocol-level `MCPError` that
    `raise_on_error=False` does not suppress:

        FAILED tests/test_tools_accounts.py::
        test_accounts_list_validation_error_does_not_leak_the_raw_iban
        mcp.shared.exceptions.MCPError: Invalid request parameters

        Captured log call:
        WARNING  fastmcp.server.server:server.py:1516 Invalid arguments for tool
        'accounts.list': [{'type': 'value_error', 'loc': ('iban',), 'msg': 'Value
        error, not an IBAN: expected ISO 13616 form', 'input':
        'ES0000000000000000000000', 'ctx': {'error': ValueError('not an IBAN:
        expected ISO 13616 form')}}]

    `caplog.text` carried the raw IBAN (confirming `caplog.set_level(...,
    logger="fastmcp")` is necessary: `fastmcp.propagate = False`, so a plain
    root-logger capture would have missed this). `MCPError.error.message`/
    `.data` did not carry it (verified separately: FastMCP's client-facing
    error message for this failure mode is the fixed string "Invalid request
    parameters", not the validation detail). Confirmed fixed by `build_model`
    in `facade/projection.py`, which catches the `ValidationError` inside the
    façade -- before FastMCP's dispatcher ever sees it -- and re-raises
    `BackendError(...) from None`, which takes the normal `ToolError` path
    instead (`is_error=True`, `raise_on_error=False` honored, nothing logged
    above `logger.exception`'s own safe rendering of the `BackendError`).
    """
    bad_iban = "ES0000000000000000000000"

    def _bad_iban_handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200,
            json={"accounts": [{"id": "acc_7f3a", "label": "Joint expenses", "iban": bad_iban}]},
        )

    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(_bad_iban_handler)
    )
    server = build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)

    caplog.set_level(logging.DEBUG, logger="fastmcp")
    async with Client(transport=server) as client:
        result = await client.call_tool("accounts.list", {}, raise_on_error=False)

    rendered = json.dumps(
        {
            "content": [block.model_dump(mode="json") for block in result.content],
            "structured_content": result.structured_content,
            "data": result.data,
        },
        default=str,
    )
    assert result.is_error is True
    assert bad_iban not in rendered, f"leaked in client-visible result: {rendered[:400]}"
    assert bad_iban not in caplog.text, f"leaked in the fastmcp server log: {caplog.text[:400]}"

"""`cards.list` (Task 10): last-four PAN masking, no expiry/CVV, no row cap.

`cards.list` takes no arguments and returns `list[Card]` (measured, matching
`accounts.list`'s structured-content shape from Task 8: a tool returning
`list[Model]` wraps the list under a `"result"` key). No row cap: see
`packages/postern-core/src/postern_core/facade/cards.py`'s module docstring
for the reasoning (card count is bounded by the bank's own provisioning
process, not by a widenable query parameter the way `transactions.list`'s
window is, so this façade does not carry the same `MAX_ROWS`/`truncated`
treatment Task 9 added there).
"""

import json
import logging
from typing import Any

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from postern_core.facade.client import BackendClient, StubTokenMinter

from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures import backend_responses as fx


def _handler(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(200, json=fx.CARDS)


@pytest.fixture
def server() -> FastMCP:
    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(_handler)
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


def _server_with_cards(cards: list[dict[str, Any]]) -> FastMCP:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"cards": cards})

    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(handler)
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


def _render(result: Any) -> str:
    """Matches `tests/test_masking_golden.py::_render_result`'s scan scope:
    `content` as well as `structured_content`/`data`, so a leak that reaches
    the client only through an error message is not invisible to the check.
    """
    return json.dumps(
        {
            "content": [block.model_dump(mode="json") for block in result.content],
            "structured_content": result.structured_content,
            "data": result.data,
        },
        default=str,
    )


async def test_cards_list_masks_the_pan_to_last_four(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("cards.list", {})
    assert result.structured_content is not None
    assert result.structured_content["result"][0]["pan"] == "•••• 4417"


async def test_cards_list_never_returns_expiry_or_cvv(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("cards.list", {})
    assert result.structured_content is not None
    row = result.structured_content["result"][0]
    assert set(row) == {"ref", "label", "pan", "status"}


async def test_cards_list_is_annotated_read_only(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    assert tools["cards.list"].annotations is not None
    assert tools["cards.list"].annotations.read_only_hint is True


async def test_cards_list_takes_no_arguments(server: FastMCP) -> None:
    """No `account_ref`-style argument and, per handoff §6.2, no customer
    identifier of any kind (the resolver is called with no arguments)."""
    async with Client(transport=server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    properties = tools["cards.list"].input_schema.get("properties", {})
    assert properties == {}


# --- Adversarial pass: fields beyond {ref, label, pan, status} ---


async def test_cards_list_drops_expiry_cvv_full_pan_and_cardholder_name() -> None:
    """The backend sends four fields this façade must never surface --
    `expiry`, `cvv`, `full_pan` (deliberately redundant with `pan`, in case a
    future backend duplicates the PAN under a second key) and
    `cardholder_name` -- alongside the four valid ones. `_project_card` reads
    named fields off the row one at a time (never `Card(**row)`), so these
    never reach `Card` construction at all; this proves it end to end through
    the in-process client, in both `structured_content` and `content`, not
    just by inspecting the model.
    """
    server = _server_with_cards(
        [
            {
                "id": "crd_1",
                "label": "Debit",
                "pan": fx.FULL_PAN,
                "status": "active",
                "expiry": "12/29",
                "cvv": "123",
                "full_pan": fx.FULL_PAN,
                "cardholder_name": "Jane Doe",
            }
        ]
    )
    async with Client(transport=server) as client:
        result = await client.call_tool("cards.list", {})
    assert result.structured_content is not None
    row = result.structured_content["result"][0]
    assert set(row) == {"ref", "label", "pan", "status"}
    rendered = _render(result)
    for leaked in ("expiry", "cvv", "full_pan", "cardholder_name", "12/29", "123", "Jane Doe"):
        assert leaked not in rendered, f"{leaked!r} leaked: {rendered[:400]}"
    assert fx.FULL_PAN not in rendered


# --- Adversarial pass: PAN-last-four collision between two of the customer's own cards ---


async def test_two_cards_sharing_a_last_four_are_distinguishable_by_ref_and_label() -> None:
    """Task 2's review flagged this collision as deliberate (handoff §6.5:
    last four only, never first-6-plus-last-4): two of the customer's own
    cards can share a masked `pan`. `ref` and `label` must still tell them
    apart in the tool's actual output; `pan` alone must not.
    """
    server = _server_with_cards(
        [
            {"id": "crd_1", "label": "Debit", "pan": "4111111111114417", "status": "active"},
            {"id": "crd_2", "label": "Travel", "pan": "5500000000004417", "status": "frozen"},
        ]
    )
    async with Client(transport=server) as client:
        result = await client.call_tool("cards.list", {})
    assert result.structured_content is not None
    rows = result.structured_content["result"]
    assert rows[0]["pan"] == rows[1]["pan"] == "•••• 4417"
    assert {rows[0]["ref"], rows[1]["ref"]} == {"crd_1", "crd_2"}
    assert {rows[0]["label"], rows[1]["label"]} == {"Debit", "Travel"}


# --- Adversarial pass: a status outside the Literal ---


async def test_cards_list_unrecognized_status_does_not_leak_via_build_model(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`Card.status` is `Literal["active", "frozen", "cancelled"]`. A real
    backend sending `"blocked"` or `"expired"` (a status this codebase's
    contract does not enumerate) raises `pydantic.ValidationError` while
    `_project_card` constructs `Card`. Left uncaught, that error's structured
    `.errors()` output -- which carries the raw value regardless of
    `hide_input_in_errors` -- reaches FastMCP's own dispatcher log via
    `logger.warning`; `build_model` (`facade/projection.py`) is what
    intercepts it first and re-raises a scrubbed `BackendError` instead. Same
    channel, same fix, as
    `test_tools_accounts.py::test_accounts_list_validation_error_does_not_leak_the_raw_iban`.

    Real failure captured while building this test, with
    `packages/postern-core/src/postern_core/facade/cards.py` temporarily
    reverted to construct `Card(...)` directly (no `build_model`):

        FAILED tests/test_tools_cards.py::
        test_cards_list_unrecognized_status_does_not_leak_via_build_model
        mcp.shared.exceptions.MCPError: Invalid request parameters

        Captured log call:
        WARNING  fastmcp.server.server:server.py:1516 Invalid arguments for tool
        'cards.list': [{'type': 'literal_error', 'loc': ('status',), 'msg':
        "Input should be 'active', 'frozen' or 'cancelled'", 'input': 'blocked',
        'ctx': {'expected': "'active', 'frozen' or 'cancelled'"}}]

    `caplog.text` carried the raw `'blocked'` value. Confirmed fixed by
    `build_model`: the assertions below pass against the real façade.
    """
    server = _server_with_cards(
        [{"id": "crd_1", "label": "Debit", "pan": fx.FULL_PAN, "status": "blocked"}]
    )
    caplog.set_level(logging.DEBUG, logger="fastmcp")
    async with Client(transport=server) as client:
        result = await client.call_tool("cards.list", {}, raise_on_error=False)

    rendered = _render(result)
    assert result.is_error is True
    assert "blocked" not in rendered, f"leaked in client-visible result: {rendered[:400]}"
    assert "blocked" not in caplog.text, f"leaked in the fastmcp server log: {caplog.text[:400]}"

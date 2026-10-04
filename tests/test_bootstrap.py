"""`start_session` (Task 11, handoff §4.2, "required, do not skip").

The only context-delivery mechanism that works across every client, because
it arrives as a tool result rather than as `server/discover`'s `instructions`
field (client support for which is inconsistent -- see `services/api/server.py`'s
`SERVER_INSTRUCTIONS` and this module's own `bootstrap.py` docstring).
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
from tests.fixtures.payments_http import offline_runtime


def _handler(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(200, json=fx.ACCOUNTS)


@pytest.fixture
def server() -> FastMCP:
    backend = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(_handler),
        before_backend_request=None,
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


async def test_bootstrap_returns_accounts_with_masked_ibans(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("start_session", {})
    assert result.structured_content is not None
    assert result.structured_content["accounts"][0]["iban"] == "ES•• •••• 1332"


async def test_bootstrap_reports_no_write_capability_in_this_release(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("start_session", {})
    assert result.structured_content is not None
    assert result.structured_content["write_enabled"] == []


async def test_bootstrap_explains_the_confirmation_model(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("start_session", {})
    assert result.structured_content is not None
    note = result.structured_content["confirmation_note"]
    assert "banking app" in note


async def test_bootstrap_lists_consent_per_domain(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("start_session", {})
    assert result.structured_content is not None
    domains = {c["domain"] for c in result.structured_content["consents"]}
    assert domains == {"accounts", "transactions", "cards", "payments"}


async def test_bootstrap_payments_consent_is_not_granted(server: FastMCP) -> None:
    """`ConsentSummary(domain="payments", granted=False)` must be an accurate
    statement about this release, not a placeholder: there is no payments
    tool in the registered surface (see
    `test_no_write_tool_is_registered_on_the_server` below), so nothing this
    session could do would need payments consent granted.
    """
    async with Client(transport=server) as client:
        result = await client.call_tool("start_session", {})
    assert result.structured_content is not None
    consents = {c["domain"]: c["granted"] for c in result.structured_content["consents"]}
    assert consents["payments"] is False


async def test_server_instructions_point_at_the_bootstrap_tool() -> None:
    from services.api.server import SERVER_INSTRUCTIONS

    assert "start_session" in SERVER_INSTRUCTIONS


async def test_bootstrap_is_annotated_read_only(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    assert tools["start_session"].annotations is not None
    assert tools["start_session"].annotations.read_only_hint is True


async def test_bootstrap_takes_no_arguments(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        tools = {t.name: t for t in await client.list_tools()}
    properties = tools["start_session"].input_schema.get("properties", {})
    assert properties == {}


async def test_no_write_tool_is_registered_on_the_server(server: FastMCP) -> None:
    """`write_enabled=[]` is an accurate statement about this release only if
    no write-capable tool is actually reachable through the registered
    surface -- checked here by listing tools through the client, exactly as
    a calling agent would see them, not by reading `server.py`'s source
    (handoff §4.2's own consent-vs-capability distinction: a tool the model
    can call is a capability regardless of what any tool result claims).
    """
    async with Client(transport=server) as client:
        names = {tool.name for tool in await client.list_tools()}
    assert names == {
        "start_session",
        "accounts.list",
        "accounts.get_balance",
        "transactions.list",
        "cards.list",
    }


# --- Instruction-injection question (see plan Task 11 for the full finding) ---


async def test_bootstrap_confirmation_note_flags_labels_as_customer_data(
    server: FastMCP,
) -> None:
    """`Account.label` is bank-customer-authored free text (a customer names
    their own accounts) riding inside the one result this codebase primes
    the model, via `SERVER_INSTRUCTIONS` and this tool's own description, to
    read as authoritative session setup. `FreeText` redacts PAN/IBAN-shaped
    substrings from `label` but does nothing about a label engineered to
    read as an instruction (handoff §3.1's attacker-controllable-text
    warning). This is the cheap mitigation available at this layer: the
    literal `confirmation_note` -- delivered in the tool *result*, on every
    client, unlike the tool description or `server/discover`'s
    `instructions` -- states plainly that a label is data, not a directive.
    """
    async with Client(transport=server) as client:
        result = await client.call_tool("start_session", {})
    assert result.structured_content is not None
    note = result.structured_content["confirmation_note"]
    assert "not instructions" in note or "not a directive" in note or "customer" in note.lower()


async def test_with_the_payments_flag_on_the_note_says_payments_are_proposals() -> None:
    """Spec section 10: the note changes and nothing else does. `payments`
    stays ungranted and `write_enabled` stays empty, because the note describes
    what a proposal is, not a capability this session holds."""
    runtime = offline_runtime()
    try:
        backend = BackendClient(
            "https://backend.test",
            StubTokenMinter(),
            transport=httpx2.MockTransport(_handler),
            before_backend_request=None,
        )
        server = build_server(
            Settings.for_testing(),
            resolver=lambda: TEST_CUSTOMER,
            backend=backend,
            payments=runtime,
        )
        async with Client(transport=server) as client:
            result = await client.call_tool("start_session", {})
    finally:
        await runtime.db.close()
    assert result.structured_content is not None
    note = result.structured_content["confirmation_note"]
    assert "propose a payment" in note
    assert "banking app" in note
    assert "never in this conversation" in note
    assert "not instructions" in note
    assert result.structured_content["write_enabled"] == []
    granted = {c["domain"]: c["granted"] for c in result.structured_content["consents"]}
    assert granted["payments"] is False

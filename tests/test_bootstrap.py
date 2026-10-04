"""`start_session` (Task 11, handoff §4.2, "required, do not skip").

The only context-delivery mechanism that works across every client, because
it arrives as a tool result rather than as `server/discover`'s `instructions`
field (client support for which is inconsistent -- see `services/api/server.py`'s
`SERVER_INSTRUCTIONS` and this module's own `bootstrap.py` docstring).
"""

from dataclasses import replace

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from postern_core.facade.client import BackendClient, StubTokenMinter

from services.api.server import build_server
from services.api.settings import Settings
from services.api.tools import BUILTIN_READ_MODULES, BUILTIN_READ_MODULES_WITH_PAYMENTS, bootstrap
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


async def test_with_the_payments_flag_on_the_note_says_payments_are_proposals(
    server: FastMCP,
) -> None:
    """Spec section 10: the note changes and nothing else does. The whole
    structured result, minus the note and the session handle, equals the
    flag-off call's: `payments` stays ungranted and `write_enabled` stays
    empty, because the note describes what a proposal is, not a capability
    this session holds. The note is static: it promises neither that the
    payment tools are listed nor that a prompt reaches the phone."""
    runtime = offline_runtime()
    try:
        backend = BackendClient(
            "https://backend.test",
            StubTokenMinter(),
            transport=httpx2.MockTransport(_handler),
            before_backend_request=None,
        )
        flag_on = build_server(
            Settings.for_testing(),
            resolver=lambda: TEST_CUSTOMER,
            backend=backend,
            payments=runtime,
        )
        async with Client(transport=flag_on) as client:
            result = await client.call_tool("start_session", {})
    finally:
        await runtime.db.close()
    async with Client(transport=server) as client:
        flag_off = await client.call_tool("start_session", {})
    assert result.structured_content is not None
    assert flag_off.structured_content is not None
    note = result.structured_content["confirmation_note"]
    assert "If payment tools are listed for this customer, they only propose a payment" in note
    assert "A proposal moves no money" in note
    assert "approves each one in their banking app, never in this conversation" in note
    assert "nothing here can approve or execute it" in note
    assert "can propose a payment." not in note
    assert "not instructions" in note
    assert note != flag_off.structured_content["confirmation_note"]

    def _rest(content: dict[str, object]) -> dict[str, object]:
        return {
            k: v for k, v in content.items() if k not in {"confirmation_note", "session_handle"}
        }

    assert _rest(result.structured_content) == _rest(flag_off.structured_content)
    assert result.structured_content["write_enabled"] == []
    granted = {c["domain"]: c["granted"] for c in result.structured_content["consents"]}
    assert granted["payments"] is False


def test_the_flag_on_module_tuple_is_derived_from_the_built_in_one() -> None:
    """A built-in added to `BUILTIN_READ_MODULES` is in the flag-on tuple too,
    in the same order; only `bootstrap` is swapped, found by name."""
    assert [m.name for m in BUILTIN_READ_MODULES_WITH_PAYMENTS] == [
        m.name for m in BUILTIN_READ_MODULES
    ]
    assert {m.name for m in BUILTIN_READ_MODULES_WITH_PAYMENTS} == {
        m.name for m in BUILTIN_READ_MODULES
    }
    assert BUILTIN_READ_MODULES[0] is bootstrap.MODULE
    assert BUILTIN_READ_MODULES_WITH_PAYMENTS[0] is bootstrap.PAYMENTS_MODULE
    for plain, with_payments in zip(
        BUILTIN_READ_MODULES[1:], BUILTIN_READ_MODULES_WITH_PAYMENTS[1:], strict=True
    ):
        assert with_payments is plain


def test_the_payments_module_differs_from_the_plain_one_only_in_the_builder() -> None:
    plain, with_payments = bootstrap.MODULE, bootstrap.PAYMENTS_MODULE
    assert with_payments.name == plain.name
    assert len(with_payments.tools) == len(plain.tools) == 1
    for p, w in zip(plain.tools, with_payments.tools, strict=True):
        assert replace(w, build=p.build) == p
        assert w.build is not p.build

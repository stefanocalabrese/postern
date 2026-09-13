"""Golden masking test (handoff §6.5).

Every registered tool must appear in CASES. Adding a tool without a case fails
this test, which is the point: the check must not be something you can forget.

This file also proves, by experiment, that the harness is a control and not a
decoration: with zero tools registered and CASES empty, the two coverage/leak
tests below pass trivially, and a harness that has never failed is
indistinguishable from a broken one. The `test_self_check_*` tests build a
deliberately leaky server in-process and assert that the harness's own
assertion helpers -- the exact functions the production tests call, not a
hand-rolled copy -- raise against it. If someone weakens `PAN_RE`/`IBAN_RE` or
narrows what gets scanned, these fail loudly instead of the whole file going
quietly green forever.
"""

import json
import re
from typing import Any

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.client.client import CallToolResult  # not re-exported by fastmcp.client.__init__
from fastmcp.exceptions import ToolError
from postern_core.facade.client import BackendClient, StubTokenMinter

from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures import backend_responses as fx

# Deliberately not `postern_core.domain.masking._PAN_RE` / `_IBAN_RE`. Those
# are private, fullmatch-oriented patterns for validating a single
# already-separator-stripped field (masking.py's own `_mask_pan`/`_mask_iban`
# strip `_SEPARATORS` before matching); they have no tolerance for a
# space/hyphen-grouped run still embedded in a larger serialized blob, so
# reusing them here would make this harness WEAKER at exactly the free-text
# case (a card number typed with spaces into a memo) the module's own
# `_redact_free_text` docstring names as the realistic leak shape. A golden
# test's job is to search loosely and over-flag; masking.py's job is to
# fullmatch narrowly and validate. Same underlying facts (PAN/IBAN shape,
# mod-97), different purpose -- so two patterns, not shared ones.
PAN_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
IBAN_RE = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}[A-Z0-9]{10,30}(?![A-Z0-9])")

ROUTES = {
    "/accounts": fx.ACCOUNTS,
    "/accounts/acc_7f3a/balance": fx.BALANCE,
    "/transactions": fx.TRANSACTIONS,
    "/cards": fx.CARDS,
}

CASES: dict[str, dict[str, Any]] = {
    "accounts.list": {},
    "accounts.get_balance": {"account_ref": "acc_7f3a"},
    "transactions.list": {"account_ref": "acc_7f3a"},
    "cards.list": {},
    "banking_start_session": {},
}
"""tool name -> arguments. Extended by Tasks 8, 9, 10 and 11."""


def _handler(request: httpx2.Request) -> httpx2.Response:
    body = ROUTES.get(request.url.path)
    if body is None:
        return httpx2.Response(404, json={"detail": f"no fixture for {request.url.path}"})
    return httpx2.Response(200, json=body)


@pytest.fixture
def server() -> FastMCP:
    backend = BackendClient(
        "https://backend.test", StubTokenMinter(), transport=httpx2.MockTransport(_handler)
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


def _render_result(result: CallToolResult) -> str:
    """Everything a client could actually receive from this call, not just
    the structured half.

    `structured_content` and `data` are both `None` on an error result:
    FastMCP's dispatcher puts `str(exc)` straight into a `TextContent` block
    on the error path and sets neither of the other two (fastmcp 4.0.3,
    `fastmcp/server/mixins/mcp_operations.py`, `_on_call_tool`'s
    `except FastMCPError as e` branch, verified by reading that source and by
    `test_self_check_harness_catches_a_leak_in_an_error_message` below), so a
    scan of `structured_content or data` alone is blind to a leak that
    reaches the client only through an error message -- an unscrubbed
    backend detail folded into a `ToolError`, for instance. `content` blocks
    are themselves Pydantic models (`mcp_types.ContentBlock`, a `TextContent`
    /`ImageContent`/... union), dumped through `model_dump(mode="json")` so
    they serialize the same way `structured_content` already does.

    On a *successful* result this is redundant with `structured_content`
    (FastMCP derives `content` from the same value for any handler that
    doesn't hand-build a `ToolResult`, `fastmcp/tools/base.py`), so this scan
    is deliberately wider than strictly needed on that path -- the cost is
    some duplicate matching, not a missed one.
    """
    payload = {
        "content": [block.model_dump(mode="json") for block in result.content],
        "structured_content": result.structured_content,
        "data": result.data,
    }
    return json.dumps(payload, default=str)


async def _assert_every_registered_tool_has_a_case(
    server: FastMCP, cases: dict[str, dict[str, Any]]
) -> None:
    async with Client(transport=server) as client:
        registered = {tool.name for tool in await client.list_tools()}
    missing = registered - cases.keys()
    assert not missing, f"tools with no golden masking case: {sorted(missing)}"


async def _assert_no_tool_output_leaks_a_pan_or_iban(
    server: FastMCP, cases: dict[str, dict[str, Any]]
) -> None:
    async with Client(transport=server) as client:
        for name, arguments in cases.items():
            # `raise_on_error=False`: an erroring tool must be a case this
            # scan inspects, not a `ToolError` this loop lets escape. Left at
            # the client's own default (`True`), a leaky error message would
            # still fail the build (the raised exception fails the test) but
            # via an uncaught exception whose `str()` -- carrying the raw
            # value -- lands in the pytest traceback/CI log instead of a
            # clean assertion message, and a later case in the same loop
            # never gets scanned at all because the loop stopped early.
            result = await client.call_tool(name, arguments, raise_on_error=False)
            rendered = _render_result(result)
            assert not PAN_RE.search(rendered), f"{name} leaked a PAN: {rendered[:400]}"
            assert not IBAN_RE.search(rendered), f"{name} leaked an IBAN: {rendered[:400]}"


async def test_every_registered_tool_has_a_masking_case(server: FastMCP) -> None:
    await _assert_every_registered_tool_has_a_case(server, CASES)


async def test_no_tool_output_contains_a_pan_or_iban(server: FastMCP) -> None:
    await _assert_no_tool_output_leaks_a_pan_or_iban(server, CASES)


def test_the_regexes_actually_catch_the_fixtures() -> None:
    """A masking test whose regex matches nothing is worse than no test."""
    assert PAN_RE.search(fx.FULL_PAN)
    assert IBAN_RE.search(fx.FULL_IBAN)
    assert IBAN_RE.search(fx.COUNTERPARTY_IBAN)
    assert not PAN_RE.search("•••• 4417")
    assert not IBAN_RE.search("ES•• •••• 1332")
    # A card number is just as much a leak typed with grouping (copy-pasted
    # off a statement, or entered with spaces in a memo) as in its bare form.
    assert PAN_RE.search("4111 1111 1111 4417")
    assert PAN_RE.search("4111-1111-1111-4417")


# --- Self-check: proof that the harness above is a control, not a decoration ---
#
# With zero tools registered and CASES empty, `test_every_registered_tool_has_a_masking_case`
# and `test_no_tool_output_contains_a_pan_or_iban` both pass trivially (the plan's documented,
# correct starting state). A test that has never failed is not distinguishable from a test that
# CANNOT fail. Each test below builds a deliberately leaky server in-process -- bypassing every
# domain model exactly the way handoff §6.5 warns about ("someone adding a raw passthrough
# field") -- and asserts that the SAME helpers the production tests call above (`_assert_every_
# registered_tool_has_a_case`, `_assert_no_tool_output_leaks_a_pan_or_iban`) raise against it.
# Because these call the production helpers rather than re-implementing the assertions, this
# cannot rot silently: if a future change weakens `PAN_RE`/`IBAN_RE`, narrows `_render_result`,
# or otherwise defangs the real check, the helper stops raising and `pytest.raises` here reports
# "DID NOT RAISE" -- a loud failure, not a quiet pass.


def _leaky_accounts_server() -> FastMCP:
    leaky = FastMCP(name="leaky-proof-raw-dict")

    @leaky.tool
    def leaky_accounts() -> dict[str, Any]:
        return fx.ACCOUNTS  # raw backend dict: full IBANs, no domain model at all

    return leaky


def _leaky_error_server() -> FastMCP:
    leaky = FastMCP(name="leaky-proof-error-message")

    @leaky.tool
    def leaky_error() -> dict[str, Any]:
        raise ToolError(f"backend said: account not found for {fx.FULL_IBAN}")

    return leaky


async def test_self_check_harness_catches_a_raw_passthrough_leak() -> None:
    """Real failure captured while building this test (fixture IBAN, harness's own message):

    AssertionError: leaky_accounts leaked an IBAN: {"content": [...], "structured_content":
    {"accounts": [{"id": "acc_7f3a", "label": "Joint expenses", "iban":
    "ES9121000418450200051332"}, ...]}, "data": null}
    """
    leaky = _leaky_accounts_server()
    with pytest.raises(AssertionError, match="leaked an IBAN"):
        await _assert_no_tool_output_leaks_a_pan_or_iban(leaky, {"leaky_accounts": {}})


async def test_self_check_harness_catches_an_unregistered_tool() -> None:
    """Real failure captured while building this test:

    AssertionError: tools with no golden masking case: ['leaky_accounts']
    """
    leaky = _leaky_accounts_server()
    with pytest.raises(AssertionError, match="no golden masking case"):
        await _assert_every_registered_tool_has_a_case(leaky, cases={})


async def test_self_check_harness_catches_a_leak_in_an_error_message() -> None:
    """The scan-scope half of the proof: a leak that reaches the client only
    through an error message (`content`, not `structured_content`/`data`)
    must still be caught. Confirmed missed by the naive `structured_content
    or data` expression while building this harness (see `_render_result`'s
    docstring); `_assert_no_tool_output_leaks_a_pan_or_iban` uses
    `_render_result`, which scans `content` too, so this must raise.
    """
    leaky = _leaky_error_server()
    with pytest.raises(AssertionError, match="leaked an IBAN"):
        await _assert_no_tool_output_leaks_a_pan_or_iban(leaky, {"leaky_error": {}})

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
# Separators a PAN or IBAN legitimately carries when typed with grouping or
# copy-pasted off a rendered statement. The same set `masking._SEPARATORS`
# strips for `MaskedPan`/`MaskedIban`, minus the vertical whitespace: a value
# broken across a LINE is a different question from one grouped along one,
# and admitting `\n` here would weld a column of unrelated numbers into a
# single candidate and make this gate flag its own fixtures' JSON.
_SEP = r"[   \-‐-―.]"

# Four holes this gate carried until audit finding C-07, each of which made
# it blind to a leak `masking.py` itself was measured to have:
#
# 1. The floor was 13 against `masking._PAN_MIN_DIGITS`'s 12, so the
#    module's own sharpest documented PAN residual -- a 12-digit card, the
#    length with NO slack under either floor -- was invisible to the gate
#    that exists to catch it. 11 repetitions after the leading `\d` is 12
#    digits, and the two numbers now agree.
# 2. No `re.IGNORECASE` and an `[A-Z]`-only class, so `es9121000418450200051332`
#    passed. Fixed with explicit `[A-Za-z]` classes rather than the flag,
#    because `IGNORECASE` would also silently loosen `\d` and the bullet-
#    bearing negative assertions below in ways nobody would notice.
# 3. `IBAN_RE` required contiguity, so `ES91 2100 0418 4502 0005 1332` --
#    the canonical ISO 13616 print format, i.e. how every rendered statement
#    in Europe writes one -- passed.
# 4. `PAN_RE`'s separator class was `[ -]` only, so the dot- and NBSP-grouped
#    forms passed.
#
# Deliberately unbounded above (`{11,}` / `{10,30}` with no `(?!\d)`-driven
# ceiling on the PAN side): a gate's job is to over-flag. A bounded upper
# limit does not merely miss a 20-digit run, it fails to match it AT ALL --
# the trailing `(?!\d)` rejects every backtrack -- which is the exact shape
# `masking._PAN_IN_TEXT_RE`'s own comment records as having reconstituted an
# AmEx number out of its own mask.
PAN_RE = re.compile(rf"(?<!\d)\d(?:{_SEP}?\d){{11,}}(?!\d)")
IBAN_RE = re.compile(
    rf"(?<![A-Za-z0-9])[A-Za-z]{{2}}\d{{2}}(?:{_SEP}?[A-Za-z0-9]){{10,30}}(?![A-Za-z0-9])"
)

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
    "start_session": {},
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
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(_handler),
        before_backend_request=None,
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
            # IBAN first, PAN second, matching `_redact_free_text`'s own pass
            # order and for the same reason it gives: an IBAN's numeric body
            # (ES9121000418450200051332 is 22 digits) is long enough for the
            # widened `PAN_RE` to claim, so a PAN-first scan would report a
            # leaked IBAN as "leaked a PAN" and send whoever reads the
            # failure looking in the wrong pass. Neither assertion is
            # weakened by the order: both still run on every case that
            # survives the first.
            assert not IBAN_RE.search(rendered), f"{name} leaked an IBAN: {rendered[:400]}"
            assert not PAN_RE.search(rendered), f"{name} leaked a PAN: {rendered[:400]}"


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


def test_the_regexes_catch_every_grouped_and_disguised_fixture() -> None:
    """The four holes named above `PAN_RE`, each pinned at the fixture that
    walked through it. Every one of these strings passed the previous gate
    untouched while `masking.py` was measured to emit it verbatim.

    The ordinal fixtures are here for the PAN/IBAN *shape* they carry after
    the one exempt codepoint is removed, which is what an analyst reading
    the leaked text gets: the gate itself does not delete codepoints, so it
    sees them only via the grouped/contiguous forms they decompose to. They
    are asserted through the tool-output scan (`test_no_tool_output_contains_
    a_pan_or_iban`) rather than here, and the dedicated masking tests in
    `tests/test_masking_exemption_bypass.py` pin the redaction itself.
    """
    for grouped in (fx.GROUPED_PAN, fx.HYPHEN_PAN, fx.DOTTED_PAN, fx.NBSP_PAN):
        assert PAN_RE.search(grouped), f"grouped PAN invisible to the gate: {grouped!r}"
    for grouped in (fx.GROUPED_IBAN, fx.HYPHEN_IBAN):
        assert IBAN_RE.search(grouped), f"grouped IBAN invisible to the gate: {grouped!r}"
    assert IBAN_RE.search(fx.LOWERCASE_IBAN), "a lowercase IBAN walked through the gate"
    # The floor now agrees with `masking._PAN_MIN_DIGITS`: 12, not 13.
    assert PAN_RE.search("869926608025"), "the 12-digit card the module's residual 6 names"
    assert not PAN_RE.search("86992660802"), "11 digits is under every PAN length"
    # Nothing the module legitimately emits may look like a leak to the gate,
    # or the gate fails the build on a correct redaction.
    for masked in ("•••• 1111", "ES•• •••• 1332", "•••• ", "2026-09-11T08:30:00Z", "-34.20"):
        assert not PAN_RE.search(masked), f"gate flags its own masked output: {masked!r}"
        assert not IBAN_RE.search(masked), f"gate flags its own masked output: {masked!r}"


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

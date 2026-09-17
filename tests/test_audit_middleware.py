import asyncio
import logging
import random
import string
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastmcp import Context, FastMCP
from fastmcp.client import Client
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken
from fastmcp.tools import ToolResult
from mcp.shared.exceptions import MCPError
from postern_core.domain.masking import _IBAN_SCAN_BUDGET, _MASK, redaction_budget
from postern_core.store import audit as store_audit
from postern_core.store.engine import Database
from postern_core.store.models import REFUSAL_REASONS, AuditEntry
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.middleware import audit as audit_middleware
from services.api.middleware.audit import _MAX_TOOL_NAME, AuditMiddleware, _scrub


async def rows(session: AsyncSession) -> list[AuditEntry]:
    result = await session.execute(select(AuditEntry).order_by(AuditEntry.id))
    return list(result.scalars().all())


async def test_a_successful_call_is_recorded(audit_server: FastMCP, session: AsyncSession) -> None:
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 50})
    entries = await rows(session)
    assert [(e.tool_name, e.outcome) for e in entries] == [("ok_tool", "returned")]
    assert entries[0].arguments == {"amount": 50}


async def test_a_failing_call_is_recorded(audit_server: FastMCP, session: AsyncSession) -> None:
    """The one that matters: failures arrive as raised exceptions, not a flag."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("boom_tool", {}, raise_on_error=False)
    entries = await rows(session)
    assert [(e.tool_name, e.outcome) for e in entries] == [("boom_tool", "raised")]


async def test_the_detail_records_the_exception_type_not_its_message(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """A ValidationError message carries the raw offending value."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("leaky_tool", {"pan": "4111111111114417"}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert "4111111111114417" not in (entry.detail or "")
    assert entry.detail in {"ToolError", "ValidationError", "NotFoundError"}


async def test_arguments_are_scrubbed_before_they_are_stored(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1, "memo": "IBAN ES9121000418450200051332"})
    entry = (await rows(session))[0]
    assert "ES9121000418450200051332" not in str(entry.arguments)
    assert "ES•• •••• 1332" in str(entry.arguments)


async def test_the_exception_still_propagates_after_being_recorded(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    async with Client(transport=audit_server) as c:
        result = await c.call_tool("boom_tool", {}, raise_on_error=False)
    assert result.is_error is True
    assert len(await rows(session)) == 1


# -- C1: dict keys are scrubbed, not just values -----------------------------


async def test_a_pan_shaped_argument_key_is_scrubbed_before_it_is_stored(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """Reviewer's own repro: arguments are captured before `call_next`
    validates them, so an extra, agent-chosen key is as attacker-controlled
    as any value."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1, "4111111111114417": "x"}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert "4111111111114417" not in str(entry.arguments)


def test_scrub_redacts_a_pan_shaped_dict_key_directly() -> None:
    """Same guarantee, at the unit level: fails immediately if `_scrub`'s
    dict branch goes back to `{k: _scrub(v) ...}`."""
    result = _scrub({"4111111111114417": "x", "amount": 1})
    assert "4111111111114417" not in str(result)


# -- I4: `_scrub` recursion, one case per shape ------------------------------


def test_scrub_redacts_inside_a_nested_dict() -> None:
    result = _scrub({"outer": {"memo": "call 4111111111114417 back"}})
    assert result == {"outer": {"memo": "call •••• 4417 back"}}


def test_scrub_redacts_each_string_in_a_list() -> None:
    result = _scrub(["IBAN ES9121000418450200051332", "plain text"])
    assert result == ["IBAN ES•• •••• 1332", "plain text"]


def test_scrub_redacts_pans_inside_a_list_of_dicts() -> None:
    result = _scrub([{"memo": "call 4111111111114417 back"}, {"memo": "plain"}])
    assert result == [{"memo": "call •••• 4417 back"}, {"memo": "plain"}]


# -- C2: a malformed call must not lose its own audit row --------------------


async def test_an_oversized_tool_name_still_produces_exactly_one_audit_row(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """`tool_name` is `String(64)`; a 200-char agent-supplied name must not
    turn the audit write itself into the error the caller sees."""
    long_name = "x" * 200
    async with Client(transport=audit_server) as c:
        result = await c.call_tool(long_name, {}, raise_on_error=False)
    assert result.is_error is True
    entries = await rows(session)
    assert len(entries) == 1
    assert entries[0].tool_name == long_name[:64]
    assert entries[0].outcome == "raised"


async def test_a_nul_byte_in_an_argument_still_produces_exactly_one_audit_row(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """NUL survives `FreeText` (not PAN/IBAN-shaped) but JSONB cannot store
    it; this must not turn a successful call into an audit failure."""
    async with Client(transport=audit_server) as c:
        result = await c.call_tool("ok_tool", {"amount": 1, "memo": "a\x00b"})
    assert result.is_error is False
    entries = await rows(session)
    assert len(entries) == 1
    assert entries[0].outcome == "returned"
    assert "\x00" not in str(entries[0].arguments)


# -- N1: a NUL planted inside a PAN must not reassemble it --------------------
#
# `FreeText`'s pattern is a contiguous digit run; a NUL splits a 16-digit PAN
# into two runs too short to match, so redaction finds nothing -- stripping
# the NUL *after* that failed match reassembles the full PAN. Only stripping
# before validation keeps the run contiguous when `FreeText` sees it.

_PAN = "4111111111114417"
_PAN_SPLIT_BY_NUL = _PAN[:8] + "\x00" + _PAN[8:]


async def test_a_nul_split_pan_in_a_value_does_not_reassemble(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1, "memo": _PAN_SPLIT_BY_NUL})
    entry = (await rows(session))[0]
    assert _PAN not in str(entry.arguments)


async def test_a_nul_split_pan_in_a_key_does_not_reassemble(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """The variant that also bypasses the C1 key fix: the split happens
    before `_scrub` ever sees a contiguous PAN, in a dict key this time."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1, _PAN_SPLIT_BY_NUL: "x"}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert _PAN not in str(entry.arguments)


# -- C3: a token subject that fails CustomerRef must not reach customer_ref --


async def test_a_pan_shaped_token_subject_does_not_reach_customer_ref(
    audit_server: FastMCP, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mirrors `token_customer_resolver`'s own rejection (server.py): a
    compromised issuer's `sub` is attacker-influenced, and the tool path's
    refusal of it must not be the one path that persists it anyway."""
    raw_pan = "4111111111111111"
    token = AccessToken(token="t", client_id="c", scopes=[], claims={"sub": raw_pan})  # noqa: S106
    monkeypatch.setattr("services.api.middleware.audit.get_access_token", lambda: token)
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1})
    entry = (await rows(session))[0]
    assert entry.customer_ref is None


async def test_a_conforming_token_subject_does_reach_customer_ref(
    audit_server: FastMCP, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Companion to the rejection test: a well-formed `sub` must still be
    recorded, so the fix is a validation gate, not a blanket `None`."""
    token = AccessToken(
        token="t",  # noqa: S106
        client_id="c",
        scopes=[],
        claims={"sub": "cust_7f3a"},
    )
    monkeypatch.setattr("services.api.middleware.audit.get_access_token", lambda: token)
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1})
    entry = (await rows(session))[0]
    assert entry.customer_ref == "cust_7f3a"


# -- The request-scoped budget: `_scrub`'s whole tree walk shares ONE
# `redaction_budget`, not a fresh one per string --------------------------
#
# Without this, `FreeText` gives every string it validates its own fresh
# checksum budget (masking.py's `_IBAN_SCAN_BUDGET`), so an agent that
# spreads junk across many short strings -- a list of them, rather than one
# long one -- buys a fresh allowance per element instead of spending down
# one shared one. Measured through the real `_scrub`, 1 MiB of
# 128-character junk strings: 276ms (main) vs 7451ms (a list, per-string
# budget only) vs bounded by `redaction_budget` -- see
# `services/api/middleware/audit.py` and masking.py's `_redact_free_text`
# for the full table.

_JUNK_128 = "AB12" * 32  # never checksums, ~559 checksum operations each


def test_scrub_budget_is_shared_across_a_list_not_reset_per_element() -> None:
    """A small, explicit budget (rather than the production default) for a
    fast, deterministic test: enough for roughly one element's full scan,
    not two. The real IBAN in the third element must come back bare-masked
    -- budget spent by the two junk elements ahead of it -- never with its
    correct country code and last four, and never verbatim."""
    real_iban = "MT84MALT011000012345MTLCAST001S"
    payload = [_JUNK_128, _JUNK_128, f"{_JUNK_128} {real_iban}"]
    with redaction_budget(600):
        result = _scrub(payload)
    assert real_iban not in str(result)
    assert result[2].endswith(_MASK)
    assert "MT••" not in result[2]  # never the correct, structured mask


def test_scrub_budget_is_shared_across_a_nested_payload() -> None:
    """Same property, through a nested dict-of-list-of-dict shape: `_scrub`
    recurses through all of it under the SAME ambient budget, not a fresh
    one at each level."""
    real_iban = "MT84MALT011000012345MTLCAST001S"
    payload = {
        "a": [_JUNK_128, _JUNK_128],
        "b": {"c": f"{_JUNK_128} {real_iban}"},
    }
    with redaction_budget(600):
        result = _scrub(payload)
    assert real_iban not in str(result)
    assert result["b"]["c"].endswith(_MASK)
    assert "MT••" not in result["b"]["c"]


def test_scrub_without_an_ambient_budget_gives_each_string_its_own() -> None:
    """Sanity check on the two tests above: OUTSIDE a `redaction_budget`
    block, `_scrub` falls back to `_redact_free_text`'s own per-string
    default (`_IBAN_SCAN_BUDGET`, 100,000 -- far more than 600), so the
    same three-element payload is NOT starved and the real IBAN resolves
    normally. This is what proves the previous two tests' bare masks are
    genuinely caused by a SHARED budget, not by some unrelated breakage."""
    real_iban = "MT84MALT011000012345MTLCAST001S"
    payload = [_JUNK_128, _JUNK_128, f"{_JUNK_128} {real_iban}"]
    result = _scrub(payload)
    assert result[2].endswith("MT•• •••• 001S")


async def test_on_call_tool_request_budget_bounds_a_junk_heavy_argument_list(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """Through the real middleware, not a hand-rolled combination of
    `_scrub` and `redaction_budget`: enough 128-character junk elements to
    exhaust the PRODUCTION default budget (100,000 checksums, ~559 per
    element, so at least 179) inside one tool call's argument list,
    followed by a genuine IBAN as the final element. The stored audit row
    must never contain the real IBAN, and the trailing element must be
    bare-masked rather than correctly identified -- proof that
    `on_call_tool` actually wraps `_scrub` in `redaction_budget()` in
    production, not just that the two primitives compose correctly in a
    unit test."""
    real_iban = "MT84MALT011000012345MTLCAST001S"
    payload = [_JUNK_128] * 200 + [f"{_JUNK_128} {real_iban}"]
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1, "memo": payload}, raise_on_error=False)
    entry = (await rows(session))[0]
    stored = str(entry.arguments)
    assert real_iban not in stored
    assert _MASK in stored
    assert "MT••" not in stored


# -- `redaction_budget_exhausted`: `on_call_tool` reads `RedactionScope
# .exhausted` after the `with redaction_budget():` block and threads it into
# BOTH `_write` call sites -----------------------------------------------
#
# Same derivation as `tests/test_masking_types.py`'s
# `_JUNK_TOKENS_TO_EXHAUST_BUDGET`: one 128-character junk token that never
# checksums spends ~559 checksum operations, so this many of them exhausts
# `_IBAN_SCAN_BUDGET` -- the middleware's own allowance, since `on_call_tool`
# calls `redaction_budget()` with no override -- well before the last one is
# scanned.
_JUNK_TOKENS_TO_EXHAUST_BUDGET = _IBAN_SCAN_BUDGET // 100 + 50
_EXHAUSTING_MEMO = " ".join([_JUNK_128] * _JUNK_TOKENS_TO_EXHAUST_BUDGET)


async def test_a_call_that_exhausts_the_redaction_budget_records_it_true_on_the_returned_path(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """`ok_tool` succeeds, so this goes through `on_call_tool`'s
    `"returned"` write -- its `memo` parameter is free text, so a
    succeeding call can still carry enough junk to exhaust the allowance."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1, "memo": _EXHAUSTING_MEMO})
    entry = (await rows(session))[0]
    assert entry.outcome == "returned"
    assert entry.redaction_budget_exhausted is True


async def test_a_call_that_exhausts_the_redaction_budget_records_it_true_on_the_raised_path(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """`leaky_tool` rejects a non-integer `pan`, so this goes through
    `on_call_tool`'s `"raised"` write -- the exhausting payload is scrubbed
    from the raw arguments before `call_next` ever validates them."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("leaky_tool", {"pan": _EXHAUSTING_MEMO}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert entry.outcome == "raised"
    assert entry.redaction_budget_exhausted is True


async def test_an_ordinary_call_records_the_budget_as_not_exhausted_on_the_returned_path(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 50})
    entry = (await rows(session))[0]
    assert entry.outcome == "returned"
    assert entry.redaction_budget_exhausted is False


async def test_an_ordinary_call_records_the_budget_as_not_exhausted_on_the_raised_path(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    async with Client(transport=audit_server) as c:
        await c.call_tool("boom_tool", {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert entry.outcome == "raised"
    assert entry.redaction_budget_exhausted is False


# -- The tool NAME is scrubbed the same way `arguments` is, before it reaches
# `audit_log.tool_name` -----------------------------------------------------
#
# `context.message.name` is entirely agent-chosen -- `_MAX_TOOL_NAME` (64)
# leaves ample room for a 16-digit PAN or a 31-character IBAN -- and a
# tool-lookup failure for an unregistered name still reaches `on_call_tool`'s
# "raised" write with the name intact. See the ordering comment on
# `AuditMiddleware.on_call_tool` (`services/api/middleware/audit.py`) for
# the threat this closes and why the name is scrubbed before the arguments.


def test_scrub_never_lengthens_a_string_up_to_the_tool_name_clamp() -> None:
    """Pins the measurement behind `on_call_tool`'s second, defensive clamp:
    every substitution `_scrub`'s string branch can make
    (`_redact_pan_match`, `_redact_iban_match`, `_strip_invisible`) replaces
    a match with something the same length or shorter, so scrubbing an
    already-clamped 64-character name can never overflow `audit_log
    .tool_name`'s `String(64)` column. Seeded random sampling across a fixed
    alphabet, not one hand-picked example, plus every real PAN/IBAN this
    file already exercises, at every padding offset up to the clamp. The
    alphabet includes a handful of `_strip_invisible`-stripped characters
    (U+200B ZERO WIDTH SPACE, U+3164 HANGUL FILLER, U+0001, U+E0002) so this
    test actually exercises that leg of the never-lengthens claim -- a
    plain ASCII/digit/punctuation alphabet never calls `_strip_invisible`'s
    character-removal path at all."""
    alphabet = string.ascii_uppercase + string.digits + "_.- " + "​ㅤ\U000e0002"
    rng = random.Random(0)  # noqa: S311 -- test fuzz, not cryptographic use
    for _ in range(20_000):
        length = rng.randint(0, _MAX_TOOL_NAME)
        candidate = "".join(rng.choice(alphabet) for _ in range(length))
        assert len(_scrub(candidate)) <= len(candidate)

    real_values = (
        "4111111111114417",
        "411111111111",
        "4111111111111111111",
        "ES9121000418450200051332",
        "MT84MALT011000012345MTLCAST001S",
        "GB29NWBK60161331926819",
    )
    for value in real_values:
        for pad in range(0, _MAX_TOOL_NAME - len(value) + 1):
            candidate = (("A" * pad) + value)[:_MAX_TOOL_NAME]
            assert len(_scrub(candidate)) <= len(candidate)


async def test_a_pan_shaped_tool_name_is_masked_in_the_audit_row(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    pan_name = "4111111111114417"
    async with Client(transport=audit_server) as c:
        await c.call_tool(pan_name, {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert pan_name not in entry.tool_name
    assert entry.tool_name == "•••• 4417"


async def test_an_iban_shaped_tool_name_is_masked_in_the_audit_row(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    iban_name = "ES9121000418450200051332"
    async with Client(transport=audit_server) as c:
        await c.call_tool(iban_name, {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert iban_name not in entry.tool_name
    assert entry.tool_name == "ES•• •••• 1332"


async def test_an_ordinary_tool_name_is_recorded_unchanged(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """The regression guard: a name with no PAN/IBAN-shaped substring must
    reach `audit_log.tool_name` exactly as sent, not run through masking
    that mangles every ordinary row."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("transactions.list", {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert entry.tool_name == "transactions.list"


async def test_a_call_with_a_scrubbed_name_records_exactly_one_row_on_the_returned_path(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """`call_next` still receives the untouched name -- resolution happens on
    `context.message.name`, never on the value this middleware records --
    so a tool registered under a PAN/IBAN-shaped name still resolves and
    succeeds; only the audit row's copy of the name is masked."""
    iban_name = "ES9121000418450200051332"

    async def iban_named_tool(amount: int) -> str:
        return f"ok {amount}"

    audit_server.tool(name=iban_name)(iban_named_tool)
    async with Client(transport=audit_server) as c:
        await c.call_tool(iban_name, {"amount": 1})
    entries = await rows(session)
    assert len(entries) == 1
    assert entries[0].outcome == "returned"
    assert entries[0].tool_name == "ES•• •••• 1332"


async def test_a_call_with_a_scrubbed_name_records_exactly_one_row_on_the_raised_path(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    pan_name = "4111111111114417"
    async with Client(transport=audit_server) as c:
        await c.call_tool(pan_name, {}, raise_on_error=False)
    entries = await rows(session)
    assert len(entries) == 1
    assert entries[0].outcome == "raised"
    assert entries[0].tool_name == "•••• 4417"


async def test_an_oversized_tool_name_still_produces_exactly_one_audit_row_after_scrubbing(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """Companion to the pre-existing oversized-name test: an oversized name
    with no PAN/IBAN-shaped substring is unaffected by scrubbing, clamped
    exactly as before."""
    long_name = "y" * 200
    async with Client(transport=audit_server) as c:
        result = await c.call_tool(long_name, {}, raise_on_error=False)
    assert result.is_error is True
    entries = await rows(session)
    assert len(entries) == 1
    assert entries[0].tool_name == long_name[:64]
    assert entries[0].outcome == "raised"


async def test_the_name_is_scrubbed_before_the_arguments_so_their_exhaustion_does_not_bare_mask_it(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """Pins the ordering decision in `on_call_tool`: the name is scrubbed
    BEFORE the arguments, in the same shared `redaction_budget` scope. The
    memo below (`_EXHAUSTING_MEMO`, already proven elsewhere in this file to
    exhaust the whole call's checksum allowance on its own) is scrubbed
    SECOND. If the order were reversed, that exhaustion would already be in
    effect by the time the name is scanned, and `_redact_iban_match`'s
    `budget.exhausted` branch would bare-mask the name's IBAN to `••••`
    instead of resolving it -- losing the one field an investigator uses to
    know WHAT was called. Scrubbing the bounded name first means its own
    (measured, see `services/api/middleware/audit.py`) worst case of 223
    checksums out of a 100,000 allowance can never be meaningfully dented by
    a single real IBAN, so it always resolves correctly regardless of how
    much the arguments go on to spend."""
    iban_name = "ES9121000418450200051332"

    async def iban_named_tool(amount: int, memo: str = "") -> str:
        return f"ok {amount}"

    audit_server.tool(name=iban_name)(iban_named_tool)
    async with Client(transport=audit_server) as c:
        await c.call_tool(iban_name, {"amount": 1, "memo": _EXHAUSTING_MEMO})
    entry = (await rows(session))[0]
    assert entry.tool_name == "ES•• •••• 1332"
    assert entry.redaction_budget_exhausted is True


# -- The audit-write-failure policy: docs/decisions/0006-audit-write-failure.md --
#
# `_write` raises when the audit store itself is unavailable (connection
# refused, pool exhausted, ...). `audit.append` is monkeypatched to raise
# directly, simulating that outage without taking a real database down, per
# the task's own instruction.
#
# Both paths below are FAIL CLOSED, deliberately: a database outage takes
# down every tool call, including ones that would otherwise have succeeded.
# That cost is the point of the decision record, not a bug to route around
# here. What these tests pin is narrower than the policy itself:
#   - the success path actually fails the call rather than returning a
#     silent, unaudited success;
#   - the failure path surfaces the TOOL's own exception on the wire, never
#     the database's, even though the call still fails overall;
#   - either failure is observable to an operator through the logs, not
#     just through a support ticket about a missing row.


class _SimulatedAuditOutage(RuntimeError):
    """Distinct from anything a tool itself could plausibly raise, so a test
    asserting this message is ABSENT from the caller-visible result is
    actually exercising the database-vs-tool distinction, not a coincidence
    of wording."""


async def _boom_append(*args: object, **kwargs: object) -> None:
    raise _SimulatedAuditOutage("simulated audit store outage")


async def test_an_audit_write_failure_on_the_success_path_fails_the_call(
    audit_server: FastMCP,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Chosen policy: fail closed. `ok_tool` runs and returns successfully,
    but the audit write for that success raises -- the call must not come
    back as a success with its audit trail silently missing. FastMCP only
    turns a `FastMCPError` (e.g. `ToolError`) into a `CallToolResult
    (is_error=True)`; an audit-store exception is neither, so it reaches the
    client as a raw protocol-level `MCPError`, exactly as it did before this
    fix -- the wire shape is unchanged, only the fact that this is a chosen
    policy, logged, is new."""
    monkeypatch.setattr(store_audit, "append", _boom_append)
    async with Client(transport=audit_server) as c:
        with pytest.raises(MCPError):
            await c.call_tool("ok_tool", {"amount": 1}, raise_on_error=False)
    assert await rows(session) == []


async def test_an_audit_write_failure_on_the_success_path_is_logged(
    audit_server: FastMCP,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Requirement 3: the failure must be observable to an operator, not
    just inferable from the call itself failing.

    This test used to carry a `monkeypatch.setattr(audit_middleware.logger,
    "disabled", False)` workaround, because the session-scoped `pg_url`
    fixture runs `migrations/env.py` (via `command.upgrade`) after this
    module's `logger = logging.getLogger(__name__)` already executed at
    import time, and `fileConfig`'s `disable_existing_loggers` default of
    `True` disabled every pre-existing logger it found, this one included,
    for the rest of the test session -- `caplog.set_level` cannot undo that,
    since it only restores `logging.disable`'s global threshold, never a
    logger's own `.disabled` flag.

    `c1a1275` fixed the cause (`migrations/env.py` now passes
    `disable_existing_loggers=False`), so the workaround was removed here
    rather than kept as a belt-and-braces guard against a bug that no longer
    exists -- see `docs/decisions/0006-audit-write-failure.md` for why a
    silenced logger matters: it is the only signal an operator gets that
    this middleware's fail-closed policy fired, so losing it silently turns
    fail-closed into fail-silent. The hazard itself is not Alembic-specific
    and will recur: any code that calls `fileConfig` or `dictConfig` in a
    hosting process, with that same default, can disable a logger created
    before it runs. If a log assertion in this file ever starts failing
    again for no visible reason, check for that before reaching for this
    workaround."""
    monkeypatch.setattr(store_audit, "append", _boom_append)
    caplog.set_level(logging.ERROR, logger=audit_middleware.logger.name)
    async with Client(transport=audit_server) as c:
        with pytest.raises(MCPError):
            await c.call_tool("ok_tool", {"amount": 1}, raise_on_error=False)
    assert any(
        record.levelno == logging.ERROR
        and "ok_tool" in record.getMessage()
        and record.exc_info is not None
        and isinstance(record.exc_info[1], _SimulatedAuditOutage)
        for record in caplog.records
    )


async def test_an_audit_write_failure_on_the_failure_path_still_surfaces_the_tools_own_exception(
    audit_server: FastMCP,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bug this task exists to fix: `boom_tool` raises its own
    `ValueError`, and the audit write recording THAT failure also raises.
    Before the fix, the database exception replaced the tool's via implicit
    `__context__` chaining and reached the caller as a generic `MCPError`
    ("Internal server error") -- the exact same shape as the success-path
    outage above, which told the caller nothing true about either failure.
    After the fix, the tool's own `ToolError` (a `FastMCPError`) propagates
    unchanged and is still converted into an ordinary `CallToolResult
    (is_error=True)` carrying `boom_tool`'s own message -- the call still
    fails overall (fail-closed), but for the reason the caller can see."""
    monkeypatch.setattr(store_audit, "append", _boom_append)
    async with Client(transport=audit_server) as c:
        result = await c.call_tool("boom_tool", {}, raise_on_error=False)
    assert result.is_error is True
    text = str(result.content)
    assert "internal detail" in text or "boom_tool" in text
    assert "simulated audit store outage" not in text
    assert await rows(session) == []


async def test_an_audit_write_failure_on_the_failure_path_is_logged(
    audit_server: FastMCP,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Companion to the success-path logging test: the audit failure is
    observable here too, even though the caller's own error text names only
    the tool, never the database. See `docs/decisions/0006-audit-write-failure.md`
    for why this log line matters: it is the only signal an operator gets
    that this middleware's fail-closed policy fired."""
    monkeypatch.setattr(store_audit, "append", _boom_append)
    caplog.set_level(logging.ERROR, logger=audit_middleware.logger.name)
    async with Client(transport=audit_server) as c:
        await c.call_tool("boom_tool", {}, raise_on_error=False)
    assert any(
        record.levelno == logging.ERROR
        and "boom_tool" in record.getMessage()
        and record.exc_info is not None
        and isinstance(record.exc_info[1], _SimulatedAuditOutage)
        for record in caplog.records
    )


async def test_an_audit_write_failure_on_the_failure_path_chains_the_audit_exception_as_the_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unit-level pin on the exact chaining `on_call_tool` must use: `raise
    exc from audit_exc`, not a bare `raise` inside the inner `except` (which
    would let the audit exception's own implicit propagation take over) and
    not swallowing `audit_exc` outright (which would lose it from the
    traceback entirely, defeating the requirement that the audit failure
    stay visible)."""
    from fastmcp.exceptions import ToolError

    from services.api.middleware.audit import AuditMiddleware

    middleware = AuditMiddleware(db=None)  # type: ignore[arg-type]

    class _FakeContext:
        timestamp = None
        fastmcp_context = None

        class message:  # noqa: N801 -- mirrors the real MiddlewareContext shape
            name = "boom_tool"
            arguments: dict[str, object] = {}

    async def call_next(context: object) -> None:
        raise ToolError("Error calling tool 'boom_tool': internal detail")

    async def boom_write(*args: object, **kwargs: object) -> None:
        raise _SimulatedAuditOutage("simulated audit store outage")

    monkeypatch.setattr(middleware, "_write", boom_write)
    with pytest.raises(ToolError) as excinfo:
        await middleware.on_call_tool(_FakeContext(), call_next)  # type: ignore[arg-type]
    assert isinstance(excinfo.value.__cause__, _SimulatedAuditOutage)


# -- duration_ms and request_id ----------------------------------------------
#
# Both columns are nullable and NULL means something specific on each
# (models.py): on `duration_ms`, "this row predates the column"; on
# `request_id`, "no id was available for this call". So every test below
# asserts on the difference between NULL and a value, not just on presence.
#
# All of them read the row back through the `session` fixture, a second
# connection whose identity map has never held the middleware's own
# objects, so a value that only ever existed in SQLAlchemy memory cannot
# pass them -- the middleware commits through `database.sessionmaker()`,
# which is a different session entirely.

# A tool sleeps 60 ms and the assertion floor is 50, deliberately not 60.
# `_elapsed_ms` floors (audit.py), and asyncio's timer may fire up to one
# clock resolution early -- `BaseEventLoop._run_once` compares against
# `self.time() + self._clock_resolution` -- so a 60 ms sleep can legitimately
# measure a hair under 60 and floor to 59. The 10 ms of slack buys that
# without weakening what the test proves: a real measurement of the tool's
# own latency cannot land under 50 for a 60 ms sleep, and both a hardcoded
# 0 and a NULL fail it.
_SLEEP_SECONDS = 0.06
_SLEEP_FLOOR_MS = 50

# Catches a unit error in the other direction, which the floor above cannot:
# seconds recorded as-is would floor to 0 and fail the lower bound, but
# MICROseconds would record about 60,000 and sail past it. Ten seconds for a
# 60 ms sleep is far enough above any scheduling delay on a loaded CI box
# that it does not make this test flaky.
_IMPLAUSIBLE_MS = 10_000


class _DirectContext:
    """The parts of `MiddlewareContext` that `on_call_tool` actually reads.

    Verified against `services/api/middleware/audit.py`: it touches
    `message.name`, `message.arguments`, `timestamp` and `fastmcp_context`,
    and nothing else. Used only where no real client call can produce the
    state under test -- `fastmcp_context is None`, and a `Context` whose
    `request_id` raises -- because FastMCP always supplies a usable context
    on a real in-process call. Both states are states of the REAL types:
    `MiddlewareContext.fastmcp_context` is declared `Context | None = None`
    (fastmcp 4.0.3, `fastmcp/server/middleware/middleware.py`), and
    `Context.request_id` raises `RuntimeError` whenever `request_context` is
    None, which the test below asserts before relying on it.
    """

    def __init__(
        self,
        name: str,
        arguments: dict[str, object] | None = None,
        fastmcp_context: Context | None = None,
    ) -> None:
        self.message = SimpleNamespace(name=name, arguments=arguments or {})
        self.timestamp = datetime.now(UTC)
        self.fastmcp_context = fastmcp_context


async def test_a_successful_call_records_the_duration_the_tool_actually_took(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """A row with a duration is the whole point: an investigator reading
    `audit_log` before this column could not tell a 3-second call from a
    3-millisecond one."""

    async def slow_tool() -> str:
        await asyncio.sleep(_SLEEP_SECONDS)
        return "ok"

    audit_server.tool(name="slow_tool")(slow_tool)
    async with Client(transport=audit_server) as c:
        await c.call_tool("slow_tool", {})
    entry = (await rows(session))[0]
    assert entry.outcome == "returned"
    assert entry.duration_ms is not None
    assert entry.duration_ms >= _SLEEP_FLOOR_MS
    assert entry.duration_ms < _IMPLAUSIBLE_MS


async def test_a_failing_call_records_its_duration_too(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """The `except` branch computes the duration from the same
    `time.monotonic()` reading the success path uses. A SLOW FAILURE -- a
    backend timeout, a lock held for the length of a transaction -- is
    exactly what an investigator goes looking for, so leaving this branch at
    NULL would drop the rows the column exists for. This tool sleeps before
    raising so the assertion distinguishes a real measurement from a
    hardcoded 0."""

    async def slow_boom_tool() -> str:
        await asyncio.sleep(_SLEEP_SECONDS)
        raise ValueError("internal detail")

    audit_server.tool(name="slow_boom_tool")(slow_boom_tool)
    async with Client(transport=audit_server) as c:
        await c.call_tool("slow_boom_tool", {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert entry.outcome == "raised"
    assert entry.duration_ms is not None
    assert entry.duration_ms >= _SLEEP_FLOOR_MS
    assert entry.duration_ms < _IMPLAUSIBLE_MS


@pytest.mark.parametrize("audit_write_raises", [False, True])
async def test_the_tools_own_exception_object_still_reaches_the_caller_unchanged(
    monkeypatch: pytest.MonkeyPatch, audit_write_raises: bool
) -> None:
    """Asserted, not reasoned about: `on_call_tool`'s failure path is a
    try/except nested inside a try/except, and it reads as correct while
    being wrong (that is the bug
    docs/decisions/0006-audit-write-failure.md records). Adding two
    arguments to the `_write` call inside the inner `try` is exactly the
    kind of edit that can move which exception leaves the function, so this
    pins the OBJECT identity, the type and the message -- not just "some
    ToolError came out".

    Both parametrisations matter. With the audit write succeeding, the bare
    `raise` must re-raise `exc`; with it failing, `raise exc from audit_exc`
    must substitute the tool's exception back in and attach the audit
    failure as `__cause__` rather than letting it propagate in its place.

    The captured `_write` arguments prove the second half: the audit row
    still carries a measured `duration_ms` on the raised path, a
    `request_id` of None for a context that has no `fastmcp_context`, and a
    `refusal_reason` of None for a call that reached no consent check at
    all."""
    middleware = AuditMiddleware(db=None)  # type: ignore[arg-type]
    tool_error = ToolError("Error calling tool 'boom_tool': internal detail")
    written: list[dict[str, object]] = []

    async def call_next(context: object) -> ToolResult:
        raise tool_error

    async def record_write(
        at: object,
        customer: object,
        name: object,
        arguments: object,
        outcome: object,
        detail: object,
        redaction_budget_exhausted: object,
        duration_ms: object,
        request_id: object,
        refusal_reason: object,
    ) -> None:
        written.append(
            {
                "outcome": outcome,
                "duration_ms": duration_ms,
                "request_id": request_id,
                "refusal_reason": refusal_reason,
            }
        )
        if audit_write_raises:
            raise _SimulatedAuditOutage("simulated audit store outage")

    monkeypatch.setattr(middleware, "_write", record_write)
    with pytest.raises(ToolError) as excinfo:
        await middleware.on_call_tool(_DirectContext("boom_tool"), call_next)  # type: ignore[arg-type]

    assert excinfo.value is tool_error
    assert type(excinfo.value) is ToolError
    assert str(excinfo.value) == "Error calling tool 'boom_tool': internal detail"
    assert isinstance(excinfo.value.__cause__, _SimulatedAuditOutage) is audit_write_raises
    assert written[0]["outcome"] == "raised"
    assert isinstance(written[0]["duration_ms"], int)
    assert written[0]["request_id"] is None
    assert written[0]["refusal_reason"] is None


async def test_the_request_id_is_recorded_and_differs_per_client_request(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """Two calls on ONE client session produce two rows with two different
    ids, which is the honest demonstration of what this column does and does
    not do. It ties a row to a single client request, so an investigator can
    line it up against that client's own logs. It does NOT identify a retry:
    MCP 2026-07-28 has no SSE resumability, so a client whose stream drops
    re-issues the call as a NEW request with a NEW id, and the second row
    below is indistinguishable from that case -- two rows, two ids, nothing
    here to collapse them with."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1})
        await c.call_tool("ok_tool", {"amount": 2})
    first, second = await rows(session)
    assert first.request_id is not None
    assert second.request_id is not None
    assert first.request_id != second.request_id
    assert len(first.request_id) <= 128


async def test_a_call_with_no_fastmcp_context_still_writes_the_row(
    audit_server: FastMCP, database: Database, session: AsyncSession
) -> None:
    """`fastmcp_context` is `Context | None`. When it is None there is no
    request id to record, and the row must still be written with NULL: an
    audit row lost because an optional correlation key was unavailable turns
    a missing identifier into a missing audit trail, which is strictly
    worse.

    Driven through `on_call_tool` directly with the REAL middleware and the
    real database, because a client call cannot produce this state -- FastMCP
    always attaches a context. `audit_server` is requested for its
    clear-`audit_log`-before-and-after behaviour (see its docstring), not
    for the server object."""
    middleware = AuditMiddleware(database)

    async def call_next(context: object) -> ToolResult:
        return ToolResult(content=[])

    context = _DirectContext("ok_tool", {"amount": 1})
    assert context.fastmcp_context is None
    await middleware.on_call_tool(context, call_next)  # type: ignore[arg-type]

    entry = (await rows(session))[0]
    assert entry.request_id is None
    assert entry.tool_name == "ok_tool"
    assert entry.outcome == "returned"
    assert entry.duration_ms is not None


async def test_a_context_whose_request_id_raises_still_writes_the_row(
    audit_server: FastMCP, database: Database, session: AsyncSession
) -> None:
    """The second way the id goes missing, and the one a `is None` check
    alone does not cover: `Context.request_id` is a PROPERTY that raises
    `RuntimeError` when `request_context` is None, so a non-None
    `fastmcp_context` is not enough to make the read safe. The `pytest.raises`
    below pins that precondition against the real `Context`, so this test
    starts failing if fastmcp ever changes the property to return None
    instead -- at which point the handling here would be dead code, not a
    silent no-op."""
    real_context = Context(audit_server)
    with pytest.raises(RuntimeError):
        _ = real_context.request_id

    middleware = AuditMiddleware(database)

    async def call_next(context: object) -> ToolResult:
        return ToolResult(content=[])

    context = _DirectContext("ok_tool", {"amount": 1}, fastmcp_context=real_context)
    await middleware.on_call_tool(context, call_next)  # type: ignore[arg-type]

    entry = (await rows(session))[0]
    assert entry.request_id is None
    assert entry.outcome == "returned"


# -- refusal_reason ----------------------------------------------------------
#
# NULL on this column means "this call was not refused, or the row predates
# the column" (models.py). Every call below arrives through the in-process
# `Client`, which carries no access token and reaches no consent check
# (`Client(transport=server)` accepts no auth argument), so NULL here is the
# first of those two readings. The consent-denied rows that make the column
# worth having need a real HTTP request and a real token; they live in
# `tests/test_audit_refusal_reason.py`, next to the wire-response assertion
# that pins what a denied caller is still told.


async def test_an_ordinary_successful_call_records_no_refusal_reason(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 50})
    entry = (await rows(session))[0]
    assert entry.outcome == "returned"
    assert entry.refusal_reason is None


async def test_an_ordinary_tool_failure_records_no_refusal_reason(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """The row this column most easily gets wrong. `boom_tool` raises on its
    own, and a refused call raises too -- both write through
    `on_call_tool`'s `except` branch, the one that looks a refusal up. A
    tool that failed for its own reasons was not refused, and recording
    otherwise on a regulator-facing table would invent a consent event that
    never happened."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("boom_tool", {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert entry.outcome == "raised"
    # `ToolError`, not `ValueError`: FastMCP wraps a tool's own exception
    # before the middleware sees it. Asserted anyway, because it is what
    # separates this row from the refusal rows, which carry `NotFoundError`.
    assert entry.detail == "ToolError"
    assert entry.refusal_reason is None


async def test_an_unknown_tool_name_records_no_refusal_reason(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """Half of the pair this column exists to separate, with no consent
    check in play at all: a name FastMCP does not know raises
    `NotFoundError` before any `auth=` callable runs, so nothing files a
    decision and the row reads as the non-refusal it is. The other half --
    the same `NotFoundError`, the same `detail`, a consent denial behind it
    -- is in `tests/test_audit_refusal_reason.py`."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("no_such_tool", {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert entry.tool_name == "no_such_tool"
    assert entry.outcome == "raised"
    assert entry.detail == "NotFoundError"
    assert entry.refusal_reason is None


async def test_the_database_refuses_a_reason_outside_the_documented_set(
    database: Database,
) -> None:
    """`ck_audit_log_refusal_reason` (models.py) is enforcement, not
    documentation. Nothing an agent sends reaches this column -- every value
    comes from `services/api/consent.py` -- so the only way an unlisted
    string arrives is a code change that added a refusal reason without the
    migration that widens the constraint, on a table read by queries that
    filter on the documented values. Failing the INSERT makes that change
    loud at the first refusal instead of leaving behind a value no query
    counts. Asserted against the real Postgres: a constraint that exists
    only in the SQLAlchemy metadata enforces nothing.

    On its own session rather than the `session` fixture's: a violated
    constraint aborts the transaction it lands in, and that fixture's
    transaction is shared with everything else a test does. Nothing commits
    here, so there is no row to clean up either."""
    async with database.sessionmaker() as own_session:
        with pytest.raises(IntegrityError):
            await store_audit.append(
                own_session,
                at=datetime.now(UTC),
                customer_ref=None,
                tool_name="ok_tool",
                arguments={},
                outcome="raised",
                detail="NotFoundError",
                redaction_budget_exhausted=False,
                duration_ms=0,
                request_id=None,
                refusal_reason="reason_nobody_declared",
            )


async def test_both_documented_reasons_are_accepted_by_that_constraint(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """The companion the test above needs: a constraint that rejected every
    value would satisfy it just as well. Each value in `REFUSAL_REASONS`
    goes through the real `append` and is read back, so a migration listing
    fewer values than the code can produce fails here rather than in
    production, where the cost is the audit row itself (fail closed, see
    docs/decisions/0006-audit-write-failure.md)."""
    for reason in REFUSAL_REASONS:
        await store_audit.append(
            session,
            at=datetime.now(UTC),
            customer_ref=None,
            tool_name="cards.list",
            arguments={},
            outcome="raised",
            detail="NotFoundError",
            redaction_budget_exhausted=False,
            duration_ms=0,
            request_id=None,
            refusal_reason=reason,
        )
    assert [e.refusal_reason for e in await rows(session)] == list(REFUSAL_REASONS)

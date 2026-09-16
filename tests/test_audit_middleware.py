import random
import string

import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.server.auth import AccessToken
from postern_core.domain.masking import _IBAN_SCAN_BUDGET, _MASK, redaction_budget
from postern_core.store.models import AuditEntry
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.middleware.audit import _MAX_TOOL_NAME, _scrub


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

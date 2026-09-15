import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.server.auth import AccessToken
from postern_core.store.models import AuditEntry
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.middleware.audit import _scrub


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

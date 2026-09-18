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
from postern_core.store.models import (
    ABSENCE_NO_ACCESS_TOKEN,
    ABSENCE_NO_STRING_SUBJECT,
    ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
    CUSTOMER_REF_ABSENCE_REASONS,
    OUTCOMES,
    REFUSAL_REASONS,
    AuditEntry,
)
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.middleware import audit as audit_middleware
from services.api.middleware.audit import (
    _MAX_REQUEST_ID,
    _MAX_TOOL_NAME,
    _TRUNCATED,
    AuditMiddleware,
    _clamp,
    _request_id,
    _scrub,
)


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
    assert entries[0].tool_name == ("x" * 63) + _TRUNCATED
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

# See `tests/test_store_audit.py`: `audit.append` requires a correlation key,
# and the constraint probes below write rows with no partner to pair with.
PROBE_CALL_ID = "probe-call-id"

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


# -- Which absence produced the NULL: `customer_ref_absence_reason` ----------
#
# A NULL `customer_ref` meant three different things and the row said which
# of them nowhere: no access token at all, a token with no usable `sub`, and
# a token whose `sub` is a string that fails `CustomerRef`. The third is the
# compromised-issuer case identity.py warns about, and its evidence sat in
# this table indistinguishable from an anonymous call.
#
# Every test below that inspects a row reads it back through the `session`
# fixture -- a second connection whose identity map never held the
# middleware's own objects -- so a value that only ever existed in SQLAlchemy
# memory cannot pass any of them. The three constraint tests at the end use
# their own session instead, because a violated constraint aborts the
# transaction it lands in and that fixture's transaction is shared with
# everything else a test does.

# A PAN, used as a token subject. `CustomerRef` rejects it (identity.py's
# `_OPAQUE` requires a `cust` namespace prefix), which is the shape a
# compromised issuer would mint and the reason this column exists. The same
# value the C3 tests above use.
_ISSUER_MINTED_PAN = "4111111111111111"


async def row_texts(session: AsyncSession) -> list[str]:
    """Every audit row, every column, as PostgreSQL itself renders them.

    `audit_log::text` on a whole-row reference emits one record literal per
    row covering EVERY column, including any added after this test was
    written, so the "the rejected subject is nowhere in the row" assertion
    below cannot quietly stop covering a column somebody adds later. Reading
    named attributes off an `AuditEntry` instead would only ever check the
    columns the author thought of.
    """
    result = await session.execute(text("SELECT audit_log::text FROM audit_log ORDER BY id"))
    return [str(row[0]) for row in result]


async def test_a_call_with_no_access_token_records_that_no_token_was_present(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """Case 1, and the one that needs no monkeypatch to produce: the
    in-process `fastmcp.Client` carries no credentials, so
    `get_access_token()` returns None for every call made through it -- the
    same property `tests/test_audit_refusal_reason.py`'s module docstring
    gives as its reason for running over real HTTP instead. This is an
    ordinary unauthenticated call, and the row must read as one rather than
    as anything about a subject."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1})
    entry = (await rows(session))[0]
    assert entry.customer_ref is None
    assert entry.customer_ref_absence_reason == ABSENCE_NO_ACCESS_TOKEN


@pytest.mark.parametrize(
    "claims",
    [{}, {"sub": None}, {"sub": 12345}],
    ids=["no_sub_claim", "sub_is_null", "sub_is_a_number"],
)
async def test_a_token_with_no_usable_subject_records_its_own_class(
    audit_server: FastMCP,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
    claims: dict[str, object],
) -> None:
    """Case 2: a token that passed signature, issuer and audience
    verification and still yielded no string `sub`. `_customer_ref` gates on
    `isinstance(subject, str)`, so an absent claim, an explicit null and a
    number all land here, and all three record the same value deliberately
    -- none of them is the compromised-issuer case, and splitting them later
    is a widened CHECK (see `CUSTOMER_REF_ABSENCE_REASONS` in models.py).

    What must NOT happen is any of them reading as `no_access_token`: a
    verified token with a broken subject is an issuer-side defect, while no
    token at all is just an unauthenticated caller."""
    token = AccessToken(token="t", client_id="c", scopes=[], claims=claims)  # noqa: S106
    monkeypatch.setattr("services.api.middleware.audit.get_access_token", lambda: token)
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1})
    entry = (await rows(session))[0]
    assert entry.customer_ref is None
    assert entry.customer_ref_absence_reason == ABSENCE_NO_STRING_SUBJECT


async def test_a_pan_shaped_token_subject_records_the_compromised_issuer_class(
    audit_server: FastMCP, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Case 3, the reason this column exists, and the one whose value must
    never be written.

    The token is well-formed and its `sub` is a full PAN -- what an issuer
    under attacker control mints, per identity.py's own warning that
    `_OPAQUE` is a provenance convention and not proof of opacity.
    `services/api/server.py`'s `token_customer_resolver` refuses exactly this
    on the tool path; the audit row now says so instead of recording the same
    bare NULL an unauthenticated call produces.

    The second assertion is the hard constraint: the rejected string appears
    in NO column of the row. `audit_log::text` renders the whole record, so
    this covers `detail`, `arguments`, `tool_name` and the new column alike
    -- storing the offending subject "so an investigator can see what was
    minted" would be the one write that survives the refusal it documents."""
    token = AccessToken(
        token="t",  # noqa: S106
        client_id="c",
        scopes=[],
        claims={"sub": _ISSUER_MINTED_PAN},
    )
    monkeypatch.setattr("services.api.middleware.audit.get_access_token", lambda: token)
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1})

    entry = (await rows(session))[0]
    assert entry.customer_ref is None
    assert entry.customer_ref_absence_reason == ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF
    whole_row = (await row_texts(session))[0]
    assert _ISSUER_MINTED_PAN not in whole_row
    # Nor a masked form of it: `_scrub` never sees the token subject, so a
    # `•••• 1111` anywhere in this row would mean someone routed the rejected
    # value through the redactor and stored the remainder. The class of
    # absence is the whole of what the row is allowed to carry, and it is
    # there.
    assert f"{_MASK} 1111" not in whole_row
    assert ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF in whole_row


async def test_a_conforming_subject_records_the_reference_and_no_absence_reason(
    audit_server: FastMCP, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fourth state, and the one that keeps the column from being a
    blanket stamp: an authenticated call with a valid `sub` records the
    reference and leaves this column NULL. NULL here means "`customer_ref` is
    present, or the row predates the column" (models.py) and nothing else --
    there is no "a customer was found" value, because `customer_ref` already
    carries that fact and a second copy could disagree with it."""
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
    assert entry.customer_ref_absence_reason is None


async def test_the_three_absences_are_one_predicate_apart_in_the_stored_rows(
    audit_server: FastMCP, session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The measurement the column was added for: all three absences in one
    table, told apart by a single `WHERE` on a single column.

    Each of the three calls produces a row whose `customer_ref` is NULL, and
    before this column those three rows were byte-identical in every field a
    reader could key on. The `SELECT` below is the search an investigator
    actually runs, executed against Postgres rather than reasoned about, and
    it returns the compromised-issuer row alone -- not two rows, not three."""
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 1})

    no_subject = AccessToken(token="t", client_id="c", scopes=[], claims={})  # noqa: S106
    monkeypatch.setattr("services.api.middleware.audit.get_access_token", lambda: no_subject)
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 2})

    minted = AccessToken(
        token="t",  # noqa: S106
        client_id="c",
        scopes=[],
        claims={"sub": _ISSUER_MINTED_PAN},
    )
    monkeypatch.setattr("services.api.middleware.audit.get_access_token", lambda: minted)
    async with Client(transport=audit_server) as c:
        await c.call_tool("ok_tool", {"amount": 3})

    entries = await rows(session)
    assert [e.customer_ref for e in entries] == [None, None, None]
    assert [e.customer_ref_absence_reason for e in entries] == [
        ABSENCE_NO_ACCESS_TOKEN,
        ABSENCE_NO_STRING_SUBJECT,
        ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
    ]
    found = await session.execute(
        select(AuditEntry).where(
            AuditEntry.customer_ref_absence_reason == ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF
        )
    )
    assert [e.arguments for e in found.scalars().all()] == [{"amount": 3}]


async def test_the_database_refuses_an_absence_reason_outside_the_documented_set(
    database: Database,
) -> None:
    """`ck_audit_log_customer_ref_absence_reason` (models.py) is enforcement,
    not documentation, and nothing an agent sends can reach this column:
    every value comes from `_customer_ref`. The only way an unlisted string
    arrives is a code change that added a class of absence without the
    migration that widens the constraint, on a table whose readers filter on
    the documented values. Asserted against the real Postgres, because a
    constraint that exists only in the SQLAlchemy metadata enforces nothing
    -- and because migration 3186c04c018c writes this one out itself rather
    than importing the tuple.

    Its own session, like the refusal-vocabulary test below it: a violated
    constraint aborts the transaction it lands in, and the `session`
    fixture's transaction is shared with everything else a test does."""
    async with database.sessionmaker() as own_session:
        with pytest.raises(IntegrityError):
            await store_audit.append(
                own_session,
                at=datetime.now(UTC),
                customer_ref=None,
                customer_ref_absence_reason="a_class_nobody_declared",
                tool_name="ok_tool",
                arguments={},
                outcome="returned",
                detail=None,
                redaction_budget_exhausted=False,
                duration_ms=0,
                request_id=None,
                refusal_reason=None,
                call_id=PROBE_CALL_ID,
            )


async def test_every_documented_absence_reason_is_accepted_by_that_constraint(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """The companion the test above needs: a constraint rejecting every value
    would satisfy it just as well. Each value in
    `CUSTOMER_REF_ABSENCE_REASONS` goes through the real `append` and is read
    back, so a migration listing fewer values than the code can produce fails
    here rather than in production, where the cost is the audit row itself
    and the call with it (fail closed, see
    docs/decisions/0006-audit-write-failure.md)."""
    for reason in CUSTOMER_REF_ABSENCE_REASONS:
        await store_audit.append(
            session,
            at=datetime.now(UTC),
            customer_ref=None,
            customer_ref_absence_reason=reason,
            tool_name="ok_tool",
            arguments={},
            outcome="returned",
            detail=None,
            redaction_budget_exhausted=False,
            duration_ms=0,
            request_id=None,
            refusal_reason=None,
            call_id=PROBE_CALL_ID,
        )
    assert [e.customer_ref_absence_reason for e in await rows(session)] == list(
        CUSTOMER_REF_ABSENCE_REASONS
    )


async def test_the_database_refuses_an_outcome_outside_the_documented_set(
    database: Database,
) -> None:
    """`ck_audit_log_outcome` (models.py, migration 71a4c0d9e3b2), the same
    enforcement its two neighbours have had since the revisions that added
    them.

    `outcome` went five revisions without one, which is why this test is
    newer than the column by a long way: a third value arrived on 2026-09-18
    (`reaching`), and a vocabulary that grows is exactly the one where a
    fourth value misspelled into the column needs no migration, no review,
    and shows up as rows every query filtering on the documented values
    silently misses.

    Asserted against the real Postgres, on its own session, for both reasons
    `test_the_database_refuses_a_reason_outside_the_documented_set` gives: a
    constraint living only in SQLAlchemy metadata enforces nothing, and a
    violation aborts the transaction it lands in.

    `match=` on the constraint NAME, which its three older siblings do not
    do: they argue in a comment that no other constraint on the row can
    fire, and that argument is only as durable as the next column added to
    this table. Naming it makes the test fail if some other constraint
    starts catching this row first, rather than passing for a reason it was
    not written for."""
    async with database.sessionmaker() as own_session:
        with pytest.raises(IntegrityError, match="ck_audit_log_outcome"):
            await store_audit.append(
                own_session,
                at=datetime.now(UTC),
                customer_ref=None,
                customer_ref_absence_reason=ABSENCE_NO_ACCESS_TOKEN,
                tool_name="ok_tool",
                arguments={},
                outcome="invented",
                detail=None,
                redaction_budget_exhausted=False,
                duration_ms=0,
                request_id=None,
                refusal_reason=None,
                call_id=PROBE_CALL_ID,
            )


async def test_every_documented_outcome_is_accepted_by_that_constraint(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """The companion, for the reason its two siblings give: a constraint
    rejecting everything would pass the test above too. Each value in
    `OUTCOMES` goes through the real `append` and is read back, so a
    migration listing fewer values than the code can write fails here rather
    than in production, where the cost is the row and the call with it.

    `reaching` is the one this matters most for: it is written from a
    different call site than the other two (`_PendingEntry`, not `_write`),
    so a migration that constrained `outcome` to the pair it had before
    2026-09-18 would break only the entry row, and only on calls that
    actually reach the backend."""
    for outcome in OUTCOMES:
        await store_audit.append(
            session,
            at=datetime.now(UTC),
            customer_ref=None,
            customer_ref_absence_reason=ABSENCE_NO_ACCESS_TOKEN,
            tool_name="ok_tool",
            arguments={},
            outcome=outcome,
            detail=None,
            redaction_budget_exhausted=False,
            duration_ms=0,
            request_id=None,
            refusal_reason=None,
            call_id=PROBE_CALL_ID,
        )
    assert [e.outcome for e in await rows(session)] == list(OUTCOMES)


async def test_the_database_refuses_a_row_with_no_call_id(database: Database) -> None:
    """`ck_audit_log_call_id_present` (models.py, migration 71a4c0d9e3b2).

    Written through `AuditEntry` directly rather than through `append`, and
    that is the whole point rather than a shortcut: `append` types `call_id`
    as `str`, so the Python signature already refuses None and mypy enforces
    it. What this test asks is the different question -- whether the
    DATABASE refuses it too, for a writer that bypasses `append`, which is
    the only reason the constraint exists. Before it, the non-absence of a
    correlation key was a property of one function's type hints.

    The constraint is created `NOT VALID` because every row written before
    that migration has NULL here, in a column that did not exist. `NOT
    VALID` skips those rows and still enforces on every INSERT, which on an
    append-only table is every row that will ever be written -- and this is
    what proves the second half against a real Postgres rather than against
    the migration's own docstring.

    `match=` names the constraint for the reason the outcome test above
    gives: this row satisfies every other constraint on the table today, and
    that is a fact about today."""
    async with database.sessionmaker() as own_session:
        with pytest.raises(IntegrityError, match="ck_audit_log_call_id_present"):
            own_session.add(
                AuditEntry(
                    at=datetime.now(UTC),
                    customer_ref=None,
                    customer_ref_absence_reason=ABSENCE_NO_ACCESS_TOKEN,
                    tool_name="ok_tool",
                    arguments={},
                    outcome="returned",
                    detail=None,
                    redaction_budget_exhausted=False,
                    duration_ms=0,
                    request_id=None,
                    refusal_reason=None,
                )
            )
            await own_session.commit()


async def test_the_database_refuses_a_row_with_neither_a_reference_nor_a_reason(
    database: Database,
) -> None:
    """Half of `ck_audit_log_customer_ref_xor_absence`, and the half that
    matters most: a NULL `customer_ref` whose cause went unrecorded is the
    exact defect this column removes, and without this constraint a future
    code path could reintroduce it one branch at a time while every existing
    test kept passing.

    This is also the shape every row written before migration 3186c04c018c
    has, which is why that migration adds this constraint `NOT VALID`:
    PostgreSQL then enforces it on every INSERT -- as this test proves
    against the real database -- without scanning the rows that predate it."""
    async with database.sessionmaker() as own_session:
        with pytest.raises(IntegrityError):
            await store_audit.append(
                own_session,
                at=datetime.now(UTC),
                customer_ref=None,
                customer_ref_absence_reason=None,
                tool_name="ok_tool",
                arguments={},
                outcome="returned",
                detail=None,
                redaction_budget_exhausted=False,
                duration_ms=0,
                request_id=None,
                refusal_reason=None,
                call_id=PROBE_CALL_ID,
            )


async def test_the_database_refuses_a_row_with_both_a_reference_and_a_reason(
    database: Database,
) -> None:
    """The other half: a reason sitting beside the reference it claims is
    absent. Nothing in the row would say which of the two to believe, and a
    query counting absences by this column would over-count rows that have a
    customer. `_customer_ref` cannot produce this pair -- its `_Subject`
    fills exactly one field -- so the constraint guards a future change, at
    the cost the fail-closed policy sets out: the row, and the call."""
    async with database.sessionmaker() as own_session:
        with pytest.raises(IntegrityError):
            await store_audit.append(
                own_session,
                at=datetime.now(UTC),
                customer_ref="cust_7f3a",
                customer_ref_absence_reason=ABSENCE_NO_ACCESS_TOKEN,
                tool_name="ok_tool",
                arguments={},
                outcome="returned",
                detail=None,
                redaction_budget_exhausted=False,
                duration_ms=0,
                request_id=None,
                refusal_reason=None,
                call_id=PROBE_CALL_ID,
            )


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
    assert entries[0].tool_name == ("y" * 63) + _TRUNCATED
    assert entries[0].outcome == "raised"


# -- A clipped value carries its own clipping --------------------------------
#
# The owner ruled for a sentinel inside the value over a `truncated: bool`
# column and over a second column holding the full string: the value has to
# announce its own alteration the way a masked value already does by
# containing `_MASK`. `_TRUNCATED` (U+2026 HORIZONTAL ELLIPSIS) is that
# sentinel. Two ways it can go wrong, one section each below: a written value
# one character too wide for its column, which under
# `docs/decisions/0006-audit-write-failure.md` costs the row and the tool call
# with it; and a sentinel on a value nothing was cut from, which makes the row
# lie about itself.


def test_clamp_marks_a_value_only_when_it_actually_cuts_one() -> None:
    """The no-false-positive invariant, at the boundary where an off-by-one
    lands: `limit - 1` and `limit` characters come back as the identical
    string, `limit + 1` comes back marked. `_TRUNCATED` is checked with
    `not in`, not by comparing the tail, so a marker appearing anywhere in an
    untouched value fails this too."""
    for limit in (8, _MAX_TOOL_NAME, _MAX_REQUEST_ID):
        for length in (0, 1, limit - 1, limit):
            value = "a" * length
            assert _clamp(value, limit) == value
            assert _TRUNCATED not in _clamp(value, limit)

        over = "a" * (limit + 1)
        assert _clamp(over, limit) == ("a" * (limit - len(_TRUNCATED))) + _TRUNCATED
        assert len(_clamp(over, limit)) == limit


def test_clamp_never_returns_more_characters_than_the_limit() -> None:
    """The column-width invariant, swept rather than spot-checked: writing
    `limit + 1` characters raises
    `asyncpg.exceptions.StringDataRightTruncationError` at the INSERT, which
    this module's fail-closed policy turns into a lost row. Every length from
    0 to `_MAX_REQUEST_ID + 10`, against both real limits."""
    for limit in (_MAX_TOOL_NAME, _MAX_REQUEST_ID):
        for length in range(_MAX_REQUEST_ID + 11):
            assert len(_clamp("b" * length, limit)) <= limit


def test_the_sentinel_survives_scrub_and_is_not_the_mask() -> None:
    """Why U+2026 and not a zero-width or format character. `_scrub` runs
    `_strip_invisible`, which deletes `Cf`, `Mn`,
    `_BLANK_RENDERING_CHARACTERS` and `_DEFAULT_IGNORABLE_UNASSIGNED`
    outright -- a marker drawn from any of those would be removed and the
    truncation would go back to being silent, which is the exact failure the
    sentinel exists to end. U+2026 is category `Po` and survives; U+200B ZERO
    WIDTH SPACE is shown below failing the same call, so this states a
    difference rather than a bare assertion.

    The last two lines pin the other half of the choice: a reader must not
    take a clipped value for a redacted one, so the sentinel shares no
    character with `_MASK` (`••••`, U+2022 BULLET)."""
    assert _scrub(_TRUNCATED) == _TRUNCATED
    assert _scrub("accounts.list" + _TRUNCATED) == "accounts.list" + _TRUNCATED
    assert _scrub("tool_4111111111114417" + _TRUNCATED) == "tool_•••• 4417" + _TRUNCATED
    assert _scrub("\u200b") == ""

    assert _TRUNCATED not in _MASK
    assert _MASK not in _TRUNCATED


async def test_a_clipped_tool_name_is_marked_and_fills_the_column_exactly(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """End to end, through the real middleware and the real `String(64)`
    column (models.py): a 200-character name is recorded as 63 characters of
    its own content plus the sentinel, which is exactly 64 and not one
    character more."""
    long_name = "n" * 200
    async with Client(transport=audit_server) as c:
        await c.call_tool(long_name, {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert entry.tool_name == ("n" * 63) + _TRUNCATED
    assert entry.tool_name.endswith(_TRUNCATED)
    assert len(entry.tool_name) == _MAX_TOOL_NAME


async def test_a_tool_name_exactly_at_the_column_width_is_recorded_unmarked(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """The boundary the whole design turns on: 64 characters is the longest
    name that fits, so nothing is cut and nothing may be marked. An
    implementation that slices to `_MAX_TOOL_NAME - len(_TRUNCATED)`
    unconditionally passes every over-length test above and fails this one."""
    exact_name = "e" * _MAX_TOOL_NAME
    async with Client(transport=audit_server) as c:
        await c.call_tool(exact_name, {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert entry.tool_name == exact_name
    assert _TRUNCATED not in entry.tool_name
    assert len(entry.tool_name) == _MAX_TOOL_NAME


async def test_ordinary_tool_names_gain_no_sentinel(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """The regression that would matter most in practice: every real tool
    name in this codebase is far under 64 characters and must reach
    `audit_log.tool_name` character-for-character, sentinel-free. Three
    shapes, including the dotted and underscored forms this server actually
    registers."""
    for name in ("ok_tool", "accounts.list", "transactions.list"):
        async with Client(transport=audit_server) as c:
            await c.call_tool(name, {}, raise_on_error=False)
    recorded = [e.tool_name for e in await rows(session)]
    assert recorded == ["ok_tool", "accounts.list", "transactions.list"]
    assert all(_TRUNCATED not in value for value in recorded)


async def test_the_first_clamp_reserves_the_sentinels_own_character(
    audit_server: FastMCP, session: AsyncSession
) -> None:
    """That 63 is the first clamp's slice, and not 64 rescued afterwards by
    the fail-safe.

    On a name of repeated characters the two are indistinguishable -- slicing
    to 64 and appending gives 65, which the fail-safe cuts back to the same
    63 + sentinel -- so this uses a name scrubbing SHORTENS: a 16-digit PAN
    followed by 200 'b's. The recorded value then lands at 57 characters, the
    fail-safe never fires, and the slice width shows up directly as the
    number of 'b's that survive: 63 - len("4111111111114417 ") = 46 for the
    reserved slice, 47 for a slice of 64.

    Also the only test here that proves the PAN in an over-length name is
    still masked. Clipping and masking run on the same value in the same
    expression, and an ordering slip that dropped one of them would leave a
    raw PAN in `audit_log`."""
    long_name = "4111111111114417 " + ("b" * 200)
    async with Client(transport=audit_server) as c:
        await c.call_tool(long_name, {}, raise_on_error=False)
    entry = (await rows(session))[0]
    assert "4111111111114417" not in entry.tool_name
    assert entry.tool_name == "•••• 4417 " + ("b" * 46) + _TRUNCATED
    assert entry.tool_name.count("b") == 46
    assert len(entry.tool_name) <= _MAX_TOOL_NAME


async def test_the_defensive_clamp_marks_the_name_when_a_lengthening_scrub_fires_it(
    audit_server: FastMCP,
    database: Database,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second clamp in `on_call_tool` exists, in its own comment's words,
    "not because today's masking can trigger it" but against a future `_scrub`
    whose substitutions lengthen a value. Monkeypatching `_scrub` into exactly
    that future function -- one that doubles every string handed to it -- is
    the only way to observe the branch.

    What it must still do is what it always did, keep the write inside
    `String(64)`, plus what the sentinel ruling adds: a value it cuts is a
    value that was altered, so it leaves the same marker the first clamp
    would have. A bare `name[:_MAX_TOOL_NAME]` here passes the width half and
    fails the marker half.

    The name is 40 characters, comfortably under the first clamp, so the
    marker on the row provably came from the fail-safe and not from the
    ordinary path."""
    monkeypatch.setattr(
        audit_middleware,
        "_scrub",
        lambda value: value * 2 if isinstance(value, str) else value,
    )
    middleware = AuditMiddleware(database)

    async def call_next(context: object) -> ToolResult:
        return ToolResult(content=[])

    short_name = "z" * 40  # 40 <= _MAX_TOOL_NAME, so the FIRST clamp cannot fire
    await middleware.on_call_tool(_DirectContext(short_name), call_next)  # type: ignore[arg-type]

    entry = (await rows(session))[0]
    assert entry.tool_name == ("z" * 63) + _TRUNCATED
    assert len(entry.tool_name) == _MAX_TOOL_NAME


def test_a_clipped_request_id_is_marked_and_fits_the_column() -> None:
    """`request_id` is `String(128)` (models.py) and the JSON-RPC id is chosen
    by the client, which makes it as agent-controlled as the tool name.
    Driven through `_request_id` directly rather than a client call: the
    in-process `Client` mints its own ids and offers no way to send a
    300-character one."""
    long_id = "9" * 300
    context = _DirectContext("ok_tool", fastmcp_context=SimpleNamespace(request_id=long_id))  # type: ignore[arg-type]
    recorded = _request_id(context)  # type: ignore[arg-type]
    assert recorded is not None
    assert recorded == ("9" * 127) + _TRUNCATED
    assert len(recorded) == _MAX_REQUEST_ID


def test_ordinary_request_ids_gain_no_sentinel() -> None:
    """The no-false-positive half for `request_id`, at the boundary and below
    it: a 128-character id fits exactly and must come back identical, and so
    must an ordinary short one. `str()` is still applied -- a JSON-RPC id may
    be a number -- so the integer case is checked too."""
    for value in ("7", "req-0001", "8" * (_MAX_REQUEST_ID - 1), "8" * _MAX_REQUEST_ID):
        context = _DirectContext("ok_tool", fastmcp_context=SimpleNamespace(request_id=value))  # type: ignore[arg-type]
        assert _request_id(context) == value  # type: ignore[arg-type]

    numeric = _DirectContext("ok_tool", fastmcp_context=SimpleNamespace(request_id=42))  # type: ignore[arg-type]
    assert _request_id(numeric) == "42"  # type: ignore[arg-type]


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
    `request_id` of None for a context that has no `fastmcp_context`, a
    `refusal_reason` of None for a call that reached no consent check at
    all, and the `customer_ref`/`customer_ref_absence_reason` pair that
    `ck_audit_log_customer_ref_xor_absence` (models.py) requires -- this call
    runs outside any request, so `get_access_token()` answers None and the
    row records `no_access_token` rather than a second bare NULL."""
    middleware = AuditMiddleware(db=None)  # type: ignore[arg-type]
    tool_error = ToolError("Error calling tool 'boom_tool': internal detail")
    written: list[dict[str, object]] = []

    async def call_next(context: object) -> ToolResult:
        raise tool_error

    async def record_write(
        at: object,
        customer: object,
        customer_ref_absence_reason: object,
        name: object,
        arguments: object,
        outcome: object,
        detail: object,
        redaction_budget_exhausted: object,
        duration_ms: object,
        request_id: object,
        refusal_reason: object,
        call_id: object,
    ) -> None:
        written.append(
            {
                "outcome": outcome,
                "duration_ms": duration_ms,
                "request_id": request_id,
                "refusal_reason": refusal_reason,
                "customer_ref": customer,
                "customer_ref_absence_reason": customer_ref_absence_reason,
                "call_id": call_id,
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
    assert written[0]["customer_ref"] is None
    assert written[0]["customer_ref_absence_reason"] == ABSENCE_NO_ACCESS_TOKEN


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
                # A documented value, so the only constraint this row can
                # violate is the refusal vocabulary one under test:
                # `ck_audit_log_customer_ref_xor_absence` (models.py) would
                # also reject a NULL `customer_ref` with no reason beside it,
                # and either violation raises the same `IntegrityError`.
                customer_ref_absence_reason=ABSENCE_NO_ACCESS_TOKEN,
                tool_name="ok_tool",
                arguments={},
                outcome="raised",
                detail="NotFoundError",
                redaction_budget_exhausted=False,
                duration_ms=0,
                request_id=None,
                refusal_reason="reason_nobody_declared",
                call_id=PROBE_CALL_ID,
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
            customer_ref_absence_reason=ABSENCE_NO_ACCESS_TOKEN,
            tool_name="cards.list",
            arguments={},
            outcome="raised",
            detail="NotFoundError",
            redaction_budget_exhausted=False,
            duration_ms=0,
            request_id=None,
            refusal_reason=reason,
            call_id=PROBE_CALL_ID,
        )
    assert [e.refusal_reason for e in await rows(session)] == list(REFUSAL_REASONS)

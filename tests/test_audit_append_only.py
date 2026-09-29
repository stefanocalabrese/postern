"""`audit_log` refuses UPDATE, DELETE and TRUNCATE -- and exactly where that stops.

Migration `f1860c110112` is the first thing in eleven revisions to enforce
append-only in the database rather than state it in a docstring. Before it,
`packages/postern-core/src/postern_core/store/models.py` called this table
append-only and `packages/postern-core/src/postern_core/store/audit.py`
exposed no update and no delete helper, while the application role held full
DML: any SQL injection or RCE in either service could erase the
regulator-facing record of exactly the calls the attacker made, leaving an
`id` sequence gap indistinguishable from a rolled-back INSERT.

THIS FILE IS HALF GATE AND HALF MEASUREMENT OF THE GATE'S EDGE, and the
second half is the reason it exists at all. A control whose limits are
asserted in a docstring drifts; a control whose limits are executed on every
`make ci` run cannot. So the two bypasses migration `f1860c110112` names are
not described here, they are performed -- `test_the_owner_erases_the_record_
by_disabling_the_trigger` and `test_a_superuser_erases_the_record_by_setting_
session_replication_role` both delete rows the trigger refused a moment
earlier. If either of those ever starts failing, the control got STRONGER
and this file should be read before it is "fixed".

THREE ROLES NOW, WHERE THERE USED TO BE ONE, and the whole file has been
re-pointed onto them. Until 2026-09-29 every environment this repo shipped
connected as a single role that was simultaneously the table owner, the role
migrations ran as, and a superuser, so "the owner erases the record" and "a
superuser erases the record" were one sentence measured twice. `sql/01-roles.sql`
and `sql/02-grants.sql` split it, `tests/conftest.py`'s `pg_url` applies both
and runs the migrations as the owner, and the three roles are now distinct
things with distinct costs:

    database / `clean`   the container's bootstrap SUPERUSER. Still what the
                         rest of this suite connects as, and still refused
                         UPDATE, DELETE and TRUNCATE by the triggers -- which
                         is migration f1860c110112's central claim, since a
                         superuser bypasses the ACL half entirely.
    `owner`              postern_owner. Owns every table, is NOT a superuser.
    `appender`           postern_app. Owns nothing, is not a superuser, and
                         holds exactly what `sql/02-grants.sql` grants.

WHAT THE SPLIT COST THE OWNER, measured here rather than predicted:
migration `f1860c110112`'s `REVOKE UPDATE, DELETE, TRUNCATE ... FROM
CURRENT_USER` was decorative while CURRENT_USER was a superuser, and now
binds. So the owner bypass is THREE statements, not the two item 11 was
written around -- a `GRANT` back to itself, the `DISABLE TRIGGER`, then the
`DELETE`. That migration's docstring predicted exactly this ("the
one-statement speed bump against a non-superuser owner") and
`test_the_owner_erases_the_record_by_disabling_the_trigger` is where it stops
being a prediction.

THE APPLICATION ROLE IS THE POINT OF THE OTHER HALF. `CLAUDE.md`'s operator
checklist item 11 asks operators to run the application as a role that owns
nothing, and the honest question about a checklist item is whether anyone has
ever checked what it buys. The four tests that use `appender` are that answer:
INSERT and SELECT work, UPDATE, DELETE and TRUNCATE are refused AT THE ACL
CHECK rather than by the trigger, and neither bypass is in reach.
`tests/test_application_role.py` is the other half of the answer -- that the
same role can still serve the whole application.

WHY THE SEEDED ROW IS NOT INCIDENTAL. A `FOR EACH ROW` trigger fires per
row, so `DELETE FROM audit_log WHERE id = -1` raises nothing and reports
`DELETE 0`. Every test below that expects a refusal therefore seeds a real
row first, and `test_a_delete_that_matches_no_row_still_succeeds` pins the
gap deliberately, because someone will otherwise read this control as
tamper detection. It is a wall, not a tripwire.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any, cast

import pytest
import pytest_asyncio
from postern_core.store import audit
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import select, text
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import DBAPIError

from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

#: This module's own customer reference. `database` is session-scoped and
#: shared, so everything here is seeded and torn down under one value and no
#: other module's rows are touched -- the same discipline
#: `tests/test_zt7_confirm_revocation.py` and
#: `tests/test_customer_ref_persistence.py` use.
CUSTOMER = "cust_appendonly"

CALL_ID = "append-only-probe"

#: SQLSTATE `insufficient_privilege`. Both halves of the control answer with
#: it -- the trigger because migration `f1860c110112` raises `USING ERRCODE`,
#: the `REVOKE` because that is what Postgres returns for a denied DML
#: statement -- so one code covers a refusal whichever half produced it.
INSUFFICIENT_PRIVILEGE = "42501"

#: A DELETE that matches nothing. `id` is a positive-only sequence, so
#: this predicate can never be true and the statement is a literal with
#: no bind parameter to carry.
_ZERO_ROW_DELETE = "DELETE FROM audit_log WHERE id = -1"


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def clean(database: Database) -> AsyncIterator[Database]:
    """This module's rows, gone at both ends.

    Through the bypass, because the thing under test is that a plain DELETE
    here raises. `tests/fixtures/append_only_bypass.py` is where that is
    argued; the tests below are where it is measured.
    """
    await _wipe(database)
    yield database
    await _wipe(database)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(
            s, AuditEntry.customer_ref == CUSTOMER
        )
        await s.commit()


@pytest.fixture
def appender(app_db: Database) -> Database:
    """The application role -- `postern_app`, as the shipped SQL creates it.

    RE-POINTED ON 2026-09-29, and the re-point is the whole of what changed
    about this fixture. It used to `CREATE ROLE postern_appender_probe` here
    and grant to it inline, which measured a role this file invented: item 11
    could have stayed a paragraph nobody had built, and these four tests would
    still have passed. It now takes `tests/conftest.py`'s `app_db`, whose role
    is created by `sql/01-roles.sql` and granted by `sql/02-grants.sql` -- the
    two files `docker-compose.yml` mounts and runs, and the two an operator
    runs. What passes here and what `docker compose up` applies can no longer
    disagree.
    """
    return app_db


@pytest.fixture
def owner(owner_db: Database) -> Database:
    """`postern_owner`: owns every table, and is NOT a superuser.

    The distinction this fixture exists to draw. Until the split there was one
    role wearing three hats, so "the owner erases the record" and "a superuser
    erases the record" were the same sentence measured twice. They are now two
    roles and two different costs, which the two bypass tests below measure
    separately.
    """
    return owner_db


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


async def _seed(db: Database, *, tool_name: str = "probe") -> None:
    """One real row, through the production append path.

    `audit.append` rather than a hand-written INSERT: the row has to satisfy
    every CHECK constraint on this table, and the function whose only job is
    to produce such rows is the one that knows how.
    """
    async with db.sessionmaker() as s:
        await audit.append(
            s,
            at=datetime.now(UTC),
            reaching_at=None,
            customer_ref=CUSTOMER,
            customer_ref_absence_reason=None,
            tool_name=tool_name,
            arguments={},
            outcome="returned",
            detail=None,
            redaction_budget_exhausted=False,
            duration_ms=0,
            request_id=None,
            refusal_reason=None,
            call_id=CALL_ID,
            client_id=None,
            risk_signals=None,
        )


async def _rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(
            select(AuditEntry).where(AuditEntry.customer_ref == CUSTOMER).order_by(AuditEntry.id)
        )
        return list(result.scalars().all())


async def _refused(db: Database, statement: str) -> DBAPIError:
    """Run `statement` and return the error it must raise.

    Each in its own session: a raise aborts the transaction, so a caller that
    reused one would be measuring `InFailedSqlTransaction` from the second
    statement onwards rather than the refusal it asked for.

    The customer reference goes in as a bind parameter rather than an
    f-string, so these statements are literals. That is not ceremony for a
    constant: `S608` is in this repo's ruff selection and `tests/**` ignores
    only `S101`, so an interpolated DML string here would need a `noqa` on
    every line, in a file whose subject is what an injected statement can do
    to this table.
    """
    async with db.sessionmaker() as s:
        with pytest.raises(DBAPIError) as caught:
            await s.execute(text(statement), {"customer": CUSTOMER})
    return caught.value


def _sqlstate(error: DBAPIError) -> str | None:
    """SQLSTATE off a SQLAlchemy-wrapped asyncpg error, or None.

    Read defensively rather than asserted: SQLAlchemy's asyncpg dialect wraps
    the driver exception in its own DBAPI shim, so the attribute's depth is
    the dialect's business and not this file's. Every caller pairs it with a
    message assertion that does not depend on it.
    """
    original: Any = error.orig
    for candidate in (original, getattr(original, "__cause__", None)):
        state = getattr(candidate, "sqlstate", None)
        if isinstance(state, str):
            return state
    return None


# ---------------------------------------------------------------------------
# The SUPERUSER -- the one role no privilege system binds, refused anyway.
# ---------------------------------------------------------------------------


async def test_the_superuser_cannot_update_a_row_that_exists(clean: Database) -> None:
    """The control test from the other direction: before migration
    f1860c110112 this statement reported `UPDATE 1`.

    RE-POINTED IN NAME ONLY on 2026-09-29. `clean` was "the current role"
    when one role did everything; it is the container's bootstrap superuser
    now, and this test is where the trigger half of the control earns its
    existence, because a `REVOKE` cannot touch this role at all."""
    await _seed(clean)
    error = await _refused(
        clean, "UPDATE audit_log SET outcome = 'tampered' WHERE customer_ref = :customer"
    )
    assert "append-only" in str(error)
    assert "UPDATE is not permitted" in str(error)
    assert _sqlstate(error) == INSUFFICIENT_PRIVILEGE
    assert [row.outcome for row in await _rows(clean)] == ["returned"]


async def test_the_superuser_cannot_delete_a_row_that_exists(clean: Database) -> None:
    await _seed(clean)
    error = await _refused(clean, "DELETE FROM audit_log WHERE customer_ref = :customer")
    assert "DELETE is not permitted" in str(error)
    assert _sqlstate(error) == INSUFFICIENT_PRIVILEGE
    assert len(await _rows(clean)) == 1


async def test_the_superuser_cannot_truncate_the_table(clean: Database) -> None:
    """A `FOR EACH ROW` trigger does not fire on TRUNCATE at all, so without
    the separate statement trigger this one word would empty the table."""
    await _seed(clean)
    error = await _refused(clean, "TRUNCATE audit_log")
    assert "TRUNCATE is not permitted" in str(error)
    assert _sqlstate(error) == INSUFFICIENT_PRIVILEGE
    assert len(await _rows(clean)) == 1


async def test_an_ordinary_append_still_succeeds(clean: Database) -> None:
    """The fail-closed policy (dev-docs/decisions/0006-audit-write-failure.md)
    turns a failed audit write into a failed tool call, so a control that
    caught INSERT would deny every call rather than protect any row."""
    await _seed(clean, tool_name="first")
    await _seed(clean, tool_name="second")
    assert [row.tool_name for row in await _rows(clean)] == ["first", "second"]


async def test_a_delete_that_matches_no_row_still_succeeds(clean: Database) -> None:
    """A WALL, NOT A TRIPWIRE, pinned so nobody reads this control as detection.

    Nothing here records or notices an attempt. This one is not even refused:
    the row trigger fires per row and there is no row, so the statement
    reports success having done nothing. An attacker probing the table learns
    the difference between "matched something" and "matched nothing" from
    exactly this asymmetry, and nothing in `audit_log` will say they asked.
    """
    await _seed(clean)
    async with clean.sessionmaker() as s:
        # `AsyncSession.execute` is typed `Result[Any]`, which carries no
        # `rowcount`; a DML statement returns a `CursorResult`, which does.
        # The cast is the narrowing mypy cannot do from the signature alone.
        result = cast("CursorResult[Any]", await s.execute(text(_ZERO_ROW_DELETE)))
        await s.commit()
    assert result.rowcount == 0, "the statement must report having deleted nothing"
    assert len(await _rows(clean)) == 1


# ---------------------------------------------------------------------------
# The role operator checklist item 11 asks for -- owns nothing, no superuser.
# ---------------------------------------------------------------------------


async def test_the_appender_role_can_append_and_read(clean: Database, appender: Database) -> None:
    """What item 11 must not cost: the application still writes its rows."""
    await _seed(appender, tool_name="from-appender")
    assert [row.tool_name for row in await _rows(appender)] == ["from-appender"]
    assert [row.tool_name for row in await _rows(clean)] == ["from-appender"]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_log SET outcome = 'tampered' WHERE customer_ref = :customer",
        "DELETE FROM audit_log WHERE customer_ref = :customer",
        "TRUNCATE audit_log",
    ],
    ids=["update", "delete", "truncate"],
)
async def test_the_appender_role_is_refused_every_erasing_statement(
    clean: Database, appender: Database, statement: str
) -> None:
    """Refused at the ACL check, BEFORE the trigger is consulted.

    The message is `permission denied for table audit_log`, which is
    PostgreSQL's ACL refusal, and it is asserted here ALONGSIDE the absence of
    the trigger's own text. Both directions are needed and only together do
    they say anything: the trigger raises `audit_log is append-only: UPDATE is
    not permitted`, so a message carrying neither phrase would mean the
    statement failed for some third reason, and a message carrying the
    trigger's phrase would mean this role holds the privilege and was stopped
    by the thing an owner can switch off.

    That is the whole difference item 11 buys. For this role the control is
    not a trigger that could be disabled, it is a privilege that was never
    held -- and the statement never reaches the trigger to find out.
    """
    await _seed(clean)
    error = await _refused(appender, statement)
    assert "permission denied for table audit_log" in str(error)
    assert "append-only" not in str(error), "the trigger answered, so the ACL did not"
    assert "is not permitted" not in str(error)
    assert _sqlstate(error) == INSUFFICIENT_PRIVILEGE
    assert len(await _rows(clean)) == 1


@pytest.mark.parametrize(
    ("statement", "expected"),
    [
        (
            "ALTER TABLE audit_log DISABLE TRIGGER USER",
            "must be owner of table audit_log",
        ),
        (
            "SET session_replication_role = replica",
            'permission denied to set parameter "session_replication_role"',
        ),
        (
            "DROP TRIGGER audit_log_append_only_row ON audit_log",
            "must be owner of relation audit_log",
        ),
        ("DROP TABLE audit_log", "must be owner of table audit_log"),
    ],
    ids=["disable-trigger", "replication-role", "drop-trigger", "drop-table"],
)
async def test_the_appender_role_cannot_reach_either_bypass(
    appender: Database, statement: str, expected: str
) -> None:
    """The two bypasses the tests below perform, refused to this role.

    Both of them plus the two blunter routes to the same end. This is the
    whole of what makes the control complete for a non-owner: there is no
    statement it can issue that removes the trigger or steps around it.
    """
    error = await _refused(appender, statement)
    assert expected in str(error)


# ---------------------------------------------------------------------------
# What still defeats the control, performed rather than described.
# ---------------------------------------------------------------------------


async def test_the_owner_is_refused_at_the_acl_before_it_re_grants_to_itself(
    clean: Database, owner: Database
) -> None:
    """The first of the owner's three statements, and what it costs an attacker.

    NEW MEASUREMENT, and it exists because the split changed the answer.
    Migration `f1860c110112` runs `REVOKE UPDATE, DELETE, TRUNCATE ON
    audit_log FROM CURRENT_USER`, and its docstring calls that REVOKE
    "decorative" against a superuser owner -- correctly, because a superuser
    bypasses the ACL. CURRENT_USER at migration time is now `postern_owner`,
    which is not a superuser, so the REVOKE binds and this is the refusal it
    produces. It is worth exactly one statement: the owner grants the
    privilege back to itself in the next breath, which
    `test_the_owner_erases_the_record_by_disabling_the_trigger` then does.
    """
    await _seed(clean)
    error = await _refused(owner, "DELETE FROM audit_log WHERE customer_ref = :customer")
    assert "permission denied for table audit_log" in str(error)
    assert _sqlstate(error) == INSUFFICIENT_PRIVILEGE
    assert len(await _rows(clean)) == 1


async def test_the_owner_erases_the_record_by_disabling_the_trigger(
    clean: Database, owner: Database
) -> None:
    """BYPASS ONE, and the reason the docstrings do not say "append-only".

    RE-POINTED ON 2026-09-29 FROM THE SUPERUSER TO `postern_owner`, which is
    the point of the re-point: this used to run as a role that was the owner
    AND a superuser, so it could not distinguish which of the two properties
    did the work. It is now a role holding only ownership, and ownership is
    still enough.

    THREE STATEMENTS, NOT TWO, which is the one number the split moved. The
    `GRANT ... TO CURRENT_USER` at the top is new and is not ceremony: without
    it the DELETE is refused at the ACL by migration `f1860c110112`'s REVOKE,
    which the previous superuser owner bypassed without noticing. So the price
    of this bypass went from two statements to three, and the residue is
    unchanged -- a gap in the `id` sequence that reads the same as a
    rolled-back INSERT, plus whatever watches DDL, which in this repo is
    nothing.

    This is why `CLAUDE.md`'s item 11 asks operators to keep the application
    off this role: three statements is not a wall, it is a receipt.
    """
    await _seed(clean)
    async with owner.sessionmaker() as s:
        await s.execute(text("GRANT DELETE ON audit_log TO CURRENT_USER"))
        await s.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only_row"))
        await s.execute(
            text("DELETE FROM audit_log WHERE customer_ref = :customer"), {"customer": CUSTOMER}
        )
        await s.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only_row"))
        await s.execute(text("REVOKE DELETE ON audit_log FROM CURRENT_USER"))
        await s.commit()
    assert await _rows(clean) == []
    # Re-armed, in this session and for every later test in the suite. Asserted
    # against BOTH halves: the trigger answers the superuser, and the ACL
    # answers the owner again, so a teardown that forgot either statement
    # fails here rather than silently leaving the control off for the rest of
    # the run.
    await _seed(clean)
    error = await _refused(clean, "DELETE FROM audit_log WHERE customer_ref = :customer")
    assert "DELETE is not permitted" in str(error)
    owner_error = await _refused(owner, "DELETE FROM audit_log WHERE customer_ref = :customer")
    assert "permission denied for table audit_log" in str(owner_error)


async def test_a_superuser_erases_the_record_by_setting_session_replication_role(
    clean: Database,
) -> None:
    """BYPASS TWO, needing no DDL at all.

    `session_replication_role` is a `SUSET` parameter, so a superuser sets it
    and every user trigger on every table stops firing for that session. One
    statement, no lock, nothing altered, nothing to notice afterwards.

    Nothing in a database binds a superuser, and that is not a gap this
    migration could have closed: an event trigger would need superuser to
    create and a superuser drops it, and the same role can reach the table's
    files regardless. Operator checklist item 11 is the whole mitigation --
    the application must not connect as this kind of role.

    DELIBERATELY NOT RE-POINTED. Every other test in this file moved onto one
    of the two new roles on 2026-09-29; this one stays on `clean` because
    `clean` is the superuser and a superuser is precisely what it measures.
    `test_the_appender_role_cannot_reach_either_bypass` is the other side of
    it: the application role is refused this exact statement.
    """
    await _seed(clean)
    async with clean.sessionmaker() as s:
        await s.execute(text("SET LOCAL session_replication_role = replica"))
        await s.execute(
            text("DELETE FROM audit_log WHERE customer_ref = :customer"), {"customer": CUSTOMER}
        )
        await s.commit()
    assert await _rows(clean) == []

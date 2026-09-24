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

THE NON-OWNER ROLE IS THE POINT OF THE OTHER HALF. Every environment this
repo ships with connects as one role that is simultaneously the table owner,
the role migrations run as, and a superuser (`tests/conftest.py::pg_url`'s
testcontainers user, `docker-compose.yml`'s `POSTGRES_USER: postern`). For
that role the control is a trigger away from being off. `CLAUDE.md`'s
operator checklist item 11 asks operators to run the application as a role
that owns nothing, and the honest question about a checklist item is whether
anyone has ever checked what it buys. `appender` below is that role, created
inside the test container and connected to over TCP, and the four tests that
use it are what item 11 is worth: INSERT and SELECT work, UPDATE, DELETE and
TRUNCATE are refused, and neither bypass is in reach.

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
from sqlalchemy import func, make_url, select, text
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

#: The non-owner, non-superuser login role operator checklist item 11
#: describes. Created inside the disposable test container and never dropped:
#: the container is torn down with the session, and a `DROP ROLE` would have
#: to `REASSIGN OWNED` first for no benefit here.
APPENDER_ROLE = "postern_appender_probe"

#: Not a credential: a literal for a role that exists only inside a
#: throwaway container bound to a random port on the loopback interface, and
#: whose entire privilege set is INSERT and SELECT on one table. `S105` fires
#: on the name, which has to keep saying what the value is.
APPENDER_PASSWORD = "appender-probe"  # noqa: S105

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


@pytest_asyncio.fixture(scope="session")
async def appender_url(database: Database, pg_url: str) -> str:
    """A login role that owns nothing, is not a superuser, and may only append.

    This is operator checklist item 11 built in miniature: `SELECT, INSERT`
    on `audit_log`, `USAGE` on its sequence, and nothing else. The sequence
    is resolved through `pg_get_serial_sequence` rather than spelled
    `audit_log_id_seq`, so a future migration that rebuilds the column does
    not leave this fixture granting on a name that no longer exists -- it
    would fail loudly here instead.

    Created through the owner connection, which in this container is also a
    superuser, because creating a role requires a privilege the role being
    created must not have.
    """
    async with database.sessionmaker() as s:
        await s.execute(text(f"DROP ROLE IF EXISTS {APPENDER_ROLE}"))
        await s.execute(text(f"CREATE ROLE {APPENDER_ROLE} LOGIN PASSWORD '{APPENDER_PASSWORD}'"))
        url = make_url(pg_url)
        await s.execute(text(f'GRANT CONNECT ON DATABASE "{url.database}" TO {APPENDER_ROLE}'))
        await s.execute(text(f"GRANT USAGE ON SCHEMA public TO {APPENDER_ROLE}"))
        await s.execute(text(f"GRANT SELECT, INSERT ON audit_log TO {APPENDER_ROLE}"))
        sequence = (
            await s.execute(select(func.pg_get_serial_sequence("audit_log", "id")))
        ).scalar_one()
        assert sequence is not None, "audit_log.id has no sequence to grant on"
        await s.execute(text(f"GRANT USAGE ON SEQUENCE {sequence} TO {APPENDER_ROLE}"))
        await s.commit()
    # `render_as_string(hide_password=False)`, never `str(url)`: `URL.__str__`
    # renders the password as `***`, so the obvious spelling produces a URL
    # that connects as this role with the literal password "***" and fails
    # authentication -- measured here before this line was written.
    return (
        make_url(pg_url)
        .set(username=APPENDER_ROLE, password=APPENDER_PASSWORD)
        .render_as_string(hide_password=False)
    )


@pytest_asyncio.fixture
async def appender(appender_url: str) -> AsyncIterator[Database]:
    db = Database(appender_url, null_pool=True)
    yield db
    await db.close()


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
# The role this repo actually runs as -- owner AND superuser.
# ---------------------------------------------------------------------------


async def test_the_current_role_cannot_update_a_row_that_exists(clean: Database) -> None:
    """The control test from the other direction: before migration
    f1860c110112 this statement reported `UPDATE 1`."""
    await _seed(clean)
    error = await _refused(
        clean, "UPDATE audit_log SET outcome = 'tampered' WHERE customer_ref = :customer"
    )
    assert "append-only" in str(error)
    assert "UPDATE is not permitted" in str(error)
    assert _sqlstate(error) == INSUFFICIENT_PRIVILEGE
    assert [row.outcome for row in await _rows(clean)] == ["returned"]


async def test_the_current_role_cannot_delete_a_row_that_exists(clean: Database) -> None:
    await _seed(clean)
    error = await _refused(clean, "DELETE FROM audit_log WHERE customer_ref = :customer")
    assert "DELETE is not permitted" in str(error)
    assert _sqlstate(error) == INSUFFICIENT_PRIVILEGE
    assert len(await _rows(clean)) == 1


async def test_the_current_role_cannot_truncate_the_table(clean: Database) -> None:
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
    """Refused by the `REVOKE` half, BEFORE the trigger is consulted.

    The message is `permission denied for table audit_log`, not the trigger's
    own text: this role was never granted the privilege, so Postgres stops
    the statement at the ACL check. That is the difference item 11 buys --
    for this role the control is not a trigger that could be disabled, it is
    a privilege that was never held.
    """
    await _seed(clean)
    error = await _refused(appender, statement)
    assert "permission denied for table audit_log" in str(error)
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


async def test_the_owner_erases_the_record_by_disabling_the_trigger(clean: Database) -> None:
    """BYPASS ONE, and the reason the docstrings do not say "append-only".

    Table ownership is enough. Two statements, no superuser needed, and the
    only residue is a gap in the `id` sequence that reads the same as a
    rolled-back INSERT. This is why `CLAUDE.md`'s item 11 asks operators to
    run the application as a role that owns nothing: against an owner, this
    migration buys one extra statement and an audit-log entry in whatever
    watches DDL, which in this repo is nothing.
    """
    await _seed(clean)
    async with clean.sessionmaker() as s:
        await s.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only_row"))
        await s.execute(
            text("DELETE FROM audit_log WHERE customer_ref = :customer"), {"customer": CUSTOMER}
        )
        await s.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only_row"))
        await s.commit()
    assert await _rows(clean) == []
    # Re-armed, in this session and for every later test in the suite.
    await _seed(clean)
    error = await _refused(clean, "DELETE FROM audit_log WHERE customer_ref = :customer")
    assert "DELETE is not permitted" in str(error)


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
    """
    await _seed(clean)
    async with clean.sessionmaker() as s:
        await s.execute(text("SET LOCAL session_replication_role = replica"))
        await s.execute(
            text("DELETE FROM audit_log WHERE customer_ref = :customer"), {"customer": CUSTOMER}
        )
        await s.commit()
    assert await _rows(clean) == []

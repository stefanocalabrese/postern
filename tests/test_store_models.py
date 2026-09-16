"""ORM models for the two tables this plan owns (Task 2).

`consents` and `audit_log` per handoff §9. These tests check shape only
(table names, constraint names, column types, append-only-by-construction);
migration correctness against a real database is verified separately with
`alembic check`, not by these unit tests.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest_asyncio
from postern_core.store import audit
from postern_core.store.base import Base
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ConsentRecord
from sqlalchemy import delete, select


def test_both_tables_are_registered_on_the_metadata() -> None:
    assert set(Base.metadata.tables) == {"consents", "audit_log"}


def test_consent_is_unique_per_customer_and_domain() -> None:
    # `ConsentRecord.__table__` is typed as the general `FromClause`, which
    # has no `.constraints`: SQLAlchemy's stubs allow a mapped class's table
    # to be a join in single/joined-table inheritance, and only the concrete
    # `Table` subtype carries `.constraints`. `Base.metadata.tables[...]` is
    # typed as `Table` directly, so it satisfies mypy --strict without a
    # `type: ignore` while checking the exact same constraint set.
    table = ConsentRecord.metadata.tables["consents"]
    names = {c.name for c in table.constraints}
    assert "uq_consent_customer_domain" in names


def test_audit_entry_has_no_update_or_delete_helper() -> None:
    """Append-only by construction: the model exposes no mutation helpers."""
    public = {n for n in dir(AuditEntry) if not n.startswith("_")}
    assert not {n for n in public if n.startswith(("update", "delete"))}


def test_audit_arguments_column_is_jsonb() -> None:
    from sqlalchemy.dialects.postgresql import JSONB

    assert isinstance(AuditEntry.__table__.c.arguments.type, JSONB)


def test_audit_redaction_budget_exhausted_column_is_a_non_nullable_boolean() -> None:
    from sqlalchemy import Boolean

    column = AuditEntry.__table__.c.redaction_budget_exhausted
    assert isinstance(column.type, Boolean)
    assert column.nullable is False


# -- `audit.append`, read back from Postgres, not the in-memory row ---------
#
# `append()` commits for real: it is the audit trail, and a row that only
# survives until the caller's transaction rolls back is not one. That rules
# out the rollback-based `session` fixture the consent tests use (its
# rollback cannot undo a commit that already landed), so these clear
# `audit_log` themselves, before and after, against the session-scoped
# container.


@pytest_asyncio.fixture
async def clean_audit_log(database: Database) -> AsyncIterator[None]:
    async def _clear() -> None:
        async with database.sessionmaker() as s:
            await s.execute(delete(AuditEntry))
            await s.commit()

    await _clear()
    yield
    await _clear()


async def test_append_with_redaction_budget_exhausted_true_persists_true(
    database: Database, clean_audit_log: None
) -> None:
    async with database.sessionmaker() as s:
        await audit.append(
            s,
            at=datetime.now(UTC),
            customer_ref=None,
            tool_name="probe",
            arguments={},
            outcome="returned",
            detail=None,
            redaction_budget_exhausted=True,
        )
    async with database.sessionmaker() as s:
        row = (await s.execute(select(AuditEntry))).scalar_one()
    assert row.redaction_budget_exhausted is True


async def test_append_with_redaction_budget_exhausted_false_persists_false(
    database: Database, clean_audit_log: None
) -> None:
    async with database.sessionmaker() as s:
        await audit.append(
            s,
            at=datetime.now(UTC),
            customer_ref=None,
            tool_name="probe",
            arguments={},
            outcome="returned",
            detail=None,
            redaction_budget_exhausted=False,
        )
    async with database.sessionmaker() as s:
        row = (await s.execute(select(AuditEntry))).scalar_one()
    assert row.redaction_budget_exhausted is False


async def test_append_without_the_parameter_persists_false(
    database: Database, clean_audit_log: None
) -> None:
    """Pins the temporary default in `append()`: the follow-up task that
    wires in the real value has to change this test on purpose, rather than
    the default drifting underneath it unnoticed."""
    async with database.sessionmaker() as s:
        await audit.append(
            s,
            at=datetime.now(UTC),
            customer_ref=None,
            tool_name="probe",
            arguments={},
            outcome="returned",
            detail=None,
        )
    async with database.sessionmaker() as s:
        row = (await s.execute(select(AuditEntry))).scalar_one()
    assert row.redaction_budget_exhausted is False

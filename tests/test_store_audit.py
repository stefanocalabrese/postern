"""Persisting through `store/audit.py`'s `append` (Task 2).

Unlike `test_store_models.py`, these start Postgres, commit, and read rows
back: `append()`'s own contract is that it commits, so its test coverage
has to go through a real database, not the model metadata alone.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest_asyncio
from postern_core.store import audit
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import delete, select

# `append()` commits for real, which rules out the rollback-based `session`
# fixture the consent tests use, for two reasons rather than one. First,
# `conftest.py`'s `session` binds to a connection on which `conn.begin()`
# was already called, so SQLAlchemy resolves `join_transaction_mode` to
# `rollback_only` and `append()`'s commit never reaches that outer
# transaction at all -- the row would never actually land, so a test using
# this fixture could not demonstrate that `append()` persists anything.
# Second, reading back through that same session would return the
# identity-mapped instance, which `expire_on_commit=False` never refreshes,
# so a wrong value genuinely written to Postgres would stay invisible.
# These clear `audit_log` themselves instead, before and after, against the
# session-scoped container.


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
            duration_ms=0,
            request_id=None,
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
            duration_ms=0,
            request_id=None,
        )
    async with database.sessionmaker() as s:
        row = (await s.execute(select(AuditEntry))).scalar_one()
    assert row.redaction_budget_exhausted is False

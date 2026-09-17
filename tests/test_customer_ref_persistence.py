"""A maximum-length CustomerRef must actually persist (the customer_ref width defect).

`CustomerRef` accepts up to 65 characters (`cust` + one separator + 60
alphanumerics, see `identity.py`'s `_OPAQUE`); `consents.customer_ref` and
`audit_log.customer_ref` used to be `String(64)`, one character short.
`test_customer_ref_width.py` proves that gap statically, from the model
metadata; this file proves the consequence was real by writing a
65-character ref through each table and reading it back from a real
Postgres, the way `test_store_audit.py` and `test_consent_enforcement.py`
already do for their own commit-then-read-back cases -- a rollback-scoped
session would enforce the same column width (Postgres checks it at flush,
independent of commit), but committing and reading back through a second,
independent session is the stronger proof this codebase already uses
elsewhere, so this matches that convention rather than taking a shortcut.
"""

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest_asyncio
from postern_core.identity import CustomerRef
from postern_core.store import audit
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ConsentRecord
from sqlalchemy import delete, select

# The same 65 characters `test_customer_ref_width.py` derives from
# `_OPAQUE` by parsing it; written as a literal here because this file's
# job is only to prove a value of that length actually round-trips, not to
# re-derive the bound.
MAX_REF = CustomerRef(value="cust_" + "a" * 60).value


@pytest_asyncio.fixture
async def clean_max_length_rows(database: Database) -> AsyncIterator[None]:
    """This ref's rows, before and after: leaves other tests' rows untouched."""

    async def _clear() -> None:
        async with database.sessionmaker() as s:
            await s.execute(delete(AuditEntry).where(AuditEntry.customer_ref == MAX_REF))
            await s.execute(delete(ConsentRecord).where(ConsentRecord.customer_ref == MAX_REF))
            await s.commit()

    await _clear()
    yield
    await _clear()


async def test_a_maximum_length_customer_ref_round_trips_through_audit_log(
    database: Database, clean_max_length_rows: None
) -> None:
    async with database.sessionmaker() as s:
        await audit.append(
            s,
            at=datetime.now(UTC),
            customer_ref=MAX_REF,
            tool_name="probe",
            arguments={},
            outcome="returned",
            detail=None,
            redaction_budget_exhausted=False,
            duration_ms=0,
            request_id=None,
            refusal_reason=None,
        )
    async with database.sessionmaker() as s:
        row = (
            await s.execute(select(AuditEntry).where(AuditEntry.customer_ref == MAX_REF))
        ).scalar_one()
    assert row.customer_ref == MAX_REF
    assert len(row.customer_ref) == 65


async def test_a_maximum_length_customer_ref_round_trips_through_consents(
    database: Database, clean_max_length_rows: None
) -> None:
    async with database.sessionmaker() as s:
        s.add(
            ConsentRecord(
                customer_ref=MAX_REF,
                domain="accounts",
                granted=True,
                granted_at=datetime.now(UTC),
                expires_at=None,
            )
        )
        await s.commit()
    async with database.sessionmaker() as s:
        row = (
            await s.execute(select(ConsentRecord).where(ConsentRecord.customer_ref == MAX_REF))
        ).scalar_one()
    assert row.customer_ref == MAX_REF
    assert len(row.customer_ref) == 65

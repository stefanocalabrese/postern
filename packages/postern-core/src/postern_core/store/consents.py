"""Reading consent.

Granting consent belongs to the device-grant flow (Plan 4). This module only
reads, and treats an expired row as absent rather than as an error: expiry
renewal is a flow, not a failure.
"""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from postern_core.identity import CustomerRef
from postern_core.store.models import ConsentRecord


async def granted_domains(session: AsyncSession, customer: CustomerRef) -> set[str]:
    """The domains this customer has currently consented to."""
    now = datetime.now(UTC)
    stmt = select(ConsentRecord.domain).where(
        ConsentRecord.customer_ref == customer.value,
        ConsentRecord.granted.is_(True),
        (ConsentRecord.expires_at.is_(None)) | (ConsentRecord.expires_at > now),
    )
    rows = await session.execute(stmt)
    return set(rows.scalars().all())

"""Reading consent.

Granting consent belongs to the device-grant flow (Plan 4). This module only
reads, and treats an expired row as absent rather than as an error: expiry
renewal is a flow, not a failure.
"""

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from postern_core.identity import CustomerRef
from postern_core.store.models import ConsentRecord


async def granted_domains(session: AsyncSession, customer: CustomerRef) -> set[str]:
    """The domains this customer has currently consented to.

    Expiry is judged by the database's ``now()`` inside the statement, not by
    comparing ``expires_at`` with this process's clock: the row's deadline was
    written against some other clock, and a host that disagrees with it would
    otherwise grant or refuse consent on its own say-so.
    """
    stmt = select(ConsentRecord.domain).where(
        ConsentRecord.customer_ref == customer.value,
        ConsentRecord.granted.is_(True),
        (ConsentRecord.expires_at.is_(None)) | (ConsentRecord.expires_at > func.now()),
    )
    rows = await session.execute(stmt)
    return set(rows.scalars().all())

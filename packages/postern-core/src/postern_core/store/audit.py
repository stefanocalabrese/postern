"""Appending to the audit log.

Append-only by construction: this module exposes no update and no delete.
"""

from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from postern_core.store.models import AuditEntry


async def append(
    session: AsyncSession,
    *,
    at: datetime,
    customer_ref: str | None,
    tool_name: str,
    arguments: dict[str, Any],
    outcome: str,
    detail: str | None,
) -> None:
    session.add(
        AuditEntry(
            at=at,
            customer_ref=customer_ref,
            tool_name=tool_name,
            arguments=arguments,
            outcome=outcome,
            detail=detail,
        )
    )
    await session.commit()

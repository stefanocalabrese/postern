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
    # TEMPORARY seam: neither of the middleware's two call sites can pass a
    # real value until that session publishes the API that measures budget
    # exhaustion (separate follow-up). Until then every row this function
    # writes records False here regardless of what actually happened during
    # scrubbing, so a caller must not read a False on an existing row as
    # evidence that the budget was not exhausted.
    redaction_budget_exhausted: bool = False,
) -> None:
    session.add(
        AuditEntry(
            at=at,
            customer_ref=customer_ref,
            tool_name=tool_name,
            arguments=arguments,
            outcome=outcome,
            detail=detail,
            redaction_budget_exhausted=redaction_budget_exhausted,
        )
    )
    await session.commit()

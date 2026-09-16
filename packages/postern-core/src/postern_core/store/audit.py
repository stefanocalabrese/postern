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
    # Required, not defaulted: `AuditEntry.redaction_budget_exhausted`
    # (models.py) is what this parameter fills in, and `AuditMiddleware
    # ._write` -- the one call site outside tests, reached from both its
    # raised-path and returned-path branches -- always has a real
    # `RedactionScope.exhausted` value to supply. A default here would let
    # a future caller silently record False instead of a measured value.
    redaction_budget_exhausted: bool,
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

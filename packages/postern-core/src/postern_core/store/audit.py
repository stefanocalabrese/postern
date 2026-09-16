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
    # TEMPORARY seam: `append()` has exactly one call site outside tests --
    # `AuditMiddleware._write` (services/api/middleware/audit.py:159),
    # reached from both its raised-path and returned-path branches -- and
    # it cannot pass a real value yet. `redaction_budget()` returns
    # `Iterator[None]` and `_ScanBudget`'s own tracking is a private
    # context variable (masking.py:222,228), so nothing outside that
    # module can read whether the allowance ran out once the `with` block
    # exits; a follow-up has to add that before this default can become
    # anything but False. Until then every row this function writes
    # records False here regardless of what actually happened during
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

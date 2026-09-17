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
    # Required for the same reason, with a sharper consequence than the
    # boolean above: `AuditEntry.duration_ms` is NULLABLE, and NULL on that
    # column already carries a meaning -- "this row predates the column"
    # (models.py). A default here would let a future caller write NULL from
    # a live call, which is not a gap in the data but a false statement
    # about when the row was written, on a regulator-facing table. Both
    # branches of `AuditMiddleware.on_call_tool` measure a real value,
    # including the one that handles a raised exception.
    duration_ms: int,
    # Required even though `None` is a legitimate value here, unlike on
    # `duration_ms`: NULL must mean "the middleware looked for a request id
    # and there was none", never "a caller forgot the argument". Only the
    # caller knows which of the two it is, and a default would erase that
    # difference at the one point where it is still known.
    request_id: str | None,
    # Required for the same reason as `request_id`, applied to a column
    # where the wrong value is not a gap but a contradiction: NULL on
    # `AuditEntry.refusal_reason` means "this call was not refused"
    # (models.py), and a call that WAS refused is the row a regulator reads
    # this table for. `AuditMiddleware._write` reaches `append` from both
    # branches of `on_call_tool`, and only one of them can carry a refusal;
    # a default would let a future branch answer "not refused" without ever
    # asking `services/api/consent.py` whether it refused.
    refusal_reason: str | None,
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
            duration_ms=duration_ms,
            request_id=request_id,
            refusal_reason=refusal_reason,
        )
    )
    await session.commit()

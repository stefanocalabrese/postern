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
    # Required, and the one parameter here whose wrong value is rejected by
    # the database rather than merely recorded: `ck_audit_log_customer_ref_xor
    # _absence` (models.py) makes `customer_ref IS NULL` and this being
    # non-NULL the same statement, so a caller that defaults this to None
    # while passing no `customer_ref` loses the whole row and, under the
    # fail-closed policy (docs/decisions/0006-audit-write-failure.md), the
    # call with it. Only the caller knows WHICH absence it saw -- no token,
    # no string subject, or a subject that failed `CustomerRef` -- and that
    # third case is the compromised-issuer signal the column exists to make
    # searchable, so a default that quietly filed it as one of the other two
    # would be worse than no column at all.
    customer_ref_absence_reason: str | None,
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
    #
    # `int | None` since the entry row exists: an `outcome='reaching'` row is
    # written before the tool body runs, so there is no duration in existence
    # to pass. That is the ONLY caller allowed to pass None, and it stays
    # required rather than defaulted precisely so that passing None is a
    # decision a caller writes down rather than one it inherits.
    duration_ms: int | None,
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
    # Required and never None from any caller, which is the opposite of
    # `request_id` above and is the whole point of the column existing
    # separately from it. `AuditEntry.call_id` is NULLABLE only because rows
    # written before migration 71a4c0d9e3b2 have nothing to put there; a row
    # this function writes always carries the caller's minted value, because
    # a NULL correlation key turns the entry row and the completion row for
    # one call into two unpairable orphans. Typed `str`, so mypy refuses a
    # caller that passes None rather than leaving the guarantee to a comment.
    call_id: str,
    # Required and `datetime | None`, the shape `duration_ms` above has and
    # for the mirror-image reason: `AuditEntry.reaching_at` belongs to the
    # entry row exactly as `duration_ms` belongs to the completion row, and
    # `ck_audit_log_reaching_at_matches_outcome` (models.py) rejects either
    # one written on the wrong row shape -- which under the fail-closed
    # policy (docs/decisions/0006-audit-write-failure.md) costs the row and
    # the call. A default would let a future caller file an entry row that
    # says a touch happened without saying when, which is the hole the column
    # was added to close, or stamp a completion row with a copy of its
    # partner's instant. The caller passing None is writing that decision
    # down rather than inheriting it.
    reaching_at: datetime | None,
    # Required and `str | None`, the shape `request_id` above has and for the
    # same reason applied to a different absence: NULL on
    # `AuditEntry.client_id` must mean "this call carried no access token",
    # never "a caller forgot the argument". Only the caller has seen
    # `get_access_token()`, and it has to pass the SAME value to both of a
    # call's two rows -- `services/api/middleware/audit.py` reads the token
    # once and carries the result on `_PendingEntry` precisely so the entry
    # row and the completion row cannot disagree about who made the call. A
    # default would let a future caller file a row that answers "no client"
    # for a call that had one, on the column that names the party the
    # per-client controls in the design handoff (§"Allowlist clients") act
    # on.
    client_id: str | None,
) -> None:
    session.add(
        AuditEntry(
            at=at,
            reaching_at=reaching_at,
            customer_ref=customer_ref,
            customer_ref_absence_reason=customer_ref_absence_reason,
            tool_name=tool_name,
            arguments=arguments,
            outcome=outcome,
            detail=detail,
            redaction_budget_exhausted=redaction_budget_exhausted,
            duration_ms=duration_ms,
            request_id=request_id,
            refusal_reason=refusal_reason,
            call_id=call_id,
            client_id=client_id,
        )
    )
    await session.commit()

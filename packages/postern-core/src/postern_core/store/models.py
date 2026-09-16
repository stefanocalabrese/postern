"""The two tables this plan owns (handoff §9).

`consents` records which banking domains a customer has authorized.
`audit_log` is append-only: the per-operation chain a regulator asks for.
Neither model exposes an update or delete helper, deliberately.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from postern_core.store.base import Base


class ConsentRecord(Base):
    __tablename__ = "consents"

    id: Mapped[int] = mapped_column(primary_key=True)
    # 128, not 64: identity.py's `_OPAQUE` accepts `cust` + one separator +
    # up to 60 alphanumerics, 65 characters, which a 64-wide column cannot
    # hold at all (`NOT NULL` here, so the insert fails outright rather
    # than truncating). 128 leaves room for `_OPAQUE`'s suffix bound to
    # widen again without another migration; matching it to 65 exactly
    # would put this column back at the edge on the next such change.
    customer_ref: Mapped[str] = mapped_column(String(128), index=True)
    domain: Mapped[str] = mapped_column(String(32))
    granted: Mapped[bool] = mapped_column(Boolean, default=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("customer_ref", "domain", name="uq_consent_customer_domain"),
    )


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # 128, same reasoning as `ConsentRecord.customer_ref` above: `_OPAQUE`'s
    # current maximum is 65 characters, and a failed insert here means no
    # audit row exists for that call at all, on a regulator-facing,
    # append-only table.
    customer_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSONB)
    outcome: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Reports one fact: this call's redaction checksum allowance ran out
    # (`_ScanBudget.exhausted`, masking.py, is `remaining <= 0`). That is
    # neither necessary nor sufficient for "a value on this row was
    # bare-masked instead of scanned": exhaustion can be reached on the
    # checksum that completes a full, correctly-identified scan, so True
    # can mean nothing was degraded; and a token can be bare-masked
    # without the allowance running out at all -- an over-length token
    # spends no budget (masking.py:474, returned before any checksum
    # runs), and an ambiguous token spends checksums but need not spend
    # the last one (masking.py:419-420) -- so False can still accompany a
    # bare-masked value. Named for the budget, not for "degraded", because
    # the budget is the only thing this column actually reports, and this
    # table is regulator-facing, where overclaiming precision is worse
    # than a name that needs this comment. `nullable=False,
    # server_default=false`: every row that predates this column predates
    # the signal, and NULL would invite a reader to treat "unknown" as
    # "fine".
    redaction_budget_exhausted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=false()
    )
    # How long the tool call took, in whole milliseconds, measured with
    # `time.monotonic()` around `call_next` alone
    # (`services/api/middleware/audit.py`'s `_elapsed_ms`) -- not around the
    # argument scrubbing that precedes it, and not with a wall clock, which
    # can step backwards under an NTP correction and write a negative number
    # into a regulator-facing table.
    #
    # Nullable with NO `server_default`, unlike `redaction_budget_exhausted`
    # above, and the difference is the point: NULL here means "this row
    # predates the column", and every row the application writes from now on
    # carries a measured value, on the returned path AND on the raised path
    # (a slow failure is exactly what an investigator looks for). A default
    # would stamp every pre-existing row with a number indistinguishable
    # from a call that genuinely took that long, so the table would be
    # asserting a latency nobody measured.
    #
    # A sub-millisecond call therefore records 0, not NULL: 0 means
    # "measured, under one millisecond", NULL means "no measurement exists
    # for this row". Collapsing the first into the second would make live
    # rows indistinguishable from pre-migration ones.
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The JSON-RPC id of the client request this call arrived on, stored as
    # its string form: an id may be a string or a number on the wire, and
    # one column cannot hold both shapes without a reader having to guess
    # which it is looking at.
    #
    # What it buys is TRACEABILITY, not deduplication: an investigator can
    # tie this row to one client request and line it up against client-side
    # logs. It does not identify a retry. MCP 2026-07-28 has no SSE
    # resumability, so a dropped stream makes the client re-issue the call,
    # and the re-issued call carries a NEW id -- two rows that a reader
    # cannot collapse, because at the protocol level they were two separate
    # requests. Nothing here detects, counts or merges duplicates.
    #
    # Nullable because the id is genuinely absent sometimes:
    # `MiddlewareContext.fastmcp_context` is typed `Context | None`, and
    # `Context.request_id` raises `RuntimeError` when no MCP request context
    # is established. NULL records that real state; the audit row is written
    # either way, because a missing identifier must never become a missing
    # audit row. `String(128)`, with the middleware truncating to the same
    # bound before the insert, for the reason `tool_name` is clamped there:
    # an over-long value would raise `StringDataRightTruncationError` and
    # cost the whole row.
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)

    __table_args__ = (Index("ix_audit_log_customer_at", "customer_ref", "at"),)

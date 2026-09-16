"""The two tables this plan owns (handoff §9).

`consents` records which banking domains a customer has authorized.
`audit_log` is append-only: the per-operation chain a regulator asks for.
Neither model exposes an update or delete helper, deliberately.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Index, String, Text, UniqueConstraint, false
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from postern_core.store.base import Base


class ConsentRecord(Base):
    __tablename__ = "consents"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_ref: Mapped[str] = mapped_column(String(64), index=True)
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
    customer_ref: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSONB)
    outcome: Mapped[str] = mapped_column(String(16))
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Reports one fact: this call's redaction checksum allowance ran out
    # (`_ScanBudget.exhausted`, masking.py, is `remaining <= 0`). That is
    # neither necessary nor sufficient for "a value on this row was
    # bare-masked instead of scanned": exhaustion can be reached on the
    # checksum that completes a full, correctly-identified scan, so True
    # can mean nothing was degraded; and a token can be bare-masked for
    # reasons that spend no budget at all (too long to be a real IBAN, or
    # ambiguous), so False can still accompany a bare-masked value. Named
    # for the budget, not for "degraded", because the budget is the only
    # thing this column actually reports, and this table is regulator-
    # facing, where overclaiming precision is worse than a name that needs
    # this comment. `nullable=False, server_default=false`: every row that
    # predates this column predates the signal, and NULL would invite a
    # reader to treat "unknown" as "fine".
    redaction_budget_exhausted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=false()
    )

    __table_args__ = (Index("ix_audit_log_customer_at", "customer_ref", "at"),)

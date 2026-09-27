"""separate a faulted consent check from an unreachable store

Revision ID: e08757299819
Revises: 2d2aa72c0cb3
Create Date: 2026-09-27 10:40:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e08757299819"
down_revision: str | Sequence[str] | None = "2d2aa72c0cb3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Hardcoded rather than imported from
# `postern_core.store.models.REFUSAL_REASONS`, for the reason revision
# 0eb813c87298 states and revision 2d2aa72c0cb3 demonstrated: that tuple has
# now grown twice, and a migration that had imported it would claim to have
# created constraints it never created. Both sets are here because
# `downgrade` has to restore the exact one the previous revision built.
_WAS = ("no_customer_ref", "domain_not_consented", "consent_store_unavailable")
_NOW = (
    "no_customer_ref",
    "domain_not_consented",
    "consent_store_unavailable",
    "consent_check_faulted",
)
_CONSTRAINT = "ck_audit_log_refusal_reason"


def upgrade() -> None:
    """Upgrade schema.

    `consent_store_unavailable` was being written for two unrelated causes.
    `services/api/consent.py` caught `Exception` around the consent lookup
    and filed that one value whatever had been raised, so a connection pool
    at its ceiling and a migration nobody had applied produced the same row.
    One of those is the operator's infrastructure and the other is this
    software, and an operator alerting on the value was being woken for our
    own SQL.

    Revision 2d2aa72c0cb3 made that worse rather than better, which is why
    this one follows it so closely: since that revision the cause is
    remembered for the rest of the HTTP request, so a single misclassified
    exception labels every refusal in the request instead of one.

    `consent_check_faulted` is the fourth admissible value, 21 characters in
    a `VARCHAR(32)`, so no column change. It means the lookup raised
    something that is not a reachability failure, and nothing more
    specific: the class lists that decide which exceptions those are live in
    `services/api/consent.py` beside the code that catches, because they are
    read off the installed SQLAlchemy and asyncpg rather than being a
    property of the schema.

    The three populations this column now separates are the customer
    (`no_customer_ref`, `domain_not_consented`), the operator's
    infrastructure (`consent_store_unavailable`) and this software
    (`consent_check_faulted`). A query that counts consent denials must
    exclude the last two, and an infrastructure alert must exclude the
    fourth.

    THE DENIAL IS UNCHANGED BY THIS REVISION AND BY THE CODE THAT FEEDS IT.
    A faulted check refuses exactly as an unreachable one does: a bug in the
    consent lookup must never become a reason to allow a call. This revision
    widens what the row can SAY, never what the server does.

    Drop and recreate, because PostgreSQL has no `ALTER ... CHECK`. Both
    statements take ACCESS EXCLUSIVE on `audit_log` and the rebuild scans
    every row, which is admissible for the reason revision 2d2aa72c0cb3
    gave: this is a WIDENING, so every row the old constraint admitted the
    new one admits and the scan cannot fail. Migration f1860c110112's
    append-only triggers do not reach this revision -- adding and dropping a
    constraint is DDL on the table, not a row event, and nothing here
    rewrites a row.
    """
    op.drop_constraint(_CONSTRAINT, "audit_log", type_="check")
    op.create_check_constraint(_CONSTRAINT, "audit_log", sa.column("refusal_reason").in_(_NOW))


def downgrade() -> None:
    """Downgrade schema.

    Restores the three-value constraint, which FAILS on any database that
    has recorded a faulted check: those rows hold a value the old set does
    not admit and the rebuild scans them. Same answer revision
    2d2aa72c0cb3's downgrade gives, for the same reason -- `audit_log` is
    append-only, so there is no `UPDATE` that could rewrite them, and
    folding them back into `consent_store_unavailable` would restate a
    defect in this software as an outage in the operator's infrastructure,
    which is the exact confusion this revision exists to end.
    """
    op.drop_constraint(_CONSTRAINT, "audit_log", type_="check")
    op.create_check_constraint(_CONSTRAINT, "audit_log", sa.column("refusal_reason").in_(_WAS))

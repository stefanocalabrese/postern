"""widen refusal_reason for an unreachable consent store

Revision ID: 2d2aa72c0cb3
Revises: f1860c110112
Create Date: 2026-09-26 21:40:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2d2aa72c0cb3"
down_revision: str | Sequence[str] | None = "f1860c110112"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Hardcoded, not imported from `postern_core.store.models.REFUSAL_REASONS`,
# for the reason revision 0eb813c87298 states and this revision is the first
# demonstration of: that tuple grew, and a migration that had imported it
# would now claim to have created a constraint it never created. Both copies
# are here, old and new, because this revision's `downgrade` has to restore
# the exact set the previous one built.
_WAS = ("no_customer_ref", "domain_not_consented")
_NOW = ("no_customer_ref", "domain_not_consented", "consent_store_unavailable")
_CONSTRAINT = "ck_audit_log_refusal_reason"


def upgrade() -> None:
    """Upgrade schema.

    A consent check that could not reach the consents table was recorded as
    a call nobody refused. `services/api/consent.py`'s `_refuse` sat on the
    two branches after the database read, so when that read raised, FastMCP
    masked the exception as a denial (`fastmcp/utilities/authorization.py`'s
    `_evaluate_check`) and the row read `outcome='raised'`,
    `detail='NotFoundError'`, `refusal_reason` NULL: the same row a mistyped
    tool name produces. An operator paging through `audit_log` during a
    connection-pool saturation could not tell a saturated pool from a
    customer who never granted access.

    `consent_store_unavailable` is the third admissible value. It is the
    only one of the three that describes the operator's own infrastructure,
    and it is deliberately not a security signal: the two values beside it
    are facts about a customer, and a query counting consent denials has to
    exclude this one or it counts an outage as customer state.
    `packages/postern-core/src/postern_core/store/models.py`'s
    `REFUSAL_REASONS` carries the same reasoning beside the values.

    NO COLUMN CHANGE. `refusal_reason` is `VARCHAR(32)` and the new value is
    25 characters, so this revision is one dropped constraint and one
    rebuilt one. The 7 characters of headroom that leaves are recorded in
    the column's own comment rather than spent here: widening the width is a
    separate decision with a separate cost, and nothing needs it today.

    Drop and recreate, because PostgreSQL has no `ALTER ... CHECK`. Both
    statements take ACCESS EXCLUSIVE on `audit_log` and the rebuild scans
    every row, which is admissible for the same reason revision 0eb813c87298
    gave when it created this constraint: this is a WIDENING, so every row
    the old constraint admitted the new one admits, and the scan cannot
    fail. A `NOT VALID` add would skip the scan but needs two transactions
    to help at all, and Alembic runs this revision inside one.

    Migration f1860c110112 makes `UPDATE`, `DELETE` and `TRUNCATE` on this
    table raise through triggers. It does not reach this revision: adding
    and dropping a constraint is DDL on the table, not a row event, and
    nothing here rewrites a row.
    """
    op.drop_constraint(_CONSTRAINT, "audit_log", type_="check")
    op.create_check_constraint(_CONSTRAINT, "audit_log", sa.column("refusal_reason").in_(_NOW))


def downgrade() -> None:
    """Downgrade schema.

    Restores the two-value constraint, which FAILS on any database that has
    recorded an unreachable-store refusal: those rows hold a value the old
    set does not admit, and the rebuild scans them. That is the honest
    outcome and not an oversight to work around -- `audit_log` is
    append-only, so there is no `UPDATE` available to rewrite them into an
    admissible value, and inventing one would restate an outage as a
    customer's consent state on a regulator-facing table. Downgrading past
    this revision means deciding what to do with those rows first.
    """
    op.drop_constraint(_CONSTRAINT, "audit_log", type_="check")
    op.create_check_constraint(_CONSTRAINT, "audit_log", sa.column("refusal_reason").in_(_WAS))

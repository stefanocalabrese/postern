"""widen customer_ref columns to 128

Revision ID: 1c64b7ed3f4b
Revises: f45183f7ff50
Create Date: 2026-09-16 20:21:36.095278

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1c64b7ed3f4b"
down_revision: str | Sequence[str] | None = "f45183f7ff50"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema.

    `identity.py`'s `_OPAQUE` accepts up to 65 characters (`cust` + one
    separator + 60 alphanumerics); both columns were `String(64)`, one
    character short, so a maximum-length `CustomerRef` passed validation
    and then failed to insert. Widened to 128, not 65, so a future
    widening of `_OPAQUE`'s suffix bound does not reopen the same gap.
    Widening a `varchar(n)` in PostgreSQL rewrites only the catalog, not
    the table, regardless of row count.
    """
    op.alter_column("consents", "customer_ref", type_=sa.String(length=128))
    op.alter_column("audit_log", "customer_ref", type_=sa.String(length=128))


def downgrade() -> None:
    """Downgrade schema.

    Narrows back to 64. This fails if any row's `customer_ref` is already
    longer than 64 characters -- exactly the values this migration exists
    to allow -- so downgrading past this revision on a database that has
    taken live traffic since needs those rows dealt with first; this does
    not do that for you.
    """
    op.alter_column("consents", "customer_ref", type_=sa.String(length=64))
    op.alter_column("audit_log", "customer_ref", type_=sa.String(length=64))

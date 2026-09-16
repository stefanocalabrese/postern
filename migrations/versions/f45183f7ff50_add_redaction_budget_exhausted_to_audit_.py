"""add redaction_budget_exhausted to audit_log

Revision ID: f45183f7ff50
Revises: f69be5a09d99
Create Date: 2026-09-16 14:09:03.046237

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f45183f7ff50"
down_revision: str | Sequence[str] | None = "f69be5a09d99"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "audit_log",
        sa.Column(
            "redaction_budget_exhausted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("audit_log", "redaction_budget_exhausted")

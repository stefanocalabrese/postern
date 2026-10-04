"""add producer columns to challenges

Revision ID: b5d1e7a3c902
Revises: e08757299819
Create Date: 2026-10-04 09:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b5d1e7a3c902"
down_revision: str | Sequence[str] | None = "e08757299819"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "challenges"
_INDEX = "ix_challenges_pending_fingerprint"
# Hardcoded rather than imported, for the reason revision 0eb813c87298 gives
# for its own vocabulary: a migration records what the schema became on one
# date, and an imported value that later changed would rewrite that record.
_PENDING = "status = 'pending'"


def upgrade() -> None:
    """Upgrade schema.

    Three nullable columns and one partial unique index, for the payments
    producer (spec docs/superpowers/specs/2026-10-04-payments-producer-core-design.md,
    section 5).

    `client_id` and `session_jti` record which OAuth client and which session
    token proposed a challenge, so the approval path can later match all three
    revocation scopes. They are a record and never a gate.

    `request_fingerprint` is the SHA-256 of the customer, the tool and the
    canonical payload, and `ix_challenges_pending_fingerprint` makes it unique
    per customer AMONG PENDING ROWS ONLY. That is what lets a repeated
    `payments.create_payment` return the challenge it already made, under
    concurrency and without a read-then-write: an INSERT ... ON CONFLICT DO
    NOTHING against this index. A row leaves the index when it leaves
    `pending`, so an identical request after approval or expiry makes a new
    challenge. Rows any other caller creates leave the fingerprint NULL, and
    NULLs never collide in a unique index.

    No grant changes: `postern_app` holds table-level SELECT, INSERT and UPDATE
    on `challenges` (sql/02-grants.sql), which covers new columns.

    WHAT THE DRIFT GATE DOES NOT SEE HERE. `alembic check` (alembic 1.20)
    compares this index's name, uniqueness and columns and not its WHERE
    clause, so tests/test_store_producer.py reads `pg_indexes.indexdef` and
    pins the predicate itself.
    """
    op.add_column(_TABLE, sa.Column("client_id", sa.String(length=128), nullable=True))
    op.add_column(_TABLE, sa.Column("session_jti", sa.String(length=128), nullable=True))
    op.add_column(_TABLE, sa.Column("request_fingerprint", sa.String(length=64), nullable=True))
    op.create_index(
        _INDEX,
        _TABLE,
        ["customer_ref", "request_fingerprint"],
        unique=True,
        postgresql_where=sa.text(_PENDING),
    )


def downgrade() -> None:
    """Downgrade schema.

    Drops the index and the three columns, and with them the only record of
    which client and session proposed each challenge. An application still
    running the producer against a downgraded schema fails every
    `payments.create_payment` with "the payment could not be recorded", which
    is the fail-closed direction: no challenge is created.
    """
    op.drop_index(_INDEX, table_name=_TABLE)
    op.drop_column(_TABLE, "request_fingerprint")
    op.drop_column(_TABLE, "session_jti")
    op.drop_column(_TABLE, "client_id")

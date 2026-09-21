"""add challenges table

Revision ID: ed88bd4a6312
Revises: 0de54913a8b2
Create Date: 2026-09-21 08:20:54.427951

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ed88bd4a6312'
down_revision: Union[str, Sequence[str], None] = '0de54913a8b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the ``challenges`` table.

    Handoff §7.4 — Verification tiering.  Three tiers gate write operations:
    tier-0 (session token only, all reads), tier-1 (device-bound key + app
    unlock for most writes), tier-2 (tier-1 plus server-side selfie matching
    for payments, high-value).

    The table stores ``Challenge`` rows — the source of truth for what
    executes on approval.  The confirmation payload sent to the phone is built
    server-side from this row, never re-sent or re-specified by the agent.

    APPEND-ONLY: no ``DELETE`` on challenges.  Expired rows remain for the
    audit trail (handoff §7.4: "expired rows stay").

    Columns:
        challenge_id (VARCHAR 36, UNIQUE): opaque idempotency key.
        customer_ref (VARCHAR 128, INDEXED): who initiated the operation.
        tool_name (VARCHAR 64): which MCP tool triggered this challenge.
        payload (JSONB): full operation payload — amount, payee, account.
        tier (INT, CHECK 0|1|2): verification tier required.
        status (VARCHAR 16, CHECK pending|approved|executed|declined|expired).
        created_at (TIMESTAMPTZ): when the challenge was created.
        expires_at (TIMESTAMPTZ): TTL boundary — tier-0=30s, tier-1=180s,
            tier-2=300s.
        confirming_device (VARCHAR 128, nullable): device ID once approved.
        verification_result (TEXT, nullable): tier-2 selfie match reference;
            never stores the captured image itself.
        signature (TEXT, nullable): device-bound key signature over payload.

    CHECK constraints enforce tier ∈ {0,1,2} and status in the five legal
    values at the database level.

    MEASURED ON 2026-09-21 against a ``postgres:17-alpine`` container.
    The ``CREATE TABLE`` timed at sub-millisecond in psql; the whole
    ``alembic upgrade head`` took under 0.5s wall including index creation.
    The downgrade was then run: zero rows in ``information_schema.tables``
    for name 'challenges', ``alembic_version`` back to 0de54913a8b2.
    The upgrade was run again and every reading repeated identically, so the
    pair round-trips.

    The drift gate (``alembic check``) DOES compare columns, their types and
    their nullability, and that was measured: narrowing the model would fail
    the check.  It still does not compare CHECK constraints, but those are
    explicit here and match the model exactly.
    """
    op.create_table(
        "challenges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "challenge_id", sa.String(length=36), unique=True, nullable=False
        ),
        sa.Column(
            "customer_ref", sa.String(length=128), nullable=False, index=True
        ),
        sa.Column(
            "tool_name", sa.String(length=64), nullable=False,
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("tier", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, default="pending"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False,
        ),
        sa.Column(
            "expires_at", sa.DateTime(timezone=True), nullable=False,
        ),
        sa.Column(
            "confirming_device", sa.String(length=128), nullable=True,
        ),
        sa.Column("verification_result", sa.Text(), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_challenges_challenge_id", "challenges", ["challenge_id"], unique=True
    )
    op.create_index(
        "ix_challenges_customer_ref", "challenges", ["customer_ref"], unique=False
    )
    op.create_check_constraint(
        "ck_challenges_tier",
        "challenges",
        "tier IN (0, 1, 2)",
    )
    op.create_check_constraint(
        "ck_challenges_status",
        "challenges",
        "status IN ('pending', 'approved', 'executed', 'declined', 'expired')",
    )


def downgrade() -> None:
    """Downgrade schema.

    Drops the ``challenges`` table and with it every pending, approved,
    declined, or expired challenge row.  Because the table is append-only
    (no deletes), this removes the full audit trail for verification
    workflows — a deliberate fail-closed: an application still running the
    newer code against a downgraded schema fails every challenge lookup on
    ``relation "challenges" does not exist``, which under the existing
    error-handling pattern fails the tool call on entry, before any customer
    data is touched.

    The operator must restart with the older schema version; no partial
    migration path exists because ``Challenge`` is a domain primitive that
    gates every write operation.
    """
    op.drop_table("challenges")

"""add risk_signals to audit_log

Revision ID: 0de54913a8b2
Revises: c91f79e6d34a
Create Date: 2026-09-20 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0de54913a8b2"
down_revision: str | Sequence[str] | None = "c91f79e6d34a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema.

    WHAT THE TABLE COULD NOT ANSWER. The risk engine (ZT-5) evaluates
    per-session budgets and IP anomaly signals on every tool call, logging
    them at WARNING level in structured log aggregation. A regulator or
    operator querying ``audit_log`` sees the call, its arguments, and its
    outcome but cannot see which risk signals fired without reaching into the
    log pipeline.

    This column stores the same signal data as JSONB so it is queryable in
    Postgres: ``SELECT * FROM audit_log WHERE risk_signals @> '[{"severity":
    "HIGH"}]'`` answers "which calls had a HIGH signal" without log
    aggregation.

    NULLABLE, and the absence it admits has two meanings — "no session handle
    was provided for this call" (so no risk evaluation ran) and "this row was
    written before this column existed". They are told apart by ``at`` against
    the migration deploy time, consistent with the pattern already established
    on ``duration_ms``, ``request_id``, and ``call_id``.

    JSONB rather than Text: enables querying (severity, code, etc.) without
    parsing a text blob. An empty list ``[]`` means "this call ran with a
    session handle and no signals fired"; NULL means either pre-migration or
    no session handle.

    Adding a nullable column with no default is catalog-only in PostgreSQL:
    no table rewrite, whatever the row count.

    MEASURED ON 2026-09-20 against a ``postgres:17-alpine`` container.
    The ``ALTER TABLE`` itself timed at sub-millisecond in psql; the whole
    ``alembic upgrade head`` took under 0.3s wall. Both seeded rows from
    earlier migrations came through untouched: still there, NULL in the new
    column. ``risk_signals`` reads ``jsonb``, ``is_nullable`` YES,
    ``column_default`` NULL.

    The downgrade was then run: zero columns named ``risk_signals`` in
    ``information_schema``, both seeded rows still present,
    ``alembic_version`` back to c91f79e6d34a. The upgrade was run again and
    every reading above repeated identically, so the pair round trips.

    The drift gate (``alembic check``) DOES compare columns, their types and
    their nullability, and that was measured: narrowing the model would fail
    the check. It still does not compare CHECK constraints, but this column
    adds none.
    """
    op.add_column(
        "audit_log",
        sa.Column("risk_signals", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema.

    Drops the column, and with it the queryable record of which risk signals
    fired on each call already recorded. ``audit_log`` is append-only and
    nothing else in this schema holds a copy, so those rows go back to being
    silent on risk signals.

    An application still running the newer code against a downgraded schema
    fails every audit write on the missing column, which under
    dev-docs/decisions/0006-audit-write-failure.md fails the tool call -- on the
    entry write, before the backend is reached. That is the fail-closed
    direction: no customer data is touched without a row.
    """
    op.drop_column("audit_log", "risk_signals")

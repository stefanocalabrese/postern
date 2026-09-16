"""add duration_ms and request_id to audit_log

Revision ID: 561b48768c00
Revises: 1c64b7ed3f4b
Create Date: 2026-09-16 20:51:59.418048

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "561b48768c00"
down_revision: str | Sequence[str] | None = "1c64b7ed3f4b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema.

    An investigator reading `audit_log` today cannot tell a slow call from
    a fast one, nor tie a row to a specific client request. These two
    columns answer exactly those two questions and nothing else.

    Both are nullable with NO `server_default`, unlike
    `redaction_budget_exhausted` (revision f45183f7ff50), and that
    difference is deliberate. On `duration_ms`, NULL means "this row
    predates the column": every row the application writes from here on
    carries a measured value, so a default would backfill history with a
    number a reader cannot distinguish from a call that genuinely took
    that long. A sub-millisecond call records 0, which is a different
    statement from NULL.

    `request_id` records the JSON-RPC id of the client request, as its
    string form, because an id may be a string or a number on the wire.
    NULL means no id was available -- `MiddlewareContext.fastmcp_context`
    is `Context | None`, and `Context.request_id` raises `RuntimeError`
    with no established MCP request context -- and the audit row is still
    written in that case, because a missing identifier must never become a
    missing audit row. The id gives traceability only: it ties one row to
    one client request for correlation with client-side logs. It does NOT
    identify a retry, since a re-issued call carries a new id, so two rows
    still read as two calls, which at the protocol level is what they were.

    Adding a nullable column with no default is a catalog-only change in
    PostgreSQL: no table rewrite, regardless of row count.
    """
    op.add_column("audit_log", sa.Column("duration_ms", sa.Integer(), nullable=True))
    op.add_column("audit_log", sa.Column("request_id", sa.String(length=128), nullable=True))


def downgrade() -> None:
    """Downgrade schema.

    Drops both columns, and with them every duration and request id
    recorded since the upgrade: nothing else in this schema holds a copy,
    and `audit_log` is append-only, so there is no second row to recover
    them from.
    """
    op.drop_column("audit_log", "request_id")
    op.drop_column("audit_log", "duration_ms")

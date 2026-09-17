"""add refusal_reason to audit_log

Revision ID: 0eb813c87298
Revises: 561b48768c00
Create Date: 2026-09-17 19:24:46.083092

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0eb813c87298"
down_revision: str | Sequence[str] | None = "561b48768c00"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Hardcoded, not imported from `postern_core.store.models.REFUSAL_REASONS`.
# This migration records what the schema became on the date above; importing
# a tuple that a later task widens would silently change what an
# already-applied revision claims to have created, and would make this file's
# `upgrade()` and the database it produced disagree on every machine that ran
# it before the widening.
_REASONS = ("no_customer_ref", "domain_not_consented")
_CONSTRAINT = "ck_audit_log_refusal_reason"


def upgrade() -> None:
    """Upgrade schema.

    Before this column, a consent denial and a mistyped tool name produced
    byte-identical audit rows. FastMCP returns no tool both when the name is
    unknown and when a tool's `auth=` check denies it, so both reach
    `AuditMiddleware` as one `NotFoundError` and both recorded
    `outcome='raised'`, `detail='NotFoundError'`, differing only in
    `tool_name`. An investigator could not tell a refused `cards.list` from
    a misspelled one. Measured against the running server, 2026-09-17.

    Two values, and only two, both written by
    `services/api/consent.py`'s check: `no_customer_ref` (the access token
    yielded nothing that parses as a `CustomerRef`, so there was no customer
    to look consent up for) and `domain_not_consented` (a customer
    reference was read, and the tool's domain was not among that customer's
    currently granted domains). Neither says anything about the token's
    validity or about why consent is missing.

    Nullable with NO `server_default`, like `duration_ms` and `request_id`
    (revision 561b48768c00) and unlike `redaction_budget_exhausted`
    (f45183f7ff50): NULL means the call was not refused, or the row predates
    this column. Those two are separated by `at` against this migration's
    deploy time, not by a third value -- a "not refused" string would assert
    something about pre-existing rows that nothing recorded.

    The CHECK constraint keeps the set closed in the database. Every value
    is chosen by this codebase, never by an agent, so the only way an
    unlisted string reaches an INSERT is a code change that added a reason
    without widening this constraint -- which then fails loudly on the first
    refusal instead of leaving an undocumented value in a regulator-facing
    table for every query to miss. Widening it later is one statement, which
    is why this is a `VARCHAR` plus a CHECK rather than a Postgres `ENUM`.

    Two lock notes, both about a table that only ever grows. Adding a
    nullable column with no default is catalog-only in PostgreSQL: no
    rewrite, whatever the row count. Adding the constraint is not free in
    the same way -- it takes ACCESS EXCLUSIVE and scans every existing row
    -- but each of those rows holds NULL, which the constraint admits
    (`NULL IN (...)` is NULL, and a CHECK passes unless it evaluates FALSE).
    The `NOT VALID` + `VALIDATE CONSTRAINT` pattern that avoids the scan
    needs the two statements in separate transactions to help at all, and
    Alembic runs this revision inside one, so it is not used here.

    The client-visible response is untouched by this revision. A refused
    call and an unknown name both return `Unknown tool: '<name>'`; telling
    the two apart on the wire would confirm to an agent that a tool exists
    and that this customer has the product behind it.
    """
    op.add_column("audit_log", sa.Column("refusal_reason", sa.String(length=32), nullable=True))
    op.create_check_constraint(_CONSTRAINT, "audit_log", sa.column("refusal_reason").in_(_REASONS))


def downgrade() -> None:
    """Downgrade schema.

    Drops the constraint and the column, and with them every refusal reason
    recorded since the upgrade: `audit_log` is append-only and nothing else
    in this schema holds a copy, so the rows revert to the state this
    revision exists to fix -- a denial indistinguishable from a typo.
    """
    op.drop_constraint(_CONSTRAINT, "audit_log", type_="check")
    op.drop_column("audit_log", "refusal_reason")

"""add customer_ref_absence_reason to audit_log

Revision ID: 3186c04c018c
Revises: 0eb813c87298
Create Date: 2026-09-17 19:42:21.056393

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "3186c04c018c"
down_revision: str | Sequence[str] | None = "0eb813c87298"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Hardcoded, not imported from
# `postern_core.store.models.CUSTOMER_REF_ABSENCE_REASONS`, exactly as
# revision 0eb813c87298 hardcodes its own refusal reasons. This file records
# what the schema became on the date above; importing a tuple that a later
# task widens would silently change what an already-applied revision claims
# to have created, and would make this `upgrade()` disagree with the database
# it produced on every machine that ran it before the widening.
_ABSENCE_REASONS = ("no_access_token", "no_string_subject", "subject_not_a_customer_ref")
_COLUMN = "customer_ref_absence_reason"
_VOCABULARY_CONSTRAINT = "ck_audit_log_customer_ref_absence_reason"
_XOR_CONSTRAINT = "ck_audit_log_customer_ref_xor_absence"


def upgrade() -> None:
    """Upgrade schema.

    Before this column, `audit_log.customer_ref IS NULL` meant three
    different things and `services/api/middleware/audit.py`'s `_customer_ref`
    returned the same `None` for all of them: no access token at all; a token
    whose `sub` claim was absent or not a string; and a token whose `sub` was
    a string that failed `CustomerRef` validation. The first two are ordinary
    unauthenticated traffic. The third is the compromised-issuer case
    `postern_core/identity.py` warns about -- its `_OPAQUE` pattern is a
    provenance convention, not proof of opacity, so an issuer under attacker
    control can mint a `sub` shaped like a bare PAN, IBAN or DNI, which
    `services/api/server.py`'s `token_customer_resolver` refuses on the tool
    path. Its evidence sat in this table indistinguishable from somebody
    calling without logging in. One column makes it one predicate:
    `WHERE customer_ref_absence_reason = 'subject_not_a_customer_ref'`.

    The rejected subject's VALUE is never written, here or anywhere else in
    the row. It is the PAN-, IBAN- or DNI-shaped string the middleware
    refuses to put in `customer_ref`, so storing it would be the one write
    that survives the refusal it documents, in the longest-lived table this
    system has. The column records the class of absence; recovering the value
    means asking the identity issuer's own logs.

    `VARCHAR(64)` plus a CHECK, not a Postgres `ENUM`, for the reason
    0eb813c87298 gives: widening a CHECK is one statement, while `ALTER TYPE
    ... ADD VALUE` cannot run in the same transaction that then uses the new
    value. 64 rather than `refusal_reason`'s 32 because the longest value
    here is 26 characters, and revision 1c64b7ed3f4b exists solely because
    two columns had been sized at their then-current maximum.

    Nullable with NO server default, like `refusal_reason` (0eb813c87298) and
    `duration_ms`/`request_id` (561b48768c00): NULL means `customer_ref` is
    present on that row, or the row predates this column.

    Three lock notes on a table that only ever grows. Adding a nullable
    column with no default is catalog-only in PostgreSQL: no rewrite,
    whatever the row count. The vocabulary constraint is added the ordinary
    way -- it takes ACCESS EXCLUSIVE and scans every existing row, and every
    one of them holds NULL in this brand-new column, which the constraint
    admits (`NULL IN (...)` is NULL, and a CHECK passes unless it evaluates
    FALSE). The equivalence constraint is the one that cannot be added that
    way, for the reason below.

    `NOT VALID`, and only on `ck_audit_log_customer_ref_xor_absence`: that
    constraint says every row has either a customer reference or a reason it
    has none, and every row written before this revision has NEITHER whenever
    its call had no customer. Adding it validated would scan those rows and
    fail the migration outright on any database that has ever recorded such a
    call, and no test would have caught it: every test database is built by
    `alembic upgrade head` against an empty table (tests/conftest.py).
    Measured on a container seeded with one such row before this revision ran
    -- validated, it fails; `NOT VALID`, it applies and the old row is left
    exactly as it was. `NOT VALID` skips the scan of existing rows and still
    enforces the constraint on every INSERT and UPDATE from here on, which on
    an append-only table is every row that will ever be written. The
    alternative, backfilling the old rows with a fourth value, was rejected:
    it would be the only UPDATE this append-only, regulator-facing table has
    ever taken, and it would assert a class of absence for calls where nobody
    recorded one. Those rows keep the meaning the column's comment gives
    them: NULL, because they predate it.

    The trailing cost of `NOT VALID` is that `pg_constraint.convalidated`
    stays false for this constraint. Running `ALTER TABLE audit_log VALIDATE
    CONSTRAINT ck_audit_log_customer_ref_xor_absence` later scans the whole
    table and fails on exactly those pre-migration rows, so it needs a
    decision about them first; it is not a tidy-up anyone should run blind.

    Raw SQL for that one statement because `op.create_check_constraint` has
    no `NOT VALID`, and the parentheses in it are load-bearing: in PostgreSQL
    `IS` binds looser than `=`, so the unparenthesised form parses as
    something other than a comparison of two null tests.
    """
    op.add_column("audit_log", sa.Column(_COLUMN, sa.String(length=64), nullable=True))
    op.create_check_constraint(
        _VOCABULARY_CONSTRAINT, "audit_log", sa.column(_COLUMN).in_(_ABSENCE_REASONS)
    )
    op.execute(
        f"ALTER TABLE audit_log ADD CONSTRAINT {_XOR_CONSTRAINT} "
        f"CHECK ((customer_ref IS NULL) = ({_COLUMN} IS NOT NULL)) NOT VALID"
    )


def downgrade() -> None:
    """Downgrade schema.

    Drops both constraints and the column, and with them every recorded class
    of absence: `audit_log` is append-only and nothing else in this schema
    holds a copy, so the rows revert to the state this revision exists to fix
    -- an attacker-minted subject indistinguishable from an anonymous call.

    The equivalence constraint is dropped first. It references the column,
    and PostgreSQL would drop it along with the column anyway; naming it here
    keeps the downgrade explicit about what it destroys rather than relying
    on a cascade.
    """
    op.drop_constraint(_XOR_CONSTRAINT, "audit_log", type_="check")
    op.drop_constraint(_VOCABULARY_CONSTRAINT, "audit_log", type_="check")
    op.drop_column("audit_log", _COLUMN)

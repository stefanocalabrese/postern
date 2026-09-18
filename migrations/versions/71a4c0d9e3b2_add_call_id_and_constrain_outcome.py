"""add call_id to audit_log and constrain outcome

Revision ID: 71a4c0d9e3b2
Revises: 3186c04c018c
Create Date: 2026-09-18 16:12:44.318907

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "71a4c0d9e3b2"
down_revision: str | Sequence[str] | None = "3186c04c018c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Hardcoded, not imported from `postern_core.store.models.OUTCOMES`, exactly
# as revisions 0eb813c87298 and 3186c04c018c hardcode their own vocabularies.
# This file records what the schema became on the date above; importing a
# tuple that a later task widens would silently change what an
# already-applied revision claims to have created.
_OUTCOMES = ("reaching", "returned", "raised")
_CALL_ID = "call_id"
_OUTCOME_CONSTRAINT = "ck_audit_log_outcome"
_CALL_ID_CONSTRAINT = "ck_audit_log_call_id_present"


def upgrade() -> None:
    """Upgrade schema.

    Two changes, and only the first is what the task asked for.

    `call_id` CORRELATES THE TWO ROWS ONE TOOL CALL NOW WRITES. Until this
    revision `audit_log` held one row per call, written after the tool
    returned or raised. It now holds a second one, `outcome='reaching'`,
    committed in its own transaction BEFORE any customer data is reached, so
    that a request cancelled after the backend was touched still leaves a
    durable record of the touch (`services/api/asgi/request_deadline.py`
    measured the gap that made this necessary; capo's ruling on 2026-09-18 is
    that this table records customer data the operator touched, not calls it
    served). Two rows need a key that joins them, and an UPDATE filling an
    outcome in afterwards was rejected because this table is append-only --
    `models.py`'s module docstring and every constraint on it assume that.

    `VARCHAR(36)`, the exact length of `str(uuid.uuid4())`, which is what
    `services/api/middleware/audit.py` mints per call. Text rather than
    PostgreSQL `uuid` so a reader greps the same string out of a `SELECT` and
    out of a log; the value is server-minted, so unlike `tool_name` or
    `request_id` there is no agent-controlled length to leave headroom for.

    Nullable with no server default, like `duration_ms`/`request_id`
    (561b48768c00) and `customer_ref_absence_reason` (3186c04c018c): NULL
    means the row predates this column. A column-level `NOT NULL` is what
    that rules out, since it would need a default or a backfill for the
    existing rows, and a backfill would be the only UPDATE this append-only
    table has ever taken while inventing a correlation between rows that were
    never correlated. No index: see the column's comment in `models.py` for
    what that costs and who should pay it.

    `ck_audit_log_call_id_present` IS THE SAME GUARANTEE WITHOUT THAT COST,
    and leaving it out would have made the non-absence a property of Python
    alone. `CHECK (call_id IS NOT NULL) NOT VALID` enforces on every INSERT
    from here on -- on an append-only table, every row that will ever be
    written -- while PostgreSQL skips the scan of the rows that predate the
    column and would all fail it. That is the mechanism this file already
    uses two paragraphs down for the outcome constraint's rejected
    alternative, and that 3186c04c018c used for
    `ck_audit_log_customer_ref_xor_absence`; not using it here would have
    left `audit.append`'s required parameter as the only thing standing
    between this table and an unpairable row.

    Its trailing cost is 3186c04c018c's, unchanged: `convalidated` stays
    false, and `VALIDATE CONSTRAINT` later scans the table and fails on
    exactly the pre-migration rows, so it needs a decision about them first.

    `ck_audit_log_outcome` IS THE SECOND CHANGE AND IS NOT REQUIRED BY THE
    FIRST. `outcome` has existed since f69be5a09d99 with no constraint, while
    `refusal_reason` (0eb813c87298) and `customer_ref_absence_reason`
    (3186c04c018c) were each constrained by the revision that added them. So
    the oldest closed vocabulary in this table was the only unenforced one,
    and adding a third value to it -- which this revision's own reason for
    existing does -- is precisely the change that makes an unenforced
    vocabulary expensive: a fourth value misspelled into that column needs no
    migration, no review, and shows up as rows that every query filtering on
    the documented values silently misses.

    Added VALIDATED, the ordinary way, unlike this table's one `NOT VALID`
    constraint. The reasoning there (3186c04c018c) was that pre-existing rows
    genuinely violate the new rule. These do not: `audit.append` is the only
    writer of this column anywhere in this repository and its two call sites
    in `AuditMiddleware.on_call_tool` have only ever passed the literals
    'returned' and 'raised'. That is a claim about this repository's history,
    not something this migration verifies -- and the verification is exactly
    what a validated constraint does. If some row does hold a fourth value,
    this statement fails, the enclosing transaction rolls back the column
    with it, and the migration stops with the table untouched, which is the
    loud outcome rather than the silent one.

    Measured on 2026-09-18 against a `postgres:17-alpine` container, five
    ways. Applied to a clean database, `pg_constraint.convalidated` reads
    true for `ck_audit_log_outcome` and false for
    `ck_audit_log_call_id_present`, which is the asymmetry the two paragraphs
    above describe. An INSERT with no `call_id` is then REJECTED naming
    `ck_audit_log_call_id_present`, and the same INSERT carrying one
    succeeds, so the `NOT VALID` constraint does enforce on new rows rather
    than merely existing. Seeded with pre-existing rows carrying NULL
    `call_id`, the revision applies and leaves them exactly as they are,
    unscanned and un-backfilled. Seeded with one `outcome='invented'` row,
    the upgrade fails with `CheckViolationError`, `call_id` is NOT on the
    table afterwards, and `alembic_version` still reads `3186c04c018c`. The
    downgrade and a second upgrade were run over the same database
    throughout, so the pair round trips.

    The cost is the scan: `ALTER TABLE ... ADD CONSTRAINT` takes ACCESS
    EXCLUSIVE and reads every existing row, on a table that only ever grows
    and whose size this migration does not know. Accepted for the same reason
    3186c04c018c accepted it for its own vocabulary constraint, with the
    difference stated plainly: there, the scan touched a column that was NULL
    on every row and could not fail; here it reads a populated column and is
    doing real work.

    Adding the nullable column itself is catalog-only in PostgreSQL -- no
    rewrite, whatever the row count -- so the column is not what makes this
    migration take a lock worth planning around.
    """
    op.add_column("audit_log", sa.Column(_CALL_ID, sa.String(length=36), nullable=True))
    op.create_check_constraint(
        _OUTCOME_CONSTRAINT, "audit_log", sa.column("outcome").in_(_OUTCOMES)
    )
    # Raw SQL because `op.create_check_constraint` has no `NOT VALID`, the
    # same reason 3186c04c018c drops to `op.execute` for its own.
    op.execute(
        f"ALTER TABLE audit_log ADD CONSTRAINT {_CALL_ID_CONSTRAINT} "
        f"CHECK ({_CALL_ID} IS NOT NULL) NOT VALID"
    )


def downgrade() -> None:
    """Downgrade schema.

    Drops the constraint and the column, and with the column every pairing
    between an entry row and its completion row: `audit_log` is append-only
    and nothing else in this schema holds a copy, so the rows survive as an
    unjoinable mixture of the two shapes, distinguishable only by `outcome`.

    The outcome constraint is named here rather than left to the column drop
    to remove, because it constrains `outcome` and not `call_id`: nothing
    would cascade it away, and leaving it in place would keep rejecting the
    'reaching' rows that an application still running this version writes.
    `ck_audit_log_call_id_present` WOULD cascade with its column, and is
    dropped explicitly anyway, for the reason 3186c04c018c gives about its
    own pair: a downgrade should say what it destroys rather than rely on
    PostgreSQL to work it out.
    """
    op.drop_constraint(_CALL_ID_CONSTRAINT, "audit_log", type_="check")
    op.drop_constraint(_OUTCOME_CONSTRAINT, "audit_log", type_="check")
    op.drop_column("audit_log", _CALL_ID)

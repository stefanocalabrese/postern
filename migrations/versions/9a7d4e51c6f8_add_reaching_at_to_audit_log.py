"""add reaching_at to audit_log

Revision ID: 9a7d4e51c6f8
Revises: 71a4c0d9e3b2
Create Date: 2026-09-18 19:41:07.220914

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9a7d4e51c6f8"
down_revision: str | Sequence[str] | None = "71a4c0d9e3b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Hardcoded, not imported from `postern_core.store.models.OUTCOME_REACHING`,
# exactly as 0eb813c87298, 3186c04c018c and 71a4c0d9e3b2 hardcode their own
# vocabularies: this file records what the schema became on the date above,
# and importing a name a later task can redefine would silently change what
# an already-applied revision claims to have created.
_REACHING = "reaching"
_REACHING_AT = "reaching_at"
_CONSTRAINT = "ck_audit_log_reaching_at_matches_outcome"


def upgrade() -> None:
    """Upgrade schema.

    WHAT THE TABLE COULD NOT ANSWER. `audit_log.at` is the instant the tool
    CALL ARRIVED, and 71a4c0d9e3b2's entry row inherited it: both rows of one
    call carry the same `at`, written from one `context.timestamp` reading.
    So a table whose stated job is to record the customer data the operator
    touched could say a touch happened and could not say WHEN -- everything
    between arrival and the first backend request (the consent lookup, the
    tool body's own work) sits inside a gap bounded by
    `Settings.request_deadline_seconds` and by nothing in this table.

    `reaching_at` is that instant: read immediately before the entry row's
    own INSERT, so it precedes the request it describes by the INSERT, the
    commit and the session exit. It errs EARLY, which is the direction
    `outcome='reaching'` already commits that row shape to (see
    `OUTCOME_REACHING` in `models.py`).

    THE NO-MIGRATION ALTERNATIVE WAS REAL AND WAS REJECTED. Redefining `at`
    on a `reaching` row to mean the touch needs no schema change at all.
    `at` is `NOT NULL`, though, and every dated boundary this table carries
    is a NULL: `duration_ms` and `request_id` (561b48768c00),
    `customer_ref_absence_reason` (3186c04c018c) and `call_id`
    (71a4c0d9e3b2) all read "NULL means the row predates this column". `at`
    offers no such NULL, and `call_id` cannot date it either, since the entry
    row and `call_id` arrived in the same commit. Two rows written under the
    two meanings would be identical bytes on an append-only,
    regulator-facing table. A new column keeps `at` saying one thing.

    THE DECIDING ARGUMENT IS NOT THAT AMBIGUITY, THOUGH, because it is about
    rows written either side of one afternoon's migration. This one is about
    a row shape that already exists and is already measured: a request
    CANCELLED after the touch. `tests/test_request_deadline.py` pins it --
    entry row committed, deadline fires, no completion row ever written --
    and it is the shape the entry row was added for. Arrival would then live
    only on the completion row that never gets written, so redefining the
    entry row's `at` to mean the touch does not move the arrival instant
    somewhere else, it deletes it, on exactly the calls where something went
    wrong and an investigator needs both instants. A separate column keeps
    both facts on the one row that is guaranteed to exist.

    THE BOUNDARY THIS COLUMN CREATES IS NOT EMPTY, though the population
    defined narrowly is, and the difference is the useful part. A `reaching`
    row with NULL `reaching_at` is one written before 9a7d4e51c6f8 was
    APPLIED to its database. That is a schema boundary and not a commit one:
    a row is pre-column because this revision had not run where it was
    written, whatever the source tree said at the time. The application
    could only have written such a row between 71a4c0d9e3b2, which is when
    entry rows began to exist at all, and this revision, and no row from
    that window is known to have been persisted anywhere.

    A HAND-SEEDED ONE HAS BEEN, on this very machine, and finding it is what
    killed the durability argument that first stood in this paragraph.
    `docker compose down` removes anonymous volumes ONLY with `-v` (docker's
    own `--help`: `-v` removes named volumes "AND anonymous volumes attached
    to containers"), so the PGDATA volume a postgres container declares
    outlives the container by default, and `docker-compose.yml` having no
    `volumes:` key for `db` buys nothing. They also pile up unnoticed, so
    there is no reason to expect anyone to have looked. One of them, created
    at 11:43 on 2026-09-18, holds a `postern` database at
    `alembic_version = 3186c04c018c` with four `audit_log` rows, one of them
    `outcome='reaching'` and one `outcome='invented'`. It is the leftover
    PGDATA of 71a4c0d9e3b2's own verification run. Read by copying the
    volume and starting Postgres on the copy, with the original mounted
    read-only and left untouched.

    So the row this revision's `NOT VALID` exists for is on a disk today,
    one DELETE and one `alembic upgrade head` from existing, in that order.
    The DELETE is not optional: the `outcome='invented'` row sitting beside
    the `reaching` one violates 71a4c0d9e3b2's VALIDATED
    `ck_audit_log_outcome`, so an upgrade run against that database today
    fails a revision short of this one and changes nothing. Remove that row
    and the upgrade proceeds, the database being pre-column means its
    `reaching` row acquires a NULL `reaching_at` as the column is added, and
    that row is then exactly what a later `VALIDATE CONSTRAINT` on this
    constraint fails on.

    What the check covered: this repository and this machine, on 2026-09-18.
    It cannot speak for a database someone ran these migrations against
    elsewhere. None of it is a claim about what can occur; it is a claim
    about what was persisted where it could be looked at.

    `ck_audit_log_reaching_at_matches_outcome` IS WHAT MAKES THE COLUMN
    TRUSTWORTHY, and it enforces both halves. Without the first
    (`reaching` implies present) a future writer could file an entry row that
    cannot answer the question this column was added for, exactly the way
    `call_id`'s non-absence was a property of one function's type hints until
    71a4c0d9e3b2. Without the second (present implies `reaching`) the same
    fact could be stamped on the completion row too, where it would be a
    second copy free to disagree with the first.

    `NOT VALID`, like `ck_audit_log_call_id_present` and
    `ck_audit_log_customer_ref_xor_absence`: every row written before this
    revision has NULL here, so the `reaching` ones among them violate the
    constraint, and whether a given database holds any is not something a
    migration can find out about a database it has not seen -- the boundary
    paragraph above is where that question is answered, for the one database
    it was possible to look at. PostgreSQL therefore skips the scan of
    existing rows and still enforces on every INSERT from here on, which on
    an append-only table is every row that will ever be written. The
    trailing cost is 3186c04c018c's, unchanged: `pg_constraint.convalidated`
    stays false, and running `VALIDATE CONSTRAINT` later scans the table and
    fails on exactly those rows, so it needs a decision about them first.

    Adding the nullable column is catalog-only in PostgreSQL -- no rewrite,
    whatever the row count -- and `ADD CONSTRAINT ... NOT VALID` takes a
    brief ACCESS EXCLUSIVE lock without reading a row, so unlike
    71a4c0d9e3b2 (whose validated `ck_audit_log_outcome` scans the whole
    table) this revision has no scan to plan around.

    Measured on 2026-09-18 against a `postgres:17-alpine` container,
    deliberately NOT against a clean database: the schema was taken to
    71a4c0d9e3b2 first, one `outcome='reaching'` row was written under it,
    and this revision was applied over that row -- the exact population the
    `NOT VALID` choice exists for. It applied, and left that row untouched:
    still there, still `reaching`, NULL in the new column, un-backfilled.
    `reaching_at` reads `timestamp with time zone`, `is_nullable` YES, and
    `pg_constraint.convalidated` is false for this constraint (true for
    `ck_audit_log_outcome`, `ck_audit_log_refusal_reason` and
    `ck_audit_log_customer_ref_absence_reason`, false for
    `ck_audit_log_call_id_present` and `ck_audit_log_customer_ref_xor
    _absence`, which is the asymmetry those revisions describe).

    Enforcement on NEW rows was then measured in all four shapes:
    `outcome='reaching'` with no `reaching_at` is rejected with
    `CheckViolationError` naming `ck_audit_log_reaching_at_matches_outcome`;
    `outcome='returned'` carrying one is rejected the same way; and
    `reaching` with an instant and `returned` without one both succeed. The
    downgrade was then run (column gone, constraint gone, the seeded row
    still there) and the upgrade again, and every reading above repeated
    identically, so the pair round trips.

    WHAT THE DRIFT GATE DOES NOT COVER, stated because the green result
    invites the opposite reading. `make migrations` (`alembic check`) answers
    "No new upgrade operations detected" for this revision, and that says
    nothing about the constraint: autogenerate does not compare CHECK
    constraints. Measured 2026-09-18 by inverting the expression in
    `models.py` to `(outcome = 'reaching') = (reaching_at IS NULL)`, the
    opposite of what this file creates, and running the check again -- still
    "No new upgrade operations detected". The two texts are equivalent here;
    nothing automated establishes that, and a future edit to either one is
    unguarded.
    """
    op.add_column("audit_log", sa.Column(_REACHING_AT, sa.DateTime(timezone=True), nullable=True))
    # Raw SQL because `op.create_check_constraint` has no `NOT VALID`, the
    # same reason 3186c04c018c and 71a4c0d9e3b2 drop to `op.execute` for
    # theirs.
    op.execute(
        f"ALTER TABLE audit_log ADD CONSTRAINT {_CONSTRAINT} "
        f"CHECK ((outcome = '{_REACHING}') = ({_REACHING_AT} IS NOT NULL)) NOT VALID"
    )


def downgrade() -> None:
    """Downgrade schema.

    Drops the constraint and the column, and with the column the only record
    of when the operator reached the backend on every call already recorded:
    `audit_log` is append-only and nothing else in this schema holds a copy,
    so those rows go back to saying that a touch happened and not when.

    The constraint WOULD cascade with its column and is dropped explicitly
    anyway, for the reason 71a4c0d9e3b2 gives about its own: a downgrade
    should say what it destroys rather than rely on PostgreSQL to work it
    out.

    An application still running the newer code against a downgraded schema
    fails every entry write on the missing column, which under
    docs/decisions/0006-audit-write-failure.md fails the call before the
    backend is reached. That is the same shape 71a4c0d9e3b2's downgrade
    leaves for `call_id`, and it is the fail-closed direction: no customer
    data is touched without a row.
    """
    op.drop_constraint(_CONSTRAINT, "audit_log", type_="check")
    op.drop_column("audit_log", _REACHING_AT)

"""make audit_log append only in the database

Revision ID: f1860c110112
Revises: ed88bd4a6312
Create Date: 2026-09-24 19:04:53.403653

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f1860c110112"
down_revision: str | Sequence[str] | None = "ed88bd4a6312"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Hardcoded rather than imported from `postern_core.store.models`, exactly as
# 0eb813c87298, 3186c04c018c, 71a4c0d9e3b2 and 9a7d4e51c6f8 hardcode their
# own vocabularies: this file records what the schema became on the date
# above, and a name a later task can redefine would silently change what an
# already-applied revision claims to have created.
_TABLE = "audit_log"
_FUNCTION = "audit_log_append_only"
_ROW_TRIGGER = "audit_log_append_only_row"
_TRUNCATE_TRIGGER = "audit_log_append_only_truncate"

# `42501` is `insufficient_privilege`. Chosen over a bare `raise_exception`
# (`P0001`) so a client library that classifies by SQLSTATE reads this as the
# denial it is rather than as an application error, and so it matches the
# SQLSTATE a non-owner role gets from the `REVOKE` below for the same
# statement -- one code for one refusal, whichever half produced it.
_ERRCODE = "42501"

# Local to this migration's transaction, never `ALTER DATABASE`: no migration
# in this repo sets `lock_timeout`, and that gap is a separate audited
# finding which is not this revision's to close. `SET LOCAL` reverts at
# COMMIT, so nothing here changes what the eleven revisions before it run
# under.
#
# 3 seconds, matching `postern_core.store.engine.Database`'s
# `command_timeout_seconds` default, which is already the bound on how long
# anything in this system waits on Postgres.
_LOCK_TIMEOUT = "3s"


def upgrade() -> None:
    """Upgrade schema.

    WHAT THIS DOES AND DOES NOT DO, stated before anything else because the
    short version of it is wrong. This does NOT make `audit_log` append-only.
    What it does: a plain `UPDATE`, `DELETE` or `TRUNCATE` on this table now
    fails for every role including the one this repo actually runs as, and
    the record remains erasable in TWO statements by anyone holding table
    ownership or superuser. Both bypasses are named at the bottom of this
    docstring and both are measured by
    `tests/test_audit_append_only.py`, so the limit is a gate rather than a
    caveat.

    WHY A TRIGGER AND NOT A `REVOKE`. `packages/postern-core/src/postern_core/store/models.py`
    states append-only as a property of this table and
    `packages/postern-core/src/postern_core/store/audit.py` exposes no update
    and no delete helper, but until this revision no `REVOKE`, trigger, rule
    or row-level security existed in any of the eleven migrations. The
    application role therefore held full DML, so any SQL injection or RCE in
    either service could erase the regulator-facing record of exactly the
    calls the attacker made, leaving an `id` sequence gap indistinguishable
    from a rolled-back INSERT.

    A `REVOKE` does not close that, and the reason is measured rather than
    recalled (postgres:17-alpine, 2026-09-24, the same image
    `tests/conftest.py::pg_url` starts). This repo has exactly one database
    role -- the URL in `POSTERN_DATABASE_URL`, which is the table owner, the
    role migrations run as, AND a superuser in every environment that exists
    (`tests/conftest.py`'s testcontainers user, `docker-compose.yml`'s
    `POSTGRES_USER: postern`). Against a superuser owner,
    `REVOKE UPDATE, DELETE, TRUNCATE` ran and the very next `UPDATE` still
    reported `UPDATE 1`: a superuser bypasses the ACL entirely, so the
    statement is a no-op. Against a NON-superuser owner the same `REVOKE`
    does bind -- `ERROR: permission denied for table` -- for exactly one
    statement, because that owner re-grants to itself and the next `UPDATE`
    reports `UPDATE 1`.

    A trigger binds where the `REVOKE` does not. Measured on the same
    database, with the triggers below installed and connected as the
    superuser owner: `UPDATE`, `DELETE` and `TRUNCATE` each raised, and
    `INSERT` reported `INSERT 0 1`.

    ROW-LEVEL SECURITY WAS REJECTED, and not for the usual reasons. With
    `FORCE ROW LEVEL SECURITY` and no `UPDATE`/`DELETE` policy those
    statements match zero rows and RETURN SUCCESS. A silent `DELETE 0` on a
    regulator-facing table is worse than an error: it tells the attacker
    nothing and it tells the operator nothing. A rule
    (`DO INSTEAD NOTHING`) has the same silent shape. Both fail the one
    requirement that matters here, which is that the statement must fail.

    AN EVENT TRIGGER WAS ALSO REJECTED. `ddl_command_start` on `ALTER TABLE`
    would block the first bypass below, but creating one needs superuser --
    so the migration would fail on precisely the deployment that did the
    right thing and made the migration role a non-superuser -- and a
    superuser drops it in one statement anyway. It buys nothing against the
    role it would have to be created by.

    WHY THE `REVOKE` IS HERE ANYWAY, AND WHAT IT IS WORTH. It is DECORATIVE
    against today's single superuser role -- the measurement two paragraphs
    up is what "decorative" means here, not a hedge -- and it is kept for two
    narrower reasons. `FROM PUBLIC` covers a database where someone has
    already run `GRANT ALL ... TO PUBLIC`, which no privilege this repo
    grants would otherwise undo. `FROM CURRENT_USER` is the one-statement
    speed bump against a non-superuser owner. Neither is what protects the
    table today. It becomes the real control only under operator checklist
    item 11 in `CLAUDE.md`, where the application connects as a role that
    does not own this table: measured against such a role, `INSERT` and
    `SELECT` succeed while `UPDATE`, `DELETE` and `TRUNCATE` are refused,
    and that role additionally cannot disable the triggers, cannot drop
    them, cannot drop the table and cannot set `session_replication_role`.

    A ZERO-ROW `DELETE` STILL SUCCEEDS. Measured: `DELETE FROM audit_log
    WHERE id = -1` reports `DELETE 0` with the row trigger installed,
    because a `FOR EACH ROW` trigger fires per row and there is no row. So
    this is a WALL, NOT A TRIPWIRE -- nothing here detects an attempt that
    matched nothing, and nothing here records an attempt that matched
    something either, since the raise aborts the transaction it would have
    been recorded in. Anyone reading this as tamper DETECTION will be wrong.

    THE TRUNCATE TRIGGER IS NOT REDUNDANT. A `FOR EACH ROW` trigger does not
    fire on `TRUNCATE` at all, so a row trigger alone would leave the whole
    table erasable by one word. It has to be a separate `FOR EACH STATEMENT`
    trigger, which is why there are two below and not one.

    LOCKING, measured on the same database rather than assumed, because the
    obvious reading of it is wrong in both directions. `CREATE TRIGGER` takes
    `ShareRowExclusiveLock` (read out of `pg_locks` during the statement),
    which does NOT conflict with `AccessShareLock` -- against a live reader
    holding one, both `CREATE TRIGGER` and the `REVOKE` completed without
    waiting. `REVOKE` takes no relation-level lock at all: `pg_locks`
    returned zero rows for this table during it. So nothing here queues
    behind a long reader.

    What it DOES queue behind is an in-flight WRITER, which is the shape that
    matters because this table is written on every tool call.
    `ShareRowExclusiveLock` conflicts with the `RowExclusiveLock` an
    uncommitted `INSERT` holds: against one, `CREATE TRIGGER` at
    `lock_timeout = '3s'` failed at 3.039s with `canceling statement due to
    lock timeout`. And while it waits it is itself blocking: a fresh
    ordinary `INSERT` arriving behind the waiting `CREATE TRIGGER` failed at
    2.057s at its own `lock_timeout = '2s'`. Under
    `dev-docs/decisions/0006-audit-write-failure.md` every one of those
    blocked inserts fails its tool call, so the cost of running this
    migration against a live system is up to `_LOCK_TIMEOUT` of calls
    failing closed. That is the reason the timeout is set at all: without
    it the default is to wait forever, and the collateral is unbounded
    rather than 3 seconds. A migration that gives up is re-runnable; a
    migration that parks the audit path is an outage.
    """
    op.execute(f"SET LOCAL lock_timeout = '{_LOCK_TIMEOUT}'")
    # `RETURN` is unreachable and still written: a plpgsql trigger function
    # must be declared to return `trigger`, and a body that can only raise
    # reads to some linters as a missing return path.
    op.execute(
        f"""
        CREATE FUNCTION {_FUNCTION}() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION
                '{_TABLE} is append-only: % is not permitted on this table', TG_OP
                USING ERRCODE = '{_ERRCODE}';
            RETURN NULL;
        END;
        $$
        """
    )
    op.execute(
        f"CREATE TRIGGER {_ROW_TRIGGER} BEFORE UPDATE OR DELETE ON {_TABLE} "
        f"FOR EACH ROW EXECUTE FUNCTION {_FUNCTION}()"
    )
    op.execute(
        f"CREATE TRIGGER {_TRUNCATE_TRIGGER} BEFORE TRUNCATE ON {_TABLE} "
        f"FOR EACH STATEMENT EXECUTE FUNCTION {_FUNCTION}()"
    )
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {_TABLE} FROM PUBLIC")
    op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {_TABLE} FROM CURRENT_USER")


def downgrade() -> None:
    """Downgrade schema.

    Restores full DML on `audit_log` for the owner, which is the hole this
    revision exists to close: after this runs, any SQL injection or RCE in
    either service can erase the rows recording the calls it made.

    The triggers are dropped explicitly rather than left to cascade with the
    function, for the reason 71a4c0d9e3b2 and 9a7d4e51c6f8 give about their
    own constraints: a downgrade should say what it destroys rather than rely
    on PostgreSQL to work it out.

    THE `GRANT` IS DELIBERATELY NARROWER THAN THE `REVOKE` IT REVERSES.
    `upgrade` revokes from `PUBLIC` and from `CURRENT_USER`; this grants back
    to `CURRENT_USER` only. Granting `UPDATE, DELETE, TRUNCATE` to `PUBLIC`
    would not restore the prior state, it would invent a wider one --
    `PUBLIC` never held those privileges on this table, since nothing in the
    eleven revisions before this one granted them. A downgrade that leaves
    the database more permissive than it found it is a worse defect than the
    one being reverted.

    No `lock_timeout` is set here, unlike `upgrade`. `DROP TRIGGER` takes
    `AccessExclusiveLock`, which conflicts with readers as well as writers,
    so this direction is strictly more disruptive than the one that has a
    timeout -- and that is the argument for running it deliberately and
    watching it, not for bounding it and retrying. Add one by hand if this is
    ever run against a live system.
    """
    op.execute(f"DROP TRIGGER {_TRUNCATE_TRIGGER} ON {_TABLE}")
    op.execute(f"DROP TRIGGER {_ROW_TRIGGER} ON {_TABLE}")
    op.execute(f"DROP FUNCTION {_FUNCTION}()")
    op.execute(f"GRANT UPDATE, DELETE, TRUNCATE ON {_TABLE} TO CURRENT_USER")

# 0019. The application connects as a role that owns nothing

Date: 29 September 2026

## Status

Accepted.

## Context

Migration `f1860c110112` makes `UPDATE`, `DELETE` and `TRUNCATE` on `audit_log`
raise. **A trigger is only as strong as the privileges of whoever can turn it
off**, and until today one role in every environment here was simultaneously the
table owner, the role migrations ran as, and a superuser. Against it the control
was two statements from being off, and `tests/test_audit_append_only.py`
performed both rather than describing them. Operator checklist item 11 asked
every operator to split that role, and nothing checked whether anyone had.

## Decision

Three roles. A bootstrap superuser that creates the other two; `postern_owner`,
which owns every table and runs `alembic upgrade`; and `postern_app`, which owns
nothing, is not a superuser, and holds exactly `SELECT, INSERT` on `audit_log`,
`SELECT` on `consents`, `SELECT, INSERT, UPDATE` on `challenges`, `USAGE` on two
sequences and on schema `public`, and `CONNECT`. Both services connect as
`postern_app`. No new environment variable -- the split is three values of one.

The grants live in two SQL scripts, `sql/01-roles.sql` (superuser, before
migrations) and `sql/02-grants.sql` (owner, after every migration), which
`docker-compose.yml` runs and which `tests/conftest.py` reads off disk and
executes. What the suite measures and what the stack applies cannot drift.

The grant set is derived from the three store modules, not listed. Two
derivations worth keeping: `SELECT` on `audit_log` is load-bearing on the write
path, because the ORM emits `INSERT ... RETURNING id` and record 0006 makes a
failed audit write a failed tool call; and nothing in either service reads
`alembic_version` or writes a `consents` row, so the role holds neither.

## Alternatives rejected

**A migration.** A role is cluster-wide and a migration is per-database; the
revision has no honest downgrade; and a `GRANT ... TO postern_app` inside one
makes the whole chain refuse to apply anywhere that role does not exist --
every database an operator has today, and every disposable test container.

**Compose only.** That is the state this record replaces.

**`ALTER DEFAULT PRIVILEGES`.** It would grant a future table the same set
silently, which is wrong in both directions. The set is explicit, and
`test_every_mapped_table_has_a_privilege_decision` fails the build when a new
table has no decision.

## Consequences

**The owner bypass costs three statements now, not two.** `f1860c110112`'s
`REVOKE ... FROM CURRENT_USER` was decorative while `CURRENT_USER` was a
superuser; it is `postern_owner` now, so the owner must grant the privilege back
to itself before disabling the trigger. That migration's docstring predicted
this; a test is where it stops being a prediction.

**`GRANT DELETE ON audit_log TO CURRENT_USER` issued by `postern_app` succeeds
and grants nothing.** PostgreSQL answers a grant-option-less GRANT with a
warning and a success tag. Found by probing the running container. A probe that
only watched for exceptions would have recorded it as a bypass that worked.

`sql/02-grants.sql` must be re-run after any migration that adds a table.
Forgetting it leaves that table reachable by nobody, which fails at the first
query rather than quietly.

**This is an integrity control, not a confidentiality one.** `postern_app`
still reads every row of all three tables, unscoped by customer, and still
appends arbitrary rows to `audit_log` -- it must, or every tool call fails. And
there is still no detection: a `DELETE` matching no row succeeds silently, a
refused one records nothing. It is a wall, not a tripwire.

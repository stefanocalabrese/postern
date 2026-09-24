"""The one deliberate bypass of `audit_log`'s append-only triggers, for test cleanup.

THIS IS NOT A UTILITY. Migration `f1860c110112` installs two triggers that
make `UPDATE`, `DELETE` and `TRUNCATE` on `audit_log` raise, for every role
including the one this suite connects as. Twelve sites across eleven test
modules delete from that table between tests, because `AuditMiddleware`
commits through its own sessionmaker and its rows survive the `session`
fixture's rollback (see `tests/conftest.py::audit_server`, which explains
the measurement that made those clears necessary). Every one of those sites
routes through the single function below, so the suite's use of the bypass
is one greppable name rather than twelve inline `DISABLE TRIGGER`s.

WHY A BYPASS AND NOT AN ESCAPE HATCH IN THE TRIGGER. The obvious
alternative is a guard in the trigger function itself -- `IF
current_setting('postern.audit_maintenance', true) = 'on' THEN RETURN ...`
-- so tests set a GUC and production does not. That was rejected: the guard
would exist in production too, and any SQL injection that can reach a `SET`
defeats the whole control with one extra statement. The bypass used here
instead requires a privilege the production application role must not have,
which means it cannot be reached by an attacker who has only that role.

WHICH BYPASS, AND WHY NOT THE OTHER ONE. Migration `f1860c110112`'s
docstring names two, both measured against postgres:17-alpine on
2026-09-24: `ALTER TABLE audit_log DISABLE TRIGGER ...`, which needs table
ownership, and `SET session_replication_role = replica`, which needs
superuser. This suite's role is both, so either would work. The GUC is used
for two reasons that are about the test suite and not about security:

1. `SET LOCAL` reverts at `COMMIT` or `ROLLBACK`, so Postgres guarantees the
   triggers are armed again after this returns. The `ALTER` form has to be
   undone by a second statement, and a `DELETE` that raises in between
   leaves the transaction in a failed state where that second statement
   cannot run -- recoverable only by the rollback, which is to say by the
   thing that was supposed to be the backstop rather than the mechanism.

2. `ALTER TABLE` takes `AccessExclusiveLock`, which conflicts with readers.
   `tests/conftest.py`'s `session` fixture holds an open connection with an
   uncommitted transaction for the whole of every test that uses it, and a
   teardown running the `ALTER` on a second connection while that one still
   holds `AccessShareLock` on `audit_log` would block until the engine's
   3-second `command_timeout` fired. `SET` takes no relation lock at all.

Neither reason weakens what the bypass demonstrates. What it demonstrates is
pinned independently by `tests/test_audit_append_only.py`, which connects as
a real non-owner, non-superuser role and measures that BOTH bypasses are out
of its reach.
"""

from __future__ import annotations

from postern_core.store.models import AuditEntry
from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

# `replica` suppresses `ORIGIN`- and `LOCAL`-scoped user triggers for the
# duration of the transaction. `audit_log` carries no foreign keys, so the
# only triggers this reaches are the two that migration f1860c110112
# installs.
_DISARM = text("SET LOCAL session_replication_role = replica")


async def delete_audit_rows_by_bypassing_the_append_only_triggers(
    session: AsyncSession, *where: ColumnElement[bool]
) -> None:
    """Delete `audit_log` rows the triggers would otherwise refuse.

    The caller owns the transaction and must `commit()` (or roll back)
    afterwards, exactly as it did when these sites called `delete()`
    directly. Both statements land in that one transaction, so the disarm
    cannot outlive it: `SET LOCAL` is scoped to the transaction whatever
    ends it, including an exception on the `DELETE` itself.

    `where` narrows the delete the way the call sites already did -- several
    of them scope to their own module's customer references because
    `database` is session-scoped and shared. With no arguments this empties
    the table.
    """
    await session.execute(_DISARM)
    await session.execute(delete(AuditEntry).where(*where))

"""What the application role may do, and what the whole application needs.

OPERATOR CHECKLIST ITEM 11 SPLITS ONE ROLE IN TWO, and this file is the half
that says the split does not break anything. `tests/test_audit_append_only.py`
is the other half: it measures what the split BUYS -- the erasing statements
refused at the ACL check, both bypasses out of reach. Neither file is worth
much without the other, because a role that cannot be tampered with and
cannot serve a request is not a control, it is an outage.

THE GRANT SET IS DERIVED, NOT COPIED FROM THE CHECKLIST. Item 11 names
``SELECT, INSERT`` on ``audit_log`` and ``USAGE`` on its sequence, which is
the whole of what the audit control needs and about half of what the
application does. The rest comes from the three modules that issue every
statement either service sends:

- `packages/postern-core/src/postern_core/store/audit.py`'s ``append``
  constructs an ``AuditEntry`` and hands it to ``session.add``, so
  ``audit_log`` takes INSERT. The ORM emits ``INSERT ... RETURNING id`` for a
  server-generated primary key, and RETURNING reads a column, so the same
  statement also needs SELECT. That is the one grant in this set that looks
  redundant and is not, so it is measured rather than asserted, by the test
  named for it below.
- `packages/postern-core/src/postern_core/store/consents.py`'s
  ``granted_domains`` is the only statement any service sends to ``consents``
  and it is a ``SELECT``. Nothing in either service writes a consent row --
  granting consent belongs to a flow this repository has not built -- so that
  table takes SELECT and its sequence takes nothing.
- `packages/postern-core/src/postern_core/store/challenges.py` inserts
  (``create_challenge``; ``create_pending_challenge_once``, an ``INSERT ... ON
  CONFLICT ... RETURNING``), reads (``get_challenge``,
  ``list_customer_challenges``) and transitions (``update_challenge_status``
  and ``expire_stale_pending``, each an ``UPDATE ... RETURNING``). So
  ``challenges`` takes SELECT, INSERT and UPDATE, and its sequence takes USAGE.
  It takes no DELETE: there is no delete helper and no caller that wants one,
  and an expired challenge is transitioned rather than
  removed.

``alembic_version`` takes NOTHING, which contradicts a reasonable guess and is
worth stating for that reason. No module under ``services/`` or
``postern_core`` reads that table -- the schema version is the migration
runner's business, and the migration runner connects as the owner.

NO ``SELECT ... FOR UPDATE`` ANYWHERE, checked rather than assumed, and it
matters more than its size: that locking clause requires the UPDATE privilege
as well as SELECT, so one appearance of it against ``audit_log`` would force a
grant that voids the whole control. There is none in the tree today, and
``test_no_module_takes_a_row_lock_on_a_table_this_role_cannot_update`` is what
keeps that true.
"""

from __future__ import annotations

import ast
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from postern_core.identity import CustomerRef
from postern_core.store import audit, challenges, consents
from postern_core.store.base import Base
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ChallengeRecord
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

#: This module's own customer reference, so nothing it writes collides with
#: another file's rows in the session-scoped container.
CUSTOMER = "cust_approle"

#: Every table the application role may touch, and the exact privilege set on
#: each. Compared against what PostgreSQL reports, so an extra grant in
#: `sql/02-grants.sql` fails here as loudly as a missing one.
EXPECTED_TABLE_PRIVILEGES: dict[str, frozenset[str]] = {
    "audit_log": frozenset({"SELECT", "INSERT"}),
    "consents": frozenset({"SELECT"}),
    "challenges": frozenset({"SELECT", "INSERT", "UPDATE"}),
    "alembic_version": frozenset(),
}

#: Every privilege PostgreSQL can hold on a table, so the comparison above is
#: over the whole space rather than over the ones this file remembered.
ALL_TABLE_PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)


async def _append_probe(db: Database, tool_name: str) -> None:
    """One audit row through the production append path.

    `postern_core.store.audit`'s ``append`` rather than a hand-written INSERT:
    the row has to satisfy every CHECK constraint on this table, and the
    function whose only job is to produce such rows is the one that knows how.
    """
    async with db.sessionmaker() as s:
        await audit.append(
            s,
            at=datetime.now(UTC),
            reaching_at=None,
            customer_ref=CUSTOMER,
            customer_ref_absence_reason=None,
            tool_name=tool_name,
            arguments={},
            outcome="returned",
            detail=None,
            redaction_budget_exhausted=False,
            duration_ms=0,
            request_id=None,
            refusal_reason=None,
            call_id=tool_name,
            client_id=None,
            risk_signals=None,
        )
        await s.commit()


async def _privileges(url_db: Database, table: str) -> frozenset[str]:
    async with url_db.sessionmaker() as s:
        held = set()
        for privilege in ALL_TABLE_PRIVILEGES:
            result = await s.execute(
                text("SELECT has_table_privilege(current_user, :t, :p)"),
                {"t": table, "p": privilege},
            )
            if result.scalar_one():
                held.add(privilege)
    return frozenset(held)


@pytest.mark.parametrize("table", sorted(EXPECTED_TABLE_PRIVILEGES))
async def test_the_application_role_holds_exactly_the_derived_privileges(
    app_db: Database, table: str
) -> None:
    assert await _privileges(app_db, table) == EXPECTED_TABLE_PRIVILEGES[table]


def test_every_mapped_table_has_a_privilege_decision() -> None:
    """A new table in the models must fail the build until someone grants on it.

    The same shape `tests/test_masking_golden.py`'s
    ``test_every_registered_tool_has_a_masking_case`` uses, for the same
    reason: "every table" is only honest if something derives the list.
    """
    assert set(Base.metadata.tables) <= set(EXPECTED_TABLE_PRIVILEGES)


async def test_the_application_role_holds_usage_on_both_sequences_it_inserts_through(
    app_db: Database,
) -> None:
    """Without this the INSERT fails at `nextval`, not at the table."""
    async with app_db.sessionmaker() as s:
        for table in ("audit_log", "challenges"):
            sequence = (
                await s.execute(text("SELECT pg_get_serial_sequence(:t, 'id')"), {"t": table})
            ).scalar_one()
            granted = (
                await s.execute(
                    text("SELECT has_sequence_privilege(current_user, :s, 'USAGE')"),
                    {"s": sequence},
                )
            ).scalar_one()
            assert granted, f"{table} inserts through {sequence} and cannot reach it"


async def test_the_application_role_has_no_privilege_on_the_consents_sequence(
    app_db: Database,
) -> None:
    """Nothing in either service writes a consent row, so nothing may."""
    async with app_db.sessionmaker() as s:
        sequence = (
            await s.execute(text("SELECT pg_get_serial_sequence('consents', 'id')"))
        ).scalar_one()
        granted = (
            await s.execute(
                text("SELECT has_sequence_privilege(current_user, :s, 'USAGE')"),
                {"s": sequence},
            )
        ).scalar_one()
    assert not granted


async def test_the_application_role_is_not_a_superuser_and_owns_nothing(app_db: Database) -> None:
    """The two attributes the whole control rests on, read back from the cluster.

    `rolsuper` is the one that defeats it outright -- a superuser sets
    ``session_replication_role`` and every trigger in the session stops firing
    -- and ownership is the one that defeats it with a single ``ALTER TABLE``.
    Both bypasses are performed against the roles that DO hold these, in
    `tests/test_audit_append_only.py`; here the point is that this role holds
    neither.
    """
    async with app_db.sessionmaker() as s:
        attributes = (
            await s.execute(
                text(
                    "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, "
                    "rolreplication FROM pg_roles WHERE rolname = current_user"
                )
            )
        ).one()
        assert list(attributes) == [False, False, False, False, False]
        owned = (
            await s.execute(
                text(
                    "SELECT count(*) FROM pg_class c JOIN pg_roles r ON r.oid = c.relowner "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE r.rolname = current_user AND n.nspname = 'public'"
                )
            )
        ).scalar_one()
    assert owned == 0, "a role that owns a relation can disable that relation's triggers"


async def test_the_application_role_cannot_create_a_table_to_own(app_db: Database) -> None:
    """CREATE on a schema is how a role that owns nothing starts owning something."""
    async with app_db.sessionmaker() as s:
        with pytest.raises(DBAPIError) as caught:
            await s.execute(text("CREATE TABLE postern_app_probe (id int)"))
    assert "permission denied for schema public" in str(caught.value)


async def test_the_insert_returning_clause_is_why_audit_log_needs_select(
    owner_db: Database, app_db: Database
) -> None:
    """The one grant in the set that reads as redundant, measured.

    `packages/postern-core/src/postern_core/store/audit.py`'s ``append`` never
    reads a row. It calls ``session.add``, and SQLAlchemy emits
    ``INSERT ... RETURNING id`` for a server-generated primary key, which is a
    read of a column. So the SELECT grant is load-bearing on the WRITE path,
    and decision record 0006 makes a failed audit write a failed tool call --
    dropping it takes the whole read surface down rather than degrading the
    log.

    Measured by taking SELECT away for the length of this test and putting it
    back, through the owner, which is the only role that can.
    """
    await _append_probe(app_db, "before-revoke")
    async with owner_db.sessionmaker() as s:
        await s.execute(text("REVOKE SELECT ON audit_log FROM postern_app"))
        await s.commit()
    try:
        with pytest.raises(DBAPIError) as caught:
            await _append_probe(app_db, "during-revoke")
        assert "permission denied for table audit_log" in str(caught.value)
        # The statement that was refused, named. Without this the test would
        # pass just as well if the append had failed on some later SELECT,
        # which is exactly the reading it exists to rule out: INSERT was never
        # revoked, so an INSERT refused for want of SELECT can only be the
        # RETURNING clause.
        statement = str(caught.value.statement or "")
        assert statement.startswith("INSERT INTO audit_log"), statement
        assert "RETURNING" in statement, statement
    finally:
        async with owner_db.sessionmaker() as s:
            await s.execute(text("GRANT SELECT ON audit_log TO postern_app"))
            await s.commit()
    await _append_probe(app_db, "after-restore")


def test_no_module_takes_a_row_lock_on_a_table_this_role_cannot_update() -> None:
    """``SELECT ... FOR UPDATE`` needs UPDATE, so one against `audit_log` voids this.

    Cheap to check and expensive to discover: PostgreSQL requires the UPDATE
    privilege for the ``FOR UPDATE``/``FOR NO KEY UPDATE`` locking clauses, so
    a reader that added one to an `audit_log` query would be asking for the
    exact privilege the append-only control exists to withhold. There is none
    in the tree today; this is what says so on every run.

    PARSED RATHER THAN GREPPED, and the first draft of this test is why. A
    substring scan over the file text matched
    `packages/postern-core/src/postern_core/store/challenges.py`'s
    ``update_challenge_status``, whose docstring explains at length that it
    used to be "a plain SELECT with no FOR UPDATE". It passed only because the
    line happens to wrap between the two words, so reflowing a paragraph would
    have failed the build over a sentence about not doing the thing. The AST
    sees neither comments nor docstrings, so what is left is the two shapes
    that can actually take a lock: the ORM's ``with_for_update`` and the
    clause inside a string a statement is built from.
    """
    sources = [
        path
        for directory in ("packages", "services")
        for path in (Path(__file__).resolve().parent.parent / directory).rglob("*.py")
    ]
    assert sources, "found no source files to scan, which makes this test vacuous"
    offenders: list[str] = []
    for path in sources:
        tree = ast.parse(path.read_text())
        docstrings = {
            id(node.body[0].value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
            and node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "with_for_update":
                offenders.append(f"{path}: .with_for_update()")
            elif (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docstrings
                and "for update" in node.value.lower()
            ):
                offenders.append(f"{path}: {node.value[:60]!r}")
    assert offenders == []


async def test_the_whole_approval_path_runs_as_the_application_role(
    app_db: Database, database: Database
) -> None:
    """Create, claim, execute, and both audit rows -- all as `postern_app`.

    THE TEST THIS FILE EXISTS FOR. A role that is correct for `audit_log` and
    breaks challenge approval is worse than no split at all, because it fails
    at the one moment the split was bought to protect: the write path, whose
    two rows are the only record that a payment approval happened. So this
    walks the sequence `services/confirm/callback.py` walks -- the pending row,
    the entry audit row, the ``pending`` -> ``approved`` claim, the
    ``approved`` -> ``executed`` transition, the completion audit row -- and
    every statement in it is issued by the application role.

    The consent read is in here too, and not as decoration: it is the only
    statement either service sends to `consents`, so a grant set that forgot
    that table would deny every tool call while every test about `audit_log`
    still passed.
    """
    challenge_id = f"chal_{uuid.uuid4().hex[:16]}"
    call_id = f"call_{uuid.uuid4().hex[:16]}"

    async with app_db.sessionmaker() as s:
        assert await consents.granted_domains(s, CustomerRef(value=CUSTOMER)) == set()

    async with app_db.sessionmaker() as s:
        await challenges.create_challenge(
            s,
            challenge_id=challenge_id,
            customer_ref=CUSTOMER,
            tool_name="payments.create_payment",
            payload={"amount": "10.00", "payee_ref": "payee_1"},
            tier=1,
        )
        await s.commit()

    await _append_probe(app_db, call_id)

    async with app_db.sessionmaker() as s:
        claimed = await challenges.update_challenge_status(
            s,
            challenge_id,
            status="approved",
            expected_status="pending",
            expiry="unexpired",
            confirming_device="dev_1",
        )
        await s.commit()
    assert claimed is not None and claimed.status == "approved"

    async with app_db.sessionmaker() as s:
        executed = await challenges.update_challenge_status(
            s, challenge_id, status="executed", expected_status="approved"
        )
        await s.commit()
    assert executed is not None and executed.status == "executed"

    await _append_probe(app_db, f"{call_id}-completion")

    async with app_db.sessionmaker() as s:
        stored = (
            await s.execute(
                select(ChallengeRecord).where(ChallengeRecord.challenge_id == challenge_id)
            )
        ).scalar_one()
        assert stored.status == "executed"
        rows = (
            (
                await s.execute(
                    select(AuditEntry).where(
                        AuditEntry.call_id.in_([call_id, f"{call_id}-completion"])
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 2, "both audit rows must be written by the application role"

    # Cleanup runs through the suite's one sanctioned bypass and the superuser
    # fixture it needs, because the application role cannot delete an audit row
    # -- which is the entire point -- and `database` is session-scoped and
    # shared, so this module owes it the rows back.
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(
            s, AuditEntry.customer_ref == CUSTOMER
        )
        await s.execute(text("DELETE FROM challenges WHERE customer_ref = :c"), {"c": CUSTOMER})
        await s.commit()


async def test_a_self_grant_by_the_application_role_reports_success_and_grants_nothing(
    app_db: Database,
) -> None:
    """The fourth route, and the only one that does not answer with an error.

    `GRANT DELETE ON audit_log TO CURRENT_USER` issued by this role does not
    raise. PostgreSQL answers a GRANT from a role holding no grant option with
    a WARNING -- `no privileges were granted for "audit_log"` -- and a
    successful command tag, so a probe that only watched for exceptions would
    record this as the bypass that worked.

    It grants nothing, which is what this measures and why the assertions are
    inside the same transaction: `has_table_privilege` is still false
    immediately after the statement, and the DELETE behind it is still refused
    at the ACL check. Found by running exactly this from inside the running
    `api` container on 2026-09-29, where it printed SUCCEEDED beside nine
    refusals.
    """
    async with app_db.sessionmaker() as s:
        before = (
            await s.execute(text("SELECT has_table_privilege(current_user, 'audit_log', 'DELETE')"))
        ).scalar_one()
        assert before is False
        await s.execute(text("GRANT DELETE ON audit_log TO CURRENT_USER"))
        after = (
            await s.execute(text("SELECT has_table_privilege(current_user, 'audit_log', 'DELETE')"))
        ).scalar_one()
        assert after is False, "the GRANT reported success; it must still grant nothing"
        with pytest.raises(DBAPIError) as caught:
            await s.execute(text("DELETE FROM audit_log WHERE customer_ref = :c"), {"c": CUSTOMER})
        assert "permission denied for table audit_log" in str(caught.value)
        await s.rollback()

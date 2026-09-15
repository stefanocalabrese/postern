"""ORM models for the two tables this plan owns (Task 2).

`consents` and `audit_log` per handoff §9. These tests check shape only
(table names, constraint names, column types, append-only-by-construction);
migration correctness against a real database is verified separately with
`alembic check`, not by these unit tests.
"""

from postern_core.store.base import Base
from postern_core.store.models import AuditEntry, ConsentRecord


def test_both_tables_are_registered_on_the_metadata() -> None:
    assert set(Base.metadata.tables) == {"consents", "audit_log"}


def test_consent_is_unique_per_customer_and_domain() -> None:
    # `ConsentRecord.__table__` is typed as the general `FromClause`, which
    # has no `.constraints`: SQLAlchemy's stubs allow a mapped class's table
    # to be a join in single/joined-table inheritance, and only the concrete
    # `Table` subtype carries `.constraints`. `Base.metadata.tables[...]` is
    # typed as `Table` directly, so it satisfies mypy --strict without a
    # `type: ignore` while checking the exact same constraint set.
    table = ConsentRecord.metadata.tables["consents"]
    names = {c.name for c in table.constraints}
    assert "uq_consent_customer_domain" in names


def test_audit_entry_has_no_update_or_delete_helper() -> None:
    """Append-only by construction: the model exposes no mutation helpers."""
    public = {n for n in dir(AuditEntry) if not n.startswith("_")}
    assert not {n for n in public if n.startswith(("update", "delete"))}


def test_audit_arguments_column_is_jsonb() -> None:
    from sqlalchemy.dialects.postgresql import JSONB

    assert isinstance(AuditEntry.__table__.c.arguments.type, JSONB)

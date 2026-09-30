"""``PairingAudit`` carries a serialized signal to the row it is handed to, and only there.

Section 5 of ``dev-docs/pairing-network-signal-spec.md``, at the writer. The
handler that hands it over is ``tests/test_scan_network_signal.py``'s subject;
this file pins that ``approved`` and ``approved_again`` write what they are
given into ``risk_signals``, and that every other row, and every call without
the keyword, keeps the column NULL. Read back out of Postgres, because the
column's type is a property of the database and not of a mock.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import select, text

from services.confirm.audit import (
    DETAIL_ALREADY_APPROVED,
    DETAIL_ALREADY_SCANNED,
    DETAIL_QR_STALE,
    SCAN_ROUTE,
    SCAN_TOOL_NAME,
    PairingAudit,
)
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

CUSTOMER = "cust_s1gnal"

SIGNAL: list[dict[str, Any]] = [
    {
        "code": "PAIRING_NETWORK",
        "severity": "LOW",
        "description": "pairing creator and scanner network relation: different",
        "details": {
            "relation": "different",
            "proxy_hops": 2,
            "asn_match": False,
            "country_match": "unknown",
        },
    }
]


async def _wipe(database: Database) -> None:
    async with database.sessionmaker() as session:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(
            session, AuditEntry.customer_ref == CUSTOMER
        )
        await session.commit()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    await _wipe(database)
    yield database
    await _wipe(database)


def _audit(database: Database) -> PairingAudit:
    return PairingAudit(
        db=database,
        call_id="00000000-0000-4000-8000-00000000516e",
        at=datetime.now(UTC),
        started=0.0,
        subject=CUSTOMER,
        claims={},
        client_ip_value="198.51.100.7",
        tool_name=SCAN_TOOL_NAME,
        route=SCAN_ROUTE,
    )


async def _only_row(database: Database) -> AuditEntry:
    async with database.sessionmaker() as session:
        result = await session.execute(
            select(AuditEntry).where(AuditEntry.customer_ref == CUSTOMER)
        )
        entries = list(result.scalars().all())
    assert len(entries) == 1, f"expected exactly one row, got {len(entries)}"
    return entries[0]


async def test_approved_writes_the_signal_it_is_handed(clean: Database) -> None:
    await _audit(clean).approved(risk_signals=SIGNAL)

    row = await _only_row(clean)
    assert row.detail is None
    assert row.risk_signals == SIGNAL


async def test_approved_again_writes_the_signal_it_is_handed(clean: Database) -> None:
    await _audit(clean).approved_again(DETAIL_ALREADY_SCANNED, risk_signals=SIGNAL)

    row = await _only_row(clean)
    assert row.detail == DETAIL_ALREADY_SCANNED
    assert row.risk_signals == SIGNAL


async def test_approved_without_the_keyword_keeps_null(clean: Database) -> None:
    await _audit(clean).approved()
    assert (await _only_row(clean)).risk_signals is None


async def test_the_already_approved_repeat_keeps_null(clean: Database) -> None:
    await _audit(clean).approved_again()

    row = await _only_row(clean)
    assert row.detail == DETAIL_ALREADY_APPROVED
    assert row.risk_signals is None


async def test_a_refusal_keeps_null(clean: Database) -> None:
    await _audit(clean).refused(DETAIL_QR_STALE)
    assert (await _only_row(clean)).risk_signals is None


async def test_a_mint_keeps_null(clean: Database) -> None:
    await _audit(clean).minted()
    assert (await _only_row(clean)).risk_signals is None


async def test_the_signal_is_readable_by_the_query_the_spec_promises(clean: Database) -> None:
    """One JSONB predicate answers "completed from somewhere else"."""
    await _audit(clean).approved(risk_signals=SIGNAL)

    async with clean.engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT risk_signals->0->'details'->>'relation', "
                "risk_signals->0->'details'->>'asn_match', "
                "risk_signals->0->'details'->>'country_match', "
                "jsonb_exists(risk_signals->0->'details', 'asn_match') "
                "FROM audit_log WHERE customer_ref = :customer"
            ),
            {"customer": CUSTOMER},
        )
        assert result.one() == ("different", "false", "unknown", True)

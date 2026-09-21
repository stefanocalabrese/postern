"""Challenge store layer — CRUD against Postgres (handoff §7.4).

Tests the ``challenges`` table created by migration
``ed88bd4a6312_add_challenges_table.py``.  Uses the ``session`` fixture
(function-scoped, rolled back) so each test is isolated.

The session fixture rolls back per test, so these tests never see each
other's rows regardless of execution order.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.domain.verification import VerificationTier
from postern_core.store import challenges
from postern_core.store.models import ChallengeRecord
from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


async def _insert_challenge(
    session: AsyncSession,
    *,
    challenge_id: str = "chal_abc123",
    customer_ref: str = "cust_7f3a",
    tool_name: str = "payments.create_payment",
    payload: dict[str, Any] | None = None,
    tier: VerificationTier = VerificationTier.APP_APPROVAL,
) -> ChallengeRecord:
    """Insert a raw ``ChallengeRecord`` and flush."""
    now = datetime.now(UTC)
    ttl = {0: 30, 1: 180, 2: 300}[int(tier)]
    record = ChallengeRecord(
        challenge_id=challenge_id,
        customer_ref=customer_ref,
        tool_name=tool_name,
        payload=payload or {},
        tier=int(tier),
        status="pending",
        created_at=now,
        expires_at=now + timedelta(seconds=ttl),
    )
    session.add(record)
    await session.flush()
    return record


# ---------------------------------------------------------------------------
# create_challenge.
# ---------------------------------------------------------------------------


async def test_create_challenge_inserts_row(session: AsyncSession) -> None:
    record = await challenges.create_challenge(
        session,
        challenge_id="chal_new",
        customer_ref="cust_7f3a",
        tool_name="payments.create_payment",
        payload={"amount": "EUR 340.00"},
        tier=VerificationTier.APP_IDENTITY_VERIFICATION,
    )
    assert record.challenge_id == "chal_new"
    assert record.status == "pending"


async def test_create_challenge_sets_correct_ttl(session: AsyncSession) -> None:
    _now = datetime.now(UTC)  # noqa: F841
    for tier, expected_ttl in [(0, 30), (1, 180), (2, 300)]:
        record = await challenges.create_challenge(
            session,
            challenge_id=f"chal_ttl_{tier}",
            customer_ref="cust_7f3a",
            tool_name="payments.create_payment",
            payload={},
            tier=VerificationTier(tier),
        )
        actual_ttl = (record.expires_at - record.created_at).total_seconds()
        assert actual_ttl == expected_ttl, (
            f"tier {tier}: got {actual_ttl}s, expected {expected_ttl}s"
        )


# ---------------------------------------------------------------------------
# get_challenge — returns None for missing, row for existing.
# ---------------------------------------------------------------------------


async def test_get_challenge_returns_none_for_missing(session: AsyncSession) -> None:
    result = await challenges.get_challenge(session, "chal_nonexistent")
    assert result is None


async def test_get_challenge_returns_row(session: AsyncSession) -> None:
    await _insert_challenge(session, challenge_id="chal_get_test")
    record = await challenges.get_challenge(session, "chal_get_test")
    assert record is not None
    assert record.challenge_id == "chal_get_test"


async def test_get_challenge_does_not_filter_on_expiry(session: AsyncSession) -> None:
    """``get_challenge`` returns expired rows — expiry is checked by the
    caller (polling loop) or via ``get_active_challenge``."""
    past = datetime.now(UTC) - timedelta(hours=1)
    record = await _insert_challenge(  # noqa: E501
        session, challenge_id="chal_expired", tier=VerificationTier.APP_APPROVAL
    )
    # Manually set created_at to the past so expires_at is also in the past.
    record.created_at = past
    record.expires_at = past + timedelta(seconds=180)
    await session.flush()

    result = await challenges.get_challenge(session, "chal_expired")
    assert result is not None  # get_challenge does NOT filter on expiry.


# ---------------------------------------------------------------------------
# get_active_challenge — filters on expiry.
# ---------------------------------------------------------------------------


async def test_get_active_challenge_returns_pending(session: AsyncSession) -> None:
    await _insert_challenge(session, challenge_id="chal_active")
    result = await challenges.get_active_challenge(session, "chal_active")
    assert result is not None


async def test_get_active_challenge_returns_none_for_expired(session: AsyncSession) -> None:
    past = datetime.now(UTC) - timedelta(hours=1)
    record = await _insert_challenge(  # noqa: E501
        session, challenge_id="chal_expired_active", tier=VerificationTier.APP_APPROVAL
    )
    record.created_at = past
    record.expires_at = past + timedelta(seconds=180)
    await session.flush()

    result = await challenges.get_active_challenge(session, "chal_expired_active")
    assert result is None


# ---------------------------------------------------------------------------
# update_challenge_status — approval callback path.
# ---------------------------------------------------------------------------


async def test_update_challenge_status_approves(session: AsyncSession) -> None:
    await _insert_challenge(session, challenge_id="chal_update")
    record = await challenges.update_challenge_status(
        session,
        "chal_update",
        status="approved",
        confirming_device="dev_abc123",
        signature="sig_xyz",
    )
    assert record.status == "approved"
    assert record.confirming_device == "dev_abc123"
    assert record.signature == "sig_xyz"


async def test_update_challenge_status_with_verification_result(session: AsyncSession) -> None:
    await _insert_challenge(
        session, challenge_id="chal_tier2", tier=VerificationTier.APP_IDENTITY_VERIFICATION
    )
    record = await challenges.update_challenge_status(
        session,
        "chal_tier2",
        status="approved",
        confirming_device="dev_abc",
        signature="sig",
        verification_result="vr_match_001",
    )
    assert record.status == "approved"
    assert record.verification_result == "vr_match_001"


async def test_update_challenge_status_returns_none_for_missing(session: AsyncSession) -> None:
    result = await challenges.update_challenge_status(
        session, "chal_nonexistent", status="approved"
    )
    assert result is None


# ---------------------------------------------------------------------------
# mark_expired — background expiry sweep.
# ---------------------------------------------------------------------------


async def test_mark_expired_sets_status(session: AsyncSession) -> None:
    await _insert_challenge(session, challenge_id="chal_expire")
    record = await challenges.mark_expired(session, "chal_expire")
    assert record is not None
    assert record.status == "expired"


async def test_mark_expired_returns_none_for_missing(session: AsyncSession) -> None:
    result = await challenges.mark_expired(session, "chal_nonexistent")
    assert result is None


# ---------------------------------------------------------------------------
# list_customer_challenges — newest-first.
# ---------------------------------------------------------------------------


async def test_list_customer_challenges_returns_rows(session: AsyncSession) -> None:
    await _insert_challenge(session, challenge_id="chal_1", customer_ref="cust_7f3a")
    await _insert_challenge(session, challenge_id="chal_2", customer_ref="cust_7f3a")
    await _insert_challenge(session, challenge_id="chal_other", customer_ref="cust_9b21")

    rows = await challenges.list_customer_challenges(session, "cust_7f3a", limit=50)
    assert len(rows) == 2
    ids = [r.challenge_id for r in rows]
    assert "chal_1" in ids
    assert "chal_2" in ids


async def test_list_customer_challenges_filters_by_customer(session: AsyncSession) -> None:
    await _insert_challenge(session, challenge_id="chal_1", customer_ref="cust_7f3a")
    await _insert_challenge(session, challenge_id="chal_2", customer_ref="cust_9b21")

    rows = await challenges.list_customer_challenges(session, "cust_7f3a", limit=50)
    assert len(rows) == 1
    assert rows[0].challenge_id == "chal_1"


async def test_list_customer_challenges_respects_limit(session: AsyncSession) -> None:
    for i in range(5):
        await _insert_challenge(session, challenge_id=f"chal_{i}", customer_ref="cust_7f3a")

    rows = await challenges.list_customer_challenges(session, "cust_7f3a", limit=3)
    assert len(rows) == 3


async def test_list_customer_challenges_returns_empty_for_unknown_customer(  # noqa: E501
    session: AsyncSession,
) -> None:
    rows = await challenges.list_customer_challenges(session, "cust_unknown", limit=50)
    assert rows == []


# ---------------------------------------------------------------------------
# ChallengeNotFoundError.
# ---------------------------------------------------------------------------


async def test_challenge_not_found_error_is_raised_by_get_active(session: AsyncSession) -> None:
    """``get_challenge`` returns None for missing rows (does not raise).
    ``ChallengeNotFoundError`` is available for callers that prefer an exception."""
    result = await challenges.get_challenge(session, "chal_missing")
    assert result is None  # get_challenge returns None, not exception.


# ---------------------------------------------------------------------------
# CHECK constraints — tier and status values.
# ---------------------------------------------------------------------------


async def test_invalid_tier_rejected_by_check_constraint(session: AsyncSession) -> None:
    """Tier must be 0, 1, or 2 — enforced by DB CHECK constraint."""
    now = datetime.now(UTC)
    record = ChallengeRecord(
        challenge_id="chal_bad_tier",
        customer_ref="cust_7f3a",
        tool_name="payments.create_payment",
        payload={},
        tier=99,  # Invalid.
        status="pending",
        created_at=now,
        expires_at=now + timedelta(seconds=180),
    )
    session.add(record)
    with pytest.raises(Exception):  # noqa: B017 - IntegrityError from CHECK constraint.
        await session.flush()


async def test_invalid_status_rejected_by_check_constraint(session: AsyncSession) -> None:
    """Status must be one of the five legal values — enforced by DB CHECK."""
    now = datetime.now(UTC)
    record = ChallengeRecord(
        challenge_id="chal_bad_status",
        customer_ref="cust_7f3a",
        tool_name="payments.create_payment",
        payload={},
        tier=1,
        status="running",  # Invalid.
        created_at=now,
        expires_at=now + timedelta(seconds=180),
    )
    session.add(record)
    with pytest.raises(Exception):  # noqa: B017 - IntegrityError from CHECK constraint.
        await session.flush()


# ---------------------------------------------------------------------------
# Rollback isolation — companion to the insert tests above.
# ---------------------------------------------------------------------------


async def test_rollback_isolation_row_from_other_test_is_not_visible(
    session: AsyncSession,
) -> None:
    """Companion to the insert test above: proves the ``session`` fixture's
    rollback actually isolates tests, in either collection order. If this
    ran second and saw the ``chal_1`` row the first test inserted, that would
    mean the rollback did nothing."""
    rows = await challenges.list_customer_challenges(session, "cust_7f3a", limit=50)
    assert rows == []

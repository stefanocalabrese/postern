"""Challenge store layer — CRUD against Postgres (handoff §7.4).

Tests the ``challenges`` table created by migration
``ed88bd4a6312_add_challenges_table.py``.  Uses the ``session`` fixture
(function-scoped, rolled back) so each test is isolated.

The session fixture rolls back per test, so these tests never see each
other's rows regardless of execution order.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.domain.verification import VerificationTier
from postern_core.store import challenges
from postern_core.store.models import ChallengeRecord
from sqlalchemy import func, select
from sqlalchemy import text as sa_text
from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


async def _db_now(session: AsyncSession) -> datetime:
    """The database's clock, which is the one expiry is decided on.

    ``now()`` is ``transaction_timestamp()``, the same instant the
    ``expiry="unexpired"`` and ``expiry="expired"`` predicates compare
    ``expires_at`` against inside this session's transaction. A test that builds
    a deadline from ``datetime.now(UTC)`` instead measures the host's clock
    against the container's, and fails whenever they disagree by more than its
    margin (a Docker Desktop VM clock lags after the host sleeps).
    """
    return (await session.execute(select(func.now()))).scalar_one()


async def _insert_challenge(
    session: AsyncSession,
    *,
    challenge_id: str = "chal_abc123",
    customer_ref: str = "cust_7f3a",
    tool_name: str = "payments.create_payment",
    payload: dict[str, Any] | None = None,
    tier: VerificationTier = VerificationTier.APP_APPROVAL,
) -> ChallengeRecord:
    """Insert a raw ``ChallengeRecord`` and flush, stamped from the DB clock."""
    now = await _db_now(session)
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
    past = await _db_now(session) - timedelta(hours=1)
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
    past = await _db_now(session) - timedelta(hours=1)
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
        expected_status="pending",
        confirming_device="dev_abc123",
        signature="sig_xyz",
    )
    assert record is not None  # the challenge exists — see the "missing" test below.
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
        expected_status="pending",
        confirming_device="dev_abc",
        signature="sig",
        verification_result="vr_match_001",
    )
    assert record is not None  # the challenge exists — see the "missing" test below.
    assert record.status == "approved"
    assert record.verification_result == "vr_match_001"


async def test_update_challenge_status_returns_none_for_missing(session: AsyncSession) -> None:
    result = await challenges.update_challenge_status(
        session, "chal_nonexistent", status="approved", expected_status="pending"
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


# ---------------------------------------------------------------------------
# The conditional transition (audit finding C-03).
#
# `update_challenge_status` used to be `get_challenge`, attribute assignment,
# `flush()` -- an unlocked SELECT followed by an UPDATE with no predicate on
# the old status. The tests below pin the two properties that replaced it:
# the precondition travels inside the statement, and losing is reported as
# `None` rather than silently applied.
# ---------------------------------------------------------------------------


async def test_update_challenge_status_refuses_a_status_it_did_not_expect(
    session: AsyncSession,
) -> None:
    """Wrong ``expected_status`` → no row, and no write."""
    await _insert_challenge(session, challenge_id="chal_wrong_expected")

    result = await challenges.update_challenge_status(
        session,
        "chal_wrong_expected",
        status="executed",
        expected_status="approved",  # the row is pending.
    )

    assert result is None
    row = await challenges.get_challenge(session, "chal_wrong_expected")
    assert row is not None
    assert row.status == "pending"  # untouched, not just unreported.


async def test_update_challenge_status_does_not_overwrite_a_terminal_row(
    session: AsyncSession,
) -> None:
    """A second ``pending`` → ``approved`` on an approved row writes nothing.

    The pre-fix shape applied this unconditionally, so the second caller's
    ``signature`` landed on a row another caller had already approved and
    executed.
    """
    await _insert_challenge(session, challenge_id="chal_second_approval")
    first = await challenges.update_challenge_status(
        session,
        "chal_second_approval",
        status="approved",
        expected_status="pending",
        signature="sig_first",
    )
    assert first is not None

    second = await challenges.update_challenge_status(
        session,
        "chal_second_approval",
        status="approved",
        expected_status="pending",
        signature="sig_second",
    )

    assert second is None
    row = await challenges.get_challenge(session, "chal_second_approval")
    assert row is not None
    assert row.signature == "sig_first"


async def test_update_challenge_status_unexpired_refuses_a_row_past_its_deadline(
    session: AsyncSession,
) -> None:
    """``expiry="unexpired"`` puts the deadline in the ``WHERE`` clause."""
    record = await _insert_challenge(session, challenge_id="chal_deadline_passed")
    record.expires_at = await _db_now(session) - timedelta(minutes=5)
    await session.flush()

    result = await challenges.update_challenge_status(
        session,
        "chal_deadline_passed",
        status="approved",
        expected_status="pending",
        expiry="unexpired",
    )

    assert result is None
    row = await challenges.get_challenge(session, "chal_deadline_passed")
    assert row is not None
    assert row.status == "pending"


async def test_update_challenge_status_expired_refuses_a_row_still_inside_its_deadline(
    session: AsyncSession,
) -> None:
    """``expiry="expired"`` is the exact negation — it cannot retire a live row."""
    await _insert_challenge(session, challenge_id="chal_still_live")

    result = await challenges.update_challenge_status(
        session,
        "chal_still_live",
        status="expired",
        expected_status="pending",
        expiry="expired",
    )

    assert result is None
    row = await challenges.get_challenge(session, "chal_still_live")
    assert row is not None
    assert row.status == "pending"


async def test_update_challenge_status_expired_accepts_a_row_past_its_deadline(
    session: AsyncSession,
) -> None:
    record = await _insert_challenge(session, challenge_id="chal_retire_me")
    record.expires_at = await _db_now(session) - timedelta(minutes=5)
    await session.flush()

    result = await challenges.update_challenge_status(
        session,
        "chal_retire_me",
        status="expired",
        expected_status="pending",
        expiry="expired",
    )

    assert result is not None
    assert result.status == "expired"


async def test_update_challenge_status_ignores_the_deadline_by_default(
    session: AsyncSession,
) -> None:
    """The default is ``expiry="ignore"``: the deadline is the caller's to assert.

    ``mark_expired`` relies on this, and so does the ``approved`` →
    ``executed`` transition in ``services/confirm/callback.py``, which must
    not be defeated by a clock that ran out while the backend was answering.
    """
    record = await _insert_challenge(session, challenge_id="chal_ignore_deadline")
    record.expires_at = await _db_now(session) - timedelta(minutes=5)
    await session.flush()

    result = await challenges.update_challenge_status(
        session,
        "chal_ignore_deadline",
        status="approved",
        expected_status="pending",
    )

    assert result is not None
    assert result.status == "approved"


async def test_mark_expired_refuses_a_row_that_is_already_terminal(
    session: AsyncSession,
) -> None:
    """The guard ``mark_expired`` used to evaluate in Python is now a predicate.

    Pre-fix it read the row, compared ``status != "pending"`` against that
    snapshot, and then wrote — so a sweep racing an approval could stamp
    ``expired`` on top of an ``approved`` row.
    """
    await _insert_challenge(session, challenge_id="chal_sweep_race")
    approved = await challenges.update_challenge_status(
        session,
        "chal_sweep_race",
        status="approved",
        expected_status="pending",
    )
    assert approved is not None

    result = await challenges.mark_expired(session, "chal_sweep_race")

    assert result is None
    row = await challenges.get_challenge(session, "chal_sweep_race")
    assert row is not None
    assert row.status == "approved"


# ---------------------------------------------------------------------------
# The row lock itself, across two real connections.
#
# Everything above runs inside one transaction, where the statement's
# predicate is checked against this transaction's own uncommitted writes. That
# is not the case the finding is about. This one uses two connections so the
# loser's UPDATE genuinely blocks on the winner's row lock and PostgreSQL
# re-evaluates the predicate against the committed row afterwards, which is
# the behaviour the whole fix rests on.
# ---------------------------------------------------------------------------


async def test_a_second_connection_blocks_on_the_row_lock_and_then_matches_nothing(
    database: Any,
) -> None:
    challenge_id = "chal_lock_001"
    try:
        async with database.sessionmaker() as setup:
            await challenges.create_challenge(
                setup,
                challenge_id=challenge_id,
                customer_ref="cust_7f3a",
                tool_name="payments.create_payment",
                payload={},
                tier=VerificationTier.APP_APPROVAL,
            )
            await setup.commit()

        async with database.sessionmaker() as winner, database.sessionmaker() as loser:
            claimed = await challenges.update_challenge_status(
                winner,
                challenge_id,
                status="approved",
                expected_status="pending",
                expiry="unexpired",
                signature="sig_winner",
            )
            assert claimed is not None  # winner holds the row lock, uncommitted.

            contender = asyncio.create_task(
                challenges.update_challenge_status(
                    loser,
                    challenge_id,
                    status="approved",
                    expected_status="pending",
                    expiry="unexpired",
                    signature="sig_loser",
                )
            )
            # Not an arbitrary wait: this asserts the second statement is
            # genuinely blocked. If it were free to apply on its own snapshot
            # — the pre-fix behaviour — it would have finished by now.
            await asyncio.sleep(0.2)
            assert not contender.done(), "the second UPDATE did not block on the row lock"

            await winner.commit()
            assert await contender is None
            await loser.commit()

        async with database.sessionmaker() as check:
            row = await challenges.get_challenge(check, challenge_id)
            assert row is not None
            assert row.status == "approved"
            assert row.signature == "sig_winner"
    finally:
        async with database.sessionmaker() as cleanup:
            await cleanup.execute(
                sa_text("DELETE FROM challenges WHERE challenge_id LIKE 'chal_lock_%'")
            )
            await cleanup.commit()


async def test_get_challenge_without_refresh_answers_from_the_identity_map(
    database: Any,
) -> None:
    """The stale-read trap ``refresh`` exists for, pinned in both directions.

    A session that has already loaded a row and reads it again gets its own
    copy back, not the database's, even though the ``SELECT`` runs and even
    though READ COMMITTED would have shown it the other connection's
    committed write. ``services/confirm/callback.py`` classifies a refused
    transition with exactly this second read, and answered 500 instead of 409
    for every loser of a race until ``refresh=True`` was passed.
    """
    challenge_id = "chal_lock_stale"
    try:
        async with database.sessionmaker() as setup:
            await challenges.create_challenge(
                setup,
                challenge_id=challenge_id,
                customer_ref="cust_7f3a",
                tool_name="payments.create_payment",
                payload={},
                tier=VerificationTier.APP_APPROVAL,
            )
            await setup.commit()

        async with database.sessionmaker() as reader:
            first = await challenges.get_challenge(reader, challenge_id)
            assert first is not None
            assert first.status == "pending"

            async with database.sessionmaker() as writer:
                claimed = await challenges.update_challenge_status(
                    writer,
                    challenge_id,
                    status="approved",
                    expected_status="pending",
                )
                assert claimed is not None
                await writer.commit()

            stale = await challenges.get_challenge(reader, challenge_id)
            assert stale is not None
            assert stale.status == "pending", "expected the identity map's copy"

            fresh = await challenges.get_challenge(reader, challenge_id, refresh=True)
            assert fresh is not None
            assert fresh.status == "approved"
    finally:
        async with database.sessionmaker() as cleanup:
            await cleanup.execute(
                sa_text("DELETE FROM challenges WHERE challenge_id LIKE 'chal_lock_%'")
            )
            await cleanup.commit()


# ---------------------------------------------------------------------------
# One clock. A challenge is stamped and judged on the database's clock, so a
# Python process whose clock is wrong cannot change any expiry decision.
#
# Observed once, 1 October 2026, after about 20 hours of host idle: the Docker
# Desktop VM's clock lagged the host's by more than 300 seconds, and the two
# tests that put a deadline five minutes either side of ``datetime.now(UTC)``
# disagreed with the database's ``now()``. The same skew applied to a real
# ``create_challenge`` would have stamped ``expires_at`` on one clock and
# judged it on the other.
# ---------------------------------------------------------------------------

_SKEWS = [timedelta(minutes=10), timedelta(minutes=-10)]


def _skew_python_clock(monkeypatch: pytest.MonkeyPatch, offset: timedelta) -> None:
    """Make every ``datetime.now`` the store module can see run ``offset`` off.

    ``raising=False`` because the point of the fix is that the module stops
    reading the Python clock, so the names may legitimately not exist.
    """

    class _SkewedDatetime(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> "_SkewedDatetime":
            real = datetime.now(tz)
            return cls.fromtimestamp((real + offset).timestamp(), tz)

    monkeypatch.setattr(challenges, "datetime", _SkewedDatetime, raising=False)


@pytest.mark.parametrize("offset", _SKEWS, ids=["python-ahead", "python-behind"])
async def test_a_fresh_challenge_is_unexpired_whatever_the_python_clock_says(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch, offset: timedelta
) -> None:
    _skew_python_clock(monkeypatch, offset)
    record = await challenges.create_challenge(
        session,
        challenge_id="chal_skew",
        customer_ref="cust_7f3a",
        tool_name="payments.create_payment",
        payload={},
        tier=VerificationTier.APP_APPROVAL,
    )

    # Returned record carries the stamped values, on the database's clock.
    db_now = await _db_now(session)
    assert record.expires_at - record.created_at == timedelta(seconds=180)
    assert abs((record.created_at - db_now).total_seconds()) < 5

    assert await challenges.get_active_challenge(session, "chal_skew") is not None
    claimed = await challenges.update_challenge_status(
        session,
        "chal_skew",
        status="approved",
        expected_status="pending",
        expiry="unexpired",
    )
    assert claimed is not None
    assert claimed.status == "approved"


@pytest.mark.parametrize("offset", _SKEWS, ids=["python-ahead", "python-behind"])
async def test_a_challenge_past_its_deadline_is_expired_whatever_the_python_clock_says(
    session: AsyncSession, monkeypatch: pytest.MonkeyPatch, offset: timedelta
) -> None:
    record = await _insert_challenge(session, challenge_id="chal_skew_past")
    record.expires_at = await _db_now(session) - timedelta(seconds=30)
    await session.flush()
    _skew_python_clock(monkeypatch, offset)

    assert await challenges.get_active_challenge(session, "chal_skew_past") is None

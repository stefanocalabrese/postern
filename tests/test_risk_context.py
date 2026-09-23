"""Per-session risk context (ZT-5).

Tracks cumulative records returned, distinct accounts touched, widest
time window requested, and session age. No thresholds — that lives in the
engine. This module is about correct accumulation, snapshotting, and
verification tier escalation.
"""

from postern_core.domain.verification import VerificationTier
from postern_core.risk.context import RiskContext
from postern_core.risk.types import RiskActionError, Severity


def test_initial_state_has_zero_records() -> None:
    ctx = RiskContext()
    assert ctx.record_count.total == 0


def test_initial_state_has_no_accounts() -> None:
    ctx = RiskContext()
    assert ctx.distinct_accounts == 0


def test_initial_state_has_zero_max_days() -> None:
    ctx = RiskContext()
    assert ctx.max_days_requested == 0


def test_initial_session_age_is_near_zero() -> None:
    ctx = RiskContext()
    assert ctx.session_age_seconds < 1.0


def test_record_records_accumulates() -> None:
    ctx = RiskContext()
    ctx.record_records(50)
    assert ctx.record_count.total == 50
    ctx.record_records(30)
    assert ctx.record_count.total == 80


def test_record_account_tracks_distinct() -> None:
    ctx = RiskContext()
    ctx.record_account("acc_1")
    assert ctx.distinct_accounts == 1
    ctx.record_account("acc_2")
    assert ctx.distinct_accounts == 2
    # Duplicate does not increase count
    ctx.record_account("acc_1")
    assert ctx.distinct_accounts == 2


def test_record_days_tracks_widest() -> None:
    ctx = RiskContext()
    ctx.record_days(30)
    assert ctx.max_days_requested == 30
    ctx.record_days(90)
    assert ctx.max_days_requested == 90
    # Narrower window does not reduce max
    ctx.record_days(7)
    assert ctx.max_days_requested == 90


def test_snapshot_returns_serialisable_dict() -> None:
    ctx = RiskContext()
    ctx.record_records(100)
    ctx.record_account("acc_1")
    ctx.record_days(60)

    snap = ctx.snapshot()

    assert snap["records"] == 100
    assert snap["distinct_accounts"] == 1
    assert snap["max_days_requested"] == 60
    assert isinstance(snap["session_age_seconds"], float)


def test_snapshot_values_match_properties() -> None:
    ctx = RiskContext()
    ctx.record_records(42)
    ctx.record_account("x")

    snap = ctx.snapshot()
    assert snap["records"] == ctx.record_count.total
    assert snap["distinct_accounts"] == ctx.distinct_accounts


# --- Verification tier tests (ZT-5 escalation) ---


def test_initial_verification_tier_is_session_only() -> None:
    """New sessions start at SESSION_ONLY (tier 0)."""
    ctx = RiskContext()
    assert ctx.verification_tier == VerificationTier.SESSION_ONLY


def test_escalate_tier_moves_session_to_app_approval() -> None:
    """First escalation moves SESSION_ONLY → APP_APPROVAL."""
    ctx = RiskContext()
    assert ctx.verification_tier.value == 0

    ctx.escalate_tier()
    assert ctx.verification_tier.value == 1


def test_escalate_tier_moves_app_approval_to_identity_verification() -> None:
    """Second escalation moves APP_APPROVAL → APP_IDENTITY_VERIFICATION."""
    ctx = RiskContext()
    ctx.escalate_tier()  # SESSION_ONLY → APP_APPROVAL
    assert ctx.verification_tier.value == 1

    ctx.escalate_tier()  # APP_APPROVAL → APP_IDENTITY_VERIFICATION
    assert ctx.verification_tier.value == 2


def test_escalate_tier_is_no_op_at_max() -> None:
    """Escalating beyond APP_IDENTITY_VERIFICATION is a no-op."""
    ctx = RiskContext()
    ctx.escalate_tier()  # → APP_APPROVAL
    ctx.escalate_tier()  # → APP_IDENTITY_VERIFICATION

    before = ctx.verification_tier.value
    ctx.escalate_tier()  # should not change anything

    assert ctx.verification_tier.value == before
    assert ctx.verification_tier.value == 2


def test_snapshot_includes_verification_tier() -> None:
    """snapshot() includes the current verification tier."""
    ctx = RiskContext()
    snap = ctx.snapshot()
    assert snap["verification_tier"] == "session"

    ctx.escalate_tier()
    snap = ctx.snapshot()
    assert snap["verification_tier"] == "app_approval"


def test_serialization_preserves_verification_tier() -> None:
    """to_dict / from_dict round-trip preserves the tier."""
    ctx = RiskContext(session_id="tier-test")
    ctx.record_records(10)
    ctx.escalate_tier()  # SESSION_ONLY → APP_APPROVAL

    data = ctx.to_dict()
    restored = RiskContext.from_dict(data)

    assert restored.verification_tier.value == 1
    assert restored.session_id == "tier-test"


def test_serialization_preserves_max_tier() -> None:
    """to_dict / from_dict round-trip preserves APP_IDENTITY_VERIFICATION."""
    ctx = RiskContext(session_id="tier-max")
    ctx.escalate_tier()  # → APP_APPROVAL
    ctx.escalate_tier()  # → APP_IDENTITY_VERIFICATION

    data = ctx.to_dict()
    restored = RiskContext.from_dict(data)

    assert restored.verification_tier.value == 2


def test_json_round_trip_preserves_verification_tier() -> None:
    """to_json / from_json round-trip preserves the tier."""
    ctx = RiskContext(session_id="tier-json")
    ctx.escalate_tier()  # → APP_APPROVAL

    json_str = ctx.to_json()
    restored = RiskContext.from_json(json_str)

    assert restored.verification_tier.value == 1


def test_serialization_default_tier_is_zero() -> None:
    """from_dict with missing tier field defaults to SESSION_ONLY.

    The field names lost their leading underscores when the serialised shape
    became a validated model (2026-09-22); `started_at` is the one field with
    no default, because a stored context whose creation instant is unknown
    cannot be aged and must be refused rather than restored as new.
    """
    import time

    data: dict[str, object] = {
        "session_id": "no-tier",
        "started_at": time.time(),
    }

    ctx = RiskContext.from_dict(data)
    assert ctx.verification_tier.value == 0


def test_escalate_tier_after_serialization_restores_correctly() -> None:
    """Escalating a restored context continues from its tier, not 0."""
    ctx = RiskContext(session_id="restore-escalate")
    ctx.escalate_tier()  # → APP_APPROVAL

    data = ctx.to_dict()
    restored = RiskContext.from_dict(data)
    assert restored.verification_tier.value == 1

    # Escalating the restored context should go to tier 2, not back to 0
    restored.escalate_tier()
    assert restored.verification_tier.value == 2


# --- RiskActionError tests ---


def test_risk_action_error_carries_signals() -> None:
    """RiskActionError stores the signals that caused the block."""
    from postern_core.risk.types import RiskSignal

    signals = [
        RiskSignal(
            code="RECORD_BUDGET_EXHAUSTED",
            description="Record budget exhausted",
            severity=Severity.HIGH,
        ),
    ]

    error = RiskActionError(signals)
    assert error.signals == signals


def test_risk_action_error_message_includes_codes() -> None:
    """Error message lists the signal codes."""
    from postern_core.risk.types import RiskSignal

    signals = [
        RiskSignal(
            code="RECORD_BUDGET_EXHAUSTED",
            description="Record budget exhausted",
            severity=Severity.HIGH,
        ),
        RiskSignal(
            code="ACCOUNT_DIVERSITY_EXHAUSTED",
            description="Account diversity exhausted",
            severity=Severity.HIGH,
        ),
    ]

    error = RiskActionError(signals)
    msg = str(error)
    assert "RECORD_BUDGET_EXHAUSTED" in msg
    assert "ACCOUNT_DIVERSITY_EXHAUSTED" in msg


def test_risk_action_error_message_includes_count() -> None:
    """Error message includes the number of blocking signals."""
    from postern_core.risk.types import RiskSignal

    signals = [
        RiskSignal(
            code="SIGNAL_A",
            description="A",
            severity=Severity.HIGH,
        ),
    ]

    error = RiskActionError(signals)
    assert "1 risk signal" in str(error)


def test_risk_action_error_with_multiple_signals_includes_count() -> None:
    """Error message includes the count of blocking signals."""
    from postern_core.risk.types import RiskSignal

    signals = [
        RiskSignal(
            code="SIGNAL_A",
            description="A",
            severity=Severity.HIGH,
        ),
        RiskSignal(
            code="SIGNAL_B",
            description="B",
            severity=Severity.HIGH,
        ),
    ]

    error = RiskActionError(signals)
    msg = str(error)
    assert "2 risk signal" in msg  # message uses "signal(s)" format

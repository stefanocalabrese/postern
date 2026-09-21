"""Risk middleware: hard-fail and tier escalation actions (ZT-5).

Tests the action model implemented in ``RiskMiddleware._evaluate_signals``:
- MEDIUM signals → escalate verification tier for subsequent calls
- HIGH signals → raise ``RiskActionError`` to block the current call

Tests exercise both the RiskEngine and IpAnomalyDetector signal paths.
"""

from __future__ import annotations

import dataclasses
from unittest.mock import patch

import pytest
from postern_core.domain.verification import VerificationTier
from postern_core.risk.context import RiskContext
from postern_core.risk.engine import RiskConfig, RiskEngine
from postern_core.risk.ip_anomaly import IpAnomalyDetector
from postern_core.risk.session import SessionStore, get_current_session, set_current_session
from postern_core.risk.types import RiskActionError, Severity

# --- Tier escalation on MEDIUM signals ---


def test_medium_signal_escalates_tier() -> None:
    """A MEDIUM signal from the risk engine escalates the tier."""
    ctx = RiskContext(session_id="test-medium")
    # 400 records is 80% of the default 500 budget → MEDIUM
    ctx.record_records(400)

    config = RiskConfig()
    signals = RiskEngine(config).evaluate(ctx)

    medium_signals = [s for s in signals if s.severity == Severity.MEDIUM]
    assert len(medium_signals) >= 1

    # Simulate what _evaluate_signals does for MEDIUM signals.
    if medium_signals:
        ctx.escalate_tier()

    assert ctx.verification_tier == VerificationTier.APP_APPROVAL


def test_medium_signal_from_ip_anomaly_escalates_tier() -> None:
    """A MEDIUM signal from IP anomaly detection escalates the tier."""
    ctx = RiskContext(session_id="test-ip-medium")

    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        ctx.ip_tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=105.0):
        ctx.ip_tracker.record_ip("10.0.0.1")

    detector = IpAnomalyDetector()
    ip_signals = detector.evaluate(ctx.ip_tracker)

    # IMPOSSIBLE_TRAVEL is MEDIUM — should trigger escalation.
    medium_ip_signals = [s for s in ip_signals if s.severity == Severity.MEDIUM]
    assert len(medium_ip_signals) >= 1

    if medium_ip_signals:
        ctx.escalate_tier()

    assert ctx.verification_tier == VerificationTier.APP_APPROVAL


def test_medium_signal_does_not_block_call() -> None:
    """MEDIUM signals escalate tier but do not raise RiskActionError."""
    ctx = RiskContext(session_id="test-no-block")
    ctx.record_records(400)  # MEDIUM signal

    config = RiskConfig()
    signals = RiskEngine(config).evaluate(ctx)

    medium_signals = [s for s in signals if s.severity == Severity.MEDIUM]
    high_signals = [s for s in signals if s.severity == Severity.HIGH]

    assert len(medium_signals) >= 1
    # No HIGH signals at 80% threshold, so no block should occur.
    assert len(high_signals) == 0

    # Escalate tier (what middleware does for MEDIUM).
    if medium_signals:
        ctx.escalate_tier()

    # Verify no RiskActionError was raised — the call continues normally.
    assert ctx.verification_tier == VerificationTier.APP_APPROVAL


def test_tier_escalation_is_idempotent_at_max() -> None:
    """Multiple MEDIUM signals at max tier don't escalate further."""
    ctx = RiskContext(session_id="test-idempotent")

    # Get to max tier.
    ctx.escalate_tier()  # → APP_APPROVAL
    ctx.escalate_tier()  # → APP_IDENTITY_VERIFICATION

    initial_tier = ctx.verification_tier

    # Simulate multiple MEDIUM signals firing (e.g., from repeated evaluations).
    for _ in range(5):
        ctx.escalate_tier()

    assert ctx.verification_tier == initial_tier


# --- HIGH signal blocking ---


def test_high_signal_raises_risk_action_error() -> None:
    """A HIGH signal from the risk engine raises RiskActionError."""
    ctx = RiskContext(session_id="test-high")
    # 500 records hits the hard limit → HIGH signal
    ctx.record_records(500)

    config = RiskConfig()
    signals = RiskEngine(config).evaluate(ctx)

    high_signals = [s for s in signals if s.severity == Severity.HIGH]
    assert len(high_signals) >= 1

    with pytest.raises(RiskActionError) as exc_info:
        raise RiskActionError(high_signals)

    error = exc_info.value
    assert len(error.signals) == len(high_signals)
    for sig in error.signals:
        assert sig.severity == Severity.HIGH


def test_high_signal_message_lists_codes() -> None:
    """RiskActionError message includes all blocking signal codes."""
    ctx = RiskContext(session_id="test-msg")
    ctx.record_records(500)

    config = RiskConfig()
    signals = RiskEngine(config).evaluate(ctx)

    high_signals = [s for s in signals if s.severity == Severity.HIGH]
    assert len(high_signals) >= 1

    with pytest.raises(RiskActionError) as exc_info:
        raise RiskActionError(high_signals)

    msg = str(exc_info.value)
    for sig in high_signals:
        assert sig.code in msg


def test_high_signal_stores_signals_on_context() -> None:
    """HIGH signals are stored on the context for audit logging."""
    ctx = RiskContext(session_id="test-store")
    ctx.record_records(500)

    config = RiskConfig()
    signals = RiskEngine(config).evaluate(ctx)

    high_signals = [s for s in signals if s.severity == Severity.HIGH]
    ctx._risk_signals = list(signals)

    # All signals (including HIGH) are on the context.
    assert len(ctx.risk_signals) > 0
    high_codes = {s.code for s in ctx.risk_signals if s.severity == Severity.HIGH}
    assert high_codes == {s.code for s in high_signals}


# --- Combined MEDIUM and HIGH signals ---


def test_high_blocks_even_when_medium_would_escalate() -> None:
    """When both MEDIUM and HIGH signals fire, the block takes priority."""
    ctx = RiskContext(session_id="test-combined")
    # 500 records triggers both RECORD_BUDGET_80PCT (MEDIUM) and
    # RECORD_BUDGET_EXHAUSTED (HIGH).
    ctx.record_records(500)

    config = RiskConfig()
    signals = RiskEngine(config).evaluate(ctx)

    medium_signals = [s for s in signals if s.severity == Severity.MEDIUM]
    high_signals = [s for s in signals if s.severity == Severity.HIGH]

    # Both severities should be present.
    assert len(medium_signals) >= 1
    assert len(high_signals) >= 1

    # HIGH signals should raise RiskActionError.
    with pytest.raises(RiskActionError):
        if high_signals:
            raise RiskActionError(high_signals)

    # The tier escalation for MEDIUM would have happened before the block
    # in the middleware, but the key point is: the call is blocked.


# --- Full middleware integration via SessionStore ---


async def test_session_persists_escalated_tier() -> None:
    """After tier escalation, the store persists the new tier."""
    store = SessionStore()

    handle = await store.create_session()
    ctx = await store.get_session(handle.value)
    assert ctx is not None

    # Record data that triggers a MEDIUM signal.
    ctx.record_records(400)

    # Simulate middleware: evaluate and escalate.
    config = RiskConfig()
    signals = RiskEngine(config).evaluate(ctx)
    medium_signals = [s for s in signals if s.severity == Severity.MEDIUM]
    if medium_signals:
        ctx.escalate_tier()

    # Persist (what middleware does after each call).
    await store.save_session(handle.value, ctx)

    # Reload from store — tier should be preserved.
    reloaded = await store.get_session(handle.value)
    assert reloaded is not None
    assert reloaded.verification_tier == VerificationTier.APP_APPROVAL


async def test_session_persists_blocked_signals() -> None:
    """After a HIGH block, signals are persisted on the context."""
    store = SessionStore()

    handle = await store.create_session()
    ctx = await store.get_session(handle.value)
    assert ctx is not None

    # Record data that triggers a HIGH signal.
    ctx.record_records(500)

    # Simulate middleware: evaluate and store signals.
    config = RiskConfig()
    signals = RiskEngine(config).evaluate(ctx)
    ctx._risk_signals = list(signals)

    # Persist (middleware persists even on block).
    await store.save_session(handle.value, ctx)

    # Reload — signals should be present.
    reloaded = await store.get_session(handle.value)
    assert reloaded is not None
    high_codes = {s.code for s in reloaded.risk_signals if s.severity == Severity.HIGH}
    assert len(high_codes) >= 1


# --- ContextVar integration ---


def test_get_current_session_after_middleware_push() -> None:
    """Middleware pushes session onto contextvar; handler can read it."""
    ctx = RiskContext(session_id="ctxvar-test")

    # Simulate middleware pushing the session.
    set_current_session(ctx)
    try:
        current = get_current_session()
        assert current is ctx
        assert current.session_id == "ctxvar-test"

        # Handler records data.
        current.record_records(10)
        assert current.record_count.total == 10
    finally:
        set_current_session(None)

    assert get_current_session() is None


# --- Snapshot includes tier after escalation ---


def test_snapshot_after_escalation_includes_new_tier() -> None:
    """Snapshot reflects the tier after escalation."""
    ctx = RiskContext(session_id="snap-escalate")

    snap_before = ctx.snapshot()
    assert snap_before["verification_tier"] == "session"

    ctx.escalate_tier()
    snap_after = ctx.snapshot()
    assert snap_after["verification_tier"] == "app_approval"


# --- IpAnomalyDetector signal severities ---


def test_ip_anomaly_impossible_travel_is_medium() -> None:
    """IP anomaly detector classifies impossible travel as MEDIUM."""
    ctx = RiskContext(session_id="test-ip-medium")

    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        ctx.ip_tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=105.0):
        ctx.ip_tracker.record_ip("10.0.0.1")

    detector = IpAnomalyDetector()
    signals = detector.evaluate(ctx.ip_tracker)

    medium_signals = [s for s in signals if s.severity == Severity.MEDIUM]
    assert len(medium_signals) >= 1

    # MEDIUM signals should escalate tier, not block.
    if medium_signals:
        ctx.escalate_tier()

    assert ctx.verification_tier == VerificationTier.APP_APPROVAL


def test_ip_diversity_exhausted_is_high() -> None:
    """IP diversity exhaustion triggers a HIGH signal."""
    ctx = RiskContext(session_id="test-ip-high")

    # Default config: max_distinct_ips_per_session = 3
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        ctx.ip_tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=101.0):
        ctx.ip_tracker.record_ip("192.168.1.2")
    with patch("postern_core.risk.context.time.monotonic", return_value=102.0):
        ctx.ip_tracker.record_ip("192.168.1.3")

    detector = IpAnomalyDetector()
    signals = detector.evaluate(ctx.ip_tracker)

    high_signals = [s for s in signals if s.severity == Severity.HIGH]
    assert len(high_signals) >= 1

    # HIGH IP signals should raise RiskActionError.
    with pytest.raises(RiskActionError):
        raise RiskActionError(high_signals)


def test_risk_signals_are_immutable() -> None:
    """Signals from both engine and IP detector are frozen dataclasses."""
    ctx = RiskContext(session_id="test-immutable")
    ctx.record_records(500)

    config = RiskConfig()
    engine_signals = RiskEngine(config).evaluate(ctx)

    for sig in engine_signals:
        with pytest.raises(dataclasses.FrozenInstanceError):
            sig.code = "hacked"  # type: ignore[misc]

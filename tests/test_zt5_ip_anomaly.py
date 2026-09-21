"""IP/ASN anomaly detection (ZT-5 follow-up).

Tests cover ``IpTracker`` and ``IpAnomalyDetector``:
- IpTracker: records IPs, tracks distinct count, last IP, time since change.
- IpAnomalyDetector: impossible travel, IP diversity escalation/hard limit,
  custom config thresholds, signal immutability.

See ``dev-docs/decisions/0010-dpop-sender-constraint.md`` for the threat model:
without DPoP, IP anomaly detection is the primary compensating control for
stolen-token replay from attacker infrastructure (threat A4).

Note: IP diversity escalation and hard limit are mutually exclusive —
at the hard limit only the hard-limit signal fires (escalation requires
distinct_ips < max_distinct_ips_per_session).
"""

import dataclasses
from unittest.mock import patch

import pytest
from postern_core.risk.context import IpTracker, RiskContext
from postern_core.risk.ip_anomaly import (
    IpAnomalyConfig,
    IpAnomalyDetector,
)
from postern_core.risk.types import Severity


def _mock_tracker(ips: list[str], times: list[float]) -> IpTracker:
    """Create an IpTracker with pre-recorded IPs at specific monotonic times.

    Args:
        ips: list of IP addresses to record in order.
        times: corresponding monotonic time values for each recording.
               Must be same length as ips and monotonically increasing.
    """
    tracker = IpTracker()
    for ip, t in zip(ips, times, strict=True):
        with patch("postern_core.risk.context.time.monotonic", return_value=t):
            tracker.record_ip(ip)
    return tracker


# --- IpTracker tests ---


def test_tracker_initial_state_has_no_entries() -> None:
    tracker = IpTracker()
    assert tracker.distinct_ips == 0
    assert tracker.last_ip is None
    assert tracker.entries == []


def test_tracker_records_ip() -> None:
    tracker = IpTracker()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        tracker.record_ip("192.168.1.1")
    assert tracker.distinct_ips == 1
    assert tracker.last_ip == "192.168.1.1"
    assert len(tracker.entries) == 1


def test_tracker_tracks_distinct_ips() -> None:
    tracker = IpTracker()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=101.0):
        tracker.record_ip("10.0.0.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=102.0):
        tracker.record_ip("172.16.0.1")
    assert tracker.distinct_ips == 3


def test_tracker_duplicate_ip_does_not_increase_distinct() -> None:
    tracker = IpTracker()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=101.0):
        tracker.record_ip("10.0.0.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=102.0):
        tracker.record_ip("192.168.1.1")  # repeat
    assert tracker.distinct_ips == 2


def test_tracker_last_ip_returns_most_recent() -> None:
    tracker = IpTracker()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=101.0):
        tracker.record_ip("10.0.0.1")
    assert tracker.last_ip == "10.0.0.1"


def test_tracker_time_since_last_change_same_ip() -> None:
    """Same IP repeated → no change detected."""
    tracker = IpTracker()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=200.0):
        tracker.record_ip("192.168.1.1")  # same IP
    assert tracker.time_since_last_change() is None


def test_tracker_time_since_last_change_different_ip() -> None:
    """Different IP → returns elapsed seconds."""
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1"],
        times=[100.0, 200.0],
    )
    elapsed = tracker.time_since_last_change()
    assert elapsed is not None
    assert elapsed == 100.0


def test_tracker_time_since_last_change_single_entry() -> None:
    """Only one entry → no change."""
    tracker = IpTracker()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        tracker.record_ip("192.168.1.1")
    assert tracker.time_since_last_change() is None


def test_tracker_snapshot_returns_dict() -> None:
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1"],
        times=[100.0, 200.0],
    )
    snap = tracker.snapshot()
    assert snap["distinct_ips"] == 2
    assert snap["last_ip"] == "10.0.0.1"


def test_tracker_entries_preserves_order() -> None:
    tracker = _mock_tracker(
        ips=["1.1.1.1", "2.2.2.2", "3.3.3.3"],
        times=[100.0, 200.0, 300.0],
    )
    ips = [e.ip_address for e in tracker.entries]
    assert ips == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]


# --- IpAnomalyDetector tests ---


def test_no_signals_single_ip() -> None:
    """Single IP, no change → no signals."""
    tracker = IpTracker()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        tracker.record_ip("192.168.1.1")
    detector = IpAnomalyDetector()
    signals = detector.evaluate(tracker)
    assert signals == []


def test_no_signals_same_ip_repeated() -> None:
    """Same IP repeated → no signals (no change detected)."""
    tracker = IpTracker()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=200.0):
        tracker.record_ip("192.168.1.1")
    detector = IpAnomalyDetector()
    signals = detector.evaluate(tracker)
    assert signals == []


def test_impossible_travel_detected() -> None:
    """IP changes within 5-minute window → MEDIUM impossible travel signal.

    With 2 distinct IPs, IP diversity escalation also fires (both are
    independent checks). The test verifies impossible travel is present.
    """
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1"],
        times=[100.0, 110.0],  # 10 seconds apart (well under 300s)
    )
    detector = IpAnomalyDetector()
    signals = detector.evaluate(tracker)

    codes = {s.code for s in signals}
    assert "IMPOSSIBLE_TRAVEL" in codes
    travel_sig = next(s for s in signals if s.code == "IMPOSSIBLE_TRAVEL")
    assert travel_sig.severity == Severity.MEDIUM
    assert "192.168.1.1" in travel_sig.description
    assert "10.0.0.1" in travel_sig.description


def test_no_impossible_travel_slow_change() -> None:
    """IP changes after 10 minutes → no impossible travel (legitimate roaming)."""
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1"],
        times=[100.0, 750.0],  # 650 seconds > 300s threshold
    )
    detector = IpAnomalyDetector()
    signals = detector.evaluate(tracker)

    codes = {s.code for s in signals}
    assert "IMPOSSIBLE_TRAVEL" not in codes


def test_ip_diversity_escalation_at_two_ips() -> None:
    """Two distinct IPs → MEDIUM IP_DIVERSITY_80PCT signal."""
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1"],
        times=[100.0, 750.0],  # slow change to avoid impossible travel
    )
    detector = IpAnomalyDetector()
    signals = detector.evaluate(tracker)

    codes = {s.code for s in signals}
    assert "IP_DIVERSITY_80PCT" in codes
    # Should be MEDIUM severity
    div_sig = next(s for s in signals if s.code == "IP_DIVERSITY_80PCT")
    assert div_sig.severity == Severity.MEDIUM


def test_ip_diversity_hard_limit_at_three_ips() -> None:
    """Three distinct IPs → HIGH IP_DIVERSITY_EXHAUSTED signal.

    At the hard limit, escalation does NOT fire (escalation requires
    distinct_ips < max_distinct_ips_per_session). Only the hard-limit
    signal fires.
    """
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        times=[100.0, 750.0, 800.0],  # slow changes to avoid impossible travel
    )
    detector = IpAnomalyDetector()
    signals = detector.evaluate(tracker)

    codes = {s.code for s in signals}
    assert "IP_DIVERSITY_EXHAUSTED" in codes
    hard_sig = next(s for s in signals if s.code == "IP_DIVERSITY_EXHAUSTED")
    assert hard_sig.severity == Severity.HIGH
    # Escalation does NOT fire at the hard limit (mutually exclusive)
    assert "IP_DIVERSITY_80PCT" not in codes


def test_combined_impossible_travel_and_ip_diversity() -> None:
    """Rapid IP changes trigger impossible travel + diversity signals.

    With 3 IPs changing rapidly: IMPOSSIBLE_TRAVEL fires (rapid change),
    IP_DIVERSITY_EXHAUSTED fires (3 IPs = hard limit). Escalation does
    not fire at the hard limit.
    """
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        times=[100.0, 110.0, 120.0],  # rapid changes (under 300s)
    )
    detector = IpAnomalyDetector()
    signals = detector.evaluate(tracker)

    codes = {s.code for s in signals}
    assert "IMPOSSIBLE_TRAVEL" in codes
    assert "IP_DIVERSITY_EXHAUSTED" in codes
    # Escalation does NOT fire at the hard limit
    assert "IP_DIVERSITY_80PCT" not in codes


def test_custom_config_tightens_impossible_travel_window() -> None:
    """Custom threshold is respected — 60s gap fires with default (300s)
    but not with a tightened 30s window.

    This proves the detector uses the config value, not a hardcoded one.
    """
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1"],
        times=[100.0, 160.0],  # 60 seconds apart
    )

    # Default config (300s threshold) — 60s gap triggers impossible travel
    default_detector = IpAnomalyDetector()
    default_signals = default_detector.evaluate(tracker)
    assert "IMPOSSIBLE_TRAVEL" in {s.code for s in default_signals}

    # Tightened config (30s threshold) — 60s gap does NOT trigger
    tight_config = IpAnomalyConfig(impossible_travel_window_seconds=30.0)
    tight_detector = IpAnomalyDetector(tight_config)
    tight_signals = tight_detector.evaluate(tracker)
    assert "IMPOSSIBLE_TRAVEL" not in {s.code for s in tight_signals}


def test_custom_config_increases_ip_diversity_limit() -> None:
    """A higher IP limit allows more distinct IPs without hard-fail."""
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        times=[100.0, 750.0, 800.0],
    )
    config = IpAnomalyConfig(max_distinct_ips_per_session=5)
    detector = IpAnomalyDetector(config)
    signals = detector.evaluate(tracker)

    codes = {s.code for s in signals}
    assert "IP_DIVERSITY_EXHAUSTED" not in codes


def test_custom_config_decreases_ip_diversity_limit() -> None:
    """A lower IP limit triggers hard-fail at fewer IPs."""
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1"],
        times=[100.0, 750.0],
    )
    config = IpAnomalyConfig(max_distinct_ips_per_session=2)
    detector = IpAnomalyDetector(config)
    signals = detector.evaluate(tracker)

    codes = {s.code for s in signals}
    assert "IP_DIVERSITY_EXHAUSTED" in codes


# --- Signal immutability ---


def test_ip_anomaly_signal_is_immutable() -> None:
    """Signals are frozen dataclasses — no mutation after creation."""
    tracker = _mock_tracker(
        ips=["192.168.1.1", "10.0.0.1"],
        times=[100.0, 110.0],
    )
    detector = IpAnomalyDetector()
    signals = detector.evaluate(tracker)

    sig = signals[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        sig.code = "hacked"  # type: ignore[misc]


# --- RiskContext integration ---


def test_risk_context_has_ip_tracker() -> None:
    """RiskContext exposes an IpTracker for anomaly detection."""
    ctx = RiskContext()
    assert ctx.ip_tracker is not None
    assert isinstance(ctx.ip_tracker, IpTracker)


def test_risk_context_ip_tracker_records_ips() -> None:
    """IPs recorded on context's tracker are accessible."""
    ctx = RiskContext()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        ctx.ip_tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=101.0):
        ctx.ip_tracker.record_ip("10.0.0.1")
    assert ctx.ip_tracker.distinct_ips == 2


def test_risk_context_snapshot_includes_ip_data() -> None:
    """Snapshot includes IP tracker data."""
    ctx = RiskContext()
    ctx.record_records(10)
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        ctx.ip_tracker.record_ip("192.168.1.1")
    snap = ctx.snapshot()
    assert snap["records"] == 10
    assert snap["distinct_ips"] == 1
    assert snap["last_ip"] == "192.168.1.1"


# --- Import smoke test ---


def test_all_exports_available_from_risk_package() -> None:
    """All new and existing types are importable from postern_core.risk."""
    from postern_core.risk import (
        IpAnomalyDetector,
        IpTracker,
        RiskEngine,
        RiskSignal,
    )

    # Verify they are the right types
    assert issubclass(IpTracker, object)
    assert issubclass(IpAnomalyDetector, object)
    assert issubclass(RiskEngine, object)
    assert isinstance(RiskSignal, type) or hasattr(RiskSignal, "code")

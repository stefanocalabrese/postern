"""IP/ASN anomaly detection for ZT-5 follow-up.

Detects three classes of client-side anomalies that suggest a stolen bearer
token being replayed from different infrastructure (threat A4):

1. **Impossible travel** — the client IP changed within a short time window,
   making it physically implausible that the same person is using the session.
2. **Excessive IP diversity** — a single session touches too many distinct IPs,
   suggesting automated replay from a botnet or proxy pool.
3. **ASN change** — the autonomous system changed, indicating a network-level
   shift (complementary to IP tracking; ASN enrichment is optional).

Signals follow the same severity model as the rest of the risk engine:
- ``MEDIUM`` — escalate tier for the next call.
- ``HIGH`` — hard-fail the call and end the session.

This module is stateless: it takes an ``IpTracker`` snapshot and returns
signals. The caller decides what to do with them.

See ``docs/decisions/0010-dpop-sender-constraint.md`` for the threat model
context: without DPoP, IP anomaly detection is the primary compensating
control for stolen-token replay from attacker infrastructure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from postern_core.risk.types import RiskSignal, Severity

if TYPE_CHECKING:
    from postern_core.risk.context import IpTracker


@dataclass(frozen=True)
class IpAnomalyConfig:
    """Thresholds for IP/ASN anomaly detection.

    All values are hard limits — exceeding them triggers a HIGH signal
    that ends the session. Sub-thresholds trigger MEDIUM signals that
    escalate tier.

    Sizing rationale:
    - ``impossible_travel_window_seconds = 300`` (5 minutes) is generous
      enough for legitimate roaming (airplane, train) but tight enough to
      catch automated replay from distant infrastructure.
    - ``max_distinct_ips_per_session = 3`` allows a user to switch networks
      (WiFi → cellular) but flags botnet-style replay.
    - ``max_distinct_ips_escalation = 2`` triggers tier escalation at the
      second distinct IP (60% of hard limit).
    """

    # Impossible travel: time window for IP change detection
    impossible_travel_window_seconds: float = 300.0
    """Seconds within which an IP change triggers impossible-travel detection."""

    # IP diversity: hard limit
    max_distinct_ips_per_session: int = 3
    """Maximum distinct IPs allowed in one session before hard-fail."""

    # IP diversity: sub-threshold (escalation)
    max_distinct_ips_escalation: int = 2
    """Distinct IPs at which to escalate tier (default 2 of 3)."""

    # ASN tracking (optional enrichment)
    known_suspicious_asns: frozenset[str] = field(default_factory=frozenset)
    """Set of ASN identifiers considered suspicious (e.g. known proxy providers)."""


class IpAnomalyDetector:
    """Evaluates an ``IpTracker`` for client-side anomalies.

    Stateless: takes a tracker and config, returns a list of signals. The
    caller decides what to do with them (log, escalate tier, hard-fail).

    Usage:
        config = IpAnomalyConfig()
        detector = IpAnomalyDetector(config)
        signals = detector.evaluate(context.ip_tracker)
        for signal in signals:
            handle(signal)
    """

    def __init__(self, config: IpAnomalyConfig | None = None) -> None:
        self.config = config or IpAnomalyConfig()

    def evaluate(self, tracker: IpTracker) -> list[RiskSignal]:
        """Run all IP/ASN checks and return non-empty signal list.

        Returns an empty list when the session is within normal bounds.
        """
        signals: list[RiskSignal] = []

        # 1. Impossible travel — IP changed within the time window (MEDIUM)
        if self._impossible_travel_detected(tracker):
            signals.append(self._signal_impossible_travel(tracker))

        # 2. IP diversity — escalation (MEDIUM)
        if self._ip_diversity_escalation(tracker):
            signals.append(self._signal_ip_diversity_escalation(tracker))

        # 3. IP diversity — hard limit (HIGH)
        if self._ip_diversity_hard_limit(tracker):
            signals.append(self._signal_ip_diversity_hard_limit(tracker))

        # 4. Suspicious ASN (HIGH)
        if self._suspicious_asn_detected(tracker):
            signals.append(self._signal_suspicious_asn())

        return signals

    # --- Check helpers ---

    def _impossible_travel_detected(self, tracker: IpTracker) -> bool:
        """IP changed within the impossible travel window."""
        elapsed = tracker.time_since_last_change()
        if elapsed is None:
            return False  # fewer than 2 entries, or same IP
        return elapsed <= self.config.impossible_travel_window_seconds

    def _ip_diversity_escalation(self, tracker: IpTracker) -> bool:
        """Distinct IPs reached escalation threshold."""
        return (
            tracker.distinct_ips >= self.config.max_distinct_ips_escalation
            and tracker.distinct_ips < self.config.max_distinct_ips_per_session
        )

    def _ip_diversity_hard_limit(self, tracker: IpTracker) -> bool:
        """Distinct IPs exceeded hard limit."""
        return tracker.distinct_ips >= self.config.max_distinct_ips_per_session

    def _suspicious_asn_detected(self, tracker: IpTracker) -> bool:
        """No ASN enrichment yet — always false until ASN data is wired."""
        return False

    # --- Signal factories ---

    def _signal_impossible_travel(self, tracker: IpTracker) -> RiskSignal:
        elapsed = tracker.time_since_last_change() or 0.0
        entries = tracker.entries
        prev_ip = entries[-2].ip_address if len(entries) >= 2 else "unknown"
        last_ip = entries[-1].ip_address if entries else "unknown"
        return RiskSignal(
            code="IMPOSSIBLE_TRAVEL",
            description=(
                f"Client IP changed from {prev_ip} to {last_ip} "
                f"in {elapsed:.0f}s (threshold: "
                f"{self.config.impossible_travel_window_seconds:.0f}s). "
                f"Escalate tier for subsequent calls."
            ),
            severity=Severity.MEDIUM,
            details={
                "previous_ip": prev_ip,
                "current_ip": last_ip,
                "elapsed_seconds": round(elapsed, 1),
                "threshold_seconds": self.config.impossible_travel_window_seconds,
            },
        )

    def _signal_ip_diversity_escalation(self, tracker: IpTracker) -> RiskSignal:
        return RiskSignal(
            code="IP_DIVERSITY_80PCT",
            description=(
                f"Session has used {tracker.distinct_ips} distinct IPs "
                f"(≥{self.config.max_distinct_ips_escalation} of "
                f"{self.config.max_distinct_ips_per_session}). "
                f"Escalate tier for subsequent calls."
            ),
            severity=Severity.MEDIUM,
            details={
                "distinct_ips": tracker.distinct_ips,
                "escalation_threshold": self.config.max_distinct_ips_escalation,
                "hard_limit": self.config.max_distinct_ips_per_session,
            },
        )

    def _signal_ip_diversity_hard_limit(self, tracker: IpTracker) -> RiskSignal:
        return RiskSignal(
            code="IP_DIVERSITY_EXHAUSTED",
            description=(
                f"Session IP budget exhausted ({tracker.distinct_ips} / "
                f"{self.config.max_distinct_ips_per_session}). End session."
            ),
            severity=Severity.HIGH,
            details={
                "distinct_ips": tracker.distinct_ips,
                "hard_limit": self.config.max_distinct_ips_per_session,
            },
        )

    def _signal_suspicious_asn(self) -> RiskSignal:
        return RiskSignal(
            code="SUSPICIOUS_ASN",
            description=("Client connected from a known suspicious ASN. End session."),
            severity=Severity.HIGH,
            details={},
        )

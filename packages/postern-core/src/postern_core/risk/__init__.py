"""Session risk tracking and anomaly detection (ZT-5).

Tracks per-session budgets (total records returned, distinct accounts
touched, time span requested) and emits risk signals when thresholds are
exceeded. Signals escalate the tier rather than hard-failing, per the
zero-trust plan §4.

This is an in-memory tracker — no persistence, no baseline learning.
Baselines and ZT-1 refresh integration are future work (blocked on the
fraud/risk platform team for ZT-1).
"""

from postern_core.risk.context import RecordCount, RiskContext
from postern_core.risk.engine import RiskConfig, RiskEngine, RiskSignal, Severity

__all__ = [
    "RecordCount",
    "RiskConfig",
    "RiskContext",
    "RiskEngine",
    "RiskSignal",
    "Severity",
]

"""Risk engine: evaluates session context against thresholds and emits signals.

Per the zero-trust plan §4, ZT-5 escalates tier rather than hard-failing.
Signals carry a `Severity` that maps to the appropriate response:

- ``LOW`` — informational, log only.
- ``MEDIUM`` — escalate tier for the next call (tier 1 → tier 2).
- ``HIGH`` — hard-fail the call and end the session.

Thresholds are configurable via `RiskConfig`. Defaults are sized against
the handoff's "not 200 records" framing (§6.5) and the MAX_ROWS=100
already in `facade/transactions.py`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from postern_core.risk.context import RiskContext


@dataclass(frozen=True)
class RiskSignal:
    """One anomaly detected by the engine.

    Immutable so it can be logged, serialized, or passed to a tier-escalation
    decision without mutation concerns.
    """

    code: str
    """Machine-readable identifier (e.g. ``RECORD_BUDGET_80PCT``)."""

    description: str
    """Human-readable explanation for logs and audit trails."""

    severity: Severity
    """What kind of response this signal demands."""

    details: dict[str, Any] = field(default_factory=dict)
    """Structured data for alerting systems (record counts, thresholds, etc.)."""


class Severity(Enum):
    """How urgently the signal demands action."""

    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


@dataclass(frozen=True)
class RiskConfig:
    """Thresholds for ZT-5 anomaly detection.

    All values are hard limits — exceeding them triggers a HIGH signal
    that ends the session. Sub-thresholds (80% of hard limit) trigger
    MEDIUM signals that escalate tier.

    Sizing rationale:
    - ``max_records_per_session = 500`` is 2.5× the handoff's "not 200
      records" (§6.5) and 5× the ``MAX_ROWS=100`` per-call cap, allowing
      a customer to reasonably ask for balances on all accounts plus a
      wide transaction window without hitting the budget.
    - ``max_distinct_accounts = 10`` matches the handoff's implicit
      assumption that a personal banking customer has fewer than 10
      accounts. Corporate multi-account customers are out of scope for
      this release.
    - ``max_days_per_call = 365`` matches ``MAX_DAYS`` in the transactions
      façade — a session budget wider than one call is pointless.
    - ``max_session_age_minutes = 480`` (8 hours) is a generous session
      lifetime; ZT-1's token refresh will be the primary shortening
      mechanism.
    """

    # Record budget (cumulative across all tool calls)
    max_records_per_session: int = 500
    """Hard limit on total records returned in one session."""

    # Account diversity budget
    max_distinct_accounts: int = 10
    """Hard limit on distinct accounts touched in one session."""

    # Time window budget (per call, not cumulative)
    max_days_per_call: int = 365
    """Maximum ``days`` parameter allowed per call."""

    # Session lifetime
    max_session_age_minutes: float = 480.0
    """Maximum session age in minutes before forced termination."""

    # Sub-thresholds (fraction of hard limit → MEDIUM escalation)
    record_escalation_pct: float = 0.8
    """Record count at which to escalate tier (default 80% of hard limit)."""

    account_escalation_pct: float = 0.8
    """Distinct accounts at which to escalate tier (default 80% of hard limit)."""


class RiskEngine:
    """Evaluates a ``RiskContext`` against ``RiskConfig`` and emits signals.

    Stateless: takes context + config, returns a list of signals. The caller
    decides what to do with them (log, escalate tier, hard-fail).

    Usage:
        config = RiskConfig()
        engine = RiskEngine(config)
        signals = engine.evaluate(context)
        for signal in signals:
            handle(signal)
    """

    def __init__(self, config: RiskConfig | None = None) -> None:
        self.config = config or RiskConfig()

    def evaluate(self, context: RiskContext) -> list[RiskSignal]:
        """Run all checks and return non-empty signal list.

        Returns an empty list when the session is within normal bounds.
        """
        signals: list[RiskSignal] = []

        # 1. Record budget — sub-threshold (MEDIUM: escalate tier)
        if self._record_budget_exceeded(context):
            signals.append(self._signal_record_escalation(context))

        # 2. Record budget — hard limit (HIGH: end session)
        if self._record_budget_hard_limit(context):
            signals.append(self._signal_record_hard_limit(context))

        # 3. Account diversity — sub-threshold (MEDIUM: escalate tier)
        if self._account_diversity_exceeded(context):
            signals.append(self._signal_account_escalation(context))

        # 4. Account diversity — hard limit (HIGH: end session)
        if self._account_diversity_hard_limit(context):
            signals.append(self._signal_account_hard_limit(context))

        # 5. Session age — hard limit (HIGH: end session)
        if self._session_age_exceeded(context):
            signals.append(self._signal_session_age(context))

        # 6. Time window — per-call check (HIGH: reject call)
        if self._time_window_exceeded(context):
            signals.append(self._signal_time_window(context))

        return signals

    # --- Budget helpers (on engine, not config, because config is frozen) ---

    def _record_used_pct(self, ctx: RiskContext) -> float:
        """Fraction of record budget used (0.0–1.0)."""
        if self.config.max_records_per_session == 0:
            return 1.0
        return min(1.0, ctx.record_count.total / self.config.max_records_per_session)

    def _account_used_pct(self, ctx: RiskContext) -> float:
        """Fraction of account budget used (0.0–1.0)."""
        if self.config.max_distinct_accounts == 0:
            return 1.0
        return min(1.0, ctx.distinct_accounts / self.config.max_distinct_accounts)

    # --- Individual checks ---

    def _record_budget_exceeded(self, ctx: RiskContext) -> bool:
        """80% of record budget reached → tier escalation."""
        return (
            ctx.record_count.total > 0
            and self._record_used_pct(ctx) >= self.config.record_escalation_pct
        )

    def _record_budget_hard_limit(self, ctx: RiskContext) -> bool:
        """Record budget exhausted → session end."""
        return ctx.record_count.total >= self.config.max_records_per_session

    def _account_diversity_exceeded(self, ctx: RiskContext) -> bool:
        """80% of account budget reached → tier escalation."""
        return (
            ctx.distinct_accounts > 0
            and self._account_used_pct(ctx) >= self.config.account_escalation_pct
        )

    def _account_diversity_hard_limit(self, ctx: RiskContext) -> bool:
        """Account budget exhausted → session end."""
        return ctx.distinct_accounts >= self.config.max_distinct_accounts

    def _session_age_exceeded(self, ctx: RiskContext) -> bool:
        """Session age exceeds max → session end."""
        return ctx.session_age_seconds >= self.config.max_session_age_minutes * 60

    def _time_window_exceeded(self, ctx: RiskContext) -> bool:
        """Days requested exceeds max → call rejected."""
        return ctx.max_days_requested > self.config.max_days_per_call

    # --- Signal factories ---

    def _signal_record_escalation(self, ctx: RiskContext) -> RiskSignal:
        used_pct = self._record_used_pct(ctx) * 100
        return RiskSignal(
            code="RECORD_BUDGET_80PCT",
            description=(
                f"Session has returned {ctx.record_count.total} records "
                f"(≥{int(self.config.record_escalation_pct * 100)}% of budget). "
                f"Escalate tier for subsequent calls."
            ),
            severity=Severity.MEDIUM,
            details={
                "records_returned": ctx.record_count.total,
                "budget_limit": self.config.max_records_per_session,
                "used_pct": round(used_pct, 1),
            },
        )

    def _signal_record_hard_limit(self, ctx: RiskContext) -> RiskSignal:
        return RiskSignal(
            code="RECORD_BUDGET_EXHAUSTED",
            description=(
                f"Session record budget exhausted ({ctx.record_count.total} / "
                f"{self.config.max_records_per_session}). End session."
            ),
            severity=Severity.HIGH,
            details={
                "records_returned": ctx.record_count.total,
                "budget_limit": self.config.max_records_per_session,
            },
        )

    def _signal_account_escalation(self, ctx: RiskContext) -> RiskSignal:
        used_pct = self._account_used_pct(ctx) * 100
        return RiskSignal(
            code="ACCOUNT_DIVERSITY_80PCT",
            description=(
                f"Session has touched {ctx.distinct_accounts} distinct accounts "
                f"(≥{int(self.config.account_escalation_pct * 100)}% of budget). "
                f"Escalate tier for subsequent calls."
            ),
            severity=Severity.MEDIUM,
            details={
                "distinct_accounts": ctx.distinct_accounts,
                "budget_limit": self.config.max_distinct_accounts,
                "used_pct": round(used_pct, 1),
            },
        )

    def _signal_account_hard_limit(self, ctx: RiskContext) -> RiskSignal:
        return RiskSignal(
            code="ACCOUNT_DIVERSITY_EXHAUSTED",
            description=(
                f"Session account budget exhausted ({ctx.distinct_accounts} / "
                f"{self.config.max_distinct_accounts}). End session."
            ),
            severity=Severity.HIGH,
            details={
                "distinct_accounts": ctx.distinct_accounts,
                "budget_limit": self.config.max_distinct_accounts,
            },
        )

    def _signal_session_age(self, ctx: RiskContext) -> RiskSignal:
        hours = ctx.session_age_seconds / 3600
        return RiskSignal(
            code="SESSION_AGE_EXCEEDED",
            description=(
                f"Session age {hours:.1f}h exceeds maximum "
                f"{self.config.max_session_age_minutes / 60:.0f}h. End session."
            ),
            severity=Severity.HIGH,
            details={
                "session_age_seconds": round(ctx.session_age_seconds, 1),
                "max_minutes": self.config.max_session_age_minutes,
            },
        )

    def _signal_time_window(self, ctx: RiskContext) -> RiskSignal:
        return RiskSignal(
            code="TIME_WINDOW_EXCEEDED",
            description=(
                f"Time window {ctx.max_days_requested} days exceeds maximum "
                f"{self.config.max_days_per_call} days. Reject call."
            ),
            severity=Severity.HIGH,
            details={
                "days_requested": ctx.max_days_requested,
                "max_days": self.config.max_days_per_call,
            },
        )

"""Risk engine: threshold evaluation and signal emission (ZT-5).

Tests cover every code path in ``RiskEngine.evaluate``:
- Record budget sub-threshold (MEDIUM escalation)
- Record budget hard limit (HIGH session end)
- Account diversity sub-threshold (MEDIUM escalation)
- Account diversity hard limit (HIGH session end)
- Session age exceeded (HIGH session end)
- Time window exceeded (HIGH call rejection)

Signals are immutable; the engine is stateless.
"""

import dataclasses

import pytest

from postern_core.risk.context import RiskContext
from postern_core.risk.engine import (
    RiskConfig,
    RiskEngine,
    RiskSignal,
    Severity,
)


def _make_context(
    records: int = 0,
    accounts: list[str] | None = None,
    days: int = 0,
) -> RiskContext:
    """Thin helper to avoid repeating setup in every test."""
    ctx = RiskContext()
    ctx.record_records(records)
    for acc in accounts or []:
        ctx.record_account(acc)
    ctx.record_days(days)
    return ctx


# --- Record budget: sub-threshold (MEDIUM escalation at 80%) ---


def test_no_signals_when_within_bounds() -> None:
    ctx = _make_context(records=10, accounts=["acc_1"], days=30)
    engine = RiskEngine()
    signals = engine.evaluate(ctx)
    assert signals == []


def test_record_budget_escalation_at_80pct() -> None:
    """400 records is 80% of the default 500 budget → MEDIUM signal."""
    ctx = _make_context(records=400, accounts=["acc_1"], days=30)
    engine = RiskEngine()
    signals = engine.evaluate(ctx)

    assert len(signals) == 1
    sig = signals[0]
    assert sig.code == "RECORD_BUDGET_80PCT"
    assert sig.severity == Severity.MEDIUM
    assert "400" in sig.description
    assert sig.details["records_returned"] == 400


def test_record_budget_no_escalation_below_80pct() -> None:
    """399 records is just under 80% → no signal."""
    ctx = _make_context(records=399, accounts=["acc_1"], days=30)
    engine = RiskEngine()
    signals = engine.evaluate(ctx)
    assert signals == []


# --- Record budget: hard limit (HIGH session end) ---


def test_record_budget_hard_limit() -> None:
    """500 records = budget limit → HIGH signal."""
    ctx = _make_context(records=500, accounts=["acc_1"], days=30)
    engine = RiskEngine()
    signals = engine.evaluate(ctx)

    codes = {s.code for s in signals}
    assert "RECORD_BUDGET_80PCT" in codes  # escalation fires first
    assert "RECORD_BUDGET_EXHAUSTED" in codes  # hard limit fires too


def test_record_budget_no_hard_limit_below_threshold() -> None:
    """499 records is under the hard limit."""
    ctx = _make_context(records=499, accounts=["acc_1"], days=30)
    engine = RiskEngine()
    signals = engine.evaluate(ctx)

    codes = {s.code for s in signals}
    assert "RECORD_BUDGET_EXHAUSTED" not in codes


# --- Account diversity: sub-threshold (MEDIUM escalation at 80%) ---


def test_account_diversity_escalation_at_80pct() -> None:
    """8 distinct accounts is 80% of the default 10 → MEDIUM signal."""
    ctx = _make_context(
        records=10,
        accounts=[f"acc_{i}" for i in range(8)],
        days=30,
    )
    engine = RiskEngine()
    signals = engine.evaluate(ctx)

    assert len(signals) == 1
    sig = signals[0]
    assert sig.code == "ACCOUNT_DIVERSITY_80PCT"
    assert sig.severity == Severity.MEDIUM


def test_account_diversity_no_escalation_below_80pct() -> None:
    """7 distinct accounts is just under 80% → no signal."""
    ctx = _make_context(
        records=10,
        accounts=[f"acc_{i}" for i in range(7)],
        days=30,
    )
    engine = RiskEngine()
    signals = engine.evaluate(ctx)
    assert signals == []


# --- Account diversity: hard limit (HIGH session end) ---


def test_account_diversity_hard_limit() -> None:
    """10 distinct accounts = budget limit → HIGH signal."""
    ctx = _make_context(
        records=10,
        accounts=[f"acc_{i}" for i in range(10)],
        days=30,
    )
    engine = RiskEngine()
    signals = engine.evaluate(ctx)

    codes = {s.code for s in signals}
    assert "ACCOUNT_DIVERSITY_EXHAUSTED" in codes


# --- Session age: hard limit (HIGH session end) ---


def test_session_age_exceeded() -> None:
    """A context with a long session age triggers HIGH signal."""
    ctx = RiskContext()
    # Manually set a long session age by patching the internal clock.
    # We can't actually wait 8 hours, so we use a custom config with
    # a very short max age.
    ctx._start_time = -100000  # ~27 hours ago
    config = RiskConfig(max_session_age_minutes=1.0)  # 1 minute max
    engine = RiskEngine(config)
    signals = engine.evaluate(ctx)

    codes = {s.code for s in signals}
    assert "SESSION_AGE_EXCEEDED" in codes


def test_session_age_within_bounds() -> None:
    """Fresh session with generous config → no signal."""
    ctx = RiskContext()
    config = RiskConfig(max_session_age_minutes=480.0)
    engine = RiskEngine(config)
    signals = engine.evaluate(ctx)
    assert signals == []


# --- Time window: per-call check (HIGH call rejection) ---


def test_time_window_exceeded() -> None:
    """400 days exceeds the 365-day max → HIGH signal."""
    ctx = _make_context(records=10, accounts=["acc_1"], days=400)
    engine = RiskEngine()
    signals = engine.evaluate(ctx)

    codes = {s.code for s in signals}
    assert "TIME_WINDOW_EXCEEDED" in codes


def test_time_window_within_bounds() -> None:
    """365 days is exactly the max → no signal."""
    ctx = _make_context(records=10, accounts=["acc_1"], days=365)
    engine = RiskEngine()
    signals = engine.evaluate(ctx)
    assert signals == []


# --- Multiple simultaneous signals ---


def test_multiple_signals_when_all_budgets_exhausted() -> None:
    """Both record and account budgets at hard limit → multiple signals."""
    ctx = _make_context(
        records=500,
        accounts=[f"acc_{i}" for i in range(10)],
        days=400,  # also exceeds time window
    )
    engine = RiskEngine()
    signals = engine.evaluate(ctx)

    codes = {s.code for s in signals}
    assert "RECORD_BUDGET_EXHAUSTED" in codes
    assert "ACCOUNT_DIVERSITY_EXHAUSTED" in codes
    assert "TIME_WINDOW_EXCEEDED" in codes


# --- Signal immutability ---


def test_signal_is_immutable() -> None:
    """Signals are frozen dataclasses — no mutation after creation."""
    ctx = _make_context(records=400, accounts=["acc_1"], days=30)
    engine = RiskEngine()
    signals = engine.evaluate(ctx)

    sig = signals[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        sig.code = "hacked"  # type: ignore[misc]


# --- Custom config ---


def test_custom_config_changes_thresholds() -> None:
    """A tighter config triggers signals earlier."""
    ctx = _make_context(records=50, accounts=["acc_1"], days=30)
    config = RiskConfig(max_records_per_session=100, record_escalation_pct=0.5)
    engine = RiskEngine(config)
    signals = engine.evaluate(ctx)

    # 50/100 = 50% = exactly at escalation threshold
    assert len(signals) >= 1


def test_custom_config_hard_limit_at_100_records() -> None:
    """With max_records_per_session=100, 100 records triggers hard limit."""
    ctx = _make_context(records=100, accounts=["acc_1"], days=30)
    config = RiskConfig(max_records_per_session=100)
    engine = RiskEngine(config)
    signals = engine.evaluate(ctx)

    codes = {s.code for s in signals}
    assert "RECORD_BUDGET_EXHAUSTED" in codes


# --- Budget used helpers (on engine, not config) ---


def test_record_used_pct_returns_fraction() -> None:
    ctx = _make_context(records=250, accounts=["acc_1"], days=30)
    engine = RiskEngine()
    used = engine._record_used_pct(ctx)
    assert used == 0.5


def test_record_used_pct_is_one_when_exhausted() -> None:
    ctx = _make_context(records=600, accounts=["acc_1"], days=30)
    engine = RiskEngine()
    used = engine._record_used_pct(ctx)
    assert used == 1.0


def test_account_used_pct_returns_fraction() -> None:
    ctx = _make_context(records=10, accounts=["acc_1", "acc_2"], days=30)
    engine = RiskEngine()
    used = engine._account_used_pct(ctx)
    assert used == 0.2


def test_account_used_pct_is_one_when_exhausted() -> None:
    ctx = _make_context(
        records=10,
        accounts=[f"acc_{i}" for i in range(15)],
        days=30,
    )
    engine = RiskEngine()
    used = engine._account_used_pct(ctx)
    assert used == 1.0


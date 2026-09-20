"""Per-session risk context (ZT-5).

Tracks cumulative records returned, distinct accounts touched, widest
time window requested, and session age. No thresholds — that lives in the
engine. This module is about correct accumulation and snapshotting.
"""

from postern_core.risk.context import RiskContext


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

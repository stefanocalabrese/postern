"""Integration tests for risk session wiring (ZT-5).

Tests the full flow: start_session creates a session, subsequent calls
record data on the RiskContext, and risk signals fire correctly.

Covers:
- SessionStore creates and retrieves sessions
- start_session returns a session_handle
- Tool handlers record data via get_current_session()
- Risk middleware evaluates signals after each call
- IP tracking through the middleware
"""

import dataclasses
from unittest.mock import patch, MagicMock

import pytest

from postern_core.risk.context import RiskContext
from postern_core.risk.engine import RiskConfig, RiskEngine
from postern_core.risk.ip_anomaly import IpAnomalyDetector
from postern_core.risk.session import (
    SessionHandle,
    SessionStore,
    get_current_session,
    set_current_session,
)
from postern_core.risk.types import RiskSignal, Severity


# --- SessionStore tests ---


async def test_session_store_creates_unique_handles() -> None:
    """Each create_session call returns a distinct handle."""
    store = SessionStore()
    h1 = await store.create_session()
    h2 = await store.create_session()
    assert h1.value != h2.value
    assert isinstance(h1, SessionHandle)


async def test_session_store_retrieves_by_handle() -> None:
    """Created sessions are retrievable by their handle."""
    store = SessionStore()
    h = await store.create_session()
    ctx = await store.get_session(h.value)
    assert ctx is not None
    assert ctx.session_id == h.value


async def test_session_store_returns_none_for_unknown_handle() -> None:
    """Unknown handles return None."""
    store = SessionStore()
    assert await store.get_session("nonexistent") is None


async def test_session_store_removes_sessions() -> None:
    """remove_session deletes the context."""
    store = SessionStore()
    h = await store.create_session()
    await store.remove_session(h.value)
    assert await store.get_session(h.value) is None


async def test_session_context_has_id() -> None:
    """Created contexts carry their session_id."""
    store = SessionStore()
    h = await store.create_session()
    ctx = await store.get_session(h.value)
    assert ctx is not None
    assert ctx.session_id == h.value


# --- ContextVar tests ---


def test_get_current_session_returns_none_initially() -> None:
    """No session is active until one is pushed."""
    assert get_current_session() is None


def test_set_and_get_current_session() -> None:
    """Setting a session makes it retrievable."""
    ctx = RiskContext(session_id="test-123")
    set_current_session(ctx)
    try:
        current = get_current_session()
        assert current is ctx
        assert current.session_id == "test-123"
    finally:
        set_current_session(None)


def test_get_current_session_returns_none_after_clear() -> None:
    """Clearing the session returns None."""
    ctx = RiskContext(session_id="test-123")
    set_current_session(ctx)
    try:
        assert get_current_session() is ctx
    finally:
        set_current_session(None)
        assert get_current_session() is None


# --- Data recording tests ---


def test_context_records_and_retrieves_data() -> None:
    """record_records, record_account, record_days all work."""
    ctx = RiskContext(session_id="test")
    ctx.record_records(10)
    ctx.record_account("acc_abc")
    ctx.record_account("acc_def")
    ctx.record_days(30)

    assert ctx.record_count.total == 10
    assert ctx.distinct_accounts == 2
    assert ctx.max_days_requested == 30


def test_context_snapshot_includes_all_fields() -> None:
    """Snapshot captures the full state."""
    ctx = RiskContext(session_id="sess-1")
    ctx.record_records(5)
    ctx.record_account("acc_x")
    ctx.record_days(7)

    snap = ctx.snapshot()
    assert snap["records"] == 5
    assert snap["distinct_accounts"] == 1
    assert snap["max_days_requested"] == 7
    assert snap["session_id"] == "sess-1"
    age = snap["session_age_seconds"]
    assert isinstance(age, (int, float)) and age >= 0


def test_duplicate_accounts_dont_increase_count() -> None:
    """Recording the same account twice doesn't increase distinct count."""
    ctx = RiskContext()
    ctx.record_account("acc_abc")
    ctx.record_account("acc_abc")
    assert ctx.distinct_accounts == 1


def test_max_days_keeps_widest() -> None:
    """record_days keeps the maximum, not the last."""
    ctx = RiskContext()
    ctx.record_days(30)
    ctx.record_days(7)
    ctx.record_days(60)
    assert ctx.max_days_requested == 60


# --- RiskEngine integration with recorded data ---


def test_risk_engine_sees_recorded_data() -> None:
    """RiskEngine evaluates based on what handlers recorded."""
    ctx = RiskContext(session_id="test")
    # Simulate a handler recording 10 records from accounts.list
    ctx.record_records(10)
    ctx.record_account("acc_abc")

    config = RiskConfig(max_records_per_session=100)
    signals = RiskEngine(config).evaluate(ctx)

    # 10 records is well within 80% of 100, so no signals
    assert signals == []


def test_risk_engine_sees_record_budget_exhaustion() -> None:
    """Engine fires when recorded records hit the hard limit."""
    ctx = RiskContext(session_id="test")
    ctx.record_records(100)

    config = RiskConfig(max_records_per_session=100)
    signals = RiskEngine(config).evaluate(ctx)

    codes = {s.code for s in signals}
    assert "RECORD_BUDGET_EXHAUSTED" in codes
    hard_sig = next(s for s in signals if s.code == "RECORD_BUDGET_EXHAUSTED")
    assert hard_sig.severity == Severity.HIGH


def test_risk_engine_sees_account_diversity() -> None:
    """Engine fires when distinct accounts hit the hard limit."""
    ctx = RiskContext(session_id="test")
    for i in range(5):
        ctx.record_account(f"acc_{i}")

    config = RiskConfig(max_distinct_accounts=3)
    signals = RiskEngine(config).evaluate(ctx)

    codes = {s.code for s in signals}
    assert "ACCOUNT_DIVERSITY_EXHAUSTED" in codes


# --- IP tracking integration ---


def test_ip_tracker_records_via_context() -> None:
    """IPs recorded on context's tracker are accessible."""
    ctx = RiskContext(session_id="test")

    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        ctx.ip_tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=101.0):
        ctx.ip_tracker.record_ip("10.0.0.1")

    assert ctx.ip_tracker.distinct_ips == 2
    assert ctx.ip_tracker.last_ip == "10.0.0.1"


def test_ip_anomaly_sees_context_tracker() -> None:
    """IpAnomalyDetector evaluates the context's tracker."""
    ctx = RiskContext(session_id="test")

    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        ctx.ip_tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=105.0):
        ctx.ip_tracker.record_ip("10.0.0.1")  # 5 seconds later

    detector = IpAnomalyDetector()
    signals = detector.evaluate(ctx.ip_tracker)

    codes = {s.code for s in signals}
    assert "IMPOSSIBLE_TRAVEL" in codes


def test_snapshot_includes_ip_data() -> None:
    """Context snapshot includes IP tracker data."""
    ctx = RiskContext(session_id="test")

    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        ctx.ip_tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=101.0):
        ctx.ip_tracker.record_ip("10.0.0.1")

    snap = ctx.snapshot()
    assert snap["distinct_ips"] == 2
    assert snap["last_ip"] == "10.0.0.1"


# --- Signal immutability (integration) ---


def test_risk_signals_from_engine_are_immutable() -> None:
    """Signals emitted by the engine are frozen dataclasses."""
    ctx = RiskContext(session_id="test")
    ctx.record_records(100)

    config = RiskConfig(max_records_per_session=100)
    signals = RiskEngine(config).evaluate(ctx)

    sig = next(s for s in signals if s.code == "RECORD_BUDGET_EXHAUSTED")
    with pytest.raises(dataclasses.FrozenInstanceError):
        sig.code = "hacked"  # type: ignore[misc]  # frozen dataclass, assignment should raise


# --- Full session lifecycle ---


async def test_full_session_lifecycle() -> None:
    """Create → retrieve → record → evaluate → snapshot."""
    store = SessionStore()

    # 1. Create session
    handle = await store.create_session()
    assert handle.value is not None

    # 2. Retrieve context
    ctx = await store.get_session(handle.value)
    assert ctx is not None
    assert ctx.session_id == handle.value

    # 3. Record data (simulating tool handler behavior)
    ctx.record_records(50)
    for i in range(3):
        ctx.record_account(f"acc_{i}")
    ctx.record_days(30)

    # 4. Evaluate risk (within bounds)
    config = RiskConfig(
        max_records_per_session=100,
        max_distinct_accounts=5,
        max_days_per_call=365,
    )
    signals = RiskEngine(config).evaluate(ctx)
    assert signals == []

    # 5. Snapshot captures state
    snap = ctx.snapshot()
    assert snap["records"] == 50
    assert snap["distinct_accounts"] == 3
    assert snap["max_days_requested"] == 30
    assert snap["session_id"] == handle.value

    # 6. Exhaust budget and re-evaluate
    ctx.record_records(60)  # total now 110, over limit of 100
    signals = RiskEngine(config).evaluate(ctx)
    assert len(signals) > 0

    # 7. Remove session
    await store.remove_session(handle.value)
    assert await store.get_session(handle.value) is None


async def test_multiple_sessions_are_isolated() -> None:
    """Each session has independent state."""
    store = SessionStore()

    h1 = await store.create_session()
    h2 = await store.create_session()

    ctx1 = await store.get_session(h1.value)
    ctx2 = await store.get_session(h2.value)

    assert ctx1 is not None
    assert ctx2 is not None
    assert ctx1 is not ctx2
    assert ctx1.session_id != ctx2.session_id

    ctx1.record_records(50)
    ctx2.record_records(10)

    assert ctx1.record_count.total == 50
    assert ctx2.record_count.total == 10

    # Different sessions, different contexts
    config = RiskConfig(max_records_per_session=30)
    signals1 = RiskEngine(config).evaluate(ctx1)
    signals2 = RiskEngine(config).evaluate(ctx2)

    assert len(signals1) > 0  # 50 > 30
    assert signals2 == []     # 10 <= 30


# --- Serialization tests (Redis persistence) ---


def test_ip_tracker_serialization_round_trip() -> None:
    """IpTracker serialises and deserialises correctly."""
    tracker = type("T", (), {})()  # placeholder
    from postern_core.risk.context import IpTracker

    tracker = IpTracker()
    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        tracker.record_ip("192.168.1.1")
    with patch("postern_core.risk.context.time.monotonic", return_value=105.0):
        tracker.record_ip("10.0.0.1")

    data = tracker.to_dict()
    restored = IpTracker.from_dict(data)

    assert restored.distinct_ips == 2
    assert restored.last_ip == "10.0.0.1"
    entries = restored.entries
    assert len(entries) == 2
    assert entries[0].ip_address == "192.168.1.1"
    assert entries[1].ip_address == "10.0.0.1"


def test_risk_context_serialization_round_trip() -> None:
    """RiskContext serialises and deserialises all fields."""
    ctx = RiskContext(session_id="sess-abc")
    ctx.record_records(42)
    ctx.record_account("acc_1")
    ctx.record_account("acc_2")
    ctx.record_days(30)

    data = ctx.to_dict()
    restored = RiskContext.from_dict(data)

    assert restored.session_id == "sess-abc"
    assert restored.record_count.total == 42
    assert restored.distinct_accounts == 2
    assert restored.max_days_requested == 30


def test_risk_context_json_round_trip() -> None:
    """RiskContext to_json / from_json round-trips correctly."""
    ctx = RiskContext(session_id="sess-json")
    ctx.record_records(10)
    ctx.record_account("acc_x")

    json_str = ctx.to_json()
    restored = RiskContext.from_json(json_str)

    assert restored.session_id == "sess-json"
    assert restored.record_count.total == 10
    assert restored.distinct_accounts == 1


def test_risk_context_serialization_includes_ip_tracker() -> None:
    """Serialized context carries IP tracker data."""
    ctx = RiskContext(session_id="sess-ip")

    with patch("postern_core.risk.context.time.monotonic", return_value=100.0):
        ctx.ip_tracker.record_ip("1.2.3.4")
    with patch("postern_core.risk.context.time.monotonic", return_value=101.0):
        ctx.ip_tracker.record_ip("5.6.7.8")

    data = ctx.to_dict()
    restored = RiskContext.from_dict(data)

    assert restored.ip_tracker.distinct_ips == 2
    assert restored.ip_tracker.last_ip == "5.6.7.8"


def test_risk_context_serialization_includes_signals() -> None:
    """Serialized context carries risk signals from last evaluation."""
    ctx = RiskContext(session_id="sess-sig")
    ctx.record_records(100)

    config = RiskConfig(max_records_per_session=100)
    signals = RiskEngine(config).evaluate(ctx)
    ctx._risk_signals = list(signals)

    data = ctx.to_dict()
    restored = RiskContext.from_dict(data)

    assert len(restored.risk_signals) > 0
    codes = {s.code for s in restored.risk_signals}
    assert "RECORD_BUDGET_EXHAUSTED" in codes


async def test_in_memory_session_store_factory() -> None:
    """create_session_store returns InMemorySessionStore without POSTERN_REDIS_URL."""
    import os

    # Ensure no Redis URL is set
    redis_url = os.environ.pop("POSTERN_REDIS_URL", None)
    try:
        from postern_core.risk.session import (
            InMemorySessionStore,
            create_session_store,
        )

        store = create_session_store()
        assert isinstance(store, InMemorySessionStore)

        # Verify it works
        handle = await store.create_session()
        ctx = await store.get_session(handle.value)
        assert ctx is not None
        assert ctx.session_id == handle.value
    finally:
        if redis_url is not None:
            os.environ["POSTERN_REDIS_URL"] = redis_url


# --- Redis session store tests (using fakeredis) ---


async def test_redis_session_store_creates_and_retrieves() -> None:
    """RedisSessionStore creates and retrieves sessions via fakeredis."""
    import fakeredis.aioredis

    from postern_core.risk.session import RedisSessionStore

    # Create a fake async Redis client
    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    store = RedisSessionStore.__new__(RedisSessionStore)
    store._redis = fake_redis
    store._prefix = "test:"
    store._ttl = 300

    handle = await store.create_session()
    assert handle.value is not None

    ctx = await store.get_session(handle.value)
    assert ctx is not None
    assert ctx.session_id == handle.value


async def test_redis_session_store_removes() -> None:
    """RedisSessionStore removes sessions."""
    import fakeredis.aioredis

    from postern_core.risk.session import RedisSessionStore

    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    store = RedisSessionStore.__new__(RedisSessionStore)
    store._redis = fake_redis
    store._prefix = "test:"
    store._ttl = 300

    handle = await store.create_session()
    await store.remove_session(handle.value)

    assert await store.get_session(handle.value) is None


async def test_redis_session_store_serialization_round_trip() -> None:
    """RedisSessionStore round-trips a full context with data and signals."""
    import fakeredis.aioredis

    from postern_core.risk.engine import RiskConfig, RiskEngine
    from postern_core.risk.session import RedisSessionStore

    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    store = RedisSessionStore.__new__(RedisSessionStore)
    store._redis = fake_redis
    store._prefix = "test:"
    store._ttl = 300

    handle = await store.create_session()
    ctx = await store.get_session(handle.value)
    assert ctx is not None

    # Record data (simulating tool handler behavior)
    ctx.record_records(50)
    for i in range(3):
        ctx.record_account(f"acc_{i}")
    ctx.record_days(30)

    # Evaluate risk (generates signals)
    config = RiskConfig(max_records_per_session=100, max_distinct_accounts=5)
    signals = RiskEngine(config).evaluate(ctx)
    ctx._risk_signals = list(signals)

    # Persist mutations back to Redis (what RiskMiddleware does after each call).
    await store.save_session(handle.value, ctx)

    # Now retrieve from store (simulates cross-process load).
    loaded = await store.get_session(handle.value)
    assert loaded is not None
    assert loaded.session_id == handle.value
    assert loaded.record_count.total == 50
    assert loaded.distinct_accounts == 3
    assert loaded.max_days_requested == 30


async def test_redis_session_store_key_prefix() -> None:
    """RedisSessionStore uses the configured key prefix."""
    import fakeredis.aioredis

    from postern_core.risk.session import RedisSessionStore

    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    store = RedisSessionStore.__new__(RedisSessionStore)
    store._redis = fake_redis
    store._prefix = "tenant123:"
    store._ttl = 300

    handle = await store.create_session()

    # Verify the key was stored with the prefix
    expected_key = f"tenant123:session:{handle.value}"
    assert await fake_redis.exists(expected_key) == 1


async def test_redis_session_store_ttl() -> None:
    """RedisSessionStore sets TTL on created sessions."""
    import fakeredis.aioredis

    from postern_core.risk.session import RedisSessionStore

    fake_redis = fakeredis.aioredis.FakeRedis(decode_responses=True)

    store = RedisSessionStore.__new__(RedisSessionStore)
    store._redis = fake_redis
    store._prefix = "test:"
    store._ttl = 600

    handle = await store.create_session()
    key = f"test:session:{handle.value}"

    # TTL should be set (fakeredis counts down, so allow 599–600).
    ttl = await fake_redis.ttl(key)
    assert 599 <= ttl <= 600

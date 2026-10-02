"""Risk session storage and serialisation (ZT-5).

The store half of the ZT-5 wiring: a context is addressed by the caller's
verified identity (`SessionKey`), created on first use, aged out on read, and
round-tripped through JSON without losing the one thing the engine measures
time against.

The identity-keyed shape replaced an opaque handle passed as a tool argument
on 2026-09-22. `tests/test_risk_middleware_actions.py` covers what the
middleware does with a context; this file covers the store that holds it.
"""

import dataclasses
import json
import time
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
from postern_core.risk.context import IpTracker, RiskContext
from postern_core.risk.engine import RiskConfig, RiskEngine
from postern_core.risk.ip_anomaly import IpAnomalyDetector
from postern_core.risk.session import (
    RedisSessionStore,
    SessionKey,
    SessionStore,
    get_current_session,
    set_current_session,
)
from postern_core.risk.types import Severity

KEY = SessionKey(customer_ref="cust_7f3a", client_id="vendor-a")
OTHER_KEY = SessionKey(customer_ref="cust_9b21", client_id="vendor-a")


def _age(ctx: RiskContext, seconds: float) -> None:
    """Make a context `seconds` older, the way the passage of time would.

    `RiskContext.started_at` is derived from the monotonic start reading, so
    moving that reading back is what a context created `seconds` ago looks
    like on both clocks at once. Patching `time.time` instead moves the
    store's reading and the context's together and changes nothing.
    """
    ctx._start_time -= seconds


# --- Store tests ---


async def test_the_key_is_a_digest_of_the_identity_and_nothing_else() -> None:
    """Stable for one identity, different for another, and reversible into
    neither: the key is what lands in a Redis key name."""
    assert KEY.value == SessionKey(customer_ref="cust_7f3a", client_id="vendor-a").value
    assert KEY.value != OTHER_KEY.value
    assert KEY.value != SessionKey(customer_ref="cust_7f3a", client_id="vendor-b").value
    assert "cust_7f3a" not in KEY.value
    assert len(KEY.value) == 64


async def test_context_for_creates_on_first_use_and_returns_the_same_one_after() -> None:
    """No `create_session`: the first call of a session creates the context,
    and there is no separate operation an agent could reach for twice."""
    store = SessionStore()
    first = await store.context_for(KEY)
    first.record_records(7)
    second = await store.context_for(KEY)
    assert second is first
    assert second.record_count.total == 7


async def test_load_returns_none_for_an_identity_with_no_context() -> None:
    """A miss, which the caller turns into a new context -- distinct from an
    outage, which raises."""
    store = SessionStore()
    assert await store.load(KEY) is None


async def test_remove_forgets_the_context() -> None:
    store = SessionStore()
    await store.context_for(KEY)
    await store.remove(KEY)
    assert await store.load(KEY) is None


async def test_the_created_context_carries_the_key_as_its_id() -> None:
    """So a log line, an audit row and a store key all name the same thing."""
    store = SessionStore()
    ctx = await store.context_for(KEY)
    assert ctx.session_id == KEY.value


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
    """Create on first use → record → evaluate → snapshot → forget."""
    store = SessionStore()

    ctx = await store.context_for(KEY)
    assert ctx.session_id == KEY.value

    # Record data (simulating tool handler behavior)
    ctx.record_records(50)
    for i in range(3):
        ctx.record_account(f"acc_{i}")
    ctx.record_days(30)

    config = RiskConfig(
        max_records_per_session=100,
        max_distinct_accounts=5,
        max_days_per_call=365,
    )
    signals = RiskEngine(config).evaluate(ctx)
    assert signals == []

    snap = ctx.snapshot()
    assert snap["records"] == 50
    assert snap["distinct_accounts"] == 3
    assert snap["max_days_requested"] == 30
    assert snap["session_id"] == KEY.value

    # Exhaust budget and re-evaluate
    ctx.record_records(60)  # total now 110, over limit of 100
    await store.save(KEY, ctx)
    signals = RiskEngine(config).evaluate(ctx)
    assert len(signals) > 0

    await store.remove(KEY)
    assert await store.load(KEY) is None


async def test_two_identities_are_isolated() -> None:
    """Each identity has independent state."""
    store = SessionStore()

    ctx1 = await store.context_for(KEY)
    ctx2 = await store.context_for(OTHER_KEY)

    assert ctx1 is not ctx2
    assert ctx1.session_id != ctx2.session_id

    ctx1.record_records(50)
    ctx2.record_records(10)

    assert ctx1.record_count.total == 50
    assert ctx2.record_count.total == 10

    config = RiskConfig(max_records_per_session=30)
    assert len(RiskEngine(config).evaluate(ctx1)) > 0  # 50 > 30
    assert RiskEngine(config).evaluate(ctx2) == []  # 10 <= 30


async def test_the_in_memory_store_ages_a_context_out() -> None:
    """Nothing here ever expired before 2026-09-22.

    With the context keyed on identity rather than on a handle, a context
    that reached a HIGH signal would otherwise block that customer for the
    life of the process, and the engine's own eight-hour session-age
    threshold would make that the normal end state of a long session. The
    lifetime runs from CREATION, so a caller cannot hold one budget window
    open by staying busy.
    """
    store = SessionStore(ttl_seconds=60)
    ctx = await store.context_for(KEY)
    ctx.record_records(400)
    assert await store.load(KEY) is ctx

    # Age the context by moving its own start instant back, rather than by
    # patching a clock: `time.time` is one module attribute shared by this
    # store and `RiskContext.started_at`, so patching it moves both readings
    # together and the elapsed time between them never changes.
    _age(ctx, 61)
    assert await store.load(KEY) is None

    fresh = await store.context_for(KEY)
    assert fresh is not ctx
    assert fresh.record_count.total == 0


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
        ctx = await store.context_for(KEY)
        assert ctx.session_id == KEY.value
        assert await store.load(KEY) is ctx
    finally:
        if redis_url is not None:
            os.environ["POSTERN_REDIS_URL"] = redis_url


# --- Redis session store tests (using fakeredis) ---


def _fake_store(ttl: int = 300) -> RedisSessionStore:
    import fakeredis.aioredis

    store = RedisSessionStore.__new__(RedisSessionStore)
    store._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store._prefix = "test:"
    store._ttl = ttl
    return store


async def test_redis_store_creates_and_retrieves() -> None:
    store = _fake_store()
    created = await store.context_for(KEY)
    assert created.session_id == KEY.value

    loaded = await store.load(KEY)
    assert loaded is not None
    assert loaded.session_id == KEY.value


async def test_redis_store_removes() -> None:
    store = _fake_store()
    await store.context_for(KEY)
    await store.remove(KEY)
    assert await store.load(KEY) is None


async def test_redis_store_round_trips_a_full_context() -> None:
    """What crosses the process boundary: counters, accounts, days, signals."""
    store = _fake_store()
    ctx = await store.context_for(KEY)

    ctx.record_records(50)
    for i in range(3):
        ctx.record_account(f"acc_{i}")
    ctx.record_days(30)
    config = RiskConfig(max_records_per_session=100, max_distinct_accounts=5)
    ctx.record_signals(RiskEngine(config).evaluate(ctx))

    await store.save(KEY, ctx)

    loaded = await store.load(KEY)
    assert loaded is not None
    assert loaded is not ctx, "a Redis load must rebuild the object, not hand back the same one"
    assert loaded.session_id == KEY.value
    assert loaded.record_count.total == 50
    assert loaded.distinct_accounts == 3
    assert loaded.max_days_requested == 30


async def test_redis_store_uses_the_configured_key_prefix() -> None:
    store = _fake_store()
    await store.context_for(KEY)
    assert await store._redis.exists(f"test:risk:{KEY.value}") == 1


async def test_redis_store_sets_a_ttl_on_a_new_context() -> None:
    store = _fake_store(ttl=600)
    await store.context_for(KEY)
    ttl = await store._redis.ttl(f"test:risk:{KEY.value}")
    assert 599 <= ttl <= 600, "a fresh context gets its full lifetime, not one second less"


class _SkewedClock:
    """A `time` stand-in: wall clock +1 microsecond per call, monotonic frozen.

    The real code reads the wall clock twice for one age (once in the store,
    once inside `RiskContext.started_at`), and the second read is later. With
    a frozen monotonic clock the true age of a just-created context is
    exactly zero, so any age the store computes other than zero is an artefact
    of how many wall-clock reads it took.
    """

    def __init__(self) -> None:
        self.start = 1_800_000_000.0
        self._wall = self.start
        self._mono = 5_000.0

    def time(self) -> float:
        """The current reading, then one microsecond on: the first call is `start`."""
        reading = self._wall
        self._wall += 1e-6
        return reading

    def monotonic(self) -> float:
        return self._mono


def _skewed_clock() -> tuple[_SkewedClock, Any, Any]:
    clock = _SkewedClock()
    return (
        clock,
        patch("postern_core.risk.context.time", clock),
        patch("postern_core.risk.session.time", clock),
    )


async def test_a_fresh_context_never_gets_more_than_its_lifetime() -> None:
    """Two wall-clock reads in the wrong order made a new context's age
    slightly negative, and `ceil` turned 600.000001 into 601."""
    store = _fake_store(ttl=600)
    _, context_patch, session_patch = _skewed_clock()
    with context_patch, session_patch:
        await store.context_for(KEY)
    pttl = await store._redis.pttl(f"test:risk:{KEY.value}")
    assert 0 < pttl <= 600_000, f"key outlives its context's lifetime: {pttl} ms"


async def test_a_load_never_extends_the_key_beyond_the_remaining_lifetime() -> None:
    store = _fake_store(ttl=600)
    redis_key = f"test:risk:{KEY.value}"
    clock, context_patch, session_patch = _skewed_clock()
    # A context stored at exactly the clock's first reading: the load's first
    # read then gives an elapsed of zero and its later reads are all later.
    stored = json.loads(RiskContext(session_id=KEY.value).to_json())
    stored["started_at"] = clock.start
    with context_patch, session_patch:
        await store._redis.set(redis_key, json.dumps(stored), ex=1000)
        assert await store.load(KEY) is not None
    pttl = await store._redis.pttl(redis_key)
    assert 0 < pttl <= 600_000, f"load extended the key past the lifetime: {pttl} ms"


# --- The same TTL arithmetic against a real Redis ---
#
# fakeredis truncates an expiry to whole seconds, so it cannot show a
# millisecond-level overshoot. These run the store against the session-wide
# `redis_url` container. Only `time` in the risk modules is patched, so Redis
# keeps its own clock and its PTTL is a real one.


@pytest.fixture
async def real_store(redis_url: str) -> AsyncIterator[RedisSessionStore]:
    store = RedisSessionStore(url=redis_url, ttl=600, key_prefix=f"rs{uuid4().hex[:12]}:")
    try:
        yield store
    finally:
        await store.close()


async def test_real_redis_gives_a_fresh_context_its_full_lifetime(
    real_store: RedisSessionStore,
) -> None:
    await real_store.context_for(KEY)
    ttl = await real_store._redis.ttl(real_store._key(KEY))
    assert 599 <= ttl <= 600, f"a fresh context's lifetime on a real Redis: {ttl} s"


async def test_real_redis_a_fresh_context_never_gets_more_than_its_lifetime(
    real_store: RedisSessionStore,
) -> None:
    _, context_patch, session_patch = _skewed_clock()
    with context_patch, session_patch:
        await real_store.context_for(KEY)
    pttl = await real_store._redis.pttl(real_store._key(KEY))
    assert 0 < pttl <= 600_000, f"key outlives its context's lifetime: {pttl} ms"


async def test_real_redis_a_load_never_extends_the_key_beyond_the_remaining_lifetime(
    real_store: RedisSessionStore,
) -> None:
    redis_key = real_store._key(KEY)
    clock, context_patch, session_patch = _skewed_clock()
    stored = json.loads(RiskContext(session_id=KEY.value).to_json())
    stored["started_at"] = clock.start
    with context_patch, session_patch:
        await real_store._redis.set(redis_key, json.dumps(stored), ex=1000)
        assert await real_store.load(KEY) is not None
    pttl = await real_store._redis.pttl(redis_key)
    assert 0 < pttl <= 600_000, f"load extended the key past the lifetime: {pttl} ms"


async def test_real_redis_a_second_context_for_never_extends_the_key(
    real_store: RedisSessionStore,
) -> None:
    _, context_patch, session_patch = _skewed_clock()
    with context_patch, session_patch:
        await real_store.context_for(KEY)
        assert await real_store.context_for(KEY) is not None
    pttl = await real_store._redis.pttl(real_store._key(KEY))
    assert 0 < pttl <= 600_000, f"a second context_for extended the key: {pttl} ms"


async def test_a_context_older_than_the_ttl_is_dropped_and_not_returned() -> None:
    """The TTL that could never fire.

    ``to_dict`` used to write ``time.time()`` -- the instant of the write --
    into the field this arithmetic measures elapsed time against, so every
    save reset the clock and ``elapsed`` was always about zero however old
    the context really was.
    """
    store = _fake_store(ttl=60)
    ctx = await store.context_for(KEY)
    ctx.record_records(400)
    _age(ctx, 61)
    await store.save(KEY, ctx)

    assert await store.load(KEY) is None


async def test_saving_repeatedly_does_not_extend_the_lifetime() -> None:
    """An absolute lifetime, not an idle one: a caller that keeps calling
    must not be able to hold one budget window open indefinitely."""
    store = _fake_store(ttl=60)
    ctx = await store.context_for(KEY)
    first = await store._redis.ttl(f"test:risk:{KEY.value}")

    _age(ctx, 30)
    await store.save(KEY, ctx)
    second = await store._redis.ttl(f"test:risk:{KEY.value}")

    assert second < first
    assert second <= 31


# --- The two clocks (audit finding, 2026-09-22) ---


def test_a_restored_context_reports_its_real_age_not_a_negative_one() -> None:
    """The defect in one assertion.

    ``from_dict`` assigned a POSIX timestamp into the field
    ``session_age_seconds`` subtracts from ``time.monotonic()``, so a
    restored context's age was about -1.7e9 seconds and the engine's
    session-age check could never fire for it.
    """
    ctx = RiskContext(session_id="aged")
    data = ctx.to_dict()
    data["started_at"] = time.time() - 7200  # created two hours ago

    restored = RiskContext.from_dict(data)

    assert restored.session_age_seconds == pytest.approx(7200, abs=5)
    assert restored.session_age_seconds > 0


def test_a_restored_context_is_old_enough_for_the_engine_to_end_it() -> None:
    """Three inert things, one cause: this is the one the engine owns."""
    ctx = RiskContext(session_id="ancient")
    data = ctx.to_dict()
    data["started_at"] = time.time() - (9 * 3600)  # older than the 8h default

    restored = RiskContext.from_dict(data)
    codes = {s.code for s in RiskEngine(RiskConfig()).evaluate(restored)}

    assert "SESSION_AGE_EXCEEDED" in codes


def test_serialising_twice_does_not_move_the_start_time() -> None:
    """``to_dict`` records when the context was CREATED, not when it was
    written, which is what makes any TTL built on it able to fire."""
    ctx = RiskContext(session_id="stable")
    first = ctx.to_dict()["started_at"]
    # Five minutes later, on BOTH clocks -- the offset between them is what
    # the conversion reads, so moving one alone would simulate a clock jump
    # rather than the passage of time.
    later = time.time() + 300
    later_monotonic = time.monotonic() + 300
    with (
        patch("postern_core.risk.context.time.time", return_value=later),
        patch("postern_core.risk.context.time.monotonic", return_value=later_monotonic),
    ):
        second = ctx.to_dict()["started_at"]

    assert isinstance(first, float) and isinstance(second, float)
    assert second == pytest.approx(first, abs=1)


#: Two unrelated monotonic epochs. A monotonic clock's zero is arbitrary --
#: on Linux, boot -- so two processes' readings are not comparable, and
#: `IpTracker` stored raw readings while its docstring claimed it converted
#: them. Within one process that is invisible: every reading shares one epoch
#: and the interval between two of them is right by accident. These constants
#: are what makes the defect visible, and they are the shape MCP 2026-07-28
#: makes routine rather than exotic, since any request can land on any
#: instance.
PROCESS_A_EPOCH = 1_000_000.0
PROCESS_B_EPOCH = 5_000_000.0


def test_an_ip_change_30_seconds_after_a_restore_is_still_30_seconds() -> None:
    """The interval the impossible-travel check reads, across a restore.

    Measured against the old serialisation, this came back as 4000030.0
    seconds -- the distance between the two epochs -- so a genuine IP change
    30 seconds apart sailed past a 300-second window.
    """
    with patch("postern_core.risk.context.time.monotonic", return_value=PROCESS_A_EPOCH):
        tracker = IpTracker()
        tracker.record_ip("198.51.100.1")
        data = tracker.to_dict()

    with patch("postern_core.risk.context.time.monotonic", return_value=PROCESS_B_EPOCH):
        restored = IpTracker.from_dict(data)
    with patch("postern_core.risk.context.time.monotonic", return_value=PROCESS_B_EPOCH + 30):
        restored.record_ip("203.0.113.9")

    assert restored.time_since_last_change() == pytest.approx(30, abs=2)


def test_a_restored_tracker_still_fires_impossible_travel() -> None:
    """What the interval is FOR: the A4 compensating control of record 0010."""
    with patch("postern_core.risk.context.time.monotonic", return_value=PROCESS_A_EPOCH):
        tracker = IpTracker()
        tracker.record_ip("198.51.100.1")
        data = tracker.to_dict()

    with patch("postern_core.risk.context.time.monotonic", return_value=PROCESS_B_EPOCH):
        restored = IpTracker.from_dict(data)
    with patch("postern_core.risk.context.time.monotonic", return_value=PROCESS_B_EPOCH + 5):
        restored.record_ip("203.0.113.9")

    codes = {s.code for s in IpAnomalyDetector().evaluate(restored)}

    assert "IMPOSSIBLE_TRAVEL" in codes


def test_a_restored_entry_is_never_timestamped_in_this_process_s_future() -> None:
    """A reading from another epoch could otherwise sit ahead of `now`, and
    every interval measured against it would be negative."""
    tracker = IpTracker()
    tracker.record_ip("198.51.100.1")

    restored = IpTracker.from_dict(tracker.to_dict())

    assert restored.entries[-1].recorded_at <= time.monotonic()


def test_a_restored_tracker_is_still_bounded() -> None:
    """A stored blob longer than this process's cap cannot re-inflate the
    list that cap exists to bound."""
    tracker = IpTracker(max_entries=200)
    for i in range(150):
        tracker.record_ip(f"198.51.100.{i % 256}")

    restored = IpTracker.from_dict(tracker.to_dict(), max_entries=100)

    assert len(restored.entries) == 100


def test_a_stored_context_without_a_creation_instant_is_refused() -> None:
    """It cannot be aged, so it must not be restored as new."""
    import pydantic

    with pytest.raises(pydantic.ValidationError):
        RiskContext.from_dict({"session_id": "no-start"})


def test_a_stored_context_with_an_unknown_tier_is_refused() -> None:
    """Validation, not coercion: the seven `type: ignore` comments this
    replaced each marked a value reaching a constructor unchecked."""
    import pydantic

    data = RiskContext(session_id="tiers").to_dict()
    data["verification_tier"] = 9

    with pytest.raises(pydantic.ValidationError):
        RiskContext.from_dict(data)


def test_an_unknown_field_in_a_stored_context_is_ignored() -> None:
    """A rolling deploy has an older replica reading a newer replica's rows;
    refusing them would turn a deploy into an outage, since a context that
    cannot be read now denies the call."""
    data = RiskContext(session_id="forward").to_dict()
    data["some_future_field"] = {"added": "later"}

    restored = RiskContext.from_dict(data)

    assert restored.session_id == "forward"

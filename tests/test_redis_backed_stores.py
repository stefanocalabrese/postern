"""The three Redis-backed stores, against a real Redis.

WHAT THIS FILE IS FOR. Production sets ``POSTERN_REDIS_URL`` and gets
`postern_core/auth/device_codes.py`'s `RedisDeviceCodeStore`,
`postern_core/risk/session.py`'s `RedisSessionStore` and
`postern_core/auth/revocation.py`'s `RedisRevocationStore`. Until this file,
no Redis server of any kind ran in this repository: `pg_url` in
tests/conftest.py starts a Postgres container and nothing started a Redis
one, so those three classes were verified by reading.

WHAT ``fakeredis`` ALREADY COVERS, and why this does not replace it. Four
files drive Redis code through ``fakeredis``, they are fast, they pass, and
none of them is touched here:

- tests/test_risk_session_wiring.py -- `RedisSessionStore` round trips,
  prefix, TTL arithmetic, the two-clock conversion.
- tests/test_risk_middleware_actions.py -- a corrupt stored value refusing a
  call.
- tests/test_zt7_revocation_reachable.py and
  tests/test_zt7_confirm_revocation.py -- `RedisRevocationStore` across two
  replicas and the operator's CLI, and the memory/Redis parity matrix for
  ``is_customer_revoked``.

Measured on 2026-09-25, fakeredis 2.38.0 against redis:7-alpine, over every
command these three stores issue (SETEX, GET, TTL, EXPIRE, DEL, ZADD, ZCARD,
ZREM, ZSCORE, ZRANGE, ZREMRANGEBYSCORE, SADD, SREM, SISMEMBER, SMEMBERS, and
pipelines of those): no behavioural divergence. Float scores at POSIX
magnitude round trip bit-exact through both, ``ZREMRANGEBYSCORE`` is
inclusive on both, ``TTL`` answers -2 / -1 identically, ``SISMEMBER`` returns
``int`` on both, and ``decode_responses=True`` raises ``UnicodeDecodeError``
on both. Two answers differed and neither is a behaviour: the wording of one
``ResponseError`` ("invalid expire time in setex" against "invalid expire
time in 'setex' command"), and the order a ``SMEMBERS`` reply iterates in,
which redis-py turns into a Python ``set`` before either library is asked,
so that order is Python's and not the server's.

So the case for a container is not that fakeredis answers wrongly. It is:

1. `RedisDeviceCodeStore` appears in NO test, fake or otherwise. Its sorted
   set index -- the control that bounds an unauthenticated caller's standing
   memory cost -- had never executed.
2. The clock. fakeredis expires keys in the TEST process, against the test
   process's own ``time.time``. Measured: a key with TTL 60, read while the
   test process's clock is patched an hour forward, reads ``EXISTS 0`` and
   ``TTL -2`` on fakeredis and stays ``EXISTS 1`` / ``TTL 60`` on
   redis:7-alpine. fakeredis really deletes it, so it is still gone after
   the patch lifts. A store whose TTL arithmetic is wrong can therefore look
   correct under a clock-patching fakeredis test, because the patch drops the
   key whatever TTL it carries. The expiries asserted below are the server's.
3. The constructor. tests/test_risk_session_wiring.py builds its store with
   ``RedisSessionStore.__new__`` and assigns ``_redis`` itself, so
   ``__init__`` never runs and the ``decode_responses=True`` under test is
   the test's, not the code's. Every store here is built through ``__init__``
   against a real URL.
4. A socket that refuses. fakeredis cannot be unreachable, so "fails closed"
   was asserted only where a fake could be made to raise.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import socket
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
import redis.exceptions
from postern_core.auth.device_codes import (
    MIN_DEVICE_CODE_TTL_SECONDS,
    DeviceCode,
    DeviceCodeStoreFull,
    RedisDeviceCodeStore,
    create_device_code_store,
)
from postern_core.auth.revocation import RedisRevocationStore, RevocationStoreUnavailable
from postern_core.risk.context import RiskContext
from postern_core.risk.session import (
    MIN_SESSION_TTL_SECONDS,
    RedisSessionStore,
    SessionKey,
    SessionStoreUnavailable,
    create_session_store,
)

KEY = SessionKey(customer_ref="cust_7f3a", client_id="vendor-a")
OWNER = "cust_7f3a"
OTHER = "cust_9b21"

VERIFY_URI = "https://bank.example/device"


# ---------------------------------------------------------------------------
# Harness.
# ---------------------------------------------------------------------------


class RedisStores:
    """Builds the three stores against one container and one key namespace.

    THROUGH ``__init__``, never ``__new__``, which is the point of item 3 in
    this module's docstring: ``redis.asyncio.from_url`` and the
    ``decode_responses=True`` each constructor passes are then the code's
    behaviour under test rather than the harness's.

    Every pool handed out is closed at teardown, so a suite that opens a
    store per test does not leave one connection per test open against the
    session-scoped container.
    """

    def __init__(self, url: str, prefix: str) -> None:
        self.url = url
        self.prefix = prefix
        self._opened: list[RedisSessionStore | RedisDeviceCodeStore | RedisRevocationStore] = []

    def sessions(self, ttl: int = 1800) -> RedisSessionStore:
        store = RedisSessionStore(url=self.url, ttl=ttl, key_prefix=self.prefix)
        self._opened.append(store)
        return store

    def device_codes(self, max_codes: int = 10_000, default_ttl: int = 900) -> RedisDeviceCodeStore:
        store = RedisDeviceCodeStore(
            url=self.url,
            default_ttl=default_ttl,
            key_prefix=self.prefix,
            max_codes=max_codes,
        )
        self._opened.append(store)
        return store

    def revocations(self) -> RedisRevocationStore:
        store = RedisRevocationStore(url=self.url, key_prefix=self.prefix)
        self._opened.append(store)
        return store

    async def aclose(self) -> None:
        for store in self._opened:
            await store.close()


@pytest_asyncio.fixture
async def stores(redis_url: str) -> AsyncIterator[RedisStores]:
    """One key namespace per test, over the session-scoped container.

    ISOLATION BY PREFIX, and the three alternatives and what each costs:

    - A flush between tests is a round trip per test and, worse, it is
      global: the session store, the device code store and the revocation
      store share one ``POSTERN_REDIS_URL`` by design, so a flush aimed at
      one clears the others.
    - A logical database per test (``redis://host:port/N``) runs out at 16 on
      a default server, and this file alone has more tests than that.
    - Deleting this test's keys at teardown is a ``SCAN`` plus a ``DEL`` per
      test, and ``SCAN`` is O(keyspace).

    A prefix costs nothing at either end and is what the production code is
    already parameterised on (``POSTERN_REDIS_KEY_PREFIX``, for multi-tenant
    deployments). What it costs instead: keys outlive their test, for the
    run. That is bounded and small -- every key this file writes carries a
    TTL except the three revocation sets, which carry none by design -- and
    it is safe only because nothing here counts the whole keyspace.
    `RedisDeviceCodeStore`'s own ``_index_key`` docstring rejects ``DBSIZE``
    and ``SCAN`` for exactly that reason, and
    ``test_the_cap_counts_one_prefix_and_not_the_database`` below pins it.
    """
    bundle = RedisStores(url=redis_url, prefix=f"t{uuid4().hex[:12]}:")
    yield bundle
    await bundle.aclose()


def _age(ctx: RiskContext, seconds: float) -> None:
    """Make a context `seconds` older, the way the passage of time would.

    Copied from tests/test_risk_session_wiring.py, for the reason its own
    copy gives: ``started_at`` is derived from the monotonic start reading,
    so moving that reading back is what a context created `seconds` ago looks
    like on both clocks at once. It also cannot be replaced here by patching
    ``time.time``, because on a real server the expiry that patch would have
    to move belongs to the server (item 2 of this module's docstring).
    """
    ctx._start_time -= seconds


#: How long any wait below will tolerate before failing the test. Named
#: `within` at every call site rather than `timeout`, because ASYNC109 reads
#: an async `timeout` parameter as a promise of `asyncio.timeout` semantics
#: and these helpers poll instead.
WAIT_LIMIT_SECONDS = 5.0


async def _wait_until_gone(redis: Any, key: str, *, within: float = WAIT_LIMIT_SECONDS) -> float:
    """Block until the SERVER has dropped `key`, and answer how long it took.

    Bounded and polled rather than a flat ``asyncio.sleep`` past the TTL: the
    wait is then the real expiry latency instead of a padded constant, and a
    key that never expires fails the test loudly instead of hanging the run.
    """
    started = time.monotonic()
    while time.monotonic() - started < within:
        if not await redis.exists(key):
            return time.monotonic() - started
        await asyncio.sleep(0.02)
    pytest.fail(f"{key} was still present {within}s after its TTL should have dropped it")


async def _wait_until_past(posix_instant: float, *, within: float = WAIT_LIMIT_SECONDS) -> None:
    """Block until the wall clock has passed `posix_instant`.

    What the index sweep compares against, and it is NOT the same instant the
    key dies at. ``_set_code`` writes the key with ``int(remaining)`` seconds
    and the member with the exact ``expires_at`` float, so the key always
    goes up to a second before the member becomes due.
    """
    started = time.monotonic()
    while time.monotonic() - started < within:
        if time.time() > posix_instant:
            return
        await asyncio.sleep(0.02)
    pytest.fail(f"waited {within}s and the clock had still not passed {posix_instant}")


#: The shortest lifetime `RedisDeviceCodeStore` actually stores.
#:
#: ``_set_code`` computes ``max(0, int((expires_at - now).total_seconds()))``,
#: and ``int`` truncates. A code asked for 1 second has roughly 0.9998 left by
#: the time that line runs, so it floors to 0, the ``if ttl_seconds > 0``
#: guard skips both writes, and ``create_device_code`` returns a code it
#: stored nowhere. 2 is therefore the smallest value these tests can use and
#: still have something to observe.
SHORTEST_STORED_TTL = 2


def _closed_port_url() -> str:
    """A ``redis://`` URL for a loopback port nothing is listening on.

    Binding to port 0 and closing hands back a port the kernel has just
    confirmed free, so connecting to it is refused immediately rather than
    waiting out a timeout. The explicit ``socket_connect_timeout`` bounds the
    one case where it is filtered rather than refused.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"redis://127.0.0.1:{port}/0?socket_connect_timeout=1"


# ---------------------------------------------------------------------------
# The device code store's sorted-set index. None of this had ever executed.
# ---------------------------------------------------------------------------


async def _create(store: RedisDeviceCodeStore, **kwargs: Any) -> DeviceCode:
    return await store.create_device_code(
        client_id="vendor-a", scopes="accounts:read", verification_uri=VERIFY_URI, **kwargs
    )


async def test_the_cap_refuses_a_creation_once_the_index_is_full(stores: RedisStores) -> None:
    """``ZCARD`` is what the cap reads, so three codes must be three members.

    `DeviceCodeStoreFull` carries the two numbers its message quotes, and a
    caller that trusted the exception rather than the index would not notice
    an index counting something else.
    """
    store = stores.device_codes(max_codes=3)

    created = [await _create(store) for _ in range(3)]

    with pytest.raises(DeviceCodeStoreFull) as caught:
        await _create(store)

    assert caught.value.held == 3
    assert caught.value.cap == 3
    assert await store._redis.zcard(store._index_key()) == 3
    assert len({code.device_code for code in created}) == 3


async def test_a_store_full_of_expired_codes_still_admits_a_new_pairing(
    stores: RedisStores,
) -> None:
    """The sweep runs BEFORE the cap is consulted, against the real expiry.

    `RedisDeviceCodeStore`'s ``create_device_code`` docstring calls refusing
    while holding a store of unusable codes "a denial of service performed on
    this service's behalf by its own bookkeeping". This is that sentence as
    an assertion: fill the cap with codes that live `SHORTEST_STORED_TTL`
    seconds, let the SERVER drop them, and a fourth pairing must be
    admitted. Both waits are needed and they are not the same instant: the
    key goes at ``int(remaining)`` and the member is only due at the exact
    ``expires_at`` the score carries.
    """
    store = stores.device_codes(max_codes=3)
    codes = [await _create(store, expires_in=SHORTEST_STORED_TTL) for _ in range(3)]

    with pytest.raises(DeviceCodeStoreFull):
        await _create(store, expires_in=SHORTEST_STORED_TTL)

    for code in codes:
        await _wait_until_gone(store._redis, store._key(code.device_code))
    await _wait_until_past(max(code.expires_at.timestamp() for code in codes))

    admitted = await _create(store, expires_in=900)

    assert await store.get_device_code(admitted.device_code) is not None
    assert await store._redis.zcard(store._index_key()) == 1, (
        "the three due members were swept and only the new one is indexed"
    )


async def test_revoking_a_code_frees_the_slot_the_cap_counts(stores: RedisStores) -> None:
    """The ``ZREM`` half of `RedisDeviceCodeStore`'s ``revoke_device_code``.

    Without it the index keeps counting a code that no longer exists, and a
    service that revokes normally refuses pairings it has room for. Both
    directions are asserted, because the refusal alone would also be
    satisfied by a cap that never admits anything.
    """
    store = stores.device_codes(max_codes=2)
    first = await _create(store)
    await _create(store)

    with pytest.raises(DeviceCodeStoreFull):
        await _create(store)

    await store.revoke_device_code(first.device_code)

    assert await store._redis.zcard(store._index_key()) == 1
    admitted = await _create(store)
    assert await store.get_device_code(admitted.device_code) is not None
    assert await store._redis.zcard(store._index_key()) == 2


async def test_a_revoke_leaves_the_index_and_the_keys_agreeing(stores: RedisStores) -> None:
    """Agreement is the property, not just the count.

    The revoked code must be gone from both the value keyspace and the
    index, and the other two must still be in both.
    """
    store = stores.device_codes(max_codes=10)
    codes = [await _create(store) for _ in range(3)]
    dropped, *kept = codes

    await store.revoke_device_code(dropped.device_code)

    indexed = set(await store._redis.zrange(store._index_key(), 0, -1))
    assert dropped.device_code not in indexed
    assert await store.get_device_code(dropped.device_code) is None
    for code in kept:
        assert code.device_code in indexed
        assert await store.get_device_code(code.device_code) is not None


async def test_an_update_rescores_the_index_member_instead_of_adding_a_second(
    stores: RedisStores,
) -> None:
    """``ZADD`` on every write, not only on creation.

    A sorted set cannot hold a member twice, so a count alone proves nothing
    here. The score is the assertion: after an update that moves the expiry,
    the index must name the NEW instant, or the sweep would drop a live code
    at the old one, or keep a dead code past it.
    """
    store = stores.device_codes()
    code = await _create(store, expires_in=120)
    assert await store._redis.zscore(store._index_key(), code.device_code) == pytest.approx(
        code.expires_at.timestamp(), abs=0.001
    )

    extended = dataclasses.replace(code, expires_at=code.expires_at + timedelta(seconds=600))
    await store.update_device_code(code.device_code, extended)

    assert await store._redis.zcard(store._index_key()) == 1
    assert await store._redis.zscore(store._index_key(), code.device_code) == pytest.approx(
        extended.expires_at.timestamp(), abs=0.001
    )
    assert 700 <= await store._redis.ttl(store._key(code.device_code)) <= 720, (
        "the key's own TTL moved with the score, so neither outlives the other"
    )


async def test_an_update_that_shortens_a_life_moves_the_member_earlier(
    stores: RedisStores,
) -> None:
    """The direction the cap depends on.

    An index that only ever grew scores would hold a member past the instant
    its key died, and the sweep would never reach it. That the sweep then
    does reach a due member is the same mechanism
    ``test_a_store_full_of_expired_codes_still_admits_a_new_pairing`` proves
    against the server's own clock; this pins the re-score that feeds it.
    """
    store = stores.device_codes()
    code = await _create(store, expires_in=900)
    original = await store._redis.zscore(store._index_key(), code.device_code)

    shortened = dataclasses.replace(code, expires_at=datetime.now(UTC) + timedelta(seconds=5))
    await store.update_device_code(code.device_code, shortened)

    moved = await store._redis.zscore(store._index_key(), code.device_code)
    assert moved < original
    assert moved == pytest.approx(shortened.expires_at.timestamp(), abs=0.001)


async def test_an_index_member_outlives_the_key_it_points_at_until_a_create_sweeps_it(
    stores: RedisStores,
) -> None:
    """Divergence, one direction: a member whose value has expired.

    ``SETEX`` drops the value on the server's clock; nothing drops the
    member. So between a code's expiry and the next creation, the index
    over-counts, and the cap is briefly stricter than the store's real
    contents. That is by design -- the repair is the ``ZREMRANGEBYSCORE`` on
    the next create -- and it is asserted rather than assumed, because the
    alternative reading is an index that leaks a member per expired code
    forever.
    """
    store = stores.device_codes(max_codes=10)
    doomed = await _create(store, expires_in=SHORTEST_STORED_TTL)

    await _wait_until_gone(store._redis, store._key(doomed.device_code))

    assert await store.get_device_code(doomed.device_code) is None, "the value is gone"
    assert await store._redis.zcard(store._index_key()) == 1, "the member is not"

    await _wait_until_past(doomed.expires_at.timestamp())
    await _create(store, expires_in=900)

    indexed = set(await store._redis.zrange(store._index_key(), 0, -1))
    assert doomed.device_code not in indexed, "the create swept it"
    assert len(indexed) == 1


async def test_a_key_whose_index_member_was_lost_is_still_served_but_no_longer_counted(
    stores: RedisStores,
) -> None:
    """Divergence, the other direction, and which way the store errs.

    A member removed while its value lives -- a half-applied revoke, a
    ``ZREM`` that landed when the ``DEL`` did not -- leaves the cap
    UNDER-counting. `RedisDeviceCodeStore`'s ``get_device_code`` reads the
    value and never the index, so the pairing still works and the store
    over-admits rather than refusing a customer already waiting. That is the
    same trade `DeviceCodeStoreFull` records for the cap itself, and it is
    worth having written down as behaviour rather than inferred.
    """
    store = stores.device_codes(max_codes=10)
    code = await _create(store)

    await store._redis.zrem(store._index_key(), code.device_code)

    assert await store.get_device_code(code.device_code) is not None
    assert await store._redis.zcard(store._index_key()) == 0
    assert await store._redis.exists(store._key(code.device_code)) == 1


async def test_a_code_whose_expiry_has_already_passed_is_never_written_or_indexed(
    stores: RedisStores,
) -> None:
    """``_set_code`` skips both writes when the TTL has already run out.

    Skipping the value alone would leave the index holding a member that is
    due the moment it lands, which the cap would then count until the next
    create swept it.
    """
    store = stores.device_codes()
    stale = DeviceCode(
        device_code="dc_already_dead",
        user_code="ABC234",
        verification_uri=VERIFY_URI,
        expires_at=datetime.now(UTC) - timedelta(seconds=30),
    )

    await store.update_device_code(stale.device_code, stale)

    assert await store.get_device_code(stale.device_code) is None
    assert await store._redis.zcard(store._index_key()) == 0


async def test_the_cap_counts_one_prefix_and_not_the_database(stores: RedisStores) -> None:
    """``ZCARD`` on one index, which is why the docstring rejects ``DBSIZE``.

    Two tenants share one database here, exactly as the session store and
    the revocation store share it with this one in production. Under
    ``DBSIZE`` or a ``SCAN`` count, the second tenant's first pairing would
    be refused by the first tenant's code.
    """
    tenant_a = stores.device_codes(max_codes=1)
    tenant_b = RedisDeviceCodeStore(
        url=stores.url, key_prefix=f"{stores.prefix}other:", max_codes=1
    )
    try:
        await _create(tenant_a)
        with pytest.raises(DeviceCodeStoreFull):
            await _create(tenant_a)

        admitted = await _create(tenant_b)

        assert await tenant_b.get_device_code(admitted.device_code) is not None
    finally:
        await tenant_b.close()


async def test_a_device_code_round_trips_every_field_to_a_second_connection(
    stores: RedisStores,
) -> None:
    """Two stores, two pools, one server: what a second replica reads back.

    ``expires_at`` crosses as a POSIX float and returns as a ``datetime``,
    and ``customer_ref`` and ``user_code_attempts`` are the two fields audit
    finding C-01 turned into separate fields, so a round trip that lost
    either would re-open it.
    """
    writer = stores.device_codes()
    reader = stores.device_codes()
    code = await _create(writer, expires_in=600)

    updated = dataclasses.replace(code, customer_ref="cust_7f3a", user_code_attempts=2)
    await writer.update_device_code(code.device_code, updated)

    seen = await reader.get_device_code(code.device_code)

    assert seen is not None
    assert seen.device_code == code.device_code
    assert seen.user_code == code.user_code
    assert seen.verification_uri == VERIFY_URI
    assert seen.client_id == "vendor-a"
    assert seen.scopes == "accounts:read"
    assert seen.customer_ref == "cust_7f3a"
    assert seen.user_code_attempts == 2
    assert seen.expires_at.timestamp() == pytest.approx(code.expires_at.timestamp(), abs=0.001)
    assert isinstance(await reader._redis.get(reader._key(code.device_code)), str), (
        "decode_responses=True comes from RedisDeviceCodeStore.__init__, not from a fixture"
    )


async def test_an_approval_crosses_to_a_second_connection_and_cannot_be_repeated(
    stores: RedisStores,
) -> None:
    """``approve_device_code`` reads, rebuilds and writes back over the wire."""
    writer = stores.device_codes()
    reader = stores.device_codes()
    code = await _create(writer)

    assert await writer.approve_device_code(code.device_code) is True

    seen = await reader.get_device_code(code.device_code)
    assert seen is not None
    assert seen.approved is True
    assert seen.approved_at is not None
    assert await reader.approve_device_code(code.device_code) is False, (
        "a second approval is refused on the value the server holds"
    )


async def test_the_key_carries_the_codes_own_lifetime_not_the_stores_default(
    stores: RedisStores,
) -> None:
    """``expires_in`` beats ``POSTERN_REDIS_DEVICE_CODE_TTL`` on the key too."""
    store = stores.device_codes(default_ttl=900)
    code = await _create(store, expires_in=120)

    assert 118 <= await store._redis.ttl(store._key(code.device_code)) <= 120


async def test_the_key_dies_before_the_index_says_its_member_is_due(
    stores: RedisStores,
) -> None:
    """The two halves of a write are rounded differently, so they never agree.

    ``_set_code`` writes the key with ``int(remaining)`` whole seconds and
    the member with the exact ``expires_at`` float. Measured here: a code
    asked for 120 seconds gets a key TTL of 119 and an index score 120
    seconds out. So for the last second of every code's life the index
    counts a key the server has already dropped, and the cap is that much
    stricter than the store's real contents.

    Recorded rather than corrected: it is bounded at one second per code,
    it is repaired by the next create's sweep, and it errs toward refusing a
    new pairing rather than toward admitting past the cap. A reader who
    assumed the two instants matched would mis-read every expiry test above.
    """
    store = stores.device_codes()
    code = await _create(store, expires_in=120)

    key_ttl = await store._redis.ttl(store._key(code.device_code))
    score = await store._redis.zscore(store._index_key(), code.device_code)

    assert key_ttl <= 119, "int() floored the key's lifetime below the 120 asked for"
    assert score == pytest.approx(code.expires_at.timestamp(), abs=1e-6), (
        "the member kept the exact instant the key was rounded off"
    )


# ---------------------------------------------------------------------------
# The session store: the two clocks, and a TTL the server enforces.
# ---------------------------------------------------------------------------


async def test_a_restored_context_reports_its_true_age_across_a_real_round_trip(
    stores: RedisStores,
) -> None:
    """The conversion at the serialisation boundary, over a real connection.

    ``_to_wall_clock`` on the way out and ``_from_wall_clock`` on the way in.
    Before 2026-09-22 this came back as roughly -1.7e9 seconds, which is what
    made `postern_core/risk/engine.py`'s `RiskEngine` unable to ever emit
    ``SESSION_AGE_EXCEEDED``. A second store is what reads it, because a
    monotonic reading is meaningless outside the process that took it and one
    store handing back its own object would not show that.
    """
    writer = stores.sessions(ttl=1800)
    reader = stores.sessions(ttl=1800)
    ctx = await writer.context_for(KEY)
    ctx.record_records(50)
    ctx.record_account("acc_1")
    _age(ctx, 600)
    await writer.save(KEY, ctx)

    restored = await reader.load(KEY)

    assert restored is not None
    assert restored is not ctx
    assert restored.session_age_seconds == pytest.approx(600, abs=5)
    assert restored.session_age_seconds > 0
    assert restored.record_count.total == 50
    assert restored.distinct_accounts == 1


async def test_the_ttl_the_store_sets_is_the_one_the_server_enforces(
    stores: RedisStores,
) -> None:
    """The expiry no clock patch can fake.

    fakeredis would drop this key on a patched ``time.time`` in the test
    process whatever TTL ``save`` wrote. Here the only thing that can drop it
    is the server acting on the TTL ``setex`` actually carried, and ``load``
    must then report a MISS rather than raise: an identity with no context is
    the ordinary first call of a session, not an outage.
    """
    store = stores.sessions(ttl=1)
    await store.context_for(KEY)
    assert await store._redis.exists(store._key(KEY)) == 1

    elapsed = await _wait_until_gone(store._redis, store._key(KEY))

    assert elapsed >= 0.9, "the key lived out its second rather than never being written"
    assert await store.load(KEY) is None


async def test_a_read_re_asserts_the_remaining_lifetime_and_does_not_extend_it(
    stores: RedisStores,
) -> None:
    """``load`` calls ``EXPIRE`` with what is left, never with the full TTL.

    An absolute lifetime, not an idle one: a caller that keeps calling must
    not hold one budget window open indefinitely. The existing fakeredis test
    covers the same property on ``save``; this is the ``load`` half, and it
    is the one that fires on every single tool call.
    """
    store = stores.sessions(ttl=120)
    ctx = await store.context_for(KEY)
    assert 118 <= await store._redis.ttl(store._key(KEY)) <= 120

    _age(ctx, 60)
    await store.save(KEY, ctx)
    after_save = await store._redis.ttl(store._key(KEY))

    assert await store.load(KEY) is not None

    after_load = await store._redis.ttl(store._key(KEY))
    assert 58 <= after_save <= 61
    assert 58 <= after_load <= 61, "a read must not hand the context a fresh 120 seconds"


async def test_a_context_past_its_ttl_is_deleted_from_the_server_on_load(
    stores: RedisStores,
) -> None:
    """``load`` deletes rather than leaving a dead context for the next read.

    The value is written with a long key TTL and an old ``started_at``, which
    is what a deploy that shortened ``POSTERN_REDIS_SESSION_TTL`` leaves
    behind: the key is nowhere near expiry, the context is past it, and the
    ageing is the store's job and not the server's. Asserting ``EXISTS`` on
    both sides of the ``load`` is what separates "deleted" from "was never
    there".
    """
    store = stores.sessions(ttl=60)
    ctx = RiskContext(session_id=KEY.value)
    _age(ctx, 3600)
    await store._redis.setex(store._key(KEY), 600, ctx.to_json())
    assert await store._redis.exists(store._key(KEY)) == 1

    assert await store.load(KEY) is None

    assert await store._redis.exists(store._key(KEY)) == 0


async def test_a_stored_value_that_is_not_valid_utf8_is_a_refusal_not_a_miss(
    stores: RedisStores,
) -> None:
    """A decoder failure, which is a different path from a JSON failure.

    tests/test_risk_middleware_actions.py already covers a value that parses
    as text and not as JSON. This is the one that never reaches ``json``:
    ``decode_responses=True`` makes the client decode the reply, so bytes
    that are not UTF-8 raise inside the client. Both must end as a refusal,
    because a fresh context would zero the budget the key holds.
    """
    store = stores.sessions()
    await store._redis.execute_command("SET", store._key(KEY), b"\xff\xfe\x00")

    with pytest.raises(SessionStoreUnavailable):
        await store.load(KEY)


async def test_two_replicas_share_one_budget_through_the_server(stores: RedisStores) -> None:
    """What ``POSTERN_REDIS_URL`` exists for.

    MCP 2026-07-28 removed protocol-level sessions, so any request lands on
    any instance. A budget that did not cross would be a per-replica budget,
    which is what `postern_core/risk/session.py`'s `InMemorySessionStore`
    docstring says it is and this backend exists not to be.
    """
    replica_a = stores.sessions()
    replica_b = stores.sessions()

    ctx = await replica_a.context_for(KEY)
    ctx.record_records(30)
    await replica_a.save(KEY, ctx)

    on_b = await replica_b.load(KEY)
    assert on_b is not None
    on_b.record_records(45)
    await replica_b.save(KEY, on_b)

    back_on_a = await replica_a.load(KEY)
    assert back_on_a is not None
    assert back_on_a.record_count.total == 75

    await replica_b.remove(KEY)
    assert await replica_a.load(KEY) is None


# ---------------------------------------------------------------------------
# The revocation store: SMEMBERS over a live set.
# ---------------------------------------------------------------------------


async def test_is_customer_revoked_matches_across_clients_on_a_live_set(
    stores: RedisStores,
) -> None:
    """One ``SMEMBERS`` scanned for a first element, over several members.

    `RedisRevocationStore`'s ``is_customer_revoked`` matches a customer
    through ANY client, so the interesting states are partial: two clients
    revoked for one customer, one of them restored, and another customer's
    pair sitting in the same set throughout as the negative control.
    """
    store = stores.revocations()

    assert await store.is_customer_revoked(OWNER) is False

    await store.revoke_customer_client(customer_ref=OTHER, client_id="vendor-c")
    assert await store.is_customer_revoked(OWNER) is False, "another customer's pair is not a match"

    await store.revoke_customer_client(customer_ref=OWNER, client_id="vendor-a")
    await store.revoke_customer_client(customer_ref=OWNER, client_id="vendor-b")
    assert await store.is_customer_revoked(OWNER) is True

    await store.restore_customer_client(customer_ref=OWNER, client_id="vendor-a")
    assert await store.is_customer_revoked(OWNER) is True, "vendor-b still names this customer"

    await store.restore_customer_client(customer_ref=OWNER, client_id="vendor-b")
    assert await store.is_customer_revoked(OWNER) is False
    assert await store.is_customer_revoked(OTHER) is True, "the other pair was never touched"


async def test_a_restore_reaches_a_second_replica_with_no_cached_set(
    stores: RedisStores,
) -> None:
    """Both directions across two pools, because only one would prove half.

    A store that cached the set would pass the revoke and fail the restore.
    """
    writer = stores.revocations()
    reader = stores.revocations()

    await writer.revoke_customer_client(customer_ref=OWNER, client_id="vendor-a")
    assert await reader.is_customer_revoked(OWNER) is True

    await writer.restore_customer_client(customer_ref=OWNER, client_id="vendor-a")
    assert await reader.is_customer_revoked(OWNER) is False


async def test_no_revocation_key_ever_carries_a_ttl(stores: RedisStores) -> None:
    """The module's stated invariant, asserted against the server that holds it.

    `postern_core/auth/revocation.py`'s `RedisRevocationStore` docstring:
    "a revocation that expires on a timer is a revocation the operator was
    silently un-done on". ``TTL`` answers -1 for a key with no expiry and -2
    for one that does not exist, so -1 on all three is the whole claim.
    """
    store = stores.revocations()
    await store.revoke_session(jti="jti-abc")
    await store.revoke_customer_client(customer_ref=OWNER, client_id="vendor-a")
    await store.kill_switch(client_id="vendor-rogue")

    for key in (store._sessions_key, store._pairs_key, store._clients_key):
        assert await store._redis.ttl(key) == -1, f"{key} must outlive any timer"


async def test_entries_comes_back_sorted_from_a_set_the_server_does_not_order(
    stores: RedisStores,
) -> None:
    """``SMEMBERS`` has no order to forward, so ``entries`` must impose one.

    redis-py hands a ``SMEMBERS`` reply back as a Python ``set``, so
    whatever order the server sent is gone at the client. Measured on
    2026-09-25 against redis:7-alpine, six members inserted as zulu, alpha,
    mike, bravo, yankee, charlie came back as mike, charlie, zulu, bravo,
    alpha, yankee: neither insertion order nor sorted order, and Python's
    own set iteration at that. Members go in reverse-sorted order below so a
    store that forwarded its input could not pass by luck. The ``sorted()``
    in ``entries`` is what makes the operator CLI's output stable, and it is
    the only reason these three assertions can name an order at all.
    """
    store = stores.revocations()
    for jti in ("jti-zulu", "jti-mike", "jti-charlie", "jti-alpha"):
        await store.revoke_session(jti=jti)
    for client in ("vendor-z", "vendor-m", "vendor-a"):
        await store.kill_switch(client_id=client)
    for client in ("vendor-z", "vendor-m", "vendor-a"):
        await store.revoke_customer_client(customer_ref=OWNER, client_id=client)

    snapshot = await store.entries()

    assert snapshot.sessions == ("jti-alpha", "jti-charlie", "jti-mike", "jti-zulu")
    assert snapshot.clients == ("vendor-a", "vendor-m", "vendor-z")
    assert snapshot.customer_clients == (
        (OWNER, "vendor-a"),
        (OWNER, "vendor-m"),
        (OWNER, "vendor-z"),
    )


async def test_is_revoked_answers_each_scope_over_one_real_pipeline(
    stores: RedisStores,
) -> None:
    """Three ``SISMEMBER`` calls in one non-transactional pipeline.

    The claims matrix is already pinned against the in-memory backend in
    tests/test_zt7_revocation.py. What is new here is the wire: a pipeline
    returns a list of ``int``, and ``any(bool(result) ...)`` is what turns
    that into an answer.
    """
    store = stores.revocations()
    claims = {"jti": "jti-live", "sub": OWNER, "client_id": "vendor-a"}

    assert await store.is_revoked(claims) is False
    assert await store.is_revoked({}) is False, "claims naming no scope touch no key"

    await store.revoke_session(jti="jti-live")
    assert await store.is_revoked(claims) is True
    assert await store.is_revoked({"sub": OWNER, "client_id": "vendor-a"}) is False
    await store.restore_session(jti="jti-live")

    await store.revoke_customer_client(customer_ref=OWNER, client_id="vendor-a")
    assert await store.is_revoked(claims) is True
    assert await store.is_revoked({"jti": "jti-live", "sub": OTHER, "client_id": "vendor-a"}) is (
        False
    )
    await store.restore_customer_client(customer_ref=OWNER, client_id="vendor-a")

    await store.kill_switch(client_id="vendor-a")
    assert await store.is_revoked(claims) is True
    assert await store.is_revoked({"jti": "jti-live", "sub": OWNER, "client_id": "vendor-b"}) is (
        False
    )


# ---------------------------------------------------------------------------
# A server that is not there. fakeredis cannot be unreachable.
# ---------------------------------------------------------------------------


async def test_every_session_store_operation_fails_closed_on_a_refused_socket() -> None:
    """A real ``ConnectionError``, not a mock raising on cue.

    ``load`` is the one that matters: reporting an outage as ``None`` would
    hand the caller a fresh context and zero the budget it was tracking.
    ``save`` and ``remove`` are asserted with it so a future refactor cannot
    narrow the ``except`` to the read path alone.
    """
    store = RedisSessionStore(url=_closed_port_url(), key_prefix="unreachable:")
    try:
        with pytest.raises(SessionStoreUnavailable):
            await store.load(KEY)
        with pytest.raises(SessionStoreUnavailable):
            await store.save(KEY, RiskContext(session_id=KEY.value))
        with pytest.raises(SessionStoreUnavailable):
            await store.remove(KEY)
    finally:
        with contextlib.suppress(redis.exceptions.RedisError):
            await store.close()


async def test_every_revocation_operation_fails_closed_on_a_refused_socket() -> None:
    """ZT-7's fail-closed direction, against a socket that really refuses.

    A revocation check that answered "not revoked" because Redis was down is
    the failure this store's ``except`` clauses exist for, and the write side
    is included because an operator told "revoked" by a call that reached
    nothing is worse than one told it failed.
    """
    store = RedisRevocationStore(url=_closed_port_url(), key_prefix="unreachable:")
    try:
        with pytest.raises(RevocationStoreUnavailable):
            await store.is_revoked({"jti": "j", "sub": OWNER, "client_id": "vendor-a"})
        with pytest.raises(RevocationStoreUnavailable):
            await store.is_customer_revoked(OWNER)
        with pytest.raises(RevocationStoreUnavailable):
            await store.entries()
        with pytest.raises(RevocationStoreUnavailable):
            await store.revoke_session(jti="j")
    finally:
        with contextlib.suppress(redis.exceptions.RedisError):
            await store.close()


async def test_a_device_code_store_that_cannot_reach_redis_raises_rather_than_admitting() -> None:
    """`RedisDeviceCodeStore` has no translation layer, and that is the record.

    The other two stores wrap every call and raise their own
    ``...Unavailable``. This one does not, so an outage surfaces as
    ``redis.exceptions.RedisError`` and reaches
    `services/confirm/device_auth.py` as an unhandled exception, which is a
    500 and not a device code. Pinned as behaviour because the only worse
    answer is a code handed to a caller and stored nowhere, and a future
    ``except`` added here must not quietly become one.
    """
    store = RedisDeviceCodeStore(url=_closed_port_url(), key_prefix="unreachable:")
    try:
        with pytest.raises(redis.exceptions.RedisError):
            await _create(store)
        with pytest.raises(redis.exceptions.RedisError):
            await store.get_device_code("dc_anything")
    finally:
        with contextlib.suppress(redis.exceptions.RedisError):
            await store.close()


# ---------------------------------------------------------------------------
# The two TTLs an operator configures, against the server that enforces them.
# ---------------------------------------------------------------------------


async def test_the_device_code_ttl_variable_cannot_reach_the_truncation(
    redis_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Bug B1's second operator path, closed at the composition root.

    ``POSTERN_DEVICE_CODE_TTL_SECONDS`` was floored at
    `MIN_DEVICE_CODE_TTL_SECONDS` first, and that floor covers the
    ``expires_in`` `services/confirm/device_auth.py` passes.
    ``POSTERN_REDIS_DEVICE_CODE_TTL`` reaches the SAME argument by the other
    route -- ``_default_ttl``, used whenever ``create_device_code`` is called
    with no ``expires_in``, which is the call this module's own docstring
    shows -- and it was a bare ``int()`` until 2026-09-25. Measured then at
    ``POSTERN_REDIS_DEVICE_CODE_TTL=1`` against the same container this test
    uses, through ``create_device_code_store()``::

        _default_ttl = 1
        expires_at - now = 0.999991   int() = 0
        get_device_code  -> None
        redis EXISTS key -> 0     redis ZSCORE index -> None

    ``create_device_code`` returned a `DeviceCode` on that run and had
    written nothing. The refusal below is what the operator gets instead.
    """
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_DEVICE_CODE_TTL", "1")

    with pytest.raises(ValueError, match="POSTERN_REDIS_DEVICE_CODE_TTL") as caught:
        create_device_code_store()

    assert str(MIN_DEVICE_CODE_TTL_SECONDS) in str(caught.value)


async def test_a_code_created_at_the_floor_is_on_the_server(
    redis_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other half: a floor is only worth having if the values above it work.

    No ``expires_in``, so this is the ``_default_ttl`` path the test above
    refuses one second of, driven at the lowest value it accepts. The key,
    the index member and the TTL the SERVER reports are all asserted,
    because the failure being closed here was one where
    ``create_device_code`` still returned a code.
    """
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_DEVICE_CODE_TTL", str(MIN_DEVICE_CODE_TTL_SECONDS))
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"floor{uuid4().hex[:12]}:")
    store = create_device_code_store()
    assert isinstance(store, RedisDeviceCodeStore)

    try:
        code = await store.create_device_code(
            client_id="vendor-a", scopes="accounts:read", verification_uri=VERIFY_URI
        )

        assert await store.get_device_code(code.device_code) is not None
        assert await store._redis.exists(store._key(code.device_code)) == 1
        assert await store._redis.zscore(store._index_key(), code.device_code) is not None
        key_ttl = await store._redis.ttl(store._key(code.device_code))
        assert MIN_DEVICE_CODE_TTL_SECONDS - 2 <= key_ttl <= MIN_DEVICE_CODE_TTL_SECONDS - 1, (
            "int() still truncates a second off, which is why the floor is 30 and not 2"
        )
    finally:
        await store.close()


async def test_the_session_ttl_variable_round_trips_a_context_at_its_floor(
    redis_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One second is the floor because one second still works, and zero does not.

    `MIN_SESSION_TTL_SECONDS` claims nothing more than "positive", so the
    thing worth pinning is the boundary itself: a context saved and loaded
    at ``ttl=1`` comes back, which is what makes the refusal of ``0`` a
    bound on the control rather than an arbitrary one.
    """
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_SESSION_TTL", str(MIN_SESSION_TTL_SECONDS))
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"sfloor{uuid4().hex[:12]}:")
    store = create_session_store()
    assert isinstance(store, RedisSessionStore)

    try:
        assert store._ttl == MIN_SESSION_TTL_SECONDS
        ctx = RiskContext()
        await store.save(KEY, ctx)
        assert await store.load(KEY) is not None
        assert 0 < await store._redis.ttl(store._key(KEY)) <= MIN_SESSION_TTL_SECONDS, (
            "the server holds the lifetime the variable asked for, and no more"
        )
    finally:
        await store.close()


async def test_a_session_store_at_ttl_zero_forgets_every_context_immediately(
    stores: RedisStores,
) -> None:
    """What honouring a passed ``0`` would have meant, measured not argued.

    `postern_core/config.py`'s `int_arg_or_env` refuses ``ttl=0`` rather
    than honouring it, and this is the evidence behind that sentence. The
    store is built past its own constructor, the way
    tests/test_risk_session_wiring.py builds one, because the constructor is
    now exactly what makes this state unreachable.

    ``save`` does write: ``_remaining_ttl`` floors at one second. ``load``
    then computes ``ceil(0 - elapsed) <= 0``, deletes the key and answers
    ``None`` -- so every call would start from an empty ZT-5 budget and bulk
    extraction (A6) would accumulate against nothing.
    """
    healthy = stores.sessions(ttl=1800)
    zero = RedisSessionStore.__new__(RedisSessionStore)
    zero._ttl = 0
    zero._prefix = healthy._prefix
    zero._url = healthy._url
    zero._redis = healthy._redis

    await zero.save(KEY, RiskContext())

    assert await healthy._redis.ttl(zero._key(KEY)) == 1, "_remaining_ttl floored it"
    assert await zero.load(KEY) is None, "the first read expires it"
    assert await healthy._redis.exists(zero._key(KEY)) == 0, "and deletes it"

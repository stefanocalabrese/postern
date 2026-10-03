"""``client-at``: when a client was last kill-switched, in milliseconds.

The kill-switch twin of ``tests/test_customer_revoked_at.py``. A restored kill
switch must not revive what existed before it: the api refuses an access
token whose ``iat`` is not past the stamp, and confirm's refresh refuses and
revokes a family created at or before it. So the stamp must be written in the
same step as the ``SADD``, on Redis ``TIME``, survive ``restore_client``, and
expire after `CLIENT_REVOKED_AT_TTL_SECONDS`. Both backends, against the
suite's Redis, each test in its own key prefix.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import pytest
from postern_core.auth import revocation
from postern_core.auth.refresh_sessions import SESSION_ABSOLUTE_LIFETIME
from postern_core.auth.revocation import (
    CLIENT_REVOKED_AT_TTL_SECONDS,
    PAIR_REVOKED_AT_TTL_SECONDS,
    REVOKED_AT_MARGIN_SECONDS,
    InMemoryRevocationStore,
    RedisRevocationStore,
    RevocationSnapshot,
    RevocationStoreBase,
    RevocationStoreUnavailable,
)

CLIENT = "vendor-k"
OTHER_CLIENT = "vendor-j"
CUSTOMER = "cust_k1"


@pytest.fixture(params=["memory", "redis"])
async def store(request: pytest.FixtureRequest) -> AsyncIterator[RevocationStoreBase]:
    built: RevocationStoreBase
    if request.param == "memory":
        built = InMemoryRevocationStore()
    else:
        built = RedisRevocationStore(
            url=request.getfixturevalue("redis_url"), key_prefix=f"ca{uuid4().hex[:12]}:"
        )
    yield built
    await built.close()


def _claims(client_id: str = CLIENT, **extra: Any) -> dict[str, Any]:
    return {"sub": CUSTOMER, "client_id": client_id, "jti": "jti-k", **extra}


async def _killed_and_restored(store: RevocationStoreBase) -> int:
    """Kill then restore the client; return the stamp in whole seconds."""
    await store.kill_switch(client_id=CLIENT)
    await store.restore_client(client_id=CLIENT)
    stamp = await store.client_revoked_at(CLIENT)
    assert stamp is not None
    return stamp // 1000


def test_the_ttl_outlives_the_longest_family_and_the_access_floor() -> None:
    family = int(SESSION_ABSOLUTE_LIFETIME.total_seconds())
    assert family == 3_600
    assert CLIENT_REVOKED_AT_TTL_SECONDS == max(
        family + REVOKED_AT_MARGIN_SECONDS, PAIR_REVOKED_AT_TTL_SECONDS
    )
    assert CLIENT_REVOKED_AT_TTL_SECONDS == 3_900
    assert CLIENT_REVOKED_AT_TTL_SECONDS >= 930


async def test_never_killed_is_none(store: RevocationStoreBase) -> None:
    assert await store.client_revoked_at(CLIENT) is None


async def test_the_stamp_survives_a_restore_and_names_only_its_client(
    store: RevocationStoreBase,
) -> None:
    await store.kill_switch(client_id=CLIENT)
    stamp = await store.client_revoked_at(CLIENT)
    assert stamp is not None
    await store.restore_client(client_id=CLIENT)
    assert (await store.entries()).clients == ()
    assert await store.client_revoked_at(CLIENT) == stamp
    assert await store.client_revoked_at(OTHER_CLIENT) is None


async def test_other_scopes_do_not_stamp_the_client(store: RevocationStoreBase) -> None:
    await store.revoke_session(jti="tok-k")
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=CLIENT)
    assert await store.client_revoked_at(CLIENT) is None


# ---------------------------------------------------------------------------
# The api's floor.
# ---------------------------------------------------------------------------


async def test_a_restore_still_refuses_a_token_issued_before_the_kill(
    store: RevocationStoreBase,
) -> None:
    stamp_s = await _killed_and_restored(store)
    assert await store.is_revoked(_claims(iat=stamp_s - 1)) is True
    assert await store.is_revoked(_claims(iat=stamp_s - 600)) is True
    assert await store.is_revoked(_claims(iat=stamp_s + 10)) is False


async def test_the_floor_reaches_every_customer_of_the_client(store: RevocationStoreBase) -> None:
    stamp_s = await _killed_and_restored(store)
    for customer in ("cust_a", "cust_b"):
        claims = {"sub": customer, "client_id": CLIENT, "jti": "j", "iat": stamp_s - 60}
        assert await store.is_revoked(claims) is True
    # A caller with no derivable customer is floored too: the scope is the client.
    assert await store.is_revoked({"sub": None, "client_id": CLIENT, "iat": stamp_s - 60})


async def test_another_client_is_unaffected(store: RevocationStoreBase) -> None:
    stamp_s = await _killed_and_restored(store)
    assert await store.is_revoked(_claims(OTHER_CLIENT, iat=stamp_s - 600)) is False


async def test_the_floor_carries_the_two_second_tolerance(store: RevocationStoreBase) -> None:
    await store.kill_switch(client_id=CLIENT)
    stamp_ms = await store.client_revoked_at(CLIENT)
    assert stamp_ms is not None
    await store.restore_client(client_id=CLIENT)
    last_refused_s = (stamp_ms + 2_000) // 1000
    assert await store.is_revoked(_claims(iat=last_refused_s)) is True
    assert await store.is_revoked(_claims(iat=last_refused_s + 1)) is False


@pytest.mark.parametrize("bad", [None, "soon", "", float("nan"), float("inf"), True, [], {}])
async def test_a_missing_or_unusable_iat_is_refused_while_a_client_stamp_exists(
    store: RevocationStoreBase, bad: Any
) -> None:
    await _killed_and_restored(store)
    assert await store.is_revoked(_claims(iat=bad)) is True


async def test_claims_without_an_iat_key_are_not_floored(store: RevocationStoreBase) -> None:
    """confirm's `_refresh_revoked` passes no ``iat`` key: today's answer stands."""
    await _killed_and_restored(store)
    assert await store.is_revoked(_claims()) is False
    assert await store.is_revoked({"sub": CUSTOMER, "client_id": CLIENT}) is False
    await store.kill_switch(client_id=CLIENT)
    assert await store.is_revoked({"sub": CUSTOMER, "client_id": CLIENT}) is True


async def test_the_pair_floor_still_applies_beside_the_client_floor(
    store: RevocationStoreBase,
) -> None:
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=OTHER_CLIENT)
    await store.restore_customer_client(customer_ref=CUSTOMER, client_id=OTHER_CLIENT)
    pair_stamp = await store.customer_revoked_at(CUSTOMER)
    assert pair_stamp is not None
    await _killed_and_restored(store)
    old = {"sub": CUSTOMER, "client_id": OTHER_CLIENT, "jti": "j", "iat": pair_stamp // 1000 - 60}
    assert await store.is_revoked(old) is True


# ---------------------------------------------------------------------------
# Redis: one script, one clock, one TTL; fail closed.
# ---------------------------------------------------------------------------


async def test_the_redis_kill_switch_writes_the_set_and_the_stamp_on_redis_time(
    redis_url: str,
) -> None:
    prefix = f"ca{uuid4().hex[:12]}:"
    store = RedisRevocationStore(url=redis_url, key_prefix=prefix)
    seconds, micros = await store._redis.time()
    server_ms = int(seconds) * 1000 + int(micros) // 1000
    await store.kill_switch(client_id=CLIENT)
    assert await store._redis.sismember(f"{prefix}revoked:clients", CLIENT)
    key = f"{prefix}revoked:client-at:{CLIENT}"
    stamp = await store.client_revoked_at(CLIENT)
    assert stamp is not None
    assert 0 <= stamp - server_ms < 2_000
    assert await store._redis.get(key) == str(stamp)
    ttl = await store._redis.ttl(key)
    assert CLIENT_REVOKED_AT_TTL_SECONDS - 5 <= ttl <= CLIENT_REVOKED_AT_TTL_SECONDS
    await store.restore_client(client_id=CLIENT)
    assert await store._redis.get(key) == str(stamp), "restore leaves the stamp in place"
    await store.close()


async def test_the_set_and_the_stamp_are_one_script(
    redis_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One ``EVAL`` and no bare ``SADD``: the stamp cannot be lost between two writes."""
    store = RedisRevocationStore(url=redis_url, key_prefix=f"ca{uuid4().hex[:12]}:")
    calls: list[str] = []
    real_eval = store._redis.eval

    async def eval_spy(*args: Any) -> Any:
        calls.append("eval")
        return await real_eval(*args)

    async def no_sadd(*args: Any) -> Any:
        raise AssertionError("the kill switch must not SADD outside its script")

    monkeypatch.setattr(store._redis, "eval", eval_spy)
    monkeypatch.setattr(store._redis, "sadd", no_sadd)
    await store.kill_switch(client_id=CLIENT)
    assert calls == ["eval"]
    assert await store.client_revoked_at(CLIENT) is not None
    await store.close()


async def test_a_later_kill_overwrites_the_redis_stamp_and_resets_its_ttl(redis_url: str) -> None:
    prefix = f"ca{uuid4().hex[:12]}:"
    store = RedisRevocationStore(url=redis_url, key_prefix=prefix)
    key = f"{prefix}revoked:client-at:{CLIENT}"
    await store._redis.set(key, "1", ex=5)
    await store.kill_switch(client_id=CLIENT)
    stamp = await store.client_revoked_at(CLIENT)
    assert stamp is not None and stamp > 1
    assert CLIENT_REVOKED_AT_TTL_SECONDS - 5 <= await store._redis.ttl(key)
    await store.close()


async def test_a_corrupt_client_stamp_is_unavailable_not_a_crash(redis_url: str) -> None:
    prefix = f"ca{uuid4().hex[:12]}:"
    store = RedisRevocationStore(url=redis_url, key_prefix=prefix)
    await store._redis.set(f"{prefix}revoked:client-at:{CLIENT}", "not-a-number")
    with pytest.raises(RevocationStoreUnavailable):
        await store.client_revoked_at(CLIENT)
    with pytest.raises(RevocationStoreUnavailable):
        await store.is_revoked(_claims(iat=1))
    await store.close()


async def test_an_unreachable_redis_is_unavailable_not_none() -> None:
    store = RedisRevocationStore(url="redis://127.0.0.1:1/0", key_prefix="unreachable:")
    with pytest.raises(RevocationStoreUnavailable):
        await store.client_revoked_at(CLIENT)
    with pytest.raises(RevocationStoreUnavailable):
        await store.kill_switch(client_id=CLIENT)
    await store.close()


async def test_the_in_memory_stamp_expires_after_the_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    store = InMemoryRevocationStore()
    clock = {"ms": 1_000_000_000}
    monkeypatch.setattr(revocation, "_now_ms", lambda: clock["ms"])
    await store.kill_switch(client_id=CLIENT)
    await store.restore_client(client_id=CLIENT)
    old = _claims(iat=1_000_000 - 60)
    clock["ms"] += CLIENT_REVOKED_AT_TTL_SECONDS * 1000 - 1
    assert await store.client_revoked_at(CLIENT) == 1_000_000_000
    assert await store.is_revoked(old) is True
    clock["ms"] += 1
    assert await store.client_revoked_at(CLIENT) is None
    assert await store.is_revoked(old) is False


async def test_a_second_in_memory_kill_raises_the_stamp(monkeypatch: pytest.MonkeyPatch) -> None:
    """A re-kill overwrites, as the Redis ``SET`` does: the later stamp is the floor."""
    store = InMemoryRevocationStore()
    clock = {"ms": 1_000_000_000}
    monkeypatch.setattr(revocation, "_now_ms", lambda: clock["ms"])
    await store.kill_switch(client_id=CLIENT)
    await store.restore_client(client_id=CLIENT)
    clock["ms"] += 10_000
    await store.kill_switch(client_id=CLIENT)
    await store.restore_client(client_id=CLIENT)
    assert await store.client_revoked_at(CLIENT) == 1_000_010_000
    # 5 s past the first stamp, below the second: only an overwrite refuses it.
    assert await store.is_revoked(_claims(iat=1_000_000 + 5)) is True
    assert await store.is_revoked(_claims(iat=1_000_000 + 20)) is False


async def test_a_double_that_implements_only_the_abstract_methods_answers_none() -> None:
    class Minimal(RevocationStoreBase):
        async def is_revoked(self, claims: Any) -> bool:
            return False

        async def revoke_session(self, *, jti: str) -> None: ...

        async def restore_session(self, *, jti: str) -> None: ...

        async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None: ...

        async def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None: ...

        async def kill_switch(self, *, client_id: str) -> None: ...

        async def restore_client(self, *, client_id: str) -> None: ...

        async def entries(self) -> RevocationSnapshot:
            return RevocationSnapshot()

    assert await Minimal().client_revoked_at(CLIENT) is None


# ---------------------------------------------------------------------------
# Per-jti: restoring a session revives that one access token, and only it.
# ---------------------------------------------------------------------------


async def test_restoring_a_session_revives_only_the_named_jti(store: RevocationStoreBase) -> None:
    await store.revoke_session(jti="tok-a")
    await store.revoke_session(jti="tok-b")
    await store.restore_session(jti="tok-a")
    assert await store.is_revoked({"jti": "tok-a", "sub": CUSTOMER, "client_id": CLIENT}) is False
    assert await store.is_revoked({"jti": "tok-b", "sub": CUSTOMER, "client_id": CLIENT}) is True
    # No stamp of any scope is written by the session verb, so nothing else moves.
    assert await store.client_revoked_at(CLIENT) is None
    assert await store.customer_revoked_at(CUSTOMER) is None

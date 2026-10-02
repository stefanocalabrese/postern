"""``customer_revoked_at``: when a customer was last cut off, in milliseconds.

Spec section 6 step 6 of ``dev-docs/device-grant-session-token-spec.md``. The
stamp is what lets ``POST /token`` refuse a refresh family or an approval that
predates a revocation even after the revocation is restored, so it must
survive the restore, be written in the same step as the pair, and expire after
`CUSTOMER_REVOKED_AT_TTL_SECONDS`. Both backends, against the suite's Redis.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import pytest
from postern_core.auth import revocation
from postern_core.auth.revocation import (
    CUSTOMER_REVOKED_AT_TTL_SECONDS,
    REVOKED_AT_MARGIN_SECONDS,
    InMemoryRevocationStore,
    RedisRevocationStore,
    RevocationSnapshot,
    RevocationStoreBase,
    RevocationStoreUnavailable,
)

from services.confirm.settings import MAX_DEVICE_CODE_TTL_SECONDS

CUSTOMER = "cust_7f3a"


@pytest.fixture(params=["memory", "redis"])
async def store(request: pytest.FixtureRequest) -> AsyncIterator[RevocationStoreBase]:
    built: RevocationStoreBase
    if request.param == "memory":
        built = InMemoryRevocationStore()
    else:
        built = RedisRevocationStore(
            url=request.getfixturevalue("redis_url"), key_prefix=f"ra{uuid4().hex[:12]}:"
        )
    yield built
    await built.close()


def test_the_ttl_is_the_family_plus_the_device_code_plus_a_margin() -> None:
    assert REVOKED_AT_MARGIN_SECONDS == 300
    assert CUSTOMER_REVOKED_AT_TTL_SECONDS == 3_600 + 900 + REVOKED_AT_MARGIN_SECONDS == 4_800
    assert MAX_DEVICE_CODE_TTL_SECONDS == 900


async def test_never_revoked_is_none(store: RevocationStoreBase) -> None:
    assert await store.customer_revoked_at(CUSTOMER) is None


async def test_the_stamp_is_milliseconds_and_survives_a_restore(
    store: RevocationStoreBase,
) -> None:
    before = time.time_ns() // 1_000_000
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    stamp = await store.customer_revoked_at(CUSTOMER)
    assert stamp is not None
    assert abs(stamp - before) < 2_000, "milliseconds, from a clock near this one"
    await store.restore_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    assert await store.is_customer_revoked(CUSTOMER) is False
    assert await store.customer_revoked_at(CUSTOMER) == stamp


async def test_a_later_revocation_overwrites_the_stamp(store: RevocationStoreBase) -> None:
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    first = await store.customer_revoked_at(CUSTOMER)
    await asyncio.sleep(0.01)
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-y")
    second = await store.customer_revoked_at(CUSTOMER)
    assert first is not None and second is not None
    assert second > first


async def test_the_stamp_names_only_its_customer(store: RevocationStoreBase) -> None:
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    assert await store.customer_revoked_at("cust_other") is None


async def test_session_and_kill_switch_revocations_do_not_stamp(
    store: RevocationStoreBase,
) -> None:
    await store.revoke_session(jti="tok-1")
    await store.kill_switch(client_id="vendor-x")
    assert await store.customer_revoked_at(CUSTOMER) is None


async def test_the_redis_script_writes_the_pair_and_the_stamp_on_redis_time(
    redis_url: str,
) -> None:
    prefix = f"ra{uuid4().hex[:12]}:"
    store = RedisRevocationStore(url=redis_url, key_prefix=prefix)
    seconds, micros = await store._redis.time()
    server_ms = int(seconds) * 1000 + int(micros) // 1000
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    assert await store.is_customer_revoked(CUSTOMER) is True
    stamp = await store.customer_revoked_at(CUSTOMER)
    assert stamp is not None
    assert 0 <= stamp - server_ms < 2_000
    ttl = await store._redis.ttl(f"{prefix}revoked:customer-at:{CUSTOMER}")
    assert CUSTOMER_REVOKED_AT_TTL_SECONDS - 5 <= ttl <= CUSTOMER_REVOKED_AT_TTL_SECONDS
    await store.close()


async def test_the_in_memory_stamp_expires_after_the_ttl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryRevocationStore()
    clock = {"ms": 1_000_000}
    monkeypatch.setattr(revocation, "_now_ms", lambda: clock["ms"])
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    clock["ms"] += CUSTOMER_REVOKED_AT_TTL_SECONDS * 1000 - 1
    assert await store.customer_revoked_at(CUSTOMER) == 1_000_000
    clock["ms"] += 1
    assert await store.customer_revoked_at(CUSTOMER) is None


async def test_a_corrupt_stored_stamp_is_unavailable_not_a_crash(redis_url: str) -> None:
    """A non-numeric value under the stamp's key fails closed, the way an
    unreachable store does, rather than raising ``ValueError`` past it."""
    prefix = f"ra{uuid4().hex[:12]}:"
    store = RedisRevocationStore(url=redis_url, key_prefix=prefix)
    await store._redis.set(f"{prefix}revoked:customer-at:{CUSTOMER}", "not-a-number")
    with pytest.raises(RevocationStoreUnavailable):
        await store.customer_revoked_at(CUSTOMER)
    await store.close()


async def test_an_unreachable_redis_is_unavailable_not_none() -> None:
    store = RedisRevocationStore(url="redis://127.0.0.1:1/0", key_prefix="unreachable:")
    with pytest.raises(RevocationStoreUnavailable):
        await store.customer_revoked_at(CUSTOMER)
    with pytest.raises(RevocationStoreUnavailable):
        await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
    await store.close()


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

    assert await Minimal().customer_revoked_at(CUSTOMER) is None


# ---------------------------------------------------------------------------
# The per-pair "not before" floor the api applies to an access token's `iat`.
# ---------------------------------------------------------------------------

PAIR_CLIENT = "vendor-x"


def _claims(**extra: Any) -> dict[str, Any]:
    return {"sub": CUSTOMER, "client_id": PAIR_CLIENT, "jti": "jti-1", **extra}


async def _revoked_and_restored(store: RevocationStoreBase) -> int:
    """Revoke then restore the pair; return the stamp in whole seconds."""
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    await store.restore_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    stamp = await store.customer_revoked_at(CUSTOMER)
    assert stamp is not None
    return stamp // 1000


async def test_a_restore_still_refuses_a_token_issued_before_the_revocation(
    store: RevocationStoreBase,
) -> None:
    stamp_s = await _revoked_and_restored(store)
    assert await store.is_revoked(_claims(iat=stamp_s - 1)) is True
    assert await store.is_revoked(_claims(iat=stamp_s - 600)) is True
    assert await store.is_revoked(_claims(iat=stamp_s + 10)) is False


async def test_the_floor_carries_a_two_second_tolerance(store: RevocationStoreBase) -> None:
    """``iat`` is confirm's clock and the stamp is Redis's: refuse inside 2 s."""
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    stamp_ms = await store.customer_revoked_at(CUSTOMER)
    assert stamp_ms is not None
    await store.restore_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    # Refused while iat * 1000 <= stamp_ms + 2000.
    last_refused_s = (stamp_ms + 2_000) // 1000
    assert last_refused_s * 1000 <= stamp_ms + 2_000
    assert await store.is_revoked(_claims(iat=last_refused_s)) is True
    assert await store.is_revoked(_claims(iat=last_refused_s + 1)) is False


async def test_claims_without_an_iat_key_keep_todays_answer(store: RevocationStoreBase) -> None:
    """confirm's `_refresh_revoked` passes no ``iat`` key and must not be floored."""
    await _revoked_and_restored(store)
    assert await store.is_revoked(_claims()) is False
    assert await store.is_revoked({"sub": CUSTOMER, "client_id": PAIR_CLIENT}) is False
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    assert await store.is_revoked(_claims()) is True


@pytest.mark.parametrize("bad", [None, "soon", "", float("nan"), float("inf"), True, [], {}])
async def test_a_missing_or_unusable_iat_is_refused_while_a_stamp_exists(
    store: RevocationStoreBase, bad: Any
) -> None:
    await _revoked_and_restored(store)
    assert await store.is_revoked(_claims(iat=bad)) is True


async def test_a_missing_or_unusable_iat_is_allowed_when_no_stamp_exists(
    store: RevocationStoreBase,
) -> None:
    for bad in (None, "soon", float("nan")):
        assert await store.is_revoked(_claims(iat=bad)) is False
    assert await store.is_revoked(_claims(iat=1)) is False


async def test_the_floor_is_per_pair_not_per_customer(store: RevocationStoreBase) -> None:
    stamp_s = await _revoked_and_restored(store)
    other = {"sub": CUSTOMER, "client_id": "vendor-y", "jti": "jti-2", "iat": stamp_s - 600}
    assert await store.is_revoked(other) is False
    stranger = {"sub": "cust_other", "client_id": PAIR_CLIENT, "jti": "j", "iat": stamp_s - 600}
    assert await store.is_revoked(stranger) is False


async def test_a_later_revocation_raises_the_in_memory_floor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryRevocationStore()
    clock = {"ms": 1_000_000_000}
    monkeypatch.setattr(revocation, "_now_ms", lambda: clock["ms"])
    first_s = await _revoked_and_restored(store)
    clock["ms"] += 10_000
    await _revoked_and_restored(store)
    # first_s + 5 is past the first floor (beyond its 2 s tolerance) and
    # below the second, so only an overwritten stamp refuses it.
    assert await store.is_revoked(_claims(iat=first_s + 5)) is True
    assert await store.is_revoked(_claims(iat=first_s + 20)) is False


async def test_a_later_revocation_overwrites_the_redis_pair_stamp_and_resets_its_ttl(
    redis_url: str,
) -> None:
    prefix = f"ra{uuid4().hex[:12]}:"
    store = RedisRevocationStore(url=redis_url, key_prefix=prefix)
    key = f"{prefix}revoked:pair-at:{revocation._pair_member(CUSTOMER, PAIR_CLIENT)}"
    await store._redis.set(key, "1", ex=5)
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    second = await store.customer_revoked_at(CUSTOMER)
    assert second is not None and second > 1
    assert await store._redis.get(key) == str(second)
    assert 930 - 5 <= await store._redis.ttl(key) <= 930
    await store.close()


async def test_the_redis_pair_stamp_expires_in_930_seconds_and_survives_a_restore(
    redis_url: str,
) -> None:
    assert revocation.PAIR_REVOKED_AT_TTL_SECONDS == 600 + 30 + REVOKED_AT_MARGIN_SECONDS == 930
    prefix = f"ra{uuid4().hex[:12]}:"
    store = RedisRevocationStore(url=redis_url, key_prefix=prefix)
    key = f"{prefix}revoked:pair-at:{revocation._pair_member(CUSTOMER, PAIR_CLIENT)}"
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    ttl = await store._redis.ttl(key)
    assert 930 - 5 <= ttl <= 930
    stamp = await store._redis.get(key)
    assert stamp is not None and int(stamp) == await store.customer_revoked_at(CUSTOMER)
    await store.restore_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    assert await store._redis.get(key) == stamp, "restore leaves the stamp in place"
    await store.close()


async def test_the_in_memory_pair_stamp_expires_after_930_seconds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = InMemoryRevocationStore()
    clock = {"ms": 1_000_000_000}
    monkeypatch.setattr(revocation, "_now_ms", lambda: clock["ms"])
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    await store.restore_customer_client(customer_ref=CUSTOMER, client_id=PAIR_CLIENT)
    old = {"sub": CUSTOMER, "client_id": PAIR_CLIENT, "iat": 1_000_000 - 60}
    clock["ms"] += 930 * 1000 - 1
    assert await store.is_revoked(old) is True
    clock["ms"] += 1
    assert await store.is_revoked(old) is False


async def test_a_corrupt_pair_stamp_is_unavailable_not_a_crash(redis_url: str) -> None:
    """A non-integer value under ``pair-at`` fails closed on the floor read."""
    prefix = f"ra{uuid4().hex[:12]}:"
    store = RedisRevocationStore(url=redis_url, key_prefix=prefix)
    key = f"{prefix}revoked:pair-at:{revocation._pair_member(CUSTOMER, PAIR_CLIENT)}"
    await store._redis.set(key, "not-a-number")
    with pytest.raises(RevocationStoreUnavailable):
        await store.is_revoked(_claims(iat=1))
    await store.close()


async def test_an_outage_on_the_floor_read_fails_closed() -> None:
    store = RedisRevocationStore(url="redis://127.0.0.1:1/0", key_prefix="unreachable:")
    with pytest.raises(RevocationStoreUnavailable):
        await store.is_revoked(_claims(iat=1))
    await store.close()

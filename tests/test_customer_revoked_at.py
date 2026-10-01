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
    assert CUSTOMER_REVOKED_AT_TTL_SECONDS == 3_600 + 900 + 300
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

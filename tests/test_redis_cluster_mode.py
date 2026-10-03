"""What Redis cluster mode does to the stores that write more than one key.

`docs/user-guide/components/session-store.md` and `CLAUDE.md` say the Redis must
be non-clustered because "cluster mode refuses the multi-key writes with
`CROSSSLOT`". Until this file that sentence had never been run. This measures it
against a PRIVATE single-node cluster (`redis:7-alpine --cluster-enabled yes`,
all 16384 slots assigned to the one node with `CLUSTER ADDSLOTSRANGE`).

WHAT A SINGLE NODE CAN AND CANNOT SHOW. A node that owns every slot still
enforces the same-slot rule for multi-key commands, `MULTI`/`EXEC` and `EVAL`,
so every CROSSSLOT below is the real server answer. It never answers `MOVED`,
because there is no other node to move to, so what a non-cluster redis-py
client does with `MOVED` is NOT measured here, nor is resharding, nor any
managed service's cluster endpoint. A real multi-node cluster adds failure
modes; it removes none of these.

WHAT IS PINNED, all of it measured on 3 October 2026:

* every write that spans keys without a shared hash tag is refused with
  `CROSSSLOT Keys in request don't hash to the same slot`;
* the revocation store wraps that into `RevocationStoreUnavailable` (fail
  closed); the refresh-session and device-code stores do NOT wrap anything, so
  the raw `redis.exceptions.ResponseError` reaches the caller;
* operations that touch one key per command all work, so the failure is partial
  and the service BOOTS: the startup preflight (`TIME`, `CONFIG GET`) passes;
* a hash tag in the key prefix (`{postern}:`) puts every key in one slot and
  every operation then works, at the price of one shard holding everything.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Awaitable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import docker
import pytest
import redis
from docker.errors import DockerException
from postern_core.auth import redis_preflight
from postern_core.auth.device_codes import DeviceCode, RedisDeviceCodeStore, ScanClaim
from postern_core.auth.refresh_sessions import (
    RedisRefreshSessionStore,
    RefreshSession,
    Rotation,
    hash_refresh_token,
    new_refresh_token,
    new_sid,
)
from postern_core.auth.revocation import RedisRevocationStore, RevocationStoreUnavailable
from postern_core.risk.context import RiskContext
from postern_core.risk.session import RedisSessionStore, SessionKey
from redis.exceptions import ResponseError
from testcontainers.community.redis import RedisContainer

from services.confirm.customer_rate_limit import RedisCustomerRateLimitStore
from services.confirm.rate_limit import Limit

CROSSSLOT = "CROSSSLOT Keys in request don't hash to the same slot"
CLUSTER_COMMAND = (
    "redis-server --cluster-enabled yes --cluster-config-file nodes.conf --port 6379 "
    "--appendonly no"
)
#: Slots of the keys under the prefix `postern:`, read from `CLUSTER KEYSLOT` on
#: 3 October 2026. Pinned so that "these keys differ in slot" is a verified
#: fact and never a probability.
EXPECTED_SLOTS = {
    "a": 9050,
    "b": 4921,
    "revoked:sessions": 9931,
    "revoked:sessions:exp": 4183,
    "revoked:customer-clients": 11233,
    "revoked:customer-at:cust_7f3a": 2420,
    "revoked:pair-at:PAIR": 10323,
    "revoked:clients": 2773,
    "revoked:client-at:vendor-x": 8708,
    "refresh:index": 10176,
    "refresh:session:fixedsid1": 7202,
}
FIXED_SID = "fixedsid1"
CUSTOMER = "cust_7f3a"
OTHER = "cust_9b21"
CLIENT = "vendor-a"


@pytest.fixture(scope="module")
def cluster_url() -> Iterator[str]:
    """A PRIVATE single-node cluster owning all 16384 slots.

    The container is stopped by the ``with`` block even when the slot
    assignment or the wait raises.
    """
    try:
        docker.from_env().ping()
    except DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping Redis-backed tests: {exc}")
    with RedisContainer("redis:7-alpine").with_command(CLUSTER_COMMAND) as container:
        url = f"redis://{container.get_container_host_ip()}:{container.get_exposed_port(6379)}/0"
        admin: Any = redis.Redis.from_url(url, decode_responses=True)
        try:
            admin.execute_command("CLUSTER", "ADDSLOTSRANGE", 0, 16383)
            deadline = time.monotonic() + 15
            while "cluster_state:ok" not in admin.execute_command("CLUSTER", "INFO"):
                if time.monotonic() > deadline:
                    raise RuntimeError("the single-node cluster never reached cluster_state:ok")
                time.sleep(0.1)
        finally:
            admin.close()
        yield url


@pytest.fixture
def admin(cluster_url: str) -> Iterator[Any]:
    client = redis.Redis.from_url(cluster_url, decode_responses=True)
    yield client
    client.close()


@pytest.fixture(autouse=True)
def empty_cluster(cluster_url: str) -> None:
    """Isolation by emptying the throwaway node before each test.

    The slot assertions below need a FIXED tag-free prefix, so a unique prefix
    per test is not available; the container is private, so a flush is safe.
    """
    client = redis.Redis.from_url(cluster_url)
    try:
        client.flushall()
    finally:
        client.close()


@pytest.fixture
def prefix() -> str:
    """The default prefix, with NO hash tag: the realistic shape.

    Its slots are pinned in `EXPECTED_SLOTS` and asserted against the server.
    """
    return "postern:"


@pytest.fixture
def tagged() -> str:
    """Unique per test, with the whole prefix inside one hash tag."""
    return f"{{cl{uuid4().hex[:12]}}}:"


def slot(client: Any, key: str) -> int:
    return int(client.execute_command("CLUSTER", "KEYSLOT", key))


async def refused(call: Awaitable[Any]) -> BaseException:
    """The exception ``call`` raises, failing the test if it raises none."""
    try:
        await call
    except Exception as exc:
        return exc
    raise AssertionError("expected the call to be refused, and it succeeded")


def assert_crossslot_wrapped(exc: BaseException, wrapper: type[Exception]) -> None:
    """Fail closed: the store's own exception, with the server's answer as its cause."""
    assert type(exc) is wrapper
    assert isinstance(exc.__cause__, ResponseError)
    assert str(exc.__cause__) == CROSSSLOT


def assert_crossslot_raw(exc: BaseException) -> None:
    """NOT wrapped: the redis-py exception itself reaches the caller."""
    assert type(exc) is ResponseError
    assert str(exc) == CROSSSLOT


class TestTheServerIsReallyACluster:
    def test_all_slots_are_assigned_and_the_state_is_ok(self, admin: Any) -> None:
        info = admin.execute_command("CLUSTER", "INFO")
        assert "cluster_state:ok" in info
        assert "cluster_slots_assigned:16384" in info

    def test_a_multi_key_command_across_slots_is_crossslot(
        self,
        admin: Any,
        prefix: str,
    ) -> None:
        assert slot(admin, f"{prefix}a") == EXPECTED_SLOTS["a"]
        assert slot(admin, f"{prefix}b") == EXPECTED_SLOTS["b"]
        with pytest.raises(ResponseError) as raised:
            admin.mset({f"{prefix}a": 1, f"{prefix}b": 2})
        assert str(raised.value) == CROSSSLOT

    def test_select_of_another_database_is_refused(self, cluster_url: str) -> None:
        """A `POSTERN_REDIS_URL` ending `/1` cannot connect: cluster mode has database 0 only."""
        client = redis.Redis.from_url(cluster_url.removesuffix("/0") + "/1")
        try:
            with pytest.raises(ResponseError, match="SELECT is not allowed in cluster mode"):
                client.ping()
        finally:
            client.close()

    def test_the_revocation_keys_really_land_in_different_slots(
        self,
        admin: Any,
        cluster_url: str,
        prefix: str,
    ) -> None:
        """Not slot luck: the failures below are for keys whose slots are pinned."""
        store = RedisRevocationStore(url=cluster_url, key_prefix=prefix)
        measured = {
            "revoked:customer-clients": slot(admin, store._pairs_key),
            "revoked:customer-at:cust_7f3a": slot(admin, store._revoked_at_key(CUSTOMER)),
            "revoked:pair-at:PAIR": slot(admin, store._pair_revoked_at_key(CUSTOMER, CLIENT)),
            "revoked:sessions": slot(admin, store._sessions_key),
            "revoked:sessions:exp": slot(admin, store._sessions_exp_key),
            "revoked:clients": slot(admin, store._clients_key),
            "revoked:client-at:vendor-x": slot(admin, store._client_revoked_at_key("vendor-x")),
        }
        assert measured == {key: EXPECTED_SLOTS[key] for key in measured}
        assert len(set(measured.values())) == 7


class TestRevocationStore:
    @pytest.fixture
    async def store(self, cluster_url: str, prefix: str) -> AsyncIterator[RedisRevocationStore]:
        built = RedisRevocationStore(url=cluster_url, key_prefix=prefix)
        yield built
        await built.close()

    async def test_the_three_key_customer_client_script_is_crossslot_and_writes_nothing(
        self,
        store: RedisRevocationStore,
        admin: Any,
        prefix: str,
    ) -> None:
        exc = await refused(store.revoke_customer_client(customer_ref=CUSTOMER, client_id=CLIENT))
        assert_crossslot_wrapped(exc, RevocationStoreUnavailable)
        assert admin.keys(f"{prefix}*") == []
        # The revoke was refused whole, so nothing reads as revoked afterwards.
        # The caller was told; a later reader is not.
        claims = {"sub": CUSTOMER, "client_id": CLIENT, "jti": "j1", "iat": 1}
        assert await store.is_revoked(claims) is False

    async def test_the_two_key_session_script_is_crossslot_and_the_revoke_does_not_stand(
        self,
        store: RedisRevocationStore,
        admin: Any,
        prefix: str,
    ) -> None:
        exc = await refused(store.revoke_session(jti="j1"))
        assert_crossslot_wrapped(exc, RevocationStoreUnavailable)
        assert admin.keys(f"{prefix}*") == []
        assert await store.is_revoked({"jti": "j1"}) is False

    async def test_the_two_key_kill_switch_script_is_crossslot_and_writes_nothing(
        self,
        store: RedisRevocationStore,
        admin: Any,
        prefix: str,
    ) -> None:
        """Since 3 October 2026 the kill switch is one script over the clients set and
        ``client-at:<id>`` (slots 2773 and 8708), no longer a single-key ``SADD``."""
        exc = await refused(store.kill_switch(client_id="vendor-x"))
        assert_crossslot_wrapped(exc, RevocationStoreUnavailable)
        assert admin.keys(f"{prefix}*") == []
        assert await store.is_revoked({"client_id": "vendor-x"}) is False
        assert await store.client_revoked_at("vendor-x") is None

    async def test_prune_restore_and_count_are_crossslot(self, store: RedisRevocationStore) -> None:
        assert_crossslot_wrapped(await refused(store.prune_sessions()), RevocationStoreUnavailable)
        assert_crossslot_wrapped(
            await refused(store.restore_session(jti="j1")), RevocationStoreUnavailable
        )
        assert_crossslot_wrapped(
            await refused(store.unindexed_session_count()), RevocationStoreUnavailable
        )

    async def test_the_single_key_operations_all_work(
        self,
        store: RedisRevocationStore,
        admin: Any,
        prefix: str,
    ) -> None:
        # `kill_switch` cannot seed the entry on a cluster (see the test above),
        # so it is written the way an operator's own backend might: a plain
        # SADD, plus a restored switch's stamp under its own slot.
        admin.sadd(f"{prefix}revoked:clients", "vendor-x")
        admin.set(f"{prefix}revoked:client-at:{CLIENT}", "5000", ex=60)
        snapshot = await store.entries()
        assert snapshot.clients == ("vendor-x",)
        # `is_revoked` is a NON-transactional pipeline, so each command is
        # its own single-slot request, and the kill-switch is seen.
        assert await store.is_revoked({"client_id": "vendor-x"}) is True
        # With an `iat` the pipeline also GETs `client-at` and `pair-at`, each a
        # single-key request in its own slot: the client floor refuses
        # `iat` 1 (1000 ms <= 5000 + 2000) and passes a later token.
        claims = {"sub": CUSTOMER, "client_id": CLIENT, "jti": "j"}
        assert await store.is_revoked({**claims, "iat": 1}) is True
        assert await store.is_revoked({**claims, "iat": 1_000_000}) is False
        assert await store.client_revoked_at(CLIENT) == 5000
        assert await store.customer_revoked_at(CUSTOMER) is None
        assert await store.is_customer_revoked(CUSTOMER) is False
        await store.restore_client(client_id="vendor-x")
        await store.restore_customer_client(customer_ref=CUSTOMER, client_id=CLIENT)
        assert (await store.entries()).total == 0

    async def test_a_hash_tag_prefix_makes_every_operation_work(
        self,
        cluster_url: str,
        tagged: str,
        admin: Any,
    ) -> None:
        store = RedisRevocationStore(url=cluster_url, key_prefix=tagged)
        try:
            await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=CLIENT)
            await store.revoke_session(jti="j1")  # script, then the opportunistic prune
            assert await store.prune_sessions() == 0
            assert await store.unindexed_session_count() == 0
            claims = {"sub": CUSTOMER, "client_id": CLIENT, "jti": "j1", "iat": 1}
            assert await store.is_revoked(claims) is True
            assert await store.customer_revoked_at(CUSTOMER) is not None
            await store.restore_session(jti="j1")
            assert await store.is_revoked({"jti": "j1"}) is False
            await store.kill_switch(client_id="vendor-x")  # the two-key script
            assert await store.is_revoked({"client_id": "vendor-x"}) is True
            await store.restore_client(client_id="vendor-x")
            stamp = await store.client_revoked_at("vendor-x")
            assert stamp is not None
            old = {"sub": OTHER, "client_id": "vendor-x", "jti": "j2", "iat": stamp // 1000 - 60}
            assert await store.is_revoked(old) is True, "the restore left the floor"
            assert len({slot(admin, key) for key in admin.keys(f"{tagged}*")}) == 1
        finally:
            await store.close()


def _family(sid: str | None = None) -> tuple[RefreshSession, str]:
    sid = sid or new_sid()
    token = new_refresh_token(sid)
    placeholder = datetime(2000, 1, 1, tzinfo=UTC)
    return (
        RefreshSession(
            sid=sid,
            customer_ref=CUSTOMER,
            client_id=CLIENT,
            scopes="accounts:read",
            created_at=placeholder,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            generation=0,
            current_hash=hash_refresh_token(token),
            access_tokens=(("jti-0", datetime.now(UTC) + timedelta(minutes=10)),),
        ),
        token,
    )


class TestRefreshSessionStore:
    async def test_every_operation_but_discard_is_single_key_and_works(
        self, cluster_url: str, prefix: str
    ) -> None:
        store = RedisRefreshSessionStore(url=cluster_url, key_prefix=prefix)
        try:
            family, token = _family()
            created = await store.create(family)  # TIME, MULTI on the index, SET NX, ZADD
            assert (await store.get(family.sid)) is not None
            new = new_refresh_token(family.sid)
            outcome = await store.rotate(  # WATCH / MULTI on the family key only
                family.sid,
                presented_hash=hash_refresh_token(token),
                new_hash=hash_refresh_token(new),
                access_jti="jti-1",
                access_expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
            assert outcome.rotation is Rotation.ROTATED
            assert created.sid == family.sid
            assert await store.revoke(family.sid, reason="recall") is not None
        finally:
            await store.close()

    async def test_discard_deletes_two_keys_in_a_transaction_and_is_crossslot_unwrapped(
        self,
        cluster_url: str,
        prefix: str,
        admin: Any,
    ) -> None:
        store = RedisRefreshSessionStore(url=cluster_url, key_prefix=prefix)
        try:
            family, _ = _family(FIXED_SID)
            await store.create(family)
            assert (
                slot(admin, store._key(family.sid)) == EXPECTED_SLOTS["refresh:session:fixedsid1"]
            )
            assert slot(admin, store._index_key) == EXPECTED_SLOTS["refresh:index"]
            assert_crossslot_raw(await refused(store.discard(family.sid)))
            # Nothing was deleted: the family is still there.
            assert (await store.get(family.sid)) is not None
        finally:
            await store.close()

    async def test_a_hash_tag_prefix_makes_discard_work(
        self, cluster_url: str, tagged: str
    ) -> None:
        store = RedisRefreshSessionStore(url=cluster_url, key_prefix=tagged)
        try:
            family, _ = _family()
            await store.create(family)
            await store.discard(family.sid)
            assert (await store.get(family.sid)) is None
        finally:
            await store.close()


async def _seed_untagged(
    cluster_url: str, source_tag: str, target: RedisDeviceCodeStore
) -> DeviceCode:
    """Put a complete pairing into ``target``'s namespace without its multi-key writes.

    `create_device_code` cannot succeed there, so the primary, the index entry
    and both secondary keys are written one command at a time with a raw
    client. The row is what a tagged store would have written.
    """
    maker = RedisDeviceCodeStore(url=cluster_url, key_prefix=source_tag)
    try:
        code = await maker.create_device_code(
            client_id=CLIENT, scopes="accounts:read", verification_uri="https://bank.example/d"
        )
    finally:
        await maker.close()
    raw = redis.Redis.from_url(cluster_url, decode_responses=True)
    try:
        raw.set(target._key(code.device_code), code.to_json(), ex=600)
        raw.zadd(target._index_key(), {code.device_code: code.expires_at.timestamp()})
        raw.set(target._user_code_key(code.user_code), code.device_code, ex=600)
        raw.set(target._handle_key(code.display_handle), code.device_code, ex=600)
    finally:
        raw.close()
    return code


class TestDeviceCodeStore:
    @pytest.fixture
    async def store(self, cluster_url: str, prefix: str) -> AsyncIterator[RedisDeviceCodeStore]:
        built = RedisDeviceCodeStore(url=cluster_url, key_prefix=prefix)
        yield built
        await built.close()

    async def test_create_is_crossslot_unwrapped_and_leaves_the_secondary_keys_behind(
        self,
        store: RedisDeviceCodeStore,
        admin: Any,
        prefix: str,
    ) -> None:
        """The primary and the index are written in one MULTI, two slots.

        The user_code and handle claims (`SET NX EX`, one key each) went through
        first, so a failed create strands both until their TTL: no primary, no
        index, two secondary keys.
        """
        exc = await refused(
            store.create_device_code(
                client_id=CLIENT, scopes="accounts:read", verification_uri="https://bank.example/d"
            )
        )
        assert_crossslot_raw(exc)
        left = sorted(key.removeprefix(prefix) for key in admin.keys(f"{prefix}*"))
        assert [key.split(":")[1] for key in left] == ["handle", "user_code"]
        assert all(admin.ttl(f"{prefix}{key}") > 0 for key in left)
        assert admin.exists(store._index_key()) == 0

    async def test_single_key_operations_on_a_seeded_pairing_all_work(
        self, store: RedisDeviceCodeStore, cluster_url: str, tagged: str
    ) -> None:
        code = await _seed_untagged(cluster_url, tagged, store)
        assert (await store.get_device_code(code.device_code)) is not None
        assert (await store.get_by_user_code(code.user_code)) is not None
        assert (await store.get_by_display_handle(code.display_handle)) is not None
        claim = await store.claim_scan(code.device_code, CUSTOMER, scanner_ip=None)
        assert claim is ScanClaim.CLAIMED
        assert await store.approve_scanned(code.device_code, CUSTOMER) is True
        assert await store.consume_device_code(code.device_code, session_id="s1") is True
        assert await store.consume_device_code(code.device_code, session_id="s2") is False

    async def test_the_conflict_revoke_inside_claim_scan_is_crossslot_unwrapped(
        self, store: RedisDeviceCodeStore, cluster_url: str, tagged: str
    ) -> None:
        """A second customer scanning: delete primary, zrem index, two EVALs, one MULTI."""
        code = await _seed_untagged(cluster_url, tagged, store)
        assert await store.claim_scan(code.device_code, CUSTOMER, scanner_ip=None) is (
            ScanClaim.CLAIMED
        )
        exc = await refused(store.claim_scan(code.device_code, OTHER, scanner_ip=None))
        assert_crossslot_raw(exc)
        # The revoke did not happen: the pairing the conflict should have killed lives on.
        assert (await store.get_device_code(code.device_code)) is not None

    async def test_revoke_device_code_is_crossslot_unwrapped_and_deletes_nothing(
        self, store: RedisDeviceCodeStore, cluster_url: str, tagged: str
    ) -> None:
        code = await _seed_untagged(cluster_url, tagged, store)
        assert_crossslot_raw(await refused(store.revoke_device_code(code.device_code)))
        assert (await store.get_device_code(code.device_code)) is not None
        assert (await store.get_by_user_code(code.user_code)) is not None

    async def test_a_hash_tag_prefix_makes_the_whole_lifecycle_work(
        self,
        cluster_url: str,
        tagged: str,
        admin: Any,
    ) -> None:
        store = RedisDeviceCodeStore(url=cluster_url, key_prefix=tagged)
        try:
            code = await store.create_device_code(
                client_id=CLIENT, scopes="accounts:read", verification_uri="https://bank.example/d"
            )
            assert len({slot(admin, key) for key in admin.keys(f"{tagged}*")}) == 1
            assert await store.claim_scan(code.device_code, CUSTOMER, scanner_ip=None) is (
                ScanClaim.CLAIMED
            )
            assert await store.claim_scan(code.device_code, OTHER, scanner_ip=None) is (
                ScanClaim.CONFLICT_REVOKED
            )
            assert (await store.get_device_code(code.device_code)) is None
            assert admin.keys(f"{tagged}device:*") == []
        finally:
            await store.close()


class TestSingleKeyStores:
    async def test_the_risk_session_store_works(self, cluster_url: str, prefix: str) -> None:
        store = RedisSessionStore(url=cluster_url, key_prefix=prefix)
        try:
            key = SessionKey(customer_ref=CUSTOMER, client_id=CLIENT)
            await store.save(key, RiskContext(session_id="s1"))
            loaded = await store.load(key)
            assert loaded is not None
            await store.remove(key)
            assert await store.load(key) is None
        finally:
            await store.close()

    async def test_the_customer_rate_limiter_works(self, cluster_url: str, prefix: str) -> None:
        """SET NX, INCR, TTL on ONE key in one MULTI: one slot by construction."""
        store = RedisCustomerRateLimitStore(url=cluster_url, key_prefix=prefix)
        try:
            limit = Limit(2, 60)
            assert await store.charge(CUSTOMER, "approve", limit) is None
            assert await store.charge(CUSTOMER, "approve", limit) is None
            retry_after = await store.charge(CUSTOMER, "approve", limit)
            assert retry_after is not None and 1 <= retry_after <= 60
        finally:
            await store._redis.aclose()


class TestStartupPreflight:
    def test_the_preflight_passes_so_the_service_boots(
        self, cluster_url: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`TIME` and `CONFIG GET` are keyless, so cluster mode has nothing to refuse.

        The consequence is the point: the refusal in the table above is not
        found at startup. A cluster-mode deployment starts, serves reads, and
        fails the first revocation, pairing or session write.
        """
        monkeypatch.setenv("POSTERN_REDIS_URL", cluster_url)
        redis_preflight.run_redis_preflight()

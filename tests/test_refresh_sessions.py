"""The refresh-token family store, on both backends (spec section 4).

Every test runs twice: against `InMemoryRefreshSessionStore` and against
`RedisRefreshSessionStore` on the suite's Redis container, each in its own key
prefix. The verdict is one pure function both call, so the pair is also the
check that the Redis transaction wraps it the same way the dict does.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from postern_core.auth.refresh_sessions import (
    MAX_GENERATIONS,
    SESSION_ABSOLUTE_LIFETIME,
    InMemoryRefreshSessionStore,
    RedisRefreshSessionStore,
    RefreshSession,
    RefreshSessionCollision,
    RefreshSessionStoreBase,
    RefreshSessionStoreFull,
    Rotation,
    RotationOutcome,
    _ttl_seconds,
    canonical_scope,
    create_refresh_session_store,
    from_ms,
    hash_refresh_token,
    ms_of,
    new_refresh_token,
    new_sid,
    sid_of,
)

BACKENDS = ["memory", "redis"]


def _in(seconds: int) -> datetime:
    """Whole seconds from now, as an access token's ``exp`` always is."""
    return datetime.fromtimestamp(int(time.time()) + seconds, UTC)


async def _store(
    kind: str, request: pytest.FixtureRequest, max_sessions: int = 100
) -> RefreshSessionStoreBase:
    if kind == "memory":
        return InMemoryRefreshSessionStore(max_sessions=max_sessions)
    url = request.getfixturevalue("redis_url")
    return RedisRefreshSessionStore(
        url=url, key_prefix=f"rs{uuid4().hex[:12]}:", max_sessions=max_sessions
    )


@pytest.fixture(params=BACKENDS)
async def store(request: pytest.FixtureRequest) -> AsyncIterator[RefreshSessionStoreBase]:
    built = await _store(request.param, request)
    yield built
    await built.close()


def _family(sid: str | None = None, token: str | None = None) -> tuple[RefreshSession, str]:
    sid = sid or new_sid()
    token = token or new_refresh_token(sid)
    placeholder = datetime(2000, 1, 1, tzinfo=UTC)
    session = RefreshSession(
        sid=sid,
        customer_ref="cust_7f3a",
        client_id="claude-code",
        scopes="accounts:read cards:read",
        created_at=placeholder,
        expires_at=placeholder,
        generation=0,
        current_hash=hash_refresh_token(token),
        access_tokens=(("jti-0", _in(600)),),
        device_code_handle="0123456789abcdef",
    )
    return session, token


async def _rotate(
    store: RefreshSessionStoreBase, sid: str, presented: str, *, jti: str = "jti-next"
) -> tuple[RotationOutcome, str]:
    new = new_refresh_token(sid)
    outcome = await store.rotate(
        sid,
        presented_hash=hash_refresh_token(presented),
        new_hash=hash_refresh_token(new),
        access_jti=jti,
        access_expires_at=_in(600),
    )
    return outcome, new


class TestTheToken:
    def test_the_format_and_the_sid(self) -> None:
        sid = new_sid()
        token = new_refresh_token(sid)
        assert len(sid) == 22
        prefix, named, secret = token.split(".")
        assert prefix == "prt1"
        assert named == sid
        assert len(secret) == 43
        assert sid_of(token) == sid

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "prt1..",
            "prt2." + "a" * 22 + "." + "b" * 43,
            "prt1." + "a" * 21 + "." + "b" * 43,
            "prt1." + "a" * 22 + "." + "b" * 42,
            "prt1." + "a" * 22 + "." + "b" * 43 + "x",
            "prt1." + "a" * 22 + "." + "b" * 42 + "=",
        ],
    )
    def test_a_malformed_value_names_no_family(self, value: str) -> None:
        assert sid_of(value) is None

    def test_the_hash_is_lowercase_sha256_hex_of_the_whole_value(self) -> None:
        digest = hash_refresh_token("prt1.x.y")
        assert len(digest) == 64
        assert digest == digest.lower()
        assert hash_refresh_token("prt1.x.z") != digest

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("", ""),
            ("   ", ""),
            ("b a", "a b"),
            ("a  a b", "a b"),
            ("cards:read accounts:read", "accounts:read cards:read"),
            ("B a", "B a"),
        ],
    )
    def test_canonical_scope(self, value: str, expected: str) -> None:
        assert canonical_scope(value) == expected


class TestTheRecord:
    def test_milliseconds_round_trip_exactly(self) -> None:
        for value in (0, 1, 1_727_700_000_123, 1_727_700_000_999):
            assert ms_of(from_ms(value)) == value

    def test_json_round_trip(self) -> None:
        session, _ = _family()
        session = dataclasses.replace(
            session,
            created_at=from_ms(1_727_700_000_123),
            expires_at=from_ms(1_727_703_600_123),
            revoked_at=from_ms(1_727_700_100_000),
            revoked_reason="recall",
            retained_hashes=("a" * 64,),
        )
        assert RefreshSession.from_json(session.to_json()) == session

    def test_the_ttl_is_rounded_up(self) -> None:
        now = datetime(2026, 9, 30, 12, 0, 0, tzinfo=UTC)
        assert _ttl_seconds(now + timedelta(seconds=10, milliseconds=1), now) == 11
        assert _ttl_seconds(now + timedelta(seconds=10), now) == 10
        assert _ttl_seconds(now, now) == 1


class TestCreate:
    async def test_the_store_stamps_creation_and_the_absolute_expiry(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, _ = _family()
        before = datetime.now(UTC) - timedelta(seconds=5)
        stored = await store.create(session)
        assert stored.created_at >= before
        assert stored.expires_at - stored.created_at == SESSION_ABSOLUTE_LIFETIME
        assert await store.get(session.sid) == stored

    async def test_an_existing_sid_is_a_collision(self, store: RefreshSessionStoreBase) -> None:
        session, _ = _family()
        await store.create(session)
        with pytest.raises(RefreshSessionCollision):
            await store.create(session)

    @pytest.mark.parametrize("kind", BACKENDS)
    async def test_the_cap_refuses(self, kind: str, request: pytest.FixtureRequest) -> None:
        store = await _store(kind, request, max_sessions=2)
        await store.create(_family()[0])
        await store.create(_family()[0])
        with pytest.raises(RefreshSessionStoreFull):
            await store.create(_family()[0])
        await store.close()

    async def test_get_of_a_missing_sid_is_none(self, store: RefreshSessionStoreBase) -> None:
        assert await store.get(new_sid()) is None

    async def test_discard_deletes(self, store: RefreshSessionStoreBase) -> None:
        session, _ = _family()
        await store.create(session)
        await store.discard(session.sid)
        assert await store.get(session.sid) is None


class TestRotate:
    async def test_rotated_retains_the_old_hash_and_records_the_jti(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        await store.create(session)
        outcome, new = await _rotate(store, session.sid, token, jti="jti-1")
        assert outcome.rotation is Rotation.ROTATED
        stored = await store.get(session.sid)
        assert stored is not None
        assert stored.generation == 1
        assert stored.current_hash == hash_refresh_token(new)
        assert stored.retained_hashes == (hash_refresh_token(token),)
        assert [jti for jti, _ in stored.access_tokens] == ["jti-0", "jti-1"]

    async def test_a_retained_token_is_reuse_and_revokes_in_the_same_transaction(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        await store.create(session)
        _, new = await _rotate(store, session.sid, token, jti="jti-1")
        outcome, _ = await _rotate(store, session.sid, token)
        assert outcome.rotation is Rotation.REUSED
        assert set(outcome.jtis) == {"jti-0", "jti-1"}
        stored = await store.get(session.sid)
        assert stored is not None
        assert stored.revoked_at is not None
        assert stored.revoked_reason == "reuse"
        # The current token is now refused too: both parties lose the family.
        after, _ = await _rotate(store, session.sid, new)
        assert after.rotation is Rotation.REVOKED

    async def test_revoked_writes_nothing_and_returns_the_live_jtis(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        await store.create(session)
        await store.revoke(session.sid, reason="recall")
        before = await store.get(session.sid)
        outcome, _ = await _rotate(store, session.sid, token)
        assert outcome.rotation is Rotation.REVOKED
        assert outcome.jtis == ("jti-0",)
        assert await store.get(session.sid) == before

    async def test_an_unknown_hash_writes_nothing(self, store: RefreshSessionStoreBase) -> None:
        session, _ = _family()
        stored = await store.create(session)
        outcome, _ = await _rotate(store, session.sid, new_refresh_token(session.sid))
        assert outcome.rotation is Rotation.UNKNOWN
        assert await store.get(session.sid) == stored

    async def test_exhausted_at_max_generations(self, store: RefreshSessionStoreBase) -> None:
        session, token = _family()
        await store.create(session)
        for _ in range(MAX_GENERATIONS):
            outcome, token = await _rotate(store, session.sid, token)
            assert outcome.rotation is Rotation.ROTATED
        stored = await store.get(session.sid)
        outcome, _ = await _rotate(store, session.sid, token)
        assert outcome.rotation is Rotation.EXHAUSTED
        assert await store.get(session.sid) == stored

    async def test_a_missing_family_is_gone(self, store: RefreshSessionStoreBase) -> None:
        outcome, _ = await _rotate(store, new_sid(), new_refresh_token(new_sid()))
        assert outcome.rotation is Rotation.GONE

    async def test_expired_access_tokens_are_pruned_on_write(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        session = dataclasses.replace(session, access_tokens=(("old", _in(-1)),))
        await store.create(session)
        await _rotate(store, session.sid, token, jti="fresh")
        stored = await store.get(session.sid)
        assert stored is not None
        assert [jti for jti, _ in stored.access_tokens] == ["fresh"]

    async def test_two_concurrent_rotations_are_one_rotated_and_one_reused(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, token = _family()
        await store.create(session)
        results = await asyncio.gather(
            _rotate(store, session.sid, token, jti="a"),
            _rotate(store, session.sid, token, jti="b"),
        )
        rotations = sorted(r[0].rotation.value for r in results)
        assert rotations == ["reused", "rotated"]
        stored = await store.get(session.sid)
        assert stored is not None
        assert stored.revoked_reason == "reuse"


class TestRevoke:
    async def test_revoke_is_idempotent_and_keeps_the_first_reason(
        self, store: RefreshSessionStoreBase
    ) -> None:
        session, _ = _family()
        await store.create(session)
        first = await store.revoke(session.sid, reason="recall")
        second = await store.revoke(session.sid, reason="reuse")
        assert first == second == ("jti-0",)
        stored = await store.get(session.sid)
        assert stored is not None
        assert stored.revoked_reason == "recall"

    async def test_revoke_of_a_missing_family_is_none(self, store: RefreshSessionStoreBase) -> None:
        assert await store.revoke(new_sid(), reason="recall") is None


class TestRedisSpecifics:
    async def test_the_key_ttl_is_the_absolute_lifetime(self, redis_url: str) -> None:
        prefix = f"rs{uuid4().hex[:12]}:"
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=prefix)
        session, _ = _family()
        await store.create(session)
        ttl = await store._redis.ttl(f"{prefix}refresh:session:{session.sid}")
        assert 3590 <= ttl <= 3600
        await _rotate(store, session.sid, _family(session.sid)[1])
        assert await store._redis.ttl(f"{prefix}refresh:session:{session.sid}") > 3590
        await store.close()

    async def test_an_undeserializable_record_is_gone(self, redis_url: str) -> None:
        prefix = f"rs{uuid4().hex[:12]}:"
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=prefix)
        sid = new_sid()
        await store._redis.set(f"{prefix}refresh:session:{sid}", "{not json")
        assert await store.get(sid) is None
        outcome, _ = await _rotate(store, sid, new_refresh_token(sid))
        assert outcome.rotation is Rotation.GONE
        await store.close()

    async def test_creation_is_stamped_from_the_redis_clock(self, redis_url: str) -> None:
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=f"rs{uuid4().hex[:12]}:")
        seconds, micros = await store._redis.time()
        stored = await store.create(_family()[0])
        assert abs(stored.created_ms - (int(seconds) * 1000 + int(micros) // 1000)) < 2000
        await store.close()


def test_the_factory_follows_the_redis_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)
    assert isinstance(create_refresh_session_store(), InMemoryRefreshSessionStore)
    monkeypatch.setenv("POSTERN_REDIS_URL", "redis://127.0.0.1:1/0")
    assert isinstance(create_refresh_session_store(max_sessions=5), RedisRefreshSessionStore)

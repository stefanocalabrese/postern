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
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import postern_core.auth.refresh_sessions as refresh_sessions_module
import pytest
from postern_core.auth.refresh_sessions import (
    MAX_GENERATIONS,
    SESSION_ABSOLUTE_LIFETIME,
    InMemoryRefreshSessionStore,
    RedisRefreshSessionStore,
    RefreshSession,
    RefreshSessionCollision,
    RefreshSessionStoreBase,
    RefreshSessionStoreContended,
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


def _count_decisions(
    monkeypatch: pytest.MonkeyPatch,
    before: Callable[[], None] | None = None,
    *,
    target: str = "_decide",
) -> Callable[[], int]:
    """Wrap a pure step so a test can count how often a store decided.

    ``target`` is ``_decide`` for ``rotate`` and ``_revoked`` for ``revoke``.
    ``before`` runs on each call ahead of the real decision; the contention
    tests use it to move the WATCHed key under the transaction.
    """
    calls = 0
    original = getattr(refresh_sessions_module, target)

    def counted(*args: Any, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if before is not None:
            before()
        return original(*args, **kwargs)

    monkeypatch.setattr(refresh_sessions_module, target, counted)
    return lambda: calls


def _hold_first_reads(
    monkeypatch: pytest.MonkeyPatch, store: RedisRefreshSessionStore, parties: int
) -> None:
    """Make the first ``parties`` WATCHed reads wait for one another.

    Without it the first transaction can finish before the second WATCHes,
    and the loser then reads the winner's record and never meets a moved
    key. Held here, every transaction has read the old record before any of
    them writes, so all but one must take the ``WatchError`` branch.
    """
    arrived = 0
    all_read = asyncio.Event()
    real_pipeline = store._redis.pipeline

    def pipeline(*args: Any, **kwargs: Any) -> Any:
        pipe = real_pipeline(*args, **kwargs)
        real_get = pipe.get

        async def get(key: str) -> Any:
            nonlocal arrived
            value = await real_get(key)
            if arrived < parties:
                arrived += 1
                if arrived == parties:
                    all_read.set()
                await all_read.wait()
            return value

        pipe.get = get
        return pipe

    monkeypatch.setattr(store._redis, "pipeline", pipeline)


@pytest.fixture
def other_client(redis_url: str) -> Iterator[Any]:
    """A second, synchronous Redis client: the writer a WATCH must notice."""
    import redis

    client: Any = redis.Redis.from_url(redis_url, decode_responses=True)
    yield client
    client.close()


def _interfere(
    monkeypatch: pytest.MonkeyPatch,
    other: Any,
    store: RedisRefreshSessionStore,
    sid: str,
    *,
    times: int | None,
) -> Callable[[], int]:
    """Have ``other`` rewrite the family's key inside each decision.

    It writes back the value already stored, so the record is unchanged and
    only the WATCH is broken. ``times=None`` interferes on every attempt.
    """
    key = store._key(sid)
    done = 0

    def rewrite() -> None:
        nonlocal done
        if times is not None and done >= times:
            return
        done += 1
        other.set(key, other.get(key), keepttl=True)

    return _count_decisions(monkeypatch, before=rewrite)


def _interfere_with_revoke(
    monkeypatch: pytest.MonkeyPatch,
    other: Any,
    store: RedisRefreshSessionStore,
    sid: str,
    *,
    times: int | None,
    change: Callable[[RefreshSession], RefreshSession] | None = None,
) -> Callable[[], int]:
    """`_interfere` for ``revoke``: ``other`` writes inside each ``_revoked``.

    With ``change`` the write is that record, the shape of a rotation landing
    between revoke's read and its write; without it the stored value is
    written back unchanged. ``times=None`` interferes on every attempt.
    """
    key = store._key(sid)
    done = 0

    def rewrite() -> None:
        nonlocal done
        if times is not None and done >= times:
            return
        done += 1
        raw = other.get(key)
        if change is not None:
            raw = change(RefreshSession.from_json(raw)).to_json()
        other.set(key, raw, keepttl=True)

    return _count_decisions(monkeypatch, before=rewrite, target="_revoked")


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

    def test_repr_carries_no_hash(self) -> None:
        session, _ = _family()
        session = dataclasses.replace(session, retained_hashes=("f" * 64,))
        outcome = RotationOutcome(Rotation.ROTATED, session)
        for text in (repr(session), repr(outcome)):
            assert session.current_hash not in text
            assert "f" * 64 not in text

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
        try:
            await store.create(_family()[0])
            await store.create(_family()[0])
            with pytest.raises(RefreshSessionStoreFull):
                await store.create(_family()[0])
        finally:
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

    async def test_a_wrong_secret_on_a_revoked_family_is_unknown_and_reveals_nothing(
        self, store: RefreshSessionStoreBase
    ) -> None:
        # Possession first (RFC 9700 section 4.14.2): a hash this family never
        # issued learns nothing, not even that the family is revoked.
        session, _ = _family()
        await store.create(session)
        await store.revoke(session.sid, reason="recall")
        before = await store.get(session.sid)
        outcome, _ = await _rotate(store, session.sid, new_refresh_token(session.sid))
        assert outcome.rotation is Rotation.UNKNOWN
        assert outcome.jtis == ()
        assert await store.get(session.sid) == before

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
        self, store: RefreshSessionStoreBase, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        decisions = _count_decisions(monkeypatch)
        session, token = _family()
        await store.create(session)
        if isinstance(store, RedisRefreshSessionStore):
            _hold_first_reads(monkeypatch, store, parties=2)
        results = await asyncio.gather(
            _rotate(store, session.sid, token, jti="a"),
            _rotate(store, session.sid, token, jti="b"),
        )
        rotations = sorted(r[0].rotation.value for r in results)
        assert rotations == ["reused", "rotated"]
        stored = await store.get(session.sid)
        assert stored is not None
        assert stored.revoked_reason == "reuse"
        if isinstance(store, RedisRefreshSessionStore):
            # Two presentations decided three times: the loser's EXEC met a
            # moved WATCH and re-read, so REUSED came from the retry branch
            # rather than from a read after the winner wrote.
            assert decisions() == 3


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
        session, token = _family()
        key = f"{prefix}refresh:session:{session.sid}"
        try:
            await store.create(session)
            assert 3590 <= await store._redis.ttl(key) <= 3600
            # A rotation that WRITES, so KEEPTTL is what is under test: a SET
            # without it clears the expiry and TTL answers -1.
            outcome, _ = await _rotate(store, session.sid, token)
            assert outcome.rotation is Rotation.ROTATED
            assert 0 < await store._redis.ttl(key) <= 3600
            assert await store.revoke(session.sid, reason="recall") is not None
            assert 0 < await store._redis.ttl(key) <= 3600
        finally:
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

    async def test_one_lost_watch_is_retried_and_rotates(
        self, redis_url: str, other_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=f"rs{uuid4().hex[:12]}:")
        session, token = _family()
        try:
            await store.create(session)
            decisions = _interfere(monkeypatch, other_client, store, session.sid, times=1)
            outcome, _ = await _rotate(store, session.sid, token)
            assert outcome.rotation is Rotation.ROTATED
            assert decisions() == 2
        finally:
            await store.close()

    async def test_exhausting_the_watch_retries_raises_and_writes_nothing(
        self, redis_url: str, other_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=f"rs{uuid4().hex[:12]}:")
        session, token = _family()
        try:
            before = await store.create(session)
            decisions = _interfere(monkeypatch, other_client, store, session.sid, times=None)
            with pytest.raises(RefreshSessionStoreContended):
                await _rotate(store, session.sid, token)
            assert decisions() == 3
            assert await store.get(session.sid) == before
        finally:
            await store.close()

    async def test_a_revoke_that_loses_its_watch_to_a_rotation_keeps_the_new_jti(
        self, redis_url: str, other_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A rotation lands between revoke's read and its write. Without the
        # WATCH, revoke would write the record it read and drop "jti-rotated",
        # and the recall's jti list would miss a live access token.
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=f"rs{uuid4().hex[:12]}:")
        session, _ = _family()

        def rotation(record: RefreshSession) -> RefreshSession:
            return refresh_sessions_module._rotated(
                record, "e" * 64, "jti-rotated", _in(600), datetime.now(UTC)
            )

        try:
            await store.create(session)
            calls = _interfere_with_revoke(
                monkeypatch, other_client, store, session.sid, times=1, change=rotation
            )
            jtis = await store.revoke(session.sid, reason="recall")
            assert jtis is not None
            assert set(jtis) == {"jti-0", "jti-rotated"}
            stored = await store.get(session.sid)
            assert stored is not None
            assert stored.revoked_reason == "recall"
            assert [jti for jti, _ in stored.access_tokens] == ["jti-0", "jti-rotated"]
            assert calls() == 2
        finally:
            await store.close()

    async def test_a_revoke_exhausting_its_watch_retries_raises_and_writes_nothing(
        self, redis_url: str, other_client: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = RedisRefreshSessionStore(url=redis_url, key_prefix=f"rs{uuid4().hex[:12]}:")
        session, _ = _family()
        try:
            before = await store.create(session)
            calls = _interfere_with_revoke(
                monkeypatch, other_client, store, session.sid, times=None
            )
            with pytest.raises(RefreshSessionStoreContended):
                await store.revoke(session.sid, reason="recall")
            assert calls() == 3
            assert await store.get(session.sid) == before
        finally:
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

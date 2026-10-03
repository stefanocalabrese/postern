"""Pruning of the ZT-7 session revocation set.

`revoked:sessions` is a SET and a SET member cannot carry a TTL, so a companion
sorted set (`revoked:sessions:exp`, member = jti, score = prune-after instant in
milliseconds) records when each member stops mattering. Both backends run the
same matrix; the Redis one runs against the suite's real Redis with a unique
key prefix. Nothing here sleeps: a past score is written through the store's
own `_revoke_session_for` with a negative retention, and the in-memory clock
is the module's `_now_ms`.
"""

from __future__ import annotations

import io
import logging
from collections.abc import AsyncIterator
from uuid import uuid4

import pytest
from postern_core.auth import revocation, revoke_cli
from postern_core.auth.revocation import (
    PAIR_REVOKED_AT_TTL_SECONDS,
    SESSION_REVOKED_RETENTION_SECONDS,
    InMemoryRevocationStore,
    RedisRevocationStore,
    RevocationStoreBase,
    RevocationStoreUnavailable,
)
from postern_core.auth.session_lifetime import (
    ACCESS_TOKEN_LIFETIME_SECONDS,
    SESSION_CLOCK_SKEW_SECONDS,
)

RETENTION_MS = SESSION_REVOKED_RETENTION_SECONDS * 1000


@pytest.fixture(params=["memory", "redis"])
async def store(request: pytest.FixtureRequest) -> AsyncIterator[RevocationStoreBase]:
    built: RevocationStoreBase
    if request.param == "memory":
        built = InMemoryRevocationStore()
    else:
        built = RedisRevocationStore(
            url=request.getfixturevalue("redis_url"), key_prefix=f"pr{uuid4().hex[:12]}:"
        )
    yield built
    await built.close()


async def _score(store: RevocationStoreBase, jti: str) -> int | None:
    if isinstance(store, InMemoryRevocationStore):
        return store._session_expiry.get(jti)
    assert isinstance(store, RedisRevocationStore)
    raw = await store._redis.zscore(store._sessions_exp_key, jti)
    return None if raw is None else int(raw)


async def _index_size(store: RevocationStoreBase) -> int:
    if isinstance(store, InMemoryRevocationStore):
        return len(store._session_expiry)
    assert isinstance(store, RedisRevocationStore)
    return int(await store._redis.zcard(store._sessions_exp_key))


async def _plain_sadd(store: RevocationStoreBase, jti: str) -> None:
    """What the operator's own backend does sanctioned by the module docstring."""
    if isinstance(store, InMemoryRevocationStore):
        store._list.revoke_session(jti=jti)
        store._sessions.add(jti)
        return
    assert isinstance(store, RedisRevocationStore)
    await store._redis.sadd(store._sessions_key, jti)


def test_the_retention_is_access_lifetime_plus_skew_plus_margin() -> None:
    assert SESSION_REVOKED_RETENTION_SECONDS == 600 + 30 + 300 == 930
    assert SESSION_REVOKED_RETENTION_SECONDS == (
        ACCESS_TOKEN_LIFETIME_SECONDS + SESSION_CLOCK_SKEW_SECONDS + 300
    )
    assert SESSION_REVOKED_RETENTION_SECONDS == PAIR_REVOKED_AT_TTL_SECONDS


async def test_revoke_adds_to_the_set_and_the_index_with_the_retention_score(
    store: RevocationStoreBase, monkeypatch: pytest.MonkeyPatch
) -> None:
    if isinstance(store, InMemoryRevocationStore):
        monkeypatch.setattr(revocation, "_now_ms", lambda: 1_000_000)
    import time

    before = time.time_ns() // 1_000_000
    await store.revoke_session(jti="tok-1")
    after = time.time_ns() // 1_000_000
    assert await store.is_revoked({"jti": "tok-1"}) is True
    assert (await store.entries()).sessions == ("tok-1",)
    score = await _score(store, "tok-1")
    assert score is not None
    if isinstance(store, InMemoryRevocationStore):
        assert score == 1_000_000 + RETENTION_MS
    else:
        assert before + RETENTION_MS - 2_000 <= score <= after + RETENTION_MS + 2_000


async def test_a_reassert_never_shortens_the_retention(store: RevocationStoreBase) -> None:
    long_ms = 10_000_000_000
    await store._revoke_session_for("tok-1", long_ms)  # type: ignore[attr-defined]
    longer = await _score(store, "tok-1")
    await store.revoke_session(jti="tok-1")
    assert await _score(store, "tok-1") == longer
    assert await _index_size(store) == 1


async def test_a_reassert_extends_a_shorter_retention(store: RevocationStoreBase) -> None:
    await store._revoke_session_for("tok-1", -5_000)  # type: ignore[attr-defined]
    stale = await _score(store, "tok-1")
    await store.revoke_session(jti="tok-1")
    fresh = await _score(store, "tok-1")
    assert stale is not None and fresh is not None
    assert fresh > stale


async def test_prune_removes_only_expired_entries(store: RevocationStoreBase) -> None:
    await store._revoke_session_for("old", -1_000)  # type: ignore[attr-defined]
    await store._revoke_session_for("live", 600_000)  # type: ignore[attr-defined]
    assert await store.prune_sessions() == 1
    assert await store.is_revoked({"jti": "old"}) is False
    assert await store.is_revoked({"jti": "live"}) is True
    assert (await store.entries()).sessions == ("live",)
    assert await _score(store, "old") is None
    assert await _score(store, "live") is not None
    assert await store.prune_sessions() == 0


async def test_prune_respects_the_limit(store: RevocationStoreBase) -> None:
    for n in range(5):
        await store._revoke_session_for(f"old-{n}", -1_000 - n)  # type: ignore[attr-defined]
    assert await store.prune_sessions(limit=2) == 2
    assert len((await store.entries()).sessions) == 3
    assert await _index_size(store) == 3
    assert await store.prune_sessions(limit=10) == 3
    assert (await store.entries()).sessions == ()
    assert await _index_size(store) == 0


async def test_members_without_an_index_entry_are_never_pruned(
    store: RevocationStoreBase,
) -> None:
    await _plain_sadd(store, "operator-written")
    await store._revoke_session_for("old", -1_000)  # type: ignore[attr-defined]
    assert await store.prune_sessions() == 1
    assert await store.is_revoked({"jti": "operator-written"}) is True
    assert await store.unindexed_session_count() == 1


async def test_unindexed_count_is_set_minus_index(store: RevocationStoreBase) -> None:
    assert await store.unindexed_session_count() == 0
    await store.revoke_session(jti="indexed")
    assert await store.unindexed_session_count() == 0
    await _plain_sadd(store, "a")
    await _plain_sadd(store, "b")
    assert await store.unindexed_session_count() == 2


async def test_restore_removes_the_index_entry(store: RevocationStoreBase) -> None:
    await store.revoke_session(jti="tok-1")
    await store.restore_session(jti="tok-1")
    assert await store.is_revoked({"jti": "tok-1"}) is False
    assert await _score(store, "tok-1") is None
    assert await _index_size(store) == 0


async def test_a_later_revoke_after_restore_keeps_the_higher_score_so_the_stale_one_cannot_prune_it(
    store: RevocationStoreBase,
) -> None:
    # The first revocation's retention is already over. Had restore left its
    # index entry behind, the second revoke would keep that earlier score and
    # the next prune would drop a jti that was revoked a moment ago.
    await store._revoke_session_for("tok-1", -1_000)  # type: ignore[attr-defined]
    await store.restore_session(jti="tok-1")
    await store.revoke_session(jti="tok-1")
    assert await store.prune_sessions() == 0
    assert await store.is_revoked({"jti": "tok-1"}) is True


async def test_restore_then_an_operator_sadd_is_not_pruned_by_a_stale_index_entry(
    store: RevocationStoreBase,
) -> None:
    # With the max-score rule a stale entry cannot shorten a later revoke() (the
    # case above holds even without the ZREM). The case that needs restore to
    # clean the index is the unindexed one: the operator's backend re-adds the
    # jti with a plain SADD, and a leftover past score would let the next prune
    # remove it.
    await store._revoke_session_for("tok-1", -1_000)  # type: ignore[attr-defined]
    await store.restore_session(jti="tok-1")
    await _plain_sadd(store, "tok-1")
    assert await store.prune_sessions() == 0
    assert await store.is_revoked({"jti": "tok-1"}) is True


async def test_memory_clock_advance_prunes_an_unexpired_entry_only_after_retention(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [5_000_000]
    monkeypatch.setattr(revocation, "_now_ms", lambda: now[0])
    mem = InMemoryRevocationStore()
    await mem.revoke_session(jti="tok-1")
    now[0] += RETENTION_MS - 1
    assert await mem.prune_sessions() == 0
    assert await mem.is_revoked({"jti": "tok-1"}) is True
    now[0] += 1
    assert await mem.prune_sessions() == 1
    assert await mem.is_revoked({"jti": "tok-1"}) is False


async def test_revoke_prunes_the_expired_backlog_opportunistically(
    store: RevocationStoreBase,
) -> None:
    await store._revoke_session_for("old", -1_000)  # type: ignore[attr-defined]
    await store.revoke_session(jti="new")
    assert await store.is_revoked({"jti": "old"}) is False
    assert await store.is_revoked({"jti": "new"}) is True


async def test_a_prune_error_during_revoke_does_not_fail_the_revoke(
    store: RevocationStoreBase, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def boom(*, limit: int = 1000) -> int:
        raise RevocationStoreUnavailable("prune down")

    monkeypatch.setattr(store, "prune_sessions", boom)
    with caplog.at_level(logging.WARNING, logger=revocation.logger.name):
        await store.revoke_session(jti="tok-1")
    assert await store.is_revoked({"jti": "tok-1"}) is True
    assert any("prune" in record.getMessage() for record in caplog.records)


async def test_a_redis_outage_on_revoke_still_fails_closed() -> None:
    down = RedisRevocationStore(url="redis://127.0.0.1:1/0", key_prefix="x:")
    with pytest.raises(RevocationStoreUnavailable):
        await down.revoke_session(jti="tok-1")
    with pytest.raises(RevocationStoreUnavailable):
        await down.prune_sessions()
    await down.close()


async def test_the_other_scopes_are_untouched(store: RevocationStoreBase) -> None:
    await store.revoke_customer_client(customer_ref="c", client_id="v")
    await store.kill_switch(client_id="k")
    await store._revoke_session_for("old", -1_000)  # type: ignore[attr-defined]
    await store.prune_sessions()
    assert await store.is_revoked({"sub": "c", "client_id": "v"}) is True
    assert await store.is_revoked({"client_id": "k"}) is True


async def _cli(store: RevocationStoreBase, *argv: str) -> tuple[int, str, str]:
    args = revoke_cli._parser().parse_args(list(argv))
    out, err = io.StringIO(), io.StringIO()
    code = await revoke_cli._run(args, store, out, err)
    return code, out.getvalue(), err.getvalue()


async def test_the_cli_prints_the_pruned_and_unindexed_counts(
    store: RevocationStoreBase,
) -> None:
    await store._revoke_session_for("old-1", -1_000)  # type: ignore[attr-defined]
    await store._revoke_session_for("old-2", -2_000)  # type: ignore[attr-defined]
    await _plain_sadd(store, "operator-written")
    code, text, _err = await _cli(store, "prune-sessions")
    assert code == 0
    assert "pruned 2" in text
    assert "at least 1 revoked sessions without an expiry index" in text


async def test_the_cli_limit_flag_bounds_one_batch(store: RevocationStoreBase) -> None:
    for n in range(3):
        await store._revoke_session_for(f"old-{n}", -1_000)  # type: ignore[attr-defined]
    code, text, _err = await _cli(store, "prune-sessions", "--limit", "1")
    assert code == 0
    assert "pruned 1" in text


async def test_the_cli_reports_a_store_error_and_exits_nonzero() -> None:
    class Down(InMemoryRevocationStore):
        async def prune_sessions(self, *, limit: int = 1000) -> int:
            raise RevocationStoreUnavailable("redis down")

    code, text, err = await _cli(Down(), "prune-sessions")
    assert code == 1
    assert "redis down" in err
    assert text == ""


def test_the_cli_verb_is_wired_through_main() -> None:
    out = io.StringIO()
    assert revoke_cli.main(["prune-sessions"], store=InMemoryRevocationStore(), out=out) == 0
    assert "pruned 0" in out.getvalue()


@pytest.mark.parametrize("bad", ["0", "-3", "x"])
def test_the_cli_rejects_a_non_positive_limit(bad: str) -> None:
    with pytest.raises(SystemExit):
        revoke_cli._parser().parse_args(["prune-sessions", "--limit", bad])

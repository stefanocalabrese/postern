"""The M1 revocation-ordering regressions, against REAL Redis stores.

``TestARevocationBetweenTheCheckAndTheStamp`` in ``tests/test_refresh_grant.py``
proves the order of ``_exchange`` (draw, create, ZT-7 checks, claim, sign)
against the in-memory stores, where the ordering argument is true by
construction. The argument in production rests on Redis: a revocation script
that ran before ``RedisRefreshSessionStore.create`` reads ``TIME`` is visible
to the checks that run after it. Here the confirm app is built with
``POSTERN_REDIS_URL`` set, so its refresh-family, revocation and device-code
stores are all Redis, each test in its own key prefix.

Redis ``TIME`` cannot be steered, so no assertion depends on the sub-millisecond
order of two clock reads: where S and ``created_ms`` could share a millisecond
the property asserted is the security one (refused, no family, no token).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any
from uuid import uuid4

import pytest
import redis.asyncio as aioredis
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.auth.refresh_sessions import RedisRefreshSessionStore, RefreshSession
from postern_core.auth.revocation import RedisRevocationStore, RevocationStoreUnavailable
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_ISSUED_BEFORE_REVOCATION,
    DETAIL_REVOKED,
    REFRESH_TOOL_NAME,
    TOKEN_TOOL_NAME,
)
from tests.device_grant_helpers import session_claims
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_refresh_grant import SCOPES, _refresh, _refused, _retryable, _sid
from tests.test_token_session_issuance import CUSTOMER, _app, _approved, _exchange


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    yield database


@pytest.fixture()
def prefix() -> str:
    return f"m1{uuid4().hex[:12]}:"


@pytest.fixture()
async def app(
    key_pair: RSAKeyPair, pg_url: str, redis_url: str, prefix: str, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[Starlette]:
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", prefix)
    built = _app(key_pair, pg_url, allow_process_local_sessions=False)
    assert isinstance(built.state.refresh_session_store, RedisRefreshSessionStore)
    assert isinstance(built.state.postern_revocation_store, RedisRevocationStore)
    yield built
    await built.state.refresh_session_store.close()
    await built.state.postern_revocation_store.close()


async def _family_keys(app: Starlette, prefix: str) -> list[str]:
    """Every family record and index entry under this test's prefix."""
    sessions: RedisRefreshSessionStore = app.state.refresh_session_store
    keys = [k async for k in sessions._redis.scan_iter(match=f"{prefix}refresh:session:*")]
    keys += [f"index:{m}" for m in await sessions._redis.zrange(f"{prefix}refresh:index", 0, -1)]
    return keys


async def _rows_of(db: Database, tool: str) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(
            select(AuditEntry).where(AuditEntry.tool_name == tool).order_by(AuditEntry.id)
        )
        return list(result.scalars())


async def _family(app: Starlette, body: dict[str, Any]) -> RefreshSession:
    sessions: RedisRefreshSessionStore = app.state.refresh_session_store
    family = await sessions.get(_sid(body))
    assert family is not None
    return family


class TestAnExchangeAgainstRealRedis:
    async def test_a_revocation_landing_inside_create_is_refused_and_not_revived_by_a_restore(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        prefix: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(a) The revocation script has executed before create reads TIME.

        S <= created_ms always holds here; S == created_ms is possible and is
        refused at refresh by ``>=``, and at the exchange by the checks that
        now run after create. Either way: 400, no token, no family.
        """
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        sessions: RedisRefreshSessionStore = app.state.refresh_session_store
        real_create = sessions.create
        seen: list[int | None] = []

        async def create_with_a_revocation_inside(session: RefreshSession) -> RefreshSession:
            await revocations.revoke_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
            seen.append(await revocations.customer_revoked_at(CUSTOMER))
            return await real_create(session)

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(sessions, "create", create_with_a_revocation_inside)
        response = await _exchange(app, device["device_code"])
        monkeypatch.setattr(sessions, "create", real_create)
        await revocations.restore_customer_client(customer_ref=CUSTOMER, client_id="claude-code")

        assert seen and seen[0] is not None
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "access_denied"
        assert "refresh_token" not in response.json()
        assert await _family_keys(app, prefix) == [], "no family record, no index entry"
        (row,) = await _rows_of(clean, TOKEN_TOOL_NAME)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, DETAIL_REVOKED)
        # After the restore, no refresh token can exist to be presented.
        _refused(await _refresh(app, f"prt1.{'a' * 22}.{'b' * 43}"))

    async def test_a_revocation_straight_after_create_is_seen_by_the_checks_and_discards_the_family(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        prefix: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(b1) Revoke immediately after the real create returns.

        The ZT-7 checks run after create, so they see it: 400, family discarded.
        """
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        sessions: RedisRefreshSessionStore = app.state.refresh_session_store
        real_create = sessions.create

        async def create_then_revoke(session: RefreshSession) -> RefreshSession:
            stamped = await real_create(session)
            await revocations.revoke_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
            stamp = await revocations.customer_revoked_at(CUSTOMER)
            assert stamp is not None and stamp >= stamped.created_ms
            return stamped

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(sessions, "create", create_then_revoke)
        response = await _exchange(app, device["device_code"])
        monkeypatch.setattr(sessions, "create", real_create)
        await revocations.restore_customer_client(customer_ref=CUSTOMER, client_id="claude-code")

        assert response.status_code == 400, response.text
        assert response.json()["error"] == "access_denied"
        assert "refresh_token" not in response.json()
        assert await _family_keys(app, prefix) == []
        (row,) = await _rows_of(clean, TOKEN_TOOL_NAME)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, DETAIL_REVOKED)

    async def test_a_revocation_after_the_checks_is_refused_at_refresh_once_restored(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(b2) Revoke after create's TIME AND after the step-0 checks (at the claim).

        Nothing in the exchange can see it, so it answers 200. The stamp is
        >= ``created_ms`` (it was taken later on the same Redis clock), so once
        restored the refresh is refused as ``issued_before_revocation``.
        """
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        codes = app.state.device_code_store
        real_consume = codes.consume_device_code

        async def revoke_then_claim(*args: Any, **kwargs: Any) -> Any:
            await revocations.revoke_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
            return await real_consume(*args, **kwargs)

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(codes, "consume_device_code", revoke_then_claim)
        response = await _exchange(app, device["device_code"])
        monkeypatch.setattr(codes, "consume_device_code", real_consume)
        session_claims(response, app)
        body = response.json()
        stamp = await revocations.customer_revoked_at(CUSTOMER)
        family = await _family(app, body)
        assert stamp is not None and stamp >= family.created_ms

        await revocations.restore_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        _refused(await _refresh(app, body["refresh_token"]))
        assert (await _family(app, body)).revoked_reason == "issued_before_revocation"
        (row,) = await _rows_of(clean, REFRESH_TOOL_NAME)
        assert row.detail == DETAIL_ISSUED_BEFORE_REVOCATION

    async def test_a_revocation_store_outage_leaves_no_family_and_the_code_unspent(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        prefix: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """(c) The Redis revocation store's check raises once: 503, nothing left."""
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        real = revocations.is_customer_revoked

        async def down(customer_ref: str) -> bool:
            raise RevocationStoreUnavailable("simulated outage")

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(revocations, "is_customer_revoked", down)
        _retryable(app, await _exchange(app, device["device_code"]))
        assert await _family_keys(app, prefix) == []
        (row,) = await _rows_of(clean, TOKEN_TOOL_NAME)
        assert row.detail == "RevocationStoreUnavailable"

        monkeypatch.setattr(revocations, "is_customer_revoked", real)
        app.state._approved_poll_times.clear()  # the poll pacing, not under test
        session_claims(await _exchange(app, device["device_code"]), app)
        assert len(await _family_keys(app, prefix)) == 2  # record + index entry

    async def test_an_unreachable_revocation_redis_is_an_outage_not_a_denial(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        prefix: str,
    ) -> None:
        """(c') The genuine failure path: the revocation store's Redis client cannot connect."""
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        device = await _approved(app, key_pair, scopes=SCOPES)
        original = revocations._redis
        revocations._redis = aioredis.from_url(  # type: ignore[no-untyped-call]
            "redis://127.0.0.1:1/0", decode_responses=True, socket_connect_timeout=0.5
        )
        try:
            _retryable(app, await _exchange(app, device["device_code"]))
        finally:
            await revocations._redis.aclose()
            revocations._redis = original
        assert await _family_keys(app, prefix) == []
        app.state._approved_poll_times.clear()
        session_claims(await _exchange(app, device["device_code"]), app)


class TestAnExchangeUnderAKillSwitchAgainstRealRedis:
    """The exchange's kill-switch gate on the Redis stores (in-memory twin in
    ``tests/test_refresh_grant.py``'s ``TestAnExchangeUnderAKillSwitch``)."""

    async def test_refused_while_it_stands_then_the_same_code_exchanges_after_the_restore(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, prefix: str
    ) -> None:
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        device = await _approved(app, key_pair, scopes=SCOPES)
        await revocations.kill_switch(client_id="claude-code")

        response = await _exchange(app, device["device_code"])
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "access_denied"
        assert await _family_keys(app, prefix) == []
        code = await app.state.device_code_store.get_device_code(device["device_code"])
        assert code is not None and code.exchanged_at is None, "the code is left unspent"
        (row,) = await _rows_of(clean, TOKEN_TOOL_NAME)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, DETAIL_REVOKED)

        await revocations.restore_client(client_id="claude-code")
        app.state._approved_poll_times.clear()
        session_claims(await _exchange(app, device["device_code"]), app)

    async def test_another_clients_kill_switch_does_not_touch_this_exchange(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        await revocations.kill_switch(client_id="some-other-client")
        device = await _approved(app, key_pair, scopes=SCOPES)
        session_claims(await _exchange(app, device["device_code"]), app)

    async def test_a_kill_straight_after_create_is_seen_and_discards_the_family(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        prefix: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        sessions: RedisRefreshSessionStore = app.state.refresh_session_store
        real_create = sessions.create

        async def create_then_kill(session: RefreshSession) -> RefreshSession:
            stamped = await real_create(session)
            await revocations.kill_switch(client_id="claude-code")
            return stamped

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(sessions, "create", create_then_kill)
        response = await _exchange(app, device["device_code"])
        monkeypatch.setattr(sessions, "create", real_create)
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "access_denied"
        assert await _family_keys(app, prefix) == []

    async def test_an_outage_on_the_kill_switch_read_is_a_503_with_no_family(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        prefix: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        revocations: RedisRevocationStore = app.state.postern_revocation_store

        async def down(claims: Any) -> bool:
            raise RevocationStoreUnavailable("simulated outage")

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(revocations, "is_revoked", down)
        _retryable(app, await _exchange(app, device["device_code"]))
        assert await _family_keys(app, prefix) == []
        (row,) = await _rows_of(clean, TOKEN_TOOL_NAME)
        assert row.detail == "RevocationStoreUnavailable"


class TestARestoredKillSwitchAgainstRealRedis:
    """The kill-switch stamp and the family's ``created_ms`` are both Redis ``TIME``."""

    async def test_a_family_created_before_the_kill_is_revoked_at_refresh_after_the_restore(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        device = await _approved(app, key_pair, scopes=SCOPES)
        response = await _exchange(app, device["device_code"])
        session_claims(response, app)
        body = response.json()

        await revocations.kill_switch(client_id="claude-code")
        _refused(await _refresh(app, body["refresh_token"]))
        assert (await _family(app, body)).revoked_at is None, "while it stands: refused only"

        await revocations.restore_client(client_id="claude-code")
        stamp = await revocations.client_revoked_at("claude-code")
        family = await _family(app, body)
        assert stamp is not None and stamp >= family.created_ms
        _refused(await _refresh(app, body["refresh_token"]))
        family = await _family(app, body)
        assert family.revoked_reason == "issued_before_revocation"
        jti = family.access_tokens[0][0]
        assert await revocations.is_revoked({"jti": jti}), "its live access token is listed"
        assert [row.detail for row in await _rows_of(clean, REFRESH_TOOL_NAME)] == [
            DETAIL_REVOKED,
            DETAIL_ISSUED_BEFORE_REVOCATION,
        ]

    async def test_a_family_created_after_the_restore_refreshes(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        revocations: RedisRevocationStore = app.state.postern_revocation_store
        await revocations.kill_switch(client_id="claude-code")
        await revocations.restore_client(client_id="claude-code")
        stamp = await revocations.client_revoked_at("claude-code")
        device = await _approved(app, key_pair, scopes=SCOPES)
        response = await _exchange(app, device["device_code"])
        session_claims(response, app)
        body = response.json()
        assert stamp is not None and (await _family(app, body)).created_ms > stamp
        session_claims(await _refresh(app, body["refresh_token"]), app)

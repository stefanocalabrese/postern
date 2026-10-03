"""``POST /token`` with ``grant_type=refresh_token`` (spec section 6).

Every branch, through the assembled confirm app: the shape checks and the
lookup that write nothing; the proof of possession, before which nothing is
recorded and after which every exit writes one ``device_grant.refresh`` row;
reuse detection, revocation re-assertion and its convergence; the generation
and lifetime limits; the ``client_id`` transplant signal; scope
canonicalization and narrowing; and the four ZT-7 checks, including a family
issued before a since-restored customer revocation.
"""

from __future__ import annotations

import base64
import dataclasses
import json
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.auth import refresh_sessions
from postern_core.auth.refresh_sessions import (
    MAX_GENERATIONS,
    InMemoryRefreshSessionStore,
    RefreshSession,
    RefreshSessionStoreContended,
    new_refresh_token,
)
from postern_core.auth.revocation import InMemoryRevocationStore, RevocationStoreUnavailable
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, OUTCOME_RETURNED, AuditEntry
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_CLIENT_ID_MISMATCH,
    DETAIL_ISSUED_BEFORE_REVOCATION,
    DETAIL_REFRESH_REUSED,
    DETAIL_REVOKED,
    DETAIL_SCOPE_EXCEEDED,
    DETAIL_SESSION_EXPIRED,
    DETAIL_SESSION_GENERATIONS_EXHAUSTED,
    DETAIL_SESSION_REVOKED,
    REFRESH_TOOL_NAME,
    TOKEN_ROUTE,
    TOKEN_TOOL_NAME,
)
from tests.device_grant_helpers import session_claims
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_token_session_issuance import CUSTOMER, RESOURCE, _app, _approved, _exchange

SCOPES = "accounts:read cards:read transactions:read"


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
def app(key_pair: RSAKeyPair, pg_url: str) -> Starlette:
    return _app(key_pair, pg_url)


async def _session(app: Starlette, key_pair: RSAKeyPair) -> dict[str, Any]:
    """A pairing exchanged for a session; the parsed 200 body."""
    device = await _approved(app, key_pair, scopes=SCOPES)
    response = await _exchange(app, device["device_code"])
    session_claims(response, app)
    body: dict[str, Any] = response.json()
    return body


async def _refresh(app: Starlette, refresh_token: str | None, **extra: str) -> httpx2.Response:
    data = {"grant_type": "refresh_token", **extra}
    if refresh_token is not None:
        data["refresh_token"] = refresh_token
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://t",
    ) as client:
        return await client.post("/token", data=data)


async def _post(app: Starlette, **kwargs: Any) -> httpx2.Response:
    """``POST /token`` with whatever body ``kwargs`` describes."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://t",
    ) as client:
        return await client.post("/token", **kwargs)


def _invalid_request(response: httpx2.Response) -> None:
    assert response.status_code == 400, response.text
    assert response.json()["error"] == "invalid_request"
    assert response.headers["cache-control"] == "no-store"


def _retryable(app: Starlette, response: httpx2.Response) -> None:
    assert response.status_code == 503, response.text
    assert response.json()["error"] == "temporarily_unavailable"
    assert response.headers["retry-after"] == str(app.state.settings.device_poll_interval_seconds)
    assert response.headers["cache-control"] == "no-store"


async def _rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(
            select(AuditEntry)
            .where(AuditEntry.tool_name == REFRESH_TOOL_NAME)
            .order_by(AuditEntry.id)
        )
        return list(result.scalars())


def _sid(body: dict[str, Any]) -> str:
    return str(body["refresh_token"].split(".")[1])


def _jti(body: dict[str, Any]) -> str:
    """The ``jti`` of the access token in a session body, read without verifying."""
    payload = body["access_token"].split(".")[1]
    return str(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["jti"])


async def _family(app: Starlette, body: dict[str, Any]) -> RefreshSession:
    sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
    return sessions._sessions[_sid(body)]


def _refused(response: httpx2.Response) -> None:
    assert response.status_code == 400, response.text
    assert response.json() == {
        "error": "invalid_grant",
        "error_description": "refresh token cannot be redeemed",
    }


class TestARefreshThatSucceeds:
    async def test_it_rotates_and_issues_a_fresh_access_token_in_the_same_family(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(app, first["refresh_token"])
        claims = session_claims(response, app)
        body = response.json()
        assert body["refresh_token"] != first["refresh_token"]
        assert _sid(body) == _sid(first)
        assert claims["sid"] == _sid(first)
        assert claims["scope"] == SCOPES
        family = await _family(app, body)
        assert family.generation == 1
        assert len(family.access_tokens) == 2

        (row,) = await _rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RETURNED, None)
        assert row.customer_ref == CUSTOMER
        assert row.arguments["route"] == TOKEN_ROUTE
        assert row.arguments["session_id"] == _sid(first)
        assert row.arguments["paired_client_id"] == "claude-code"
        assert "device_code_handle" not in row.arguments
        for token in (first["refresh_token"], body["refresh_token"], body["access_token"]):
            assert token not in str(row.arguments)

    async def test_a_matching_client_id_and_resource_are_accepted(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(
            app, first["refresh_token"], client_id="claude-code", resource=RESOURCE
        )
        session_claims(response, app)


class TestNothingIsRecordedBeforeTheProof:
    async def test_a_missing_token_is_invalid_request(
        self, app: Starlette, clean: Database
    ) -> None:
        response = await _refresh(app, None)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"
        assert response.headers["cache-control"] == "no-store"
        assert await _rows(clean) == []

    @pytest.mark.parametrize(
        "value", ["garbage", "prt1.short.value", "prt2." + "a" * 22 + "." + "b" * 43]
    )
    async def test_a_malformed_token_is_invalid_grant(
        self, app: Starlette, clean: Database, value: str
    ) -> None:
        _refused(await _refresh(app, value))
        assert await _rows(clean) == []

    async def test_an_unknown_family_is_invalid_grant(
        self, app: Starlette, clean: Database
    ) -> None:
        _refused(await _refresh(app, new_refresh_token("A" * 22)))
        assert await _rows(clean) == []

    async def test_an_unserved_resource_is_invalid_target(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(app, first["refresh_token"], resource="https://other.test/mcp")
        assert response.json()["error"] == "invalid_target"
        assert await _rows(clean) == []

    async def test_an_unknown_hash_under_a_real_family_writes_nothing_and_logs_once(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        first = await _session(app, key_pair)
        forged = new_refresh_token(_sid(first))
        with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
            _refused(await _refresh(app, forged))
            _refused(await _refresh(app, new_refresh_token(_sid(first))))
        assert await _rows(clean) == []
        lines = [r for r in caplog.records if "never issued" in r.getMessage()]
        assert len(lines) == 1
        assert _sid(first) in lines[0].getMessage()
        assert forged not in caplog.text
        family = await _family(app, first)
        assert family.revoked_at is None and family.generation == 0

    async def test_an_unknown_hash_under_a_revoked_family_reveals_and_reasserts_nothing(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        await sessions.revoke(_sid(first), reason="recall")
        response = await _refresh(app, new_refresh_token(_sid(first)))
        _refused(response)
        assert "retry-after" not in response.headers
        assert await _rows(clean) == []
        revocations: InMemoryRevocationStore = app.state.postern_revocation_store
        assert not await revocations.is_revoked({"jti": _jti(first)})


class TestTheRequestShape:
    @pytest.mark.parametrize("name", ["refresh_token", "client_id", "scope", "grant_type"])
    async def test_a_repeated_parameter_is_invalid_request_and_writes_nothing(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, name: str
    ) -> None:
        first = await _session(app, key_pair)
        values = {
            "refresh_token": first["refresh_token"],
            "client_id": "claude-code",
            "scope": "accounts:read",
            "grant_type": "refresh_token",
        }
        body = list(values.items())
        body.append((name, values[name]))
        response = await _post(
            app,
            content="&".join(f"{key}={value}" for key, value in body),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        _invalid_request(response)
        assert await _rows(clean) == []
        assert (await _family(app, first)).generation == 0

    @pytest.mark.parametrize("name", ["refresh_token", "client_id", "scope", "grant_type"])
    async def test_a_file_part_that_is_not_utf8_is_invalid_request(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, name: str
    ) -> None:
        first = await _session(app, key_pair)
        data = {"grant_type": "refresh_token", "refresh_token": first["refresh_token"]}
        data.pop(name, None)
        response = await _post(
            app, data=data, files={name: ("value", b"\xff\xfe\xfd", "text/plain")}
        )
        _invalid_request(response)
        assert await _rows(clean) == []
        assert (await _family(app, first)).generation == 0

    async def test_a_utf8_file_part_is_read(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        response = await _post(
            app,
            data={"grant_type": "refresh_token"},
            files={"refresh_token": ("value", first["refresh_token"].encode(), "text/plain")},
        )
        session_claims(response, app)

    async def test_a_family_store_outage_at_the_lookup_is_a_retryable_503_with_no_row(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def down(sid: str) -> RefreshSession | None:
            raise RedisConnectionError("simulated outage")

        monkeypatch.setattr(sessions, "get", down)
        _retryable(app, await _refresh(app, first["refresh_token"]))
        assert await _rows(clean) == []


class TestReuse:
    async def test_a_retained_token_revokes_the_family_and_lists_every_live_jti(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        first = await _session(app, key_pair)
        second = (await _refresh(app, first["refresh_token"])).json()
        with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
            _refused(await _refresh(app, first["refresh_token"]))
        family = await _family(app, first)
        assert family.revoked_reason == "reuse"
        assert "is revoked" in caplog.text and family.device_code_handle in caplog.text
        revocations: InMemoryRevocationStore = app.state.postern_revocation_store
        for jti, _ in family.access_tokens:
            assert await revocations.is_revoked({"jti": jti})

        _refused(await _refresh(app, second["refresh_token"]))
        assert [r.detail for r in await _rows(clean)] == [
            None,
            DETAIL_REFRESH_REUSED,
            DETAIL_SESSION_REVOKED,
        ]

    async def test_a_failed_zt7_write_at_reuse_converges_on_the_next_presentation(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        second = (await _refresh(app, first["refresh_token"])).json()
        revocations: InMemoryRevocationStore = app.state.postern_revocation_store
        real = revocations.revoke_session

        async def down(*, jti: str) -> None:
            raise RevocationStoreUnavailable("simulated outage")

        monkeypatch.setattr(revocations, "revoke_session", down)
        outage = await _refresh(app, first["refresh_token"])
        assert outage.status_code == 503
        assert outage.headers["retry-after"] == str(app.state.settings.device_poll_interval_seconds)
        family = await _family(app, first)
        assert family.revoked_at is not None
        jtis = [jti for jti, _ in family.access_tokens]
        assert not await revocations.is_revoked({"jti": jtis[0]})

        monkeypatch.setattr(revocations, "revoke_session", real)
        _refused(await _refresh(app, second["refresh_token"]))
        for jti in jtis:
            assert await revocations.is_revoked({"jti": jti})
        assert [r.detail for r in await _rows(clean)] == [
            None,
            "RevocationStoreUnavailable",
            DETAIL_SESSION_REVOKED,
        ]

    async def test_a_family_store_outage_at_reuse_is_a_retryable_503(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        await _refresh(app, first["refresh_token"])
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        real = sessions.revoke

        async def down(sid: str, *, reason: str) -> tuple[str, ...] | None:
            raise RedisConnectionError("simulated outage")

        monkeypatch.setattr(sessions, "revoke", down)
        _retryable(app, await _refresh(app, first["refresh_token"]))
        assert (await _family(app, first)).revoked_at is None

        monkeypatch.setattr(sessions, "revoke", real)
        _refused(await _refresh(app, first["refresh_token"]))
        assert (await _family(app, first)).revoked_reason == "reuse"
        assert [r.detail for r in await _rows(clean)] == [
            None,
            "ConnectionError",
            DETAIL_REFRESH_REUSED,
        ]

    async def test_a_store_fault_that_is_not_an_outage_at_reuse_is_a_500(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        await _refresh(app, first["refresh_token"])
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def broken(sid: str, *, reason: str) -> tuple[str, ...] | None:
            raise ValueError("a programming error, not an outage")

        monkeypatch.setattr(sessions, "revoke", broken)
        response = await _refresh(app, first["refresh_token"])
        assert response.status_code == 500
        assert [r.detail for r in await _rows(clean)] == [None, "ValueError"]


class TestTheFamilysLimits:
    async def test_exhausted_generations(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        sid = _sid(first)
        sessions._sessions[sid] = dataclasses.replace(
            sessions._sessions[sid], generation=MAX_GENERATIONS
        )
        _refused(await _refresh(app, first["refresh_token"]))
        assert [r.detail for r in await _rows(clean)] == [DETAIL_SESSION_GENERATIONS_EXHAUSTED]

    async def test_a_family_past_its_lifetime(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The store's ``get`` filters an expired family (answered with no
        row); this reaches the handler's own check, which a family expiring
        between the lookup and the classification meets."""
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        sid = _sid(first)
        past = datetime.now(UTC) - timedelta(seconds=1)
        expired = dataclasses.replace(sessions._sessions[sid], expires_at=past)
        sessions._sessions[sid] = expired

        async def unfiltered(wanted: str) -> RefreshSession | None:
            return sessions._sessions.get(wanted)

        monkeypatch.setattr(sessions, "get", unfiltered)
        _refused(await _refresh(app, first["refresh_token"]))
        assert [r.detail for r in await _rows(clean)] == [DETAIL_SESSION_EXPIRED]

    async def test_an_expired_family_is_unknown_to_the_lookup(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        sid = _sid(first)
        sessions._sessions[sid] = dataclasses.replace(
            sessions._sessions[sid], expires_at=datetime.now(UTC) - timedelta(seconds=1)
        )
        _refused(await _refresh(app, first["refresh_token"]))
        assert await _rows(clean) == []

    async def test_a_client_id_that_is_not_the_pairings(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        _refused(await _refresh(app, first["refresh_token"], client_id="claude-code2"))
        assert [r.detail for r in await _rows(clean)] == [DETAIL_CLIENT_ID_MISMATCH]
        assert (await _family(app, first)).generation == 0


class TestScope:
    @pytest.mark.parametrize("scope", ["", "   "])
    async def test_empty_is_the_original_grant(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, scope: str
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(app, first["refresh_token"], scope=scope)
        assert session_claims(response, app)["scope"] == SCOPES

    async def test_duplicates_and_order_are_canonicalized_and_narrowing_narrows_this_token_only(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        narrowed = await _refresh(
            app, first["refresh_token"], scope="cards:read accounts:read cards:read"
        )
        assert session_claims(narrowed, app)["scope"] == "accounts:read cards:read"
        assert (await _family(app, first)).scopes == SCOPES
        again = await _refresh(app, narrowed.json()["refresh_token"])
        assert session_claims(again, app)["scope"] == SCOPES

    async def test_a_wider_scope_is_invalid_scope(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        response = await _refresh(app, first["refresh_token"], scope="accounts:read payments:write")
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_scope"
        assert [r.detail for r in await _rows(clean)] == [DETAIL_SCOPE_EXCEEDED]


class TestZt7:
    async def _refused_as_revoked(
        self, app: Starlette, body: dict[str, Any], clean: Database
    ) -> None:
        _refused(await _refresh(app, body["refresh_token"]))
        (row,) = await _rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, DETAIL_REVOKED)
        family = await _family(app, body)
        assert family.generation == 0
        assert family.revoked_at is None, "the first two checks do not revoke the family"

    async def test_a_revoked_customer(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        await app.state.postern_revocation_store.revoke_customer_client(
            customer_ref=CUSTOMER, client_id="some-other-client"
        )
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        store._revoked_at.clear()
        await self._refused_as_revoked(app, first, clean)

    async def test_the_kill_switch(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        await app.state.postern_revocation_store.kill_switch(client_id="claude-code")
        await self._refused_as_revoked(app, first, clean)

    async def test_a_live_access_tokens_jti(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        await app.state.postern_revocation_store.revoke_session(jti=_jti(first))
        await self._refused_as_revoked(app, first, clean)

    async def test_a_family_created_before_a_since_restored_revocation_is_refused_and_revoked(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        await store.restore_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        _refused(await _refresh(app, first["refresh_token"]))
        assert await store.is_revoked({"jti": _jti(first)}), "the live access token is cut now"
        family = await _family(app, first)
        assert family.revoked_reason == "issued_before_revocation"
        assert [r.detail for r in await _rows(clean)] == [DETAIL_ISSUED_BEFORE_REVOCATION]

    async def test_a_family_created_before_a_since_restored_kill_switch_is_refused_and_revoked(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        """While the switch stands the family is refused and left unrevoked
        (``test_the_kill_switch``); once restored, its first presentation
        revokes it for good and lists its live access token."""
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.kill_switch(client_id="claude-code")
        await store.restore_client(client_id="claude-code")
        assert await store.customer_revoked_at(CUSTOMER) is None, "no customer stamp in play"
        _refused(await _refresh(app, first["refresh_token"]))
        assert await store.is_revoked({"jti": _jti(first)}), "the live access token is cut now"
        family = await _family(app, first)
        assert family.revoked_reason == "issued_before_revocation"
        assert family.revoked_at is not None
        # Revoked in the family store, so the stamp expiring could not revive it.
        _refused(await _refresh(app, first["refresh_token"]))
        assert [r.detail for r in await _rows(clean)] == [
            DETAIL_ISSUED_BEFORE_REVOCATION,
            DETAIL_SESSION_REVOKED,
        ]

    async def test_a_family_created_after_a_restored_kill_switch_refreshes(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.kill_switch(client_id="claude-code")
        await store.restore_client(client_id="claude-code")
        stamp = await store.client_revoked_at("claude-code")
        assert stamp is not None
        first = await _session(app, key_pair)
        assert (await _family(app, first)).created_ms > stamp
        session_claims(await _refresh(app, first["refresh_token"]), app)

    @pytest.mark.parametrize(("offset_ms", "refused"), [(700, True), (0, True), (-1, False)])
    async def test_the_client_stamp_decides_in_milliseconds_at_the_edge(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        offset_ms: int,
        refused: bool,
    ) -> None:
        first = await _session(app, key_pair)
        family = await _family(app, first)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        store._client_revoked_at["claude-code"] = (family.created_ms + offset_ms, 2**62)
        response = await _refresh(app, first["refresh_token"])
        if refused:
            _refused(response)
            assert (await _family(app, first)).revoked_reason == "issued_before_revocation"
        else:
            session_claims(response, app)

    async def test_only_the_client_stamp_read_failing_is_a_503_with_nothing_revoked(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store

        async def down(client_id: str) -> int | None:
            raise RevocationStoreUnavailable("simulated outage")

        monkeypatch.setattr(store, "client_revoked_at", down)
        _retryable(app, await _refresh(app, first["refresh_token"]))
        family = await _family(app, first)
        assert (family.generation, family.revoked_at) == (0, None), "nothing half-revoked"
        assert not await store.is_revoked({"jti": _jti(first)}), "nothing listed"
        assert [r.detail for r in await _rows(clean)] == ["RevocationStoreUnavailable"]

    async def test_another_clients_kill_switch_stamp_does_not_touch_this_family(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.kill_switch(client_id="some-other-client")
        await store.restore_client(client_id="some-other-client")
        session_claims(await _refresh(app, first["refresh_token"]), app)

    async def test_a_failed_zt7_write_after_issued_before_revocation_converges(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        await store.restore_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        real = store.revoke_session

        async def down(*, jti: str) -> None:
            raise RevocationStoreUnavailable("simulated outage")

        monkeypatch.setattr(store, "revoke_session", down)
        _retryable(app, await _refresh(app, first["refresh_token"]))
        assert (await _family(app, first)).revoked_reason == "issued_before_revocation"
        assert not await store.is_revoked({"jti": _jti(first)})

        monkeypatch.setattr(store, "revoke_session", real)
        _refused(await _refresh(app, first["refresh_token"]))
        assert await store.is_revoked({"jti": _jti(first)})
        assert [r.detail for r in await _rows(clean)] == [
            "RevocationStoreUnavailable",
            DETAIL_SESSION_REVOKED,
        ]

    async def test_a_family_store_outage_revoking_an_issued_before_family_still_refuses(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The family stays unrevoked, but the stamp refuses it on every
        presentation for the rest of its life."""
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        await store.restore_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def down(sid: str, *, reason: str) -> tuple[str, ...] | None:
            raise TimeoutError("simulated outage")

        monkeypatch.setattr(sessions, "revoke", down)
        with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
            _refused(await _refresh(app, first["refresh_token"]))
            _refused(await _refresh(app, first["refresh_token"]))
        assert "TimeoutError" in caplog.text and _sid(first) in caplog.text
        assert (await _family(app, first)).generation == 0
        assert await store.is_revoked({"jti": _jti(first)}), "cut even though the revoke failed"
        # The second presentation meets the cut jti in the ZT-7 checks first.
        assert [r.detail for r in await _rows(clean)] == ["TimeoutError", DETAIL_REVOKED]

    async def test_both_stores_down_on_an_issued_before_family_is_a_retryable_503(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        await store.restore_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def family_store_down(sid: str, *, reason: str) -> tuple[str, ...] | None:
            raise TimeoutError("simulated outage")

        async def revocation_store_down(*, jti: str) -> None:
            raise RevocationStoreUnavailable("simulated outage")

        monkeypatch.setattr(sessions, "revoke", family_store_down)
        monkeypatch.setattr(store, "revoke_session", revocation_store_down)
        _retryable(app, await _refresh(app, first["refresh_token"]))
        assert (await _family(app, first)).generation == 0
        assert [r.detail for r in await _rows(clean)] == ["RevocationStoreUnavailable"]

    @pytest.mark.parametrize(("offset_ms", "refused"), [(700, True), (0, True), (-1, False)])
    async def test_milliseconds_decide_at_the_edge(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        offset_ms: int,
        refused: bool,
    ) -> None:
        """A family created at .200 and a revocation at .900 of the same second
        is refused: whole seconds would have compared 0 against 0.2."""
        first = await _session(app, key_pair)
        family = await _family(app, first)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        store._revoked_at[CUSTOMER] = (family.created_ms + offset_ms, 2**62)
        response = await _refresh(app, first["refresh_token"])
        if refused:
            _refused(response)
        else:
            session_claims(response, app)

    async def test_an_outage_answers_503_and_rotates_nothing(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store

        async def down(customer_ref: str) -> bool:
            raise RevocationStoreUnavailable("simulated outage")

        monkeypatch.setattr(store, "is_customer_revoked", down)
        response = await _refresh(app, first["refresh_token"])
        assert response.status_code == 503
        assert response.json()["error"] == "temporarily_unavailable"
        assert response.headers["retry-after"] == str(
            app.state.settings.device_poll_interval_seconds
        )
        assert response.headers["cache-control"] == "no-store"
        assert (await _family(app, first)).generation == 0
        assert [r.detail for r in await _rows(clean)] == ["RevocationStoreUnavailable"]


async def _unspent(app: Starlette, device_code: str) -> bool:
    code = await app.state.device_code_store.get_device_code(device_code)
    return code is not None and code.exchanged_at is None


async def _token_rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        query = select(AuditEntry).where(AuditEntry.tool_name == TOKEN_TOOL_NAME)
        result = await s.execute(query.order_by(AuditEntry.id))
        return list(result.scalars())


def _access_denied(response: httpx2.Response) -> None:
    assert response.status_code == 400, response.text
    assert response.json()["error"] == "access_denied"
    assert "refresh_token" not in response.json()


class TestAnExchangeUnderAKillSwitch:
    """The device-code exchange refuses a client whose kill switch stands.

    Keyed on the code's ``client_id``, the browser's own unauthenticated
    choice, which is the same value the api's kill switch already keys on: the
    gate only narrows access, and a client that lies about its id gains
    nothing it did not have. Refused like a customer revocation: 400
    ``access_denied``, the family discarded, the code left unspent.
    """

    async def test_an_exchange_while_the_switch_stands_is_refused_and_the_code_survives(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair, scopes=SCOPES)  # approved before the kill
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.kill_switch(client_id="claude-code")

        _access_denied(await _exchange(app, device["device_code"]))
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        assert sessions._sessions == {}, "no family left behind"
        assert await _unspent(app, device["device_code"])
        (row,) = await _token_rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, DETAIL_REVOKED)

        # The restore lets the client back in: the unspent code now exchanges.
        await store.restore_client(client_id="claude-code")
        app.state._approved_poll_times.clear()  # the poll pacing, not under test
        session_claims(await _exchange(app, device["device_code"]), app)

    async def test_an_exchange_after_the_restore_works(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.kill_switch(client_id="claude-code")
        await store.restore_client(client_id="claude-code")
        device = await _approved(app, key_pair, scopes=SCOPES)
        session_claims(await _exchange(app, device["device_code"]), app)

    async def test_another_clients_exchange_is_unaffected(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.kill_switch(client_id="some-other-client")
        device = await _approved(app, key_pair, scopes=SCOPES)
        session_claims(await _exchange(app, device["device_code"]), app)

    async def test_an_outage_on_the_kill_switch_read_is_a_503_and_leaves_no_family(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store: InMemoryRevocationStore = app.state.postern_revocation_store

        async def down(claims: Any) -> bool:
            raise RevocationStoreUnavailable("simulated outage")

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(store, "is_revoked", down)
        _retryable(app, await _exchange(app, device["device_code"]))
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        assert sessions._sessions == {}
        assert await _unspent(app, device["device_code"])
        (row,) = await _token_rows(clean)
        assert row.detail == "RevocationStoreUnavailable"

    async def test_a_kill_landing_between_create_and_the_check_is_caught(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        real_create = sessions.create

        async def create_then_kill(session: RefreshSession) -> RefreshSession:
            stamped = await real_create(session)
            await store.kill_switch(client_id="claude-code")
            return stamped

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(sessions, "create", create_then_kill)
        response = await _exchange(app, device["device_code"])
        monkeypatch.setattr(sessions, "create", real_create)
        _access_denied(response)
        assert sessions._sessions == {}
        assert await _unspent(app, device["device_code"])


class TestRestoringASession:
    """``restore_session`` is the undo of one ``jti`` and nothing wider.

    What the verb means, pinned: it removes that ``jti`` from the ZT-7 set and
    touches no family record. A family the refresh store revoked (reuse,
    recall, ``issued_before_revocation``) stays revoked, and its next
    presentation lists the ``jti`` again. A family that was only refused
    because an operator listed one of its live ``jti`` values refreshes again,
    which it would also do on its own once that token expired.
    """

    async def test_restoring_a_reuse_listed_jti_leaves_the_family_revoked_and_relists_it(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        second = (await _refresh(app, first["refresh_token"])).json()
        _refused(await _refresh(app, first["refresh_token"]))  # reuse
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        jti = _jti(second)
        assert await store.is_revoked({"jti": jti})

        await store.restore_session(jti=jti)
        assert not await store.is_revoked({"jti": jti}), "the named token alone is revived"
        family = await _family(app, first)
        assert (family.revoked_at is not None, family.revoked_reason) == (True, "reuse")

        # The family is not refreshable, and presenting it re-lists the jti.
        _refused(await _refresh(app, second["refresh_token"]))
        assert await store.is_revoked({"jti": jti})

    async def test_restoring_an_operator_listed_live_jti_lets_its_family_refresh(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        first = await _session(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.revoke_session(jti=_jti(first))
        _refused(await _refresh(app, first["refresh_token"]))
        assert (await _family(app, first)).revoked_at is None

        await store.restore_session(jti=_jti(first))
        session_claims(await _refresh(app, first["refresh_token"]), app)


class TestARevocationBetweenTheCheckAndTheStamp:
    async def test_a_revocation_landing_inside_create_is_not_lost_to_a_later_restore(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A customer-client revocation stamped S with the exchange's step-0
        check before it and the family's ``created_ms`` after it (S < created_ms)
        is seen by neither check, and a later restore revives the family. The
        exchange must stamp the family first and check after, so it refuses."""
        revocations: InMemoryRevocationStore = app.state.postern_revocation_store
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        real_create = sessions.create

        async def create_with_a_revocation_inside(session: RefreshSession) -> RefreshSession:
            await revocations.revoke_customer_client(customer_ref=CUSTOMER, client_id="claude-code")
            stamp = await revocations.customer_revoked_at(CUSTOMER)
            assert stamp is not None
            # Strictly later, so S and created_ms cannot share a millisecond.
            monkeypatch.setattr(refresh_sessions, "now_ms", lambda: stamp + 1)
            return await real_create(session)

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(sessions, "create", create_with_a_revocation_inside)
        response = await _exchange(app, device["device_code"])
        monkeypatch.setattr(sessions, "create", real_create)
        await revocations.restore_customer_client(customer_ref=CUSTOMER, client_id="claude-code")

        assert response.status_code == 400, response.text
        assert response.json()["error"] == "access_denied"
        assert "refresh_token" not in response.json()
        assert sessions._sessions == {}, "the family is discarded, not left to be revived"
        async with clean.sessionmaker() as s:
            result = await s.execute(
                select(AuditEntry).where(AuditEntry.tool_name == TOKEN_TOOL_NAME)
            )
            (row,) = result.scalars().all()
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, DETAIL_REVOKED)

    async def test_a_revocation_store_outage_discards_the_family_and_leaves_the_code_unspent(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        revocations: InMemoryRevocationStore = app.state.postern_revocation_store
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        real = revocations.is_customer_revoked

        async def down(customer_ref: str) -> bool:
            raise RevocationStoreUnavailable("simulated outage")

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(revocations, "is_customer_revoked", down)
        _retryable(app, await _exchange(app, device["device_code"]))
        assert sessions._sessions == {}

        monkeypatch.setattr(revocations, "is_customer_revoked", real)
        app.state._approved_poll_times.clear()  # the poll pacing, not under test
        again = await _exchange(app, device["device_code"])
        session_claims(again, app)

    async def test_any_other_raise_from_the_revocation_check_discards_the_family(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        revocations: InMemoryRevocationStore = app.state.postern_revocation_store
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def broken(customer_ref: str) -> bool:
            raise RuntimeError("simulated fault")

        device = await _approved(app, key_pair, scopes=SCOPES)
        monkeypatch.setattr(revocations, "is_customer_revoked", broken)
        with pytest.raises(RuntimeError, match="simulated fault"):
            await _exchange(app, device["device_code"])
        assert sessions._sessions == {}, "the family must not outlive the raise"


class TestTheRotationItself:
    async def test_a_contended_rotation_propagates_and_is_recorded(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def contended(*args: Any, **kwargs: Any) -> Any:
            raise RefreshSessionStoreContended("beaten three times")

        monkeypatch.setattr(sessions, "rotate", contended)
        response = await _refresh(app, first["refresh_token"])
        assert response.status_code == 500
        assert [r.detail for r in await _rows(clean)] == ["RefreshSessionStoreContended"]

    @pytest.mark.parametrize(
        "exc",
        [RedisConnectionError("redis went away"), TimeoutError("timed out"), OSError("reset")],
        ids=["redis.ConnectionError", "TimeoutError", "OSError"],
    )
    async def test_a_store_outage_at_the_rotation_is_a_retryable_503(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
        exc: Exception,
    ) -> None:
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        real_rotate = sessions.rotate

        async def down(*args: Any, **kwargs: Any) -> Any:
            raise exc

        monkeypatch.setattr(sessions, "rotate", down)
        response = await _refresh(app, first["refresh_token"])
        _retryable(app, response)
        assert "access_token" not in response.text
        assert (await _family(app, first)).generation == 0
        assert [r.detail for r in await _rows(clean)] == [type(exc).__name__]

        monkeypatch.setattr(sessions, "rotate", real_rotate)
        session_claims(await _refresh(app, first["refresh_token"]), app)

    async def test_a_concurrent_winner_turns_this_refresh_into_reuse(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Another replica rotates between this one's classification and its
        compare-and-set: the transaction sees a retained hash and revokes."""
        first = await _session(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        real_rotate = sessions.rotate

        async def raced(sid: str, **kwargs: Any) -> Any:
            await real_rotate(
                sid,
                presented_hash=kwargs["presented_hash"],
                new_hash="f" * 64,
                access_jti="winner",
                access_expires_at=datetime.now(UTC) + timedelta(minutes=10),
            )
            return await real_rotate(sid, **kwargs)

        monkeypatch.setattr(sessions, "rotate", raced)
        _refused(await _refresh(app, first["refresh_token"]))
        assert (await _family(app, first)).revoked_reason == "reuse"
        revocations: InMemoryRevocationStore = app.state.postern_revocation_store
        assert await revocations.is_revoked({"jti": "winner"})
        assert await revocations.is_revoked({"jti": _jti(first)})
        assert [r.detail for r in await _rows(clean)] == [DETAIL_REFRESH_REUSED]

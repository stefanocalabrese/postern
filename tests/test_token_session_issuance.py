"""``POST /token`` with ``grant_type=device_code`` issues a layer-1 session.

Spec section 5 of ``dev-docs/device-grant-session-token-spec.md``, through the
assembled confirm app: the five keys and the two headers, a token that
verifies against ``/session/jwks.json``, the ``resource`` parameter, a full
family store, a lost claim, a revocation that predates the approval, and the
reserved ``client_id``. The hotfix's 503 path is gone.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from joserfc import jwt
from joserfc.jwk import KeySet
from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    InMemoryDeviceCodeStore,
    RedisDeviceCodeStore,
)
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.refresh_sessions import (
    InMemoryRefreshSessionStore,
    RefreshSessionStoreBase,
    ms_of,
)
from postern_core.auth.revocation import InMemoryRevocationStore
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

import services.confirm.device_auth as device_auth
from services.confirm.audit import (
    DETAIL_DEVICE_CODE_SPENT,
    DETAIL_REVOKED,
    TOKEN_TOOL_NAME,
    PairingAudit,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import scan_in_store, session_claims
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_device_grant import AUDIENCE, ISSUER, bearer

CUSTOMER = "cust_7f3a"
RESOURCE = "https://mcp.postern.test/mcp"


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    yield database


def _app(key_pair: RSAKeyPair, pg_url: str, **overrides: Any) -> Starlette:
    fields: dict[str, Any] = {
        "database_url": pg_url,
        "session_token_audience": RESOURCE,
        "allow_non_uri_audience": False,
    }
    fields.update(overrides)
    settings = dataclasses.replace(ConfirmSettings.for_testing(), **fields)
    return create_confirm_app(
        settings,
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


@pytest.fixture()
def app(key_pair: RSAKeyPair, pg_url: str) -> Starlette:
    return _app(key_pair, pg_url)


def _client(app: Starlette) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://t")


async def _approved(app: Starlette, key_pair: RSAKeyPair, **body: str) -> dict[str, Any]:
    """A device grant started, scanned in the store and approved for `CUSTOMER`."""
    async with _client(app) as client:
        started = await client.post(
            "/device_authorization", json={"client_id": "claude-code", **body}
        )
        assert started.status_code == 200, started.text
        device: dict[str, Any] = started.json()
        await scan_in_store(app, device["user_code"], CUSTOMER)
        approved = await client.post(
            "/approve", json={"user_code": device["user_code"]}, headers=bearer(key_pair)
        )
        assert approved.status_code == 200, approved.text
    return device


async def _exchange(app: Starlette, device_code: str, **extra: Any) -> httpx2.Response:
    async with _client(app) as client:
        return await client.post(
            "/token", data={"grant_type": "device_code", "device_code": device_code, **extra}
        )


async def _token_rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(
            select(AuditEntry)
            .where(AuditEntry.tool_name == TOKEN_TOOL_NAME)
            .order_by(AuditEntry.id)
        )
        return list(result.scalars())


class TestTheSuccessResponse:
    async def test_five_keys_two_headers_and_a_token_the_session_jwks_verifies(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        response = await _exchange(app, device["device_code"])
        claims = session_claims(response, app)
        async with _client(app) as client:
            published = (await client.get("/session/jwks.json")).json()
        verified = jwt.decode(response.json()["access_token"], KeySet.import_key_set(published))
        assert verified.claims["jti"] == claims["jti"]
        assert claims["aud"] == RESOURCE
        assert claims["sub"] == CUSTOMER

    async def test_the_scope_is_canonical(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair, scopes="cards:read  accounts:read cards:read")
        response = await _exchange(app, device["device_code"])
        assert session_claims(response, app)["scope"] == "accounts:read cards:read"
        assert response.json()["scope"] == "accounts:read cards:read"

    async def test_the_family_names_the_access_token_it_issued(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        claims = session_claims(await _exchange(app, device["device_code"]), app)
        family = await app.state.refresh_session_store.get(claims["sid"])
        assert family is not None
        assert family.customer_ref == CUSTOMER
        assert family.client_id == "claude-code"
        assert family.generation == 0
        assert [jti for jti, _ in family.access_tokens] == [claims["jti"]]
        assert family.expires_at - family.created_at == timedelta(hours=1)

    async def test_every_token_response_carries_no_store_and_no_cache(
        self, app: Starlette, key_pair: RSAKeyPair
    ) -> None:
        async with _client(app) as client:
            pending = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": "unknown"}
            )
            wrong = await client.post("/token", data={"grant_type": "password"})
        for response in (pending, wrong):
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["pragma"] == "no-cache"

    def test_the_hotfix_path_is_gone(self) -> None:
        assert not hasattr(device_auth, "DETAIL_ISSUANCE_DISABLED")


class TestTheResourceParameter:
    @pytest.mark.parametrize(
        "resource",
        [
            RESOURCE,
            "HTTPS://MCP.Postern.Test/mcp",
            "https://mcp.postern.test:443/mcp",
        ],
    )
    async def test_an_equal_resource_after_normalization_is_served(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, resource: str
    ) -> None:
        device = await _approved(app, key_pair)
        session_claims(await _exchange(app, device["device_code"], resource=resource), app)

    @pytest.mark.parametrize(
        "resource",
        [
            "https://mcp.postern.test/mcp/",
            "https://mcp.postern.test/MCP",
            "https://mcp.postern.test/mcp#frag",
            "/mcp",
            "https://other.postern.test/mcp",
        ],
    )
    async def test_any_other_resource_is_invalid_target_with_no_row(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, resource: str
    ) -> None:
        device = await _approved(app, key_pair)
        response = await _exchange(app, device["device_code"], resource=resource)
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_target"
        assert await _token_rows(clean) == []
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored.exchanged_at is None

    async def test_a_repeated_resource_is_invalid_target(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        async with _client(app) as client:
            response = await client.post(
                "/token",
                content=(
                    f"grant_type=device_code&device_code={device['device_code']}"
                    f"&resource={RESOURCE}&resource={RESOURCE}"
                ),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_target"

    async def test_an_empty_path_normalizes_to_slash(
        self, key_pair: RSAKeyPair, pg_url: str, clean: Database
    ) -> None:
        app = _app(key_pair, pg_url, session_token_audience="https://mcp.postern.test/")  # noqa: S106
        device = await _approved(app, key_pair)
        response = await _exchange(app, device["device_code"], resource="https://mcp.postern.test")
        session_claims(response, app)


class TestAFullFamilyStore:
    async def test_it_answers_503_with_retry_after_and_leaves_the_code_redeemable(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        real: RefreshSessionStoreBase = app.state.refresh_session_store
        app.state.refresh_session_store = InMemoryRefreshSessionStore(max_sessions=0)
        full = await _exchange(app, device["device_code"])
        assert full.status_code == 503
        assert full.headers["retry-after"] == str(app.state.settings.device_poll_interval_seconds)
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored.exchanged_at is None

        app.state.refresh_session_store = real
        app.state._approved_poll_times[device["device_code"]] -= timedelta(seconds=60)
        session_claims(await _exchange(app, device["device_code"]), app)
        assert [r.detail for r in await _token_rows(clean)] == ["RefreshSessionStoreFull", None]


class TestALostClaim:
    async def test_two_replicas_racing_one_code_issue_one_session_and_orphan_nothing(
        self, key_pair: RSAKeyPair, pg_url: str, clean: Database
    ) -> None:
        """Both replicas pass their own pacing (the maps are per process), so the
        claim decides; the loser discards the family it created."""
        first = _app(key_pair, pg_url)
        second = _app(key_pair, pg_url)
        second.state.device_code_store = first.state.device_code_store
        second.state.refresh_session_store = first.state.refresh_session_store
        device = await _approved(first, key_pair)

        answers = await asyncio.gather(
            _exchange(first, device["device_code"]),
            _exchange(second, device["device_code"]),
        )

        assert sorted(r.status_code for r in answers) == [200, 400]
        loser = next(r for r in answers if r.status_code == 400)
        assert loser.json()["error"] == "invalid_grant"
        sessions: InMemoryRefreshSessionStore = first.state.refresh_session_store
        assert len(sessions._sessions) == 1, "the losing exchange left an orphaned family"
        details = {r.detail for r in await _token_rows(clean)}
        assert details == {DETAIL_DEVICE_CODE_SPENT, None}

    async def test_a_failing_discard_is_logged_and_tolerated(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        device = await _approved(app, key_pair)
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def lost(device_code: str, *, session_id: str) -> bool:
            return False

        async def broken(sid: str) -> None:
            raise ConnectionError("redis went away")

        monkeypatch.setattr(store, "consume_device_code", lost)
        monkeypatch.setattr(sessions, "discard", broken)
        with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
            response = await _exchange(app, device["device_code"])

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_grant"
        (orphan,) = sessions._sessions
        assert f"orphaned session family {orphan}" in caplog.text
        assert "ConnectionError" in caplog.text
        assert [r.detail for r in await _token_rows(clean)] == [DETAIL_DEVICE_CODE_SPENT]


class TestARevocationThatPredatesTheApproval:
    async def _stamp(self, app: Starlette, device_code: str, offset_ms: int) -> None:
        """A customer revocation stamped ``offset_ms`` from the approval, since restored."""
        code: DeviceCode | None = await app.state.device_code_store.get_device_code(device_code)
        assert code is not None and code.approved_at is not None
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        store._revoked_at[CUSTOMER] = (ms_of(code.approved_at) + offset_ms, 2**62)

    async def test_a_restored_revocation_after_the_approval_still_refuses(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        store: InMemoryRevocationStore = app.state.postern_revocation_store
        await store.revoke_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
        await store.restore_customer_client(customer_ref=CUSTOMER, client_id="vendor-x")
        assert await store.is_customer_revoked(CUSTOMER) is False

        response = await _exchange(app, device["device_code"])

        assert response.status_code == 400
        assert response.json()["error"] == "access_denied"
        (row,) = await _token_rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, DETAIL_REVOKED)

    @pytest.mark.parametrize(("offset_ms", "refused"), [(-2000, True), (-2001, False)])
    async def test_the_two_second_tolerance_at_both_edges(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        offset_ms: int,
        refused: bool,
    ) -> None:
        device = await _approved(app, key_pair)
        await self._stamp(app, device["device_code"], offset_ms)
        response = await _exchange(app, device["device_code"])
        if refused:
            assert response.json()["error"] == "access_denied"
        else:
            session_claims(response, app)


class TestTheReservedClientId:
    async def test_a_pairing_named_dash_is_refused(self, app: Starlette) -> None:
        async with _client(app) as client:
            response = await client.post("/device_authorization", json={"client_id": "-"})
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    async def test_a_name_containing_a_dash_is_fine(self, app: Starlette) -> None:
        async with _client(app) as client:
            response = await client.post("/device_authorization", json={"client_id": "a-b"})
        assert response.status_code == 200


class TestTheRowNamesTheFamily:
    def test_the_arguments_keys_come_in_the_documented_order(self) -> None:
        audit = PairingAudit(
            db=None,  # type: ignore[arg-type]
            call_id="c",
            at=datetime.now(UTC),
            started=0.0,
            subject=CUSTOMER,
            claims={},
            client_ip_value="198.51.100.7",
        )
        audit.names(paired_client_id="claude-code")
        audit.names(session_id="s" * 22)
        audit.names(device_code="d" * 43)
        assert list(audit._arguments()) == [
            "route",
            "device_code_handle",
            "session_id",
            "client_ip",
            "paired_client_id",
        ]


@pytest.fixture(params=["memory", "redis"])
async def device_store(request: pytest.FixtureRequest) -> AsyncIterator[DeviceCodeStoreBase]:
    if request.param == "memory":
        yield InMemoryDeviceCodeStore()
        return
    store = RedisDeviceCodeStore(
        url=request.getfixturevalue("redis_url"), key_prefix=f"ts{uuid4().hex[:12]}:"
    )
    yield store
    await store.close()


class TestTheClaimRecordsTheFamily:
    async def test_consume_writes_the_session_id_with_exchanged_at(
        self, device_store: DeviceCodeStoreBase
    ) -> None:
        code = await device_store.create_device_code(
            client_id="c", scopes="accounts:read", verification_uri="https://a.test/verify"
        )
        assert await device_store.consume_device_code(code.device_code, session_id="sid-1")
        assert not await device_store.consume_device_code(code.device_code, session_id="sid-2")
        stored = await device_store.get_device_code(code.device_code)
        assert stored is not None
        assert stored.exchanged_at is not None
        assert stored.session_id == "sid-1"

    def test_a_record_without_the_field_reads_as_empty(self) -> None:
        code = DeviceCode(
            device_code="legacy",
            user_code="ABCDEF",
            verification_uri="https://a.test/verify",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        legacy = code.to_dict()
        del legacy["session_id"]
        assert DeviceCode.from_dict(legacy).session_id == ""

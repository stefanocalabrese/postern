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
    RefreshSession,
    RefreshSessionCollision,
    RefreshSessionStoreBase,
    ms_of,
)
from postern_core.auth.revocation import InMemoryRevocationStore
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, AuditEntry
from redis import exceptions as redis_exceptions
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
        refused, minted = await _token_rows(clean)
        assert [refused.detail, minted.detail] == ["RefreshSessionStoreFull", None]
        # The refused row names no family, because none was ever stored.
        assert "session_id" not in refused.arguments
        assert "session_id" in minted.arguments


class _CreateRaises(InMemoryRefreshSessionStore):
    """A family store whose ``create`` raises ``exc``; everything else is real."""

    def __init__(self, exc: BaseException) -> None:
        super().__init__()
        self._exc = exc

    async def create(self, session: RefreshSession) -> RefreshSession:
        raise self._exc


class TestAFamilyStoreThatCannotAnswer:
    """``create`` failing for a reason other than the cap (amended 1 October 2026).

    A connection or timeout error is an outage, answered like the full store:
    a retryable 503 with ``Retry-After``, the code unspent, no token, and a row
    under the exception's class name that names no family. A collision is not
    an outage, and stays a 500.
    """

    @pytest.mark.parametrize(
        "exc",
        [
            ConnectionError("refused"),
            TimeoutError("timed out"),
            redis_exceptions.ConnectionError("redis went away"),
            redis_exceptions.TimeoutError("redis timed out"),
        ],
        ids=["ConnectionError", "TimeoutError", "redis.ConnectionError", "redis.TimeoutError"],
    )
    async def test_an_outage_is_a_retryable_503_and_spends_nothing(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database, exc: BaseException
    ) -> None:
        device = await _approved(app, key_pair)
        app.state.refresh_session_store = _CreateRaises(exc)

        response = await _exchange(app, device["device_code"])

        assert response.status_code == 503, response.text
        assert response.json()["error"] == "temporarily_unavailable"
        assert response.headers["retry-after"] == str(
            app.state.settings.device_poll_interval_seconds
        )
        assert "access_token" not in response.text
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored.exchanged_at is None
        (row,) = await _token_rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, type(exc).__name__)
        assert "session_id" not in row.arguments

    async def test_a_collision_is_a_500_and_spends_nothing(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        app.state.refresh_session_store = _CreateRaises(RefreshSessionCollision("same sid"))

        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://t",
        ) as client:
            response = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )

        assert response.status_code == 500
        assert "access_token" not in response.text
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored.exchanged_at is None
        (row,) = await _token_rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, "RefreshSessionCollision")
        assert "session_id" not in row.arguments

    async def test_the_outage_tuple_has_one_definition(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``_exchange`` and the refresh grant catch the same module constant,
        so widening it widens both."""

        class Widened(Exception):
            pass

        monkeypatch.setattr(
            device_auth,
            "SESSION_STORE_OUTAGES",
            (*device_auth.SESSION_STORE_OUTAGES, Widened),
        )
        device = await _approved(app, key_pair)
        app.state.refresh_session_store = _CreateRaises(Widened("an outage by definition"))

        response = await _exchange(app, device["device_code"])

        assert response.status_code == 503, response.text
        (row,) = await _token_rows(clean)
        assert row.detail == "Widened"


class TestStrictParameters:
    """Every ``/token`` parameter is read once and strictly (1 October 2026).

    A repeated parameter (RFC 6749 section 3.2) or a file part that is not
    UTF-8 is 400 ``invalid_request``, before the lookup: no row, and the code
    is left exactly as it was.
    """

    async def _still_redeemable(
        self, app: Starlette, device: dict[str, Any], clean: Database
    ) -> None:
        assert await _token_rows(clean) == []
        stored = await app.state.device_code_store.get_device_code(device["device_code"])
        assert stored.exchanged_at is None
        session_claims(await _exchange(app, device["device_code"]), app)

    async def test_a_repeated_device_code(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        async with _client(app) as client:
            response = await client.post(
                "/token",
                content=(
                    f"grant_type=device_code&device_code={device['device_code']}"
                    f"&device_code={device['device_code']}"
                ),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_request"
        assert response.headers["cache-control"] == "no-store"
        await self._still_redeemable(app, device, clean)

    async def test_a_device_code_file_part_that_is_not_utf8(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        async with _client(app) as client:
            response = await client.post(
                "/token",
                data={"grant_type": "device_code"},
                files={"device_code": ("value", b"\xff\xfe\xfd", "text/plain")},
            )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_request"
        await self._still_redeemable(app, device, clean)

    async def test_a_utf8_device_code_file_part_is_read(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        async with _client(app) as client:
            response = await client.post(
                "/token",
                data={"grant_type": "device_code"},
                files={"device_code": ("value", device["device_code"].encode(), "text/plain")},
            )
        session_claims(response, app)

    async def test_a_repeated_grant_type_on_the_device_grant(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        async with _client(app) as client:
            response = await client.post(
                "/token",
                content=(
                    "grant_type=device_code&grant_type=device_code"
                    f"&device_code={device['device_code']}"
                ),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        assert response.status_code == 400, response.text
        assert response.json()["error"] == "invalid_request"
        await self._still_redeemable(app, device, clean)


class TestAClaimThatRaises:
    """``consume_device_code`` raising after ``create`` (amended 1 October 2026).

    The family it would have recorded is discarded before the exception
    propagates, as on a lost claim, so no family outlives an exchange that
    issued nothing; a discard that fails too is logged and tolerated, and the
    claim's own exception is the one recorded.
    """

    async def test_the_family_is_discarded_and_the_exception_recorded(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        device = await _approved(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def raises(device_code: str, *, session_id: str) -> bool:
            raise ConnectionError("redis went away mid-claim")

        monkeypatch.setattr(app.state.device_code_store, "consume_device_code", raises)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://t",
        ) as client:
            response = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )

        # An outage, and the re-read shows the code unspent: retryable.
        assert response.status_code == 503
        assert "access_token" not in response.text
        assert sessions._sessions == {}, "a claim that raised left its family behind"
        (row,) = await _token_rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, "ConnectionError")
        assert row.arguments["session_id"]

    async def test_a_failing_discard_is_logged_and_the_claims_exception_recorded(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        device = await _approved(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def raises(device_code: str, *, session_id: str) -> bool:
            raise TimeoutError("claim timed out")

        async def broken(sid: str) -> None:
            raise ConnectionError("redis went away")

        monkeypatch.setattr(app.state.device_code_store, "consume_device_code", raises)
        monkeypatch.setattr(sessions, "discard", broken)
        with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
                base_url="http://t",
            ) as client:
                response = await client.post(
                    "/token",
                    data={"grant_type": "device_code", "device_code": device["device_code"]},
                )

        assert response.status_code == 503
        (orphan,) = sessions._sessions
        assert f"orphaned session family {orphan}" in caplog.text
        (row,) = await _token_rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, "TimeoutError")


def _raw_client(app: Starlette) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://t",
    )


OUTAGES = [
    redis_exceptions.ConnectionError("redis went away"),
    TimeoutError("timed out"),
    OSError("reset by peer"),
]
OUTAGE_IDS = ["redis.ConnectionError", "TimeoutError", "OSError"]


def _assert_retryable(app: Starlette, response: httpx2.Response) -> None:
    assert response.status_code == 503, response.text
    assert response.json()["error"] == "temporarily_unavailable"
    assert response.headers["retry-after"] == str(app.state.settings.device_poll_interval_seconds)
    assert response.headers["cache-control"] == "no-store"
    assert "access_token" not in response.text


class TestADeviceCodeStoreThatCannotAnswer:
    """The device-code store is Redis too (1 October 2026).

    An outage that provably left the code unspent is a retryable 503 with
    ``Retry-After``; one that may have spent it is a 500.
    """

    @pytest.mark.parametrize("exc", OUTAGES, ids=OUTAGE_IDS)
    async def test_an_outage_at_the_lookup_is_retryable_and_writes_nothing(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
        exc: Exception,
    ) -> None:
        device = await _approved(app, key_pair)
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        real = store.get_device_code

        async def down(device_code: str) -> DeviceCode | None:
            raise exc

        monkeypatch.setattr(store, "get_device_code", down)
        async with _raw_client(app) as client:
            response = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )
        _assert_retryable(app, response)
        assert await _token_rows(clean) == []

        monkeypatch.setattr(store, "get_device_code", real)
        session_claims(await _exchange(app, device["device_code"]), app)

    async def test_an_outage_revoking_an_expired_code_is_retryable(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        device = await _approved(app, key_pair)
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        code = store._codes[device["device_code"]]
        store._codes[device["device_code"]] = dataclasses.replace(
            code, expires_at=datetime.now(UTC) - timedelta(seconds=1)
        )
        real = store.revoke_device_code

        async def down(device_code: str) -> None:
            raise TimeoutError("timed out")

        monkeypatch.setattr(store, "revoke_device_code", down)
        async with _raw_client(app) as client:
            response = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )
        _assert_retryable(app, response)
        assert await _token_rows(clean) == []

        monkeypatch.setattr(store, "revoke_device_code", real)
        again = await _exchange(app, device["device_code"])
        assert again.json()["error"] == "expired_token"

    @pytest.mark.parametrize("exc", OUTAGES, ids=OUTAGE_IDS)
    async def test_a_claim_outage_on_a_provably_unspent_code_is_retryable(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
        exc: Exception,
    ) -> None:
        device = await _approved(app, key_pair)
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        real = store.consume_device_code

        async def down(device_code: str, *, session_id: str) -> bool:
            raise exc

        monkeypatch.setattr(store, "consume_device_code", down)
        async with _raw_client(app) as client:
            response = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )
        _assert_retryable(app, response)
        assert sessions._sessions == {}
        (row,) = await _token_rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, type(exc).__name__)
        stored = await store.get_device_code(device["device_code"])
        assert stored is not None
        assert stored.exchanged_at is None

        monkeypatch.setattr(store, "consume_device_code", real)
        app.state._approved_poll_times = {}
        session_claims(await _exchange(app, device["device_code"]), app)

    async def test_a_claim_that_committed_before_the_reply_was_lost_is_a_500(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The code is spent and its family discarded: the session is lost and
        the customer re-pairs (spec section 5, note of 1 October 2026)."""
        device = await _approved(app, key_pair)
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store
        real = store.consume_device_code

        async def committed_then_lost(device_code: str, *, session_id: str) -> bool:
            assert await real(device_code, session_id=session_id)
            raise redis_exceptions.ConnectionError("reply lost after EXEC")

        monkeypatch.setattr(store, "consume_device_code", committed_then_lost)
        async with _raw_client(app) as client:
            response = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )
        assert response.status_code == 500
        assert "access_token" not in response.text
        assert sessions._sessions == {}
        stored = await store.get_device_code(device["device_code"])
        assert stored is not None
        assert stored.exchanged_at is not None
        (row,) = await _token_rows(clean)
        assert (row.outcome, row.detail) == (OUTCOME_RAISED, "ConnectionError")

    async def test_a_claim_outage_whose_re_read_fails_is_a_500(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        device = await _approved(app, key_pair)
        store: InMemoryDeviceCodeStore = app.state.device_code_store
        real_get = store.get_device_code
        reads = 0

        async def get_once(device_code: str) -> DeviceCode | None:
            nonlocal reads
            reads += 1
            if reads > 1:
                raise TimeoutError("re-read timed out")
            return await real_get(device_code)

        async def down(device_code: str, *, session_id: str) -> bool:
            raise TimeoutError("claim timed out")

        monkeypatch.setattr(store, "get_device_code", get_once)
        monkeypatch.setattr(store, "consume_device_code", down)
        async with _raw_client(app) as client:
            response = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )
        assert response.status_code == 500
        assert reads == 2
        (row,) = await _token_rows(clean)
        assert row.detail == "TimeoutError"

    async def test_a_claim_fault_that_is_not_an_outage_is_a_500(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        device = await _approved(app, key_pair)
        store: InMemoryDeviceCodeStore = app.state.device_code_store

        async def broken(device_code: str, *, session_id: str) -> bool:
            raise ValueError("a programming error")

        monkeypatch.setattr(store, "consume_device_code", broken)
        async with _raw_client(app) as client:
            response = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
            )
        assert response.status_code == 500
        (row,) = await _token_rows(clean)
        assert row.detail == "ValueError"


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

    async def test_a_lost_claims_row_names_the_family_it_discarded(
        self,
        app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Deterministic, where the race above may resolve as a plain replay.

        A lost claim's ``device_code_spent`` row carries the ``session_id`` of
        the family it created and then discarded; a replay's carries none.
        That is how an operator tells the two apart (amended 1 October 2026).
        """
        device = await _approved(app, key_pair)
        sessions: InMemoryRefreshSessionStore = app.state.refresh_session_store

        async def lost(device_code: str, *, session_id: str) -> bool:
            return False

        monkeypatch.setattr(app.state.device_code_store, "consume_device_code", lost)
        response = await _exchange(app, device["device_code"])

        assert response.json()["error"] == "invalid_grant"
        assert sessions._sessions == {}
        (row,) = await _token_rows(clean)
        assert row.detail == DETAIL_DEVICE_CODE_SPENT
        assert row.arguments["session_id"]

    async def test_a_replays_row_names_no_family(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        device = await _approved(app, key_pair)
        session_claims(await _exchange(app, device["device_code"]), app)
        replay = await _exchange(app, device["device_code"])
        assert replay.json()["error"] == "invalid_grant"
        _, replayed = await _token_rows(clean)
        assert replayed.detail == DETAIL_DEVICE_CODE_SPENT
        assert "session_id" not in replayed.arguments

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


class TestEveryTokenResponseIsHeadered:
    """RFC 6749 section 5.1's two headers on EVERY ``/token`` response
    (amended 1 October 2026), including the ones no handler writes: the
    rate limiter's 429, the body limit's 413 and the 500 Starlette's
    ``ServerErrorMiddleware`` sends for an unhandled exception. Stamped at the
    ASGI layer outside that middleware, so no exit can miss them."""

    @staticmethod
    def _assert_headered(response: httpx2.Response) -> None:
        assert response.headers.get_list("cache-control") == ["no-store"]
        assert response.headers.get_list("pragma") == ["no-cache"]

    async def test_an_unknown_code_and_a_wrong_grant_type(self, app: Starlette) -> None:
        async with _client(app) as client:
            unknown = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": "unknown"}
            )
            wrong = await client.post("/token", data={"grant_type": "password"})
        assert unknown.status_code == 400
        assert wrong.status_code == 404
        self._assert_headered(unknown)
        self._assert_headered(wrong)

    async def test_an_unhandled_exception_500(
        self, app: Starlette, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def boom(device_code: str) -> DeviceCode | None:
            raise RuntimeError("the device code store fell over")

        monkeypatch.setattr(app.state.device_code_store, "get_device_code", boom)
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://t",
        ) as client:
            response = await client.post(
                "/token", data={"grant_type": "device_code", "device_code": "any"}
            )
        assert response.status_code == 500
        self._assert_headered(response)

    async def test_a_rate_limited_refusal(self, key_pair: RSAKeyPair, pg_url: str) -> None:
        """The address-bucket limiter's refusal. On ``/token`` it is RFC 8628's
        400 ``slow_down`` rather than the 429 every other path gets
        (`services/confirm/rate_limit.py` carries why), and the limiter writes
        it without reaching the handler."""
        app = _app(key_pair, pg_url, rate_limit_token=1)
        async with _client(app) as client:
            await client.post("/token", data={"grant_type": "password"})
            limited = await client.post("/token", data={"grant_type": "password"})
        assert limited.status_code == 400
        assert limited.json()["error"] == "slow_down"
        assert "retry-after" in limited.headers
        self._assert_headered(limited)

    async def test_an_oversized_413(self, key_pair: RSAKeyPair, pg_url: str) -> None:
        app = _app(key_pair, pg_url, max_body_bytes=1024)
        async with _client(app) as client:
            response = await client.post(
                "/token",
                content=b"grant_type=device_code&device_code=" + b"a" * 2048,
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
        assert response.status_code == 413
        self._assert_headered(response)

    async def test_another_path_is_left_alone(self, app: Starlette) -> None:
        async with _client(app) as client:
            response = await client.get("/session/jwks.json")
        assert response.status_code == 200
        assert "pragma" not in response.headers


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

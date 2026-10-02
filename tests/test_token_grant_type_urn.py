"""``POST /token`` accepts RFC 8628 section 3.4's grant-type URN.

``urn:ietf:params:oauth:grant-type:device_code`` and the short literal
``device_code`` are the same grant: same response, same audit row, and one
pacing budget between them. Every other spelling is still
``404 unsupported_grant_type``, by exact string comparison.
"""

from __future__ import annotations

import dataclasses
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import InMemoryDeviceCodeStore
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import TOKEN_TOOL_NAME
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import scan_in_store
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_device_grant import AUDIENCE, ISSUER, bearer

URN = "urn:ietf:params:oauth:grant-type:device_code"
LITERAL = "device_code"
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


@pytest.fixture()
def app(key_pair: RSAKeyPair, pg_url: str) -> Starlette:
    settings = dataclasses.replace(
        ConfirmSettings.for_testing(),
        database_url=pg_url,
        session_token_audience=RESOURCE,
        allow_non_uri_audience=False,
    )
    return create_confirm_app(
        settings,
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


def _client(app: Starlette) -> httpx2.AsyncClient:
    return httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), base_url="http://t")


async def _approved(app: Starlette, key_pair: RSAKeyPair) -> dict[str, Any]:
    async with _client(app) as client:
        started = await client.post("/device_authorization", json={"client_id": "claude-code"})
        assert started.status_code == 200, started.text
        device: dict[str, Any] = started.json()
        await scan_in_store(app, device["user_code"], CUSTOMER)
        approved = await client.post(
            "/approve", json={"user_code": device["user_code"]}, headers=bearer(key_pair)
        )
        assert approved.status_code == 200, approved.text
    return device


async def _pending(app: Starlette) -> str:
    store: InMemoryDeviceCodeStore = app.state.device_code_store
    code = await store.create_device_code(
        client_id="claude-code",
        scopes="accounts:read",
        verification_uri="https://auth.example.com/verify",
    )
    return code.device_code


async def _post(app: Starlette, **form: str) -> httpx2.Response:
    async with _client(app) as client:
        return await client.post("/token", data=form)


async def _token_rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(
            select(AuditEntry)
            .where(AuditEntry.tool_name == TOKEN_TOOL_NAME)
            .order_by(AuditEntry.id)
        )
        return list(result.scalars())


_PER_EXCHANGE = {"id", "call_id", "at", "reaching_at", "completed_at", "duration_ms", "arguments"}


def _comparable(row: AuditEntry) -> dict[str, Any]:
    return {
        c.key: getattr(row, c.key)
        for c in AuditEntry.__table__.columns
        if c.key not in _PER_EXCHANGE
    }


class TestTheUrnIsTheDeviceCodeGrant:
    async def test_a_full_exchange_matches_the_literal(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        by_literal = await _approved(app, key_pair)
        by_urn = await _approved(app, key_pair)

        literal = await _post(app, grant_type=LITERAL, device_code=by_literal["device_code"])
        urn = await _post(app, grant_type=URN, device_code=by_urn["device_code"])

        assert literal.status_code == 200, literal.text
        assert urn.status_code == 200, urn.text
        assert set(urn.json()) == set(literal.json())
        assert urn.json()["token_type"] == literal.json()["token_type"]
        assert urn.json()["expires_in"] == literal.json()["expires_in"]
        assert urn.json()["scope"] == literal.json()["scope"]
        assert urn.headers["cache-control"] == literal.headers["cache-control"]
        assert urn.json()["refresh_token"].startswith("prt1.")

        # The refresh token is redeemable, so the family was created.
        refreshed = await _post(
            app, **{"grant_type": "refresh_token", "refresh_token": urn.json()["refresh_token"]}
        )
        assert refreshed.status_code == 200, refreshed.text

        first, second = await _token_rows(clean)
        assert _comparable(first) == _comparable(second)
        assert set(first.arguments or {}) == set(second.arguments or {})

    async def test_urn_alone_pends_then_slows_down(self, app: Starlette) -> None:
        code = await _pending(app)
        first = await _post(app, grant_type=URN, device_code=code)
        second = await _post(app, grant_type=URN, device_code=code)
        assert (first.status_code, first.json()["error"]) == (400, "authorization_pending")
        assert (second.status_code, second.json()["error"]) == (400, "slow_down")

    @pytest.mark.parametrize(("first", "second"), [(LITERAL, URN), (URN, LITERAL)])
    async def test_alternating_spellings_share_one_pending_budget(
        self, app: Starlette, first: str, second: str
    ) -> None:
        code = await _pending(app)
        one = await _post(app, grant_type=first, device_code=code)
        two = await _post(app, grant_type=second, device_code=code)
        assert one.json()["error"] == "authorization_pending"
        assert two.json()["error"] == "slow_down"

    @pytest.mark.parametrize("spelling", [LITERAL, URN])
    async def test_the_approved_poll_budget_binds_both_spellings(
        self, app: Starlette, key_pair: RSAKeyPair, spelling: str
    ) -> None:
        device = await _approved(app, key_pair)
        # One approved poll a moment ago, whichever spelling made it.
        app.state._approved_poll_times = {device["device_code"]: datetime.now(UTC)}
        resp = await _post(app, grant_type=spelling, device_code=device["device_code"])
        assert (resp.status_code, resp.json()["error"]) == (400, "slow_down")


class TestEverythingElseIsStillRefused:
    @pytest.mark.parametrize(
        "grant_type",
        [
            "Device_Code",
            "DEVICE_CODE",
            "device_code ",
            " device_code",
            URN.upper(),
            "URN:ietf:params:oauth:grant-type:device_code",
            URN + " ",
            URN + "x",
            "urn:ietf:params:oauth:grant-type:refresh_token",
            "urn:ietf:params:oauth:grant-type:device-code",
            "authorization_code",
            "",
        ],
    )
    async def test_near_misses_are_404(self, app: Starlette, grant_type: str) -> None:
        resp = await _post(app, grant_type=grant_type, device_code="x" * 43)
        assert resp.status_code == 404
        assert resp.json() == {
            "error": "unsupported_grant_type",
            "error_description": "only the device_code and refresh_token grants are supported",
        }

    async def test_refresh_token_is_unchanged(self, app: Starlette) -> None:
        resp = await _post(
            app, **{"grant_type": "refresh_token", "refresh_token": "prt1.nope.nope"}
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_grant"

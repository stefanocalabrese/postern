"""The whole QR pairing, as a browser and a phone drive it, over ASGI.

``POST /device_authorization`` -> ``GET /verify`` -> ``GET /verify/state`` ->
``GET /verify/qr.svg`` -> ``POST /scan`` -> ``POST /approve`` ->
``POST /token``, with the state endpoint read after the scan and after the
approval. Nothing is handed to the phone that it could not have read off the
QR: the ``user_code`` and the rotation token come out of the ``app_link`` the
state endpoint serves, which is the string the QR encodes, and the
``device_code`` never leaves the browser.

The audit trail is read back at the end: one row each for the scan, the
approval and the mint, joined on the device code's handle.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import KeySet
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, OUTCOME_RETURNED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_DEVICE_CODE_SPENT,
    DETAIL_NOT_SCANNED,
    PAIRING_TOOL_NAME,
    SCAN_TOOL_NAME,
    TOKEN_TOOL_NAME,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
CUSTOMER = "cust_7f3a"
SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    await _wipe(database)
    yield database
    await _wipe(database)


@pytest.fixture()
def app(pg_url: str) -> tuple[Starlette, RSAKeyPair]:
    key_pair = RSAKeyPair.generate()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    built = create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )
    return built, key_pair


async def test_a_browser_and_a_phone_complete_a_pairing_through_every_route(
    app: tuple[Starlette, RSAKeyPair], clean: Database
) -> None:
    confirm, key_pair = app
    assertion = key_pair.create_token(subject=CUSTOMER, issuer=ISSUER, audience=AUDIENCE)
    phone_headers = {"Authorization": f"Bearer {assertion}"}
    transport = httpx2.ASGITransport(app=confirm)

    async with (
        httpx2.AsyncClient(transport=transport, base_url="https://auth.test") as browser,
        httpx2.AsyncClient(transport=transport, base_url="https://auth.test") as phone,
    ):
        started = await browser.post("/device_authorization", json={"client_id": "claude-code"})
        assert started.status_code == 200, started.text
        grant = started.json()
        handle = parse_qs(urlsplit(grant["verification_uri_complete"]).query)["d"][0]

        page = await browser.get("/verify", params={"d": handle})
        assert page.status_code == 200
        assert grant["user_code"] in page.text

        pending = await browser.get("/verify/state", params={"d": handle}, headers=SAME_ORIGIN)
        assert pending.json()["status"] == "pending"
        qr = await browser.get("/verify/qr.svg", params={"d": handle}, headers=SAME_ORIGIN)
        assert qr.status_code == 200
        assert qr.content.startswith(b"<svg")
        assert grant["device_code"] not in page.text
        assert grant["device_code"].encode() not in qr.content
        assert grant["device_code"] not in pending.text

        # An approval before any scan is refused with the one opaque body.
        early = await phone.post(
            "/approve", json={"user_code": grant["user_code"]}, headers=phone_headers
        )
        assert early.status_code == 400
        assert early.json() == {
            "error": "invalid_grant",
            "error_description": "this pairing cannot be completed",
        }

        # What the phone's camera reads: the app link, and nothing else.
        link = parse_qs(urlsplit(pending.json()["app_link"]).query)
        assert grant["device_code"] not in pending.json()["app_link"]
        scanned = await phone.post(
            "/scan",
            json={"user_code": link["user_code"][0], "qr": link["qr"][0]},
            headers=phone_headers,
        )
        assert scanned.status_code == 200, scanned.text
        assert scanned.json()["user_code"] == grant["user_code"]
        assert scanned.json()["client_id"] == "claude-code"
        assert scanned.json()["client_id_verified"] is False

        after_scan = await browser.get("/verify/state", params={"d": handle}, headers=SAME_ORIGIN)
        assert after_scan.json() == {"status": "scanned"}
        assert grant["device_code"] not in after_scan.text
        no_more_qr = await browser.get("/verify/qr.svg", params={"d": handle}, headers=SAME_ORIGIN)
        assert no_more_qr.status_code == 404

        approved = await phone.post(
            "/approve", json={"user_code": grant["user_code"]}, headers=phone_headers
        )
        assert approved.status_code == 200, approved.text

        after_approval = await browser.get(
            "/verify/state", params={"d": handle}, headers=SAME_ORIGIN
        )
        assert after_approval.status_code == 404
        qr_after = await browser.get("/verify/qr.svg", params={"d": handle}, headers=SAME_ORIGIN)
        assert qr_after.status_code == 404

        token = await browser.post(
            "/token", data={"grant_type": "device_code", "device_code": grant["device_code"]}
        )
        second = await browser.post(
            "/token", data={"grant_type": "device_code", "device_code": grant["device_code"]}
        )

    assert token.status_code == 200, token.text
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"

    settings = ConfirmSettings.for_testing()
    read_jwks = confirm.state.postern_read_key_source.public_jwks()
    decoded = joserfc_jwt.decode(
        token.json()["access_token"], KeySet.import_key_set(read_jwks), algorithms=["RS256"]
    )
    claims = decoded.claims
    assert claims["sub"] == CUSTOMER
    # A READ token: the read key's kid and the read issuer from settings, the
    # accounts audience and scope the token endpoint mints, this service as
    # actor, and nothing that names the write side.
    assert decoded.header["kid"] == settings.read_key_kid
    assert decoded.header["kid"] in {k["kid"] for k in read_jwks["keys"]}
    assert claims["iss"] == settings.read_token_issuer
    assert claims["aud"] == "accounts.svc"
    assert claims["scope"] == "accounts:read"
    assert claims["act"] == {"sub": "svc:postern"}
    assert "payments" not in claims["aud"] and "execute" not in claims["scope"]

    async with clean.sessionmaker() as s:
        written = list((await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars())
    everything = [(r.tool_name, r.outcome, r.detail) for r in written]
    assert everything == [
        (PAIRING_TOOL_NAME, OUTCOME_RAISED, DETAIL_NOT_SCANNED),
        (SCAN_TOOL_NAME, OUTCOME_RETURNED, None),
        (PAIRING_TOOL_NAME, OUTCOME_RETURNED, None),
        (TOKEN_TOOL_NAME, OUTCOME_RETURNED, None),
        (TOKEN_TOOL_NAME, OUTCOME_RAISED, DETAIL_DEVICE_CODE_SPENT),
    ]
    successes = [r for r in written if r.outcome == OUTCOME_RETURNED]
    assert [(r.tool_name, r.detail) for r in successes] == [
        (SCAN_TOOL_NAME, None),
        (PAIRING_TOOL_NAME, None),
        (TOKEN_TOOL_NAME, None),
    ]
    assert len({r.arguments["device_code_handle"] for r in successes}) == 1

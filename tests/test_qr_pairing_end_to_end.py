"""The whole QR pairing, as a browser and a phone drive it, over ASGI.

``POST /device_authorization`` -> ``GET /verify`` -> ``GET /verify/state`` ->
``GET /verify/qr.svg`` -> ``POST /scan`` -> ``POST /approve`` ->
``POST /token``, with the state endpoint read after the scan and after the
approval. Nothing is handed to the phone that it could not have read off the
QR: the ``user_code`` and the rotation token come out of the ``app_link`` the
state endpoint serves, which is the string the QR encodes, and the
``device_code`` never leaves the browser.

``POST /token`` ends the flow with a 503 and no token, twice, one interval
apart (a poll inside the interval gets ``slow_down`` and no row), because
issuance is disabled until the layer-1 session token lands: the token it used
to return was a layer-2 backend token, signed with the read key
``services/api`` publishes. This test builds ``services/api`` over the SAME
read key as the confirm service, so a token like that one would verify
against the api's own JWKS, and asserts that no ``/token`` body carries one.

The audit trail is read back at the end: one row each for the scan and the
approval, and one ``issuance_disabled`` row per ``/token`` 503 after the
approval, joined on the device code's handle.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from joserfc.jwk import RSAKey
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, OUTCOME_RETURNED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.api.main import create_app as create_api_app
from services.api.settings import Settings as ApiSettings
from services.confirm.audit import (
    DETAIL_ISSUANCE_DISABLED,
    DETAIL_NOT_SCANNED,
    PAIRING_TOOL_NAME,
    SCAN_TOOL_NAME,
    TOKEN_TOOL_NAME,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import (
    ISSUANCE_DISABLED_BODY,
    assert_no_body_carries_a_token_the_api_trusts,
    verifies_against,
)
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
def read_key_pem(tmp_path: Path) -> str:
    """One read key on disk, for BOTH services, as a Vault deployment shares
    transit key ``postern-read`` between them. Without it each app generates
    its own key and no token of confirm's could ever verify against the api's
    JWKS, which would make the regression below pass for the wrong reason."""
    key = RSAKey.generate_key(2048, parameters={"kid": "read-1", "use": "sig", "alg": "RS256"})
    pem = tmp_path / "read.pem"
    pem.write_bytes(key.as_pem(private=True))
    return str(pem)


@pytest.fixture()
def app(pg_url: str, read_key_pem: str) -> tuple[Starlette, RSAKeyPair]:
    key_pair = RSAKeyPair.generate()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    built = create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url, read_key_pem_path=read_key_pem),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )
    return built, key_pair


@pytest.fixture()
async def api_jwks(read_key_pem: str) -> dict[str, Any]:
    """The key set ``services/api`` publishes at ``/.well-known/jwks.json``,
    fetched over ASGI from the assembled app: the set Istio trusts."""
    api = create_api_app(
        replace(ApiSettings.for_testing(), read_key_pem_path=read_key_pem),
        resolver=lambda: CustomerRef(value=CUSTOMER),
    )
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=api), base_url="http://api.test"
    ) as client:
        async with api.router.lifespan_context(api):
            published = await client.get("/.well-known/jwks.json")
    assert published.status_code == 200
    jwks: dict[str, Any] = published.json()
    return jwks


async def test_a_browser_and_a_phone_complete_a_pairing_through_every_route(
    app: tuple[Starlette, RSAKeyPair], clean: Database, api_jwks: dict[str, Any]
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
        too_soon = await browser.post(
            "/token", data={"grant_type": "device_code", "device_code": grant["device_code"]}
        )
        # The browser waits one interval, as the 503's Retry-After tells it
        # to; simulated by moving the recorded poll back rather than sleeping.
        confirm.state._approved_poll_times[grant["device_code"]] -= timedelta(
            seconds=int(token.headers["retry-after"])
        )
        second = await browser.post(
            "/token", data={"grant_type": "device_code", "device_code": grant["device_code"]}
        )

    # THE CONTROL THAT MAKES THE REGRESSION MEAN SOMETHING. The read minter is
    # still wired, and what it signs verifies against the api's published
    # JWKS: that is exactly the layer-2 token /token used to hand out. If this
    # stopped verifying, the assertion below would pass for any body at all.
    backend_token = confirm.state.read_minter.mint(
        subject=CustomerRef(value=CUSTOMER), audience="accounts.svc", scope="accounts:read"
    )
    assert verifies_against(backend_token, api_jwks)

    # The regression, before the status checks so a reintroduced token fails
    # on the property that matters rather than on a status code.
    assert_no_body_carries_a_token_the_api_trusts(
        [token.text, too_soon.text, second.text], api_jwks
    )

    # Issuance is disabled: the same 503 twice, because the code is not spent,
    # with a poll inside the interval answered slow_down in between.
    assert token.status_code == 503, token.text
    assert token.json() == ISSUANCE_DISABLED_BODY
    assert token.headers["retry-after"] == str(confirm.state.settings.device_poll_interval_seconds)
    assert too_soon.status_code == 400, too_soon.text
    assert too_soon.json()["error"] == "slow_down"
    assert second.status_code == 503, second.text
    assert second.json() == ISSUANCE_DISABLED_BODY
    stored = await confirm.state.device_code_store.get_device_code(grant["device_code"])
    assert stored is not None
    assert stored.exchanged_at is None, "a refused /token spent the device code"

    async with clean.sessionmaker() as s:
        written = list((await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars())
    everything = [(r.tool_name, r.outcome, r.detail) for r in written]
    assert everything == [
        (PAIRING_TOOL_NAME, OUTCOME_RAISED, DETAIL_NOT_SCANNED),
        (SCAN_TOOL_NAME, OUTCOME_RETURNED, None),
        (PAIRING_TOOL_NAME, OUTCOME_RETURNED, None),
        (TOKEN_TOOL_NAME, OUTCOME_RAISED, DETAIL_ISSUANCE_DISABLED),
        (TOKEN_TOOL_NAME, OUTCOME_RAISED, DETAIL_ISSUANCE_DISABLED),
    ]
    successes = [r for r in written if r.outcome == OUTCOME_RETURNED]
    assert [(r.tool_name, r.detail) for r in successes] == [
        (SCAN_TOOL_NAME, None),
        (PAIRING_TOOL_NAME, None),
    ]
    chain = successes + [r for r in written if r.tool_name == TOKEN_TOOL_NAME]
    assert len({r.arguments["device_code_handle"] for r in chain}) == 1

"""The layer-1 access token, the SESSION key and ``/session/jwks.json``.

Spec sections 2 and 3 of ``dev-docs/device-grant-session-token-spec.md``: a
third key built by the same ``choose_key_source`` call as the other two, a
minter whose claim set is exactly the table, and a JWKS route of its own that
never shares a kid or a modulus with the write set.
"""

from __future__ import annotations

import uuid
import warnings
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx2
import pytest
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, RSAKey
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.keys import FileKeySource, GeneratedKeySource
from postern_core.auth.vault import VaultSettings, VaultTransitKeySource
from postern_core.identity import CustomerRef
from starlette.applications import Starlette

from services.confirm.jwks import JWKS_PATH, SESSION_JWKS_PATH
from services.confirm.main import create_confirm_app
from services.confirm.rate_limit import DEFAULT_LIMITS, RATE_LIMIT_WINDOW_SECONDS, Limit
from services.confirm.session_token import (
    ACCESS_TOKEN_LIFETIME_SECONDS,
    SessionTokenMinter,
    build_session_minter,
)
from services.confirm.settings import ConfirmSettings

CUSTOMER = CustomerRef(value="cust_7f3a")
VAULT = VaultSettings(
    address="http://vault.invalid:8200",
    token="hvs.notarealtoken",  # noqa: S106 -- a literal in a test, not a credential
    token_path=None,
    mount="transit",
    timeout_seconds=1.0,
    public_key_ttl_seconds=300.0,
)


def _minter() -> tuple[SessionTokenMinter, GeneratedKeySource]:
    source = GeneratedKeySource(kid="session-1")
    minter = SessionTokenMinter(
        issuer="https://auth.postern.internal",
        audience="https://mcp.postern.internal/mcp",
        key_source=source,
    )
    return minter, source


class TestTheAccessToken:
    def test_the_claim_set_is_exactly_the_table(self) -> None:
        minter, source = _minter()
        claims = minter.prepare(
            customer=CUSTOMER, client_id="claude-code", scope="accounts:read", sid="s" * 22
        )
        token = minter.sign(claims)
        decoded = jwt.decode(token, KeySet.import_key_set(source.public_jwks()))
        assert set(decoded.claims) == {
            "iss",
            "aud",
            "sub",
            "client_id",
            "client_id_verified",
            "scope",
            "sid",
            "jti",
            "iat",
            "exp",
        }
        assert decoded.claims["iss"] == "https://auth.postern.internal"
        assert decoded.claims["aud"] == "https://mcp.postern.internal/mcp"
        assert decoded.claims["sub"] == "cust_7f3a"
        assert decoded.claims["client_id"] == "claude-code"
        assert decoded.claims["client_id_verified"] is False
        assert decoded.claims["scope"] == "accounts:read"
        assert decoded.claims["sid"] == "s" * 22
        assert decoded.claims["exp"] - decoded.claims["iat"] == ACCESS_TOKEN_LIFETIME_SECONDS
        assert ACCESS_TOKEN_LIFETIME_SECONDS == 600
        assert "act" not in decoded.claims
        assert "nbf" not in decoded.claims

    def test_the_header_names_the_session_kid_and_rs256(self) -> None:
        minter, source = _minter()
        token = minter.sign(
            minter.prepare(customer=CUSTOMER, client_id="c", scope="accounts:read", sid="x")
        )
        decoded = jwt.decode(token, KeySet.import_key_set(source.public_jwks()))
        assert decoded.header["alg"] == "RS256"
        assert decoded.header["kid"] == "session-1"

    def test_each_prepare_draws_a_fresh_uuid4_jti(self) -> None:
        minter, _ = _minter()
        drawn = {
            minter.prepare(customer=CUSTOMER, client_id="c", scope="s", sid="x").jti
            for _ in range(50)
        }
        assert len(drawn) == 50
        assert all(uuid.UUID(jti).version == 4 for jti in drawn)

    def test_prepare_reads_the_clock_once_and_the_claims_are_frozen(self) -> None:
        minter, _ = _minter()
        claims = minter.prepare(customer=CUSTOMER, client_id="c", scope="s", sid="x")
        assert claims.as_claims()["exp"] == claims.iat + 600
        with pytest.raises(AttributeError):
            claims.jti = "chosen"  # type: ignore[misc]


class TestTheSessionKeySource:
    def test_neither_branch_generates_and_warns_naming_the_session_variable(self) -> None:
        with pytest.warns(RuntimeWarning, match="POSTERN_SESSION_KEY_PEM_PATH") as caught:
            _, source = build_session_minter(ConfirmSettings.for_testing())
        assert isinstance(source, GeneratedKeySource)
        assert "SESSION signing key generated in process" in str(caught[0].message)

    def test_a_pem_gives_a_file_source_under_the_session_kid(self, tmp_path: Path) -> None:
        pem = tmp_path / "session.pem"
        pem.write_bytes(RSAKey.generate_key(2048).as_pem(private=True))
        settings = replace(
            ConfirmSettings.for_testing(), session_key_pem_path=str(pem), session_key_kid="s-9"
        )
        _, source = build_session_minter(settings)
        assert isinstance(source, FileKeySource)
        assert [key["kid"] for key in source.public_jwks()["keys"]] == ["s-9"]

    def test_a_public_key_pem_is_refused_at_startup(self, tmp_path: Path) -> None:
        pem = tmp_path / "public.pem"
        pem.write_bytes(RSAKey.generate_key(2048).as_pem(private=False))
        settings = replace(ConfirmSettings.for_testing(), session_key_pem_path=str(pem))
        with pytest.raises(ValueError, match="public key"):
            build_session_minter(settings)

    def test_a_vault_gives_a_transit_source_over_the_session_key(self) -> None:
        settings = replace(ConfirmSettings.for_testing(), vault=VAULT)
        _, source = build_session_minter(settings)
        assert isinstance(source, VaultTransitKeySource)
        # The session key's own name, so a wiring slip to vault_write_key_name fails here.
        assert source._key_name == "postern-session"  # noqa: SLF001
        source.close()

    def test_a_vault_and_a_pem_together_are_refused(self, tmp_path: Path) -> None:
        pem = tmp_path / "session.pem"
        pem.write_bytes(RSAKey.generate_key(2048).as_pem(private=True))
        settings = replace(
            ConfirmSettings.for_testing(), vault=VAULT, session_key_pem_path=str(pem)
        )
        with pytest.raises(ValueError, match="POSTERN_SESSION_KEY_PEM_PATH"):
            build_session_minter(settings)


def _app() -> Starlette:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        return create_confirm_app(
            ConfirmSettings.for_testing(), device_key_store=no_enrolled_devices()
        )


async def _get(app: Starlette, path: str) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="https://auth.test"
    ) as client:
        return await client.get(path)


class TestTheSessionJwksRoute:
    async def test_it_serves_the_session_key_and_nothing_else(self) -> None:
        app = _app()
        response = await _get(app, SESSION_JWKS_PATH)
        assert response.status_code == 200
        assert response.json() == app.state.postern_session_key_source.public_jwks()
        assert [key["kid"] for key in response.json()["keys"]] == ["session-1"]

    async def test_the_well_known_set_stays_write_only(self) -> None:
        app = _app()
        response = await _get(app, JWKS_PATH)
        assert response.json() == app.state.postern_write_key_source.public_jwks()

    async def test_the_two_sets_share_no_kid_and_no_modulus(self) -> None:
        app = _app()
        write: dict[str, Any] = (await _get(app, JWKS_PATH)).json()
        session: dict[str, Any] = (await _get(app, SESSION_JWKS_PATH)).json()
        assert {k["kid"] for k in write["keys"]} & {k["kid"] for k in session["keys"]} == set()
        assert {k["n"] for k in write["keys"]} & {k["n"] for k in session["keys"]} == set()

    async def test_a_token_the_app_mints_verifies_against_the_session_set_only(self) -> None:
        app = _app()
        minter: SessionTokenMinter = app.state.session_minter
        token = minter.sign(
            minter.prepare(customer=CUSTOMER, client_id="c", scope="accounts:read", sid="x")
        )
        session = (await _get(app, SESSION_JWKS_PATH)).json()
        write = (await _get(app, JWKS_PATH)).json()
        jwt.decode(token, KeySet.import_key_set(session))
        with pytest.raises(JoseError):
            jwt.decode(token, KeySet.import_key_set(write))

    async def test_it_needs_no_assertion(self) -> None:
        response = await _get(_app(), SESSION_JWKS_PATH)
        assert response.status_code == 200

    def test_it_carries_its_own_rate_limit(self) -> None:
        assert DEFAULT_LIMITS[SESSION_JWKS_PATH] == Limit(300, RATE_LIMIT_WINDOW_SECONDS)

"""`TokenClaims`, and the production provider read off a real token (spec section 7)."""

import dataclasses

import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.identity import TokenClaims, TokenClaimsProvider

from services.api.server import token_claims_provider
from tests.fixtures.payments_http import OWNER, post_tool, producer_app, result_of, token_for


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def test_token_claims_are_frozen() -> None:
    claims = TokenClaims(client_id="claude-code", jti="j-1")
    with pytest.raises(dataclasses.FrozenInstanceError):
        claims.jti = "j-2"  # type: ignore[misc]


def test_a_plain_function_satisfies_the_provider_protocol() -> None:
    def fixed() -> TokenClaims:
        return TokenClaims(client_id="claude-code", jti="j-1")

    provider: TokenClaimsProvider = fixed
    assert provider() == TokenClaims(client_id="claude-code", jti="j-1")


def test_with_no_request_there_are_no_claims() -> None:
    """The in-process transport and any code outside a request see no token,
    and the provider answers NULL for both rather than raising: the claims are
    a record, never a gate."""
    assert token_claims_provider() == TokenClaims(client_id=None, jti=None)


async def _probe(pg_url: str, key_pair: RSAKeyPair, token: str) -> dict[str, object]:
    app = producer_app(pg_url, key_pair, payments_enabled=False)
    server: FastMCP = app.state.postern_server

    async def probe_claims() -> dict[str, str | None]:
        claims = token_claims_provider()
        return {"client_id": claims.client_id, "jti": claims.jti}

    server.tool(probe_claims, name="probe_claims")
    result = result_of(await post_tool(app, token, "probe_claims"))
    assert result["isError"] is False, result
    structured: dict[str, object] = result["structuredContent"]
    return structured


async def test_a_verified_token_supplies_its_client_id_and_jti(
    pg_url: str, key_pair: RSAKeyPair, audit_server: FastMCP
) -> None:
    token = token_for(key_pair, OWNER, client_id="claude-code", jti="jti-probe-1")
    assert await _probe(pg_url, key_pair, token) == {
        "client_id": "claude-code",
        "jti": "jti-probe-1",
    }


async def test_a_token_without_those_claims_reads_as_the_revocation_layer_reads_it(
    pg_url: str, key_pair: RSAKeyPair, audit_server: FastMCP
) -> None:
    """No `jti` claim is NULL. No `client_id` claim is whatever `JWTVerifier`
    put in `AccessToken.client_id`, which falls back to `sub`: the same value
    `RevocationMiddleware` keys its client scope on, so the two agree."""
    token = token_for(key_pair, OWNER, client_id=None, jti=None)
    assert await _probe(pg_url, key_pair, token) == {"client_id": OWNER, "jti": None}

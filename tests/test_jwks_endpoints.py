import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan

from services.api.main import create_app
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER

_PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi"}

ISSUER = "https://postern-test.invalid"
AUDIENCE = "postern"


@pytest.fixture
def app() -> StarletteWithLifespan:
    return create_app(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER)


async def get(
    app: StarletteWithLifespan, path: str, headers: dict[str, str] | None = None
) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        async with app.router.lifespan_context(app):
            return await c.get(path, headers=headers or {})


async def test_the_read_jwks_is_served(app: StarletteWithLifespan) -> None:
    r = await get(app, "/.well-known/jwks.json")
    assert r.status_code == 200
    assert {e["kid"] for e in r.json()["keys"]} == {"read-1"}


async def test_the_read_jwks_carries_no_private_material(app: StarletteWithLifespan) -> None:
    for entry in (await get(app, "/.well-known/jwks.json")).json()["keys"]:
        assert set(entry) & _PRIVATE_PARAMS == set(), entry


async def test_the_read_jwks_is_anonymous(app: StarletteWithLifespan) -> None:
    """Istio fetches this without a customer token."""
    assert (await get(app, "/.well-known/jwks.json")).status_code == 200


async def test_the_read_jwks_stays_anonymous_while_customer_auth_is_enforced() -> None:
    """The test above runs against `Settings.for_testing()` with no
    `auth_override`, which configures no customer authentication at all
    (`create_app`'s `has_real_customer_auth`), so on its own it only shows
    that the route answers when nothing is enforcing anything. This builds
    the shape a gateway actually faces -- a real `JWTVerifier` over a
    generated key pair, the same `auth_override` seam
    `tests/test_audit_refusal_reason.py::_app` uses -- and pins both halves
    against ONE app object, with no `Authorization` header on either
    request: the JWKS answers 200, and `/mcp` answers 401 with
    `WWW-Authenticate: Bearer`, which is `RequireAuthMiddleware` refusing an
    anonymous caller (`fastmcp/server/http.py::create_streamable_http_app`
    wraps the `/mcp` endpoint in it). The 401 is the half
    that carries the proof. A 200 from the JWKS alone cannot distinguish
    "this route is exempt from auth" from "auth is not being enforced in
    this configuration", and those are the only two explanations.

    One `AsyncClient` and one lifespan for both requests, so "same app" is
    structural rather than a claim: the 200 and the 401 come out of the same
    `create_app` return value, in the same running lifespan.
    """
    key_pair = RSAKeyPair.generate()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = create_app(Settings.for_testing(), auth_override=verifier)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        async with app.router.lifespan_context(app):
            jwks = await client.get("/.well-known/jwks.json")
            # `tools/list`, not `tools/call`: the auth gate is reached before
            # any tool runs, so this needs no consent row and no reachable
            # Postgres even though `auth_override` turns consent enforcement on.
            mcp = await client.post(
                "/mcp",
                headers={"Accept": "application/json, text/event-stream"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            )

    assert jwks.status_code == 200
    assert jwks.json() == app.state.postern_read_key_source.public_jwks()
    assert {e["kid"] for e in jwks.json()["keys"]} == {"read-1"}
    assert mcp.status_code == 401
    assert mcp.headers["www-authenticate"] == "Bearer"


async def test_the_read_jwks_never_contains_a_write_key(app: StarletteWithLifespan) -> None:
    kids = {e["kid"] for e in (await get(app, "/.well-known/jwks.json")).json()["keys"]}
    assert not any(k.startswith("write") for k in kids)


async def test_the_header_middleware_ignores_the_jwks_get(app: StarletteWithLifespan) -> None:
    """HeaderBodyValidation short-circuits on non-POST, so a GET is never
    inspected even carrying nonsense MCP headers. Measured."""
    r = await get(app, "/.well-known/jwks.json", {"Mcp-Method": "tools/list", "Mcp-Name": "x"})
    assert r.status_code == 200

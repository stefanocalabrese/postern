import httpx2
import pytest
from fastmcp.server.http import StarletteWithLifespan

from services.api.main import create_app
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER

_PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi"}


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


async def test_the_read_jwks_never_contains_a_write_key(app: StarletteWithLifespan) -> None:
    kids = {e["kid"] for e in (await get(app, "/.well-known/jwks.json")).json()["keys"]}
    assert not any(k.startswith("write") for k in kids)


async def test_the_header_middleware_ignores_the_jwks_get(app: StarletteWithLifespan) -> None:
    """HeaderBodyValidation short-circuits on non-POST, so a GET is never
    inspected even carrying nonsense MCP headers. Measured."""
    r = await get(app, "/.well-known/jwks.json", {"Mcp-Method": "tools/list", "Mcp-Name": "x"})
    assert r.status_code == 200

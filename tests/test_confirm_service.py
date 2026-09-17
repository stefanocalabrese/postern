import httpx2
import pytest
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet
from starlette.applications import Starlette

from services.confirm.main import create_confirm_app
from services.confirm.minter import WRITE_SCOPES, build_write_minter
from services.confirm.settings import ConfirmSettings

_PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi"}


@pytest.fixture
def settings() -> ConfirmSettings:
    return ConfirmSettings.for_testing()


async def get(app: Starlette, path: str) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        return await c.get(path)


def test_the_write_minter_uses_the_write_issuer(settings: ConfirmSettings) -> None:
    minter, source = build_write_minter(settings)
    token = minter.mint(
        subject_value="cust_7f3a", audience="payments.svc", scope="payments:execute"
    )
    claims = jwt.decode(
        token, KeySet.import_key_set(source.public_jwks()), algorithms=["RS256"]
    ).claims
    assert claims["iss"] == "https://mcp-write.bank.internal"
    assert claims["aud"] == "payments.svc"


def test_every_write_scope_is_a_write_scope() -> None:
    for scope in WRITE_SCOPES.values():
        assert not scope.endswith(":read"), scope


async def test_the_write_jwks_is_served(settings: ConfirmSettings) -> None:
    r = await get(create_confirm_app(settings), "/.well-known/jwks.json")
    assert r.status_code == 200
    assert {e["kid"] for e in r.json()["keys"]} == {"write-1"}


async def test_the_write_jwks_carries_no_private_material(settings: ConfirmSettings) -> None:
    for entry in (await get(create_confirm_app(settings), "/.well-known/jwks.json")).json()["keys"]:
        assert set(entry) & _PRIVATE_PARAMS == set(), entry


async def test_the_write_jwks_never_contains_a_read_key(settings: ConfirmSettings) -> None:
    kids = {
        e["kid"]
        for e in (await get(create_confirm_app(settings), "/.well-known/jwks.json")).json()["keys"]
    }
    assert not any(k.startswith("read") for k in kids)


def test_the_confirm_settings_have_no_read_key_field() -> None:
    """The asymmetry is the point and it should be greppable."""
    import dataclasses

    names = {f.name for f in dataclasses.fields(ConfirmSettings)}
    assert not any("read" in n for n in names), names


def test_a_write_token_is_rejected_by_the_read_key_set(settings: ConfirmSettings) -> None:
    from postern_core.auth.keys import GeneratedKeySource

    minter, _ = build_write_minter(settings)
    token = minter.mint(
        subject_value="cust_7f3a", audience="payments.svc", scope="payments:execute"
    )
    read_only = KeySet.import_key_set(GeneratedKeySource(kid="read-1").public_jwks())
    with pytest.raises(InvalidKeyIdError):
        jwt.decode(token, read_only, algorithms=["RS256"])

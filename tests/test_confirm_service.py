import httpx2
import pytest
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet
from postern_core.auth.device_keys import no_enrolled_devices
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
    assert claims["iss"] == "https://mcp-write.internal"
    assert claims["aud"] == "payments.svc"


def test_every_write_scope_is_a_write_scope() -> None:
    for scope in WRITE_SCOPES.values():
        assert not scope.endswith(":read"), scope


async def test_the_write_jwks_is_served(settings: ConfirmSettings) -> None:
    r = await get(
        create_confirm_app(settings, device_key_store=no_enrolled_devices()),
        "/.well-known/jwks.json",
    )
    assert r.status_code == 200
    assert {e["kid"] for e in r.json()["keys"]} == {"write-1"}


async def test_the_write_jwks_carries_no_private_material(settings: ConfirmSettings) -> None:
    for entry in (
        await get(
            create_confirm_app(settings, device_key_store=no_enrolled_devices()),
            "/.well-known/jwks.json",
        )
    ).json()["keys"]:
        assert set(entry) & _PRIVATE_PARAMS == set(), entry


async def test_the_write_jwks_never_contains_a_read_key(settings: ConfirmSettings) -> None:
    kids = {
        e["kid"]
        for e in (
            await get(
                create_confirm_app(settings, device_key_store=no_enrolled_devices()),
                "/.well-known/jwks.json",
            )
        ).json()["keys"]
    }
    assert not any(k.startswith("read") for k in kids)


def test_the_confirm_settings_have_no_read_key_field() -> None:
    """The asymmetry is the point and it should be greppable.

    Until the layer-1 session token four ``read_*`` fields were allowed here,
    the device-grant exception: ``POST /token`` minted the browser a read
    token. It issues a session token signed by the SESSION key now, so the
    allowed set is empty and no process holds READ and WRITE together. What
    stops a process signing with a key it does not name is still the Vault
    policy on its token, measured in `tests/test_vault_live.py`.
    """
    import dataclasses

    names = {f.name for f in dataclasses.fields(ConfirmSettings)}
    read_fields = {n for n in names if "read" in n}
    assert read_fields == set(), f"Unexpected read fields: {read_fields}"


async def test_the_confirm_app_builds_and_serves_holding_no_read_key(
    settings: ConfirmSettings,
) -> None:
    """The composition root builds no read key source and no read minter.

    It still starts and serves both of its key sets: the write set at
    ``/.well-known/jwks.json`` and the session set at ``/session/jwks.json``.
    """
    app = create_confirm_app(settings, device_key_store=no_enrolled_devices())
    assert not hasattr(app.state, "postern_read_key_source")
    assert not hasattr(app.state, "read_minter")
    for path in ("/.well-known/jwks.json", "/session/jwks.json"):
        response = await get(app, path)
        assert response.status_code == 200, path
        assert not any(e["kid"].startswith("read") for e in response.json()["keys"]), path


def test_the_api_settings_name_no_write_key() -> None:
    """The other half of the asymmetry, which had no test at all.

    `services/api/settings.py` must carry no field naming a write key, a write
    kid, a write issuer or a write PEM. This is the direction that matters:
    the confirm service has held no read key since the layer-1 session token,
    and the api service holding anything write-shaped is the defect.
    """
    import dataclasses

    from services.api.settings import Settings

    write_fields = {f.name for f in dataclasses.fields(Settings) if "write" in f.name}
    # `backend_write_timeout_seconds` is a socket phase, not a key.
    assert write_fields == {"backend_write_timeout_seconds"}


def test_the_api_settings_name_no_session_key() -> None:
    """The api verifies session tokens and never signs one.

    ``services/api`` reads the session key's PUBLIC half from confirm's
    ``/session/jwks.json`` through ``POSTERN_JWKS_URI``; a settings field
    naming the session key itself would be the first step to holding it.
    """
    import dataclasses

    from services.api.settings import Settings

    assert {f.name for f in dataclasses.fields(Settings) if "session_key" in f.name} == set()


def test_a_write_token_is_rejected_by_the_read_key_set(settings: ConfirmSettings) -> None:
    from postern_core.auth.keys import GeneratedKeySource

    minter, _ = build_write_minter(settings)
    token = minter.mint(
        subject_value="cust_7f3a", audience="payments.svc", scope="payments:execute"
    )
    read_only = KeySet.import_key_set(GeneratedKeySource(kid="read-1").public_jwks())
    with pytest.raises(InvalidKeyIdError):
        jwt.decode(token, read_only, algorithms=["RS256"])

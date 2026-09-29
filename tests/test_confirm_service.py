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

    The only ``read_*`` fields are for the device-grant exception
    (both read and write keys needed to mint tokens atomically).

    ``vault_read_key_name`` JOINED THAT LIST ON 29 SEPTEMBER 2026 and is the
    same exception in the same place: the transit key whose name it carries is
    the one this service asks Vault to sign the browser's read token with,
    during the one atomic step that also mints the write token. Adding it here
    is a widening, so it is worth saying what did NOT widen -- the api
    service's settings gained `vault_read_key_name` and nothing named a write
    key, `postern_core.auth.vault.VaultSettings` names no key at all, and
    `postern_core.auth.keys.choose_key_source` takes one key and returns one
    source. The list below is a list of FIELDS; what stops a read process
    signing a payment is the Vault policy on the token each service holds,
    measured in `tests/test_vault_live.py`.
    """
    import dataclasses

    names = {f.name for f in dataclasses.fields(ConfirmSettings)}
    allowed_read_fields = {
        "read_key_pem_path",
        "read_key_kid",
        "read_token_issuer",
        "vault_read_key_name",
    }
    read_fields = {n for n in names if "read" in n}
    extra = read_fields - allowed_read_fields
    assert not extra, f"Unexpected read fields: {extra}"


def test_the_api_settings_name_no_write_key() -> None:
    """The other half of the asymmetry, which had no test at all.

    `services/api/settings.py` must carry no field naming a write key, a write
    kid, a write issuer or a write PEM. This is the direction that matters:
    the confirm service holding a read key is a recorded exception, and the api
    service holding anything write-shaped is the defect.
    """
    import dataclasses

    from services.api.settings import Settings

    write_fields = {f.name for f in dataclasses.fields(Settings) if "write" in f.name}
    # `backend_write_timeout_seconds` is a socket phase, not a key.
    assert write_fields == {"backend_write_timeout_seconds"}


def test_a_write_token_is_rejected_by_the_read_key_set(settings: ConfirmSettings) -> None:
    from postern_core.auth.keys import GeneratedKeySource

    minter, _ = build_write_minter(settings)
    token = minter.mint(
        subject_value="cust_7f3a", audience="payments.svc", scope="payments:execute"
    )
    read_only = KeySet.import_key_set(GeneratedKeySource(kid="read-1").public_jwks())
    with pytest.raises(InvalidKeyIdError):
        jwt.decode(token, read_only, algorithms=["RS256"])

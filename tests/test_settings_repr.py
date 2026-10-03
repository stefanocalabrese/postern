"""A settings object that is logged or formatted must not print a credential.

The default dataclass repr lists every field, so ``database_url`` (which
carries the database password) and the Vault ``token`` would appear in any
log line, traceback or ``%r`` that touched the object. Nothing does today;
this pins it so nothing can start to.
"""

from __future__ import annotations

import dataclasses
import pprint
from datetime import UTC, datetime

import pytest
from postern_core.auth.device_codes import DeviceCode
from postern_core.auth.internal_jwt import MintedToken
from postern_core.auth.vault import VaultSettings

from services.api.settings import Settings
from services.confirm.settings import ConfirmSettings

DB_SECRET = "sentinel-db-password-7f3a"  # noqa: S105
VAULT_SECRET = "sentinel-vault-token-91c2"  # noqa: S105
DB_URL = f"postgresql+asyncpg://postern:{DB_SECRET}@db.internal:5432/postern"


def _vault() -> VaultSettings:
    return VaultSettings(
        address="http://vault.example:8200",
        token=VAULT_SECRET,
        token_path=None,
        mount="transit",
        timeout_seconds=1.5,
        public_key_ttl_seconds=300.0,
    )


def _renderings(obj: object) -> list[str]:
    return [
        repr(obj),
        str(obj),
        f"{obj!r}",
        f"{obj}",
        "%s %r" % (obj, obj),  # noqa: UP031
        pprint.pformat(obj),
        str(dataclasses.fields(obj)),  # type: ignore[arg-type]
    ]


@pytest.mark.parametrize(
    "settings",
    [
        Settings(backend_base_url="http://backend.example", database_url=DB_URL, vault=_vault()),
        ConfirmSettings(database_url=DB_URL, vault=_vault()),
        _vault(),
    ],
    ids=["Settings", "ConfirmSettings", "VaultSettings"],
)
def test_no_secret_in_any_rendering(settings: object) -> None:
    for rendered in _renderings(settings):
        assert DB_SECRET not in rendered
        assert VAULT_SECRET not in rendered


def test_non_secret_fields_are_still_shown() -> None:
    api = repr(Settings(backend_base_url="http://backend.example", vault=_vault()))
    assert "http://backend.example" in api
    assert "http://vault.example:8200" in api
    assert "timeout_seconds=1.5" in api
    confirm = repr(ConfirmSettings(device_poll_interval_seconds=7))
    assert "device_poll_interval_seconds=7" in confirm


def test_secrets_stay_reachable_as_attributes() -> None:
    settings = ConfirmSettings(database_url=DB_URL, vault=_vault())
    assert settings.database_url == DB_URL
    assert settings.vault is not None
    assert settings.vault.token == VAULT_SECRET


BEARER = "sentinel-bearer-value-5d1e"


def test_a_minted_token_does_not_print_its_bearer_value() -> None:
    minted = MintedToken(token=BEARER, jti="jti-visible")
    for rendered in _renderings(minted):
        assert BEARER not in rendered
    assert "jti-visible" in repr(minted)
    assert minted.token == BEARER
    assert minted == MintedToken(token=BEARER, jti="jti-visible")
    assert hash(minted) == hash(MintedToken(token=BEARER, jti="jti-visible"))
    assert minted != MintedToken(token="other", jti="jti-visible")  # noqa: S106


def test_a_device_code_does_not_print_its_polling_secret() -> None:
    expires = datetime(2030, 1, 1, tzinfo=UTC)
    code = DeviceCode(
        device_code=BEARER,
        user_code="ABCD-EFGH",
        verification_uri="https://x/v",
        expires_at=expires,
    )
    for rendered in _renderings(code):
        assert BEARER not in rendered
    assert "ABCD-EFGH" in repr(code)
    assert code.device_code == BEARER
    assert code == DeviceCode(
        device_code=BEARER,
        user_code="ABCD-EFGH",
        verification_uri="https://x/v",
        expires_at=expires,
    )
    assert code != DeviceCode(
        device_code="other",
        user_code="ABCD-EFGH",
        verification_uri="https://x/v",
        expires_at=expires,
    )

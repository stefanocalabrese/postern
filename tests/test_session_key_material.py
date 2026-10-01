"""The session key is refused when it shares key MATERIAL with the read or write key.

``_refuse_shared_session_key`` compares names, kids and PEM paths, which a copied
file, a hardlink or a case-different path on a case-insensitive filesystem all
pass. ``refuse_shared_key_material`` compares the PUBLIC keys each source
publishes, by RFC 7638 thumbprint, so it also covers a Vault transit key, whose
public half arrives over the network and has no path at all.
"""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path
from typing import Any

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from joserfc.jwk import KeySet, RSAKey
from postern_core.auth.device_keys import no_enrolled_devices

from services.confirm.main import create_confirm_app
from services.confirm.session_token import jwk_thumbprints, refuse_shared_key_material
from services.confirm.settings import ConfirmSettings, check_session_token_settings
from tests.test_device_grant import AUDIENCE, ISSUER


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def _pem(path: Path, key: RSAKey | None = None) -> RSAKey:
    key = key or RSAKey.generate_key(2048)
    path.write_bytes(key.as_pem(private=True))
    return key


def _app(key_pair: RSAKeyPair, **overrides: Any) -> Any:
    return create_confirm_app(
        dataclasses.replace(ConfirmSettings.for_testing(), **overrides),
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


class _Source:
    """A key source stub that publishes only a public set, as Vault's does."""

    def __init__(self, *keys: RSAKey) -> None:
        self._keys = keys

    def public_jwks(self) -> Any:
        return KeySet(list(self._keys)).as_dict()


class TestFilesWithTheSameKey:
    def test_a_copied_file_at_another_path_is_refused(
        self, key_pair: RSAKeyPair, tmp_path: Path
    ) -> None:
        _pem(tmp_path / "read.pem")
        (tmp_path / "session.pem").write_bytes((tmp_path / "read.pem").read_bytes())
        _pem(tmp_path / "write.pem")
        with pytest.raises(ValueError) as raised:
            _app(
                key_pair,
                read_key_pem_path=str(tmp_path / "read.pem"),
                write_key_pem_path=str(tmp_path / "write.pem"),
                session_key_pem_path=str(tmp_path / "session.pem"),
            )
        message = str(raised.value)
        assert "POSTERN_SESSION_KEY_PEM_PATH" in message
        assert "POSTERN_READ_KEY_PEM_PATH" in message
        assert "MATERIAL" in message
        assert "PRIVATE" not in message

    def test_a_hardlink_is_refused(self, key_pair: RSAKeyPair, tmp_path: Path) -> None:
        _pem(tmp_path / "write.pem")
        os.link(tmp_path / "write.pem", tmp_path / "session.pem")
        _pem(tmp_path / "read.pem")
        with pytest.raises(ValueError, match="POSTERN_WRITE_KEY_PEM_PATH"):
            _app(
                key_pair,
                read_key_pem_path=str(tmp_path / "read.pem"),
                write_key_pem_path=str(tmp_path / "write.pem"),
                session_key_pem_path=str(tmp_path / "session.pem"),
            )

    def test_three_different_keys_start(self, key_pair: RSAKeyPair, tmp_path: Path) -> None:
        for name in ("read", "write", "session"):
            _pem(tmp_path / f"{name}.pem")
        app = _app(
            key_pair,
            read_key_pem_path=str(tmp_path / "read.pem"),
            write_key_pem_path=str(tmp_path / "write.pem"),
            session_key_pem_path=str(tmp_path / "session.pem"),
        )
        assert app is not None

    def test_generated_keys_start(self, key_pair: RSAKeyPair) -> None:
        assert _app(key_pair) is not None


class TestTheComparisonItself:
    """Source level, which is also the Vault shape: public keys and no path."""

    def test_the_same_public_key_under_another_kid_is_refused(self) -> None:
        shared = RSAKey.generate_key(2048, parameters={"kid": "session-1"})
        other = RSAKey.import_key(
            shared.as_pem(private=True), parameters={"kid": "postern-read-v3"}
        )
        with pytest.raises(ValueError) as raised:
            refuse_shared_key_material(
                session=_Source(shared),
                others=[("POSTERN_VAULT_READ_KEY_NAME", _Source(RSAKey.generate_key(2048), other))],
                session_variable="POSTERN_VAULT_SESSION_KEY_NAME",
            )
        assert "POSTERN_VAULT_SESSION_KEY_NAME" in str(raised.value)
        assert "POSTERN_VAULT_READ_KEY_NAME" in str(raised.value)
        assert "MATERIAL" in str(raised.value)

    def test_disjoint_sets_pass(self) -> None:
        refuse_shared_key_material(
            session=_Source(RSAKey.generate_key(2048)),
            others=[
                ("POSTERN_VAULT_READ_KEY_NAME", _Source(RSAKey.generate_key(2048))),
                ("POSTERN_VAULT_WRITE_KEY_NAME", _Source(RSAKey.generate_key(2048))),
            ],
            session_variable="POSTERN_VAULT_SESSION_KEY_NAME",
        )

    def test_a_thumbprint_ignores_kid_and_private_parts(self) -> None:
        key = RSAKey.generate_key(2048, parameters={"kid": "a"})
        again = RSAKey.import_key(key.as_pem(private=True), parameters={"kid": "b"})
        assert jwk_thumbprints(KeySet([key]).as_dict()) == jwk_thumbprints(
            KeySet([again]).as_dict()
        )


class TestVaultKeyNamesAreStripped:
    def test_a_trailing_space_does_not_make_two_names_different(self) -> None:
        settings = dataclasses.replace(
            ConfirmSettings.for_testing(),
            vault_session_key_name="postern-read ",
            vault_read_key_name="postern-read",
        )
        with pytest.raises(ValueError, match="POSTERN_VAULT_READ_KEY_NAME"):
            check_session_token_settings(settings)

    def test_from_env_strips_the_three_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var, value in (
            ("POSTERN_VAULT_READ_KEY_NAME", " r "),
            ("POSTERN_VAULT_WRITE_KEY_NAME", " w "),
            ("POSTERN_VAULT_SESSION_KEY_NAME", " s "),
        ):
            monkeypatch.setenv(var, value)
        settings = ConfirmSettings.from_env()
        assert (
            settings.vault_read_key_name,
            settings.vault_write_key_name,
            settings.vault_session_key_name,
        ) == ("r", "w", "s")

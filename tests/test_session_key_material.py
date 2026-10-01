"""The session key is refused when it shares key MATERIAL with the write key.

``_refuse_shared_session_key`` compares names, kids and PEM paths, which a copied
file, a hardlink or a case-different path on a case-insensitive filesystem all
pass. ``refuse_shared_key_material`` compares the PUBLIC keys each source
publishes, by RFC 7638 thumbprint, so it also covers a Vault transit key, whose
public half arrives over the network and has no path at all.

Since the layer-1 session token this service holds no read key, so the write
key is the only one there is to compare against.
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
        _pem(tmp_path / "write.pem")
        (tmp_path / "session.pem").write_bytes((tmp_path / "write.pem").read_bytes())
        with pytest.raises(ValueError) as raised:
            _app(
                key_pair,
                write_key_pem_path=str(tmp_path / "write.pem"),
                session_key_pem_path=str(tmp_path / "session.pem"),
            )
        message = str(raised.value)
        assert "POSTERN_SESSION_KEY_PEM_PATH" in message
        assert "POSTERN_WRITE_KEY_PEM_PATH" in message
        assert "MATERIAL" in message
        assert "PRIVATE" not in message
        # This service holds no read key, so the refusal names none.
        assert "read" not in message.lower()

    def test_a_hardlink_is_refused(self, key_pair: RSAKeyPair, tmp_path: Path) -> None:
        _pem(tmp_path / "write.pem")
        os.link(tmp_path / "write.pem", tmp_path / "session.pem")
        with pytest.raises(ValueError, match="POSTERN_WRITE_KEY_PEM_PATH"):
            _app(
                key_pair,
                write_key_pem_path=str(tmp_path / "write.pem"),
                session_key_pem_path=str(tmp_path / "session.pem"),
            )

    def test_a_case_different_path_is_refused_by_the_key_material(
        self, key_pair: RSAKeyPair, tmp_path: Path
    ) -> None:
        """Honest on both kinds of filesystem, and never skipped.

        CASE-INSENSITIVE (macOS's default APFS, Windows): ``WRITE.pem`` names
        the file written as ``write.pem``, so the session path is a different
        string for the SAME file. The path comparison in
        ``check_session_token_settings`` resolves paths but does not fold
        case, so it passes; what refuses is the key-material check.

        CASE-SENSITIVE (Linux ext4, the CI image): ``WRITE.pem`` does not exist
        until written, so it is written as a COPY with a case-different name,
        and the same key-material check is what refuses it. The assertion is
        the same on both: the message is the material one, not the path one.
        """
        _pem(tmp_path / "write.pem")
        other_case = tmp_path / "WRITE.pem"
        case_insensitive = other_case.exists()
        if not case_insensitive:
            other_case.write_bytes((tmp_path / "write.pem").read_bytes())
        assert str(other_case) != str(tmp_path / "write.pem")
        assert other_case.samefile(tmp_path / "write.pem") is case_insensitive
        with pytest.raises(ValueError) as raised:
            _app(
                key_pair,
                write_key_pem_path=str(tmp_path / "write.pem"),
                session_key_pem_path=str(other_case),
            )
        message = str(raised.value)
        assert "MATERIAL" in message
        assert "POSTERN_SESSION_KEY_PEM_PATH" in message
        assert "POSTERN_WRITE_KEY_PEM_PATH" in message

    def test_two_different_keys_start(self, key_pair: RSAKeyPair, tmp_path: Path) -> None:
        for name in ("write", "session"):
            _pem(tmp_path / f"{name}.pem")
        app = _app(
            key_pair,
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
            shared.as_pem(private=True), parameters={"kid": "postern-write-v3"}
        )
        with pytest.raises(ValueError) as raised:
            refuse_shared_key_material(
                session=_Source(shared),
                others=[
                    ("POSTERN_VAULT_WRITE_KEY_NAME", _Source(RSAKey.generate_key(2048), other))
                ],
                session_variable="POSTERN_VAULT_SESSION_KEY_NAME",
            )
        assert "POSTERN_VAULT_SESSION_KEY_NAME" in str(raised.value)
        assert "POSTERN_VAULT_WRITE_KEY_NAME" in str(raised.value)
        assert "MATERIAL" in str(raised.value)

    def test_disjoint_sets_pass(self) -> None:
        refuse_shared_key_material(
            session=_Source(RSAKey.generate_key(2048)),
            others=[("POSTERN_VAULT_WRITE_KEY_NAME", _Source(RSAKey.generate_key(2048)))],
            session_variable="POSTERN_VAULT_SESSION_KEY_NAME",
        )

    def test_a_thumbprint_ignores_kid_and_private_parts(self) -> None:
        key = RSAKey.generate_key(2048, parameters={"kid": "a"})
        again = RSAKey.import_key(key.as_pem(private=True), parameters={"kid": "b"})
        assert jwk_thumbprints(KeySet([key]).as_dict()) == jwk_thumbprints(
            KeySet([again]).as_dict()
        )

    def test_the_thumbprint_lives_in_the_shared_library(self) -> None:
        """Moved on 2 October 2026 so ``services/api`` can use it too, which
        ``.importlinter`` forbids it from importing out of this service."""
        from postern_core.auth import jwk_thumbprint

        from services.confirm import session_token

        assert session_token.jwk_thumbprints is jwk_thumbprint.jwk_thumbprints
        assert session_token.THUMBPRINT_MEMBERS is jwk_thumbprint.THUMBPRINT_MEMBERS


class TestNonRsaKeys:
    """RFC 7638 section 3.2's required members per ``kty``; anything else is skipped."""

    EC = {
        "kty": "EC",
        "crv": "P-256",
        "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "kid": "ec-1",
    }
    OKP = {"kty": "OKP", "crv": "Ed25519", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}

    def test_ec_and_okp_keys_are_thumbprinted_on_their_required_members(self) -> None:
        ec_again = {**self.EC, "kid": "another", "use": "sig", "d": "private"}
        assert jwk_thumbprints({"keys": [self.EC]}) == jwk_thumbprints({"keys": [ec_again]})
        assert len(jwk_thumbprints({"keys": [self.EC, self.OKP]})) == 2

    def test_the_rfc_7638_example_thumbprint(self) -> None:
        """RFC 7638 section 3.1's RSA example, whose thumbprint the RFC prints."""
        n = (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECP"
            "ebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Qvz"
            "qY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu"
            "0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
        )
        assert jwk_thumbprints({"keys": [{"kty": "RSA", "e": "AQAB", "n": n}]}) == {
            "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
        }

    def test_an_unknown_kty_or_a_missing_member_is_skipped(self) -> None:
        assert (
            jwk_thumbprints(
                {
                    "keys": [
                        {"kty": "oct", "k": "c2VjcmV0"},
                        {"kty": "PQC", "pub": "x"},
                        {"x": "no kty"},
                        {"kty": "EC", "crv": "P-256", "x": "only x"},
                        {"kty": "RSA", "n": "no e"},
                    ]
                }
            )
            == set()
        )

    def test_a_session_source_beside_an_ec_key_still_compares(self) -> None:
        shared = RSAKey.generate_key(2048)

        class _Mixed:
            def public_jwks(self) -> Any:
                return {"keys": [TestNonRsaKeys.EC, shared.as_dict(private=False)]}

        with pytest.raises(ValueError, match="MATERIAL"):
            refuse_shared_key_material(
                session=_Source(shared),
                others=[("POSTERN_WRITE_KEY_PEM_PATH", _Mixed())],
                session_variable="POSTERN_SESSION_KEY_PEM_PATH",
            )


class TestASessionKeyWithNoThumbprint:
    """An empty ``mine`` would pass every overlap vacuously: refused instead."""

    class _Publishes:
        def __init__(self, jwks: Any) -> None:
            self._jwks = jwks

        def public_jwks(self) -> Any:
            return self._jwks

    @pytest.mark.parametrize(
        "jwks",
        [{"keys": [{"kty": "oct", "k": "c2VjcmV0"}]}, {"keys": []}, {}],
        ids=["oct only", "no keys", "no keys member"],
    )
    def test_it_is_refused_at_startup(self, jwks: Any) -> None:
        with pytest.raises(ValueError) as raised:
            refuse_shared_key_material(
                session=self._Publishes(jwks),
                others=[("POSTERN_WRITE_KEY_PEM_PATH", _Source(RSAKey.generate_key(2048)))],
                session_variable="POSTERN_SESSION_KEY_PEM_PATH",
            )
        message = str(raised.value)
        assert "POSTERN_SESSION_KEY_PEM_PATH" in message
        assert "could not be fingerprinted" in message
        assert "read" not in message.lower()

    def test_it_is_refused_even_with_nothing_to_compare_against(self) -> None:
        with pytest.raises(ValueError, match="could not be fingerprinted"):
            refuse_shared_key_material(
                session=self._Publishes({"keys": []}),
                others=[],
                session_variable="POSTERN_VAULT_SESSION_KEY_NAME",
            )


class TestVaultKeyNamesAreStripped:
    def test_a_trailing_space_does_not_make_two_names_different(self) -> None:
        settings = dataclasses.replace(
            ConfirmSettings.for_testing(),
            vault_session_key_name="postern-write ",
            vault_write_key_name="postern-write",
        )
        with pytest.raises(ValueError, match="POSTERN_VAULT_WRITE_KEY_NAME"):
            check_session_token_settings(settings)

    def test_from_env_strips_the_two_names(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for var, value in (
            ("POSTERN_VAULT_WRITE_KEY_NAME", " w "),
            ("POSTERN_VAULT_SESSION_KEY_NAME", " s "),
        ):
            monkeypatch.setenv(var, value)
        settings = ConfirmSettings.from_env()
        assert (settings.vault_write_key_name, settings.vault_session_key_name) == ("w", "s")

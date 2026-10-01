"""``create_confirm_app`` refuses a device grant it could not run safely.

Spec sections 2 and 4 of ``dev-docs/device-grant-session-token-spec.md``: no
shared Redis and no development flag refuses to start; the flag starts and
warns; and the issuer and audience refusals of
``check_session_token_settings`` fire at startup, where a deployment would
meet them, for a settings object built by hand as much as for one read from
the environment.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices

from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.test_device_grant import AUDIENCE, ISSUER


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture(autouse=True)
def _no_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)
    monkeypatch.delenv("POSTERN_REQUIRE_REDIS", raising=False)


def _confirm(key_pair: RSAKeyPair, **overrides: Any) -> Any:
    return create_confirm_app(
        dataclasses.replace(ConfirmSettings.for_testing(), **overrides),
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


class TestSharedStateIsRequired:
    def test_no_redis_and_no_flag_refuses_naming_both_ways_out(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(RuntimeError) as raised:
            _confirm(key_pair, allow_process_local_sessions=False)
        message = str(raised.value)
        assert "POSTERN_REDIS_URL" in message
        assert "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS" in message

    @pytest.mark.parametrize("blank", ["", " ", " \t\n"])
    def test_a_blank_url_counts_as_absent(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch, blank: str
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", blank)
        with pytest.raises(RuntimeError, match="POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS"):
            _confirm(key_pair, allow_process_local_sessions=False)

    @pytest.mark.parametrize("blank", ["", " "])
    def test_a_blank_url_does_not_satisfy_the_require_redis_guard(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch, blank: str
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", blank)
        monkeypatch.setenv("POSTERN_REQUIRE_REDIS", "1")
        with pytest.raises(RuntimeError, match="POSTERN_REQUIRE_REDIS is set"):
            _confirm(key_pair, allow_process_local_sessions=True)

    def test_the_flag_starts_and_warns(
        self, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="services.confirm.main"):
            assert _confirm(key_pair, allow_process_local_sessions=True) is not None
        assert "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS is set" in caplog.text
        warnings = [r for r in caplog.records if "ALLOW_PROCESS_LOCAL_SESSIONS is set" in r.message]
        assert len(warnings) == 1

    def test_a_redis_url_starts_without_the_flag_and_without_the_warning(
        self,
        key_pair: RSAKeyPair,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "redis://127.0.0.1:6379/0")
        with caplog.at_level(logging.WARNING, logger="services.confirm.main"):
            assert _confirm(key_pair, allow_process_local_sessions=False) is not None
        assert "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS" not in caplog.text


class TestTheSessionSettingsAreCheckedAtStartup:
    def test_a_non_uri_audience_without_the_flag_refuses(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(ValueError, match="POSTERN_SESSION_TOKEN_AUDIENCE"):
            _confirm(key_pair, allow_non_uri_audience=False)

    def test_a_uri_audience_starts_without_the_flag(self, key_pair: RSAKeyPair) -> None:
        app = _confirm(
            key_pair,
            allow_non_uri_audience=False,
            session_token_audience="https://mcp.postern.internal/mcp",  # noqa: S106
        )
        assert app is not None

    def test_an_issuer_shared_with_the_write_token_refuses(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(ValueError, match="POSTERN_WRITE_TOKEN_ISSUER"):
            _confirm(key_pair, session_token_issuer="https://mcp-write.internal")  # noqa: S106

    def test_an_issuer_shared_with_the_app_assertion_refuses(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(ValueError, match="POSTERN_APP_ASSERTION_ISSUER"):
            _confirm(
                key_pair,
                app_assertion_issuer="https://app.shared.invalid",
                session_token_issuer="https://app.shared.invalid",  # noqa: S106
            )

    def test_an_audience_shared_with_the_app_assertion_refuses(self, key_pair: RSAKeyPair) -> None:
        with pytest.raises(ValueError, match="POSTERN_APP_ASSERTION_AUDIENCE"):
            _confirm(key_pair, session_token_audience=AUDIENCE)  # noqa: S106

    def test_a_hand_built_settings_object_is_refused_twice_over(self, key_pair: RSAKeyPair) -> None:
        """The dataclass defaults are the safe values: no Redis URL and a
        non-URI audience both refuse, and the Redis refusal is heard first."""
        settings = ConfirmSettings(
            app_assertion_jwks_uri="https://app.test.invalid/.well-known/jwks.json",
            app_assertion_issuer=ISSUER,
            app_assertion_audience=AUDIENCE,
        )
        with pytest.raises(RuntimeError, match="POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS"):
            create_confirm_app(
                settings,
                assertion_verifier=JWTVerifier(
                    public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
                ),
                device_key_store=no_enrolled_devices(),
            )
        with pytest.raises(ValueError, match="POSTERN_SESSION_TOKEN_AUDIENCE"):
            create_confirm_app(
                dataclasses.replace(settings, allow_process_local_sessions=True),
                assertion_verifier=JWTVerifier(
                    public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
                ),
                device_key_store=no_enrolled_devices(),
            )


class TestTheSessionKeyIsKeptSeparateByRefusal:
    """Key separation must not depend on configuration being right."""

    @pytest.mark.parametrize(
        ("session_field", "other_field", "session_var", "other_var"),
        [
            (
                "vault_session_key_name",
                "vault_read_key_name",
                "POSTERN_VAULT_SESSION_KEY_NAME",
                "POSTERN_VAULT_READ_KEY_NAME",
            ),
            (
                "vault_session_key_name",
                "vault_write_key_name",
                "POSTERN_VAULT_SESSION_KEY_NAME",
                "POSTERN_VAULT_WRITE_KEY_NAME",
            ),
            (
                "session_key_kid",
                "read_key_kid",
                "POSTERN_SESSION_KEY_KID",
                "POSTERN_READ_KEY_KID",
            ),
            (
                "session_key_kid",
                "write_key_kid",
                "POSTERN_SESSION_KEY_KID",
                "POSTERN_WRITE_KEY_KID",
            ),
        ],
    )
    def test_a_shared_name_or_kid_refuses_naming_both_variables(
        self,
        key_pair: RSAKeyPair,
        session_field: str,
        other_field: str,
        session_var: str,
        other_var: str,
    ) -> None:
        shared = "shared-key"
        with pytest.raises(ValueError) as raised:
            _confirm(key_pair, **{session_field: shared, other_field: shared})
        assert session_var in str(raised.value)
        assert other_var in str(raised.value)

    @pytest.mark.parametrize(
        ("other_field", "other_var"),
        [
            ("read_key_pem_path", "POSTERN_READ_KEY_PEM_PATH"),
            ("write_key_pem_path", "POSTERN_WRITE_KEY_PEM_PATH"),
        ],
    )
    def test_a_shared_pem_path_refuses_even_spelled_differently(
        self, key_pair: RSAKeyPair, other_field: str, other_var: str
    ) -> None:
        with pytest.raises(ValueError) as raised:
            _confirm(
                key_pair,
                session_key_pem_path="/run/keys/./a/../key.pem",
                **{other_field: "/run/keys/key.pem"},
            )
        assert "POSTERN_SESSION_KEY_PEM_PATH" in str(raised.value)
        assert other_var in str(raised.value)

    def test_unset_paths_never_collide(self, key_pair: RSAKeyPair) -> None:
        app = _confirm(
            key_pair,
            session_key_pem_path=None,
            read_key_pem_path=None,
            write_key_pem_path=None,
        )
        assert app is not None

    def test_distinct_names_paths_and_kids_pass_the_check(self) -> None:
        """Unit level: starting an app would try to load the three PEM files."""
        from services.confirm.settings import check_session_token_settings

        settings = dataclasses.replace(
            ConfirmSettings.for_testing(),
            session_key_pem_path="/run/keys/session.pem",
            read_key_pem_path="/run/keys/read.pem",
            write_key_pem_path="/run/keys/write.pem",
        )
        check_session_token_settings(settings)

    def test_the_check_itself_refuses_without_an_app(self) -> None:
        from services.confirm.settings import check_session_token_settings

        settings = dataclasses.replace(
            ConfirmSettings.for_testing(), vault_session_key_name="postern-read"
        )
        with pytest.raises(ValueError, match="POSTERN_VAULT_READ_KEY_NAME"):
            check_session_token_settings(settings)

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

    def test_an_empty_url_counts_as_absent(
        self, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("POSTERN_REDIS_URL", "")
        with pytest.raises(RuntimeError):
            _confirm(key_pair, allow_process_local_sessions=False)

    def test_the_flag_starts_and_warns(
        self, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="services.confirm.main"):
            assert _confirm(key_pair, allow_process_local_sessions=True) is not None
        assert "POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS is set" in caplog.text

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

"""The session-token settings and the startup refusals of spec section 2.

`services/confirm/settings.py`'s ``check_session_token_settings`` is pure over
a settings object, so each refusal is driven here without building an app;
`create_confirm_app` calling it is pinned where the app is built.
"""

from __future__ import annotations

import logging
from dataclasses import replace

import pytest

from services.confirm.settings import ConfirmSettings, check_session_token_settings

URI_AUDIENCE = "https://mcp.postern.internal/mcp"


def _deployable(**overrides: object) -> ConfirmSettings:
    """Settings a deployment could run: a URI audience and no development flag."""
    base = replace(
        ConfirmSettings.for_testing(),
        session_token_audience=URI_AUDIENCE,
        allow_non_uri_audience=False,
        allow_process_local_sessions=False,
    )
    return replace(base, **overrides)  # type: ignore[arg-type]


def test_the_field_defaults_are_the_safe_values() -> None:
    settings = ConfirmSettings()
    assert settings.session_key_pem_path is None
    assert settings.session_key_kid == "session-1"
    assert settings.vault_session_key_name == "postern-session"
    assert settings.session_token_issuer == "https://auth.postern.internal"  # noqa: S105
    assert settings.session_token_audience == "postern"  # noqa: S105
    assert settings.allow_non_uri_audience is False
    assert settings.allow_process_local_sessions is False
    assert settings.max_refresh_sessions == 40_000
    assert settings.rate_limit_session_jwks == 300


def test_for_testing_sets_both_development_flags() -> None:
    settings = ConfirmSettings.for_testing()
    assert settings.allow_non_uri_audience is True
    assert settings.allow_process_local_sessions is True


def test_from_env_reads_every_session_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POSTERN_SESSION_KEY_PEM_PATH", "/run/secrets/session.pem")
    monkeypatch.setenv("POSTERN_SESSION_KEY_KID", "session-7")
    monkeypatch.setenv("POSTERN_VAULT_SESSION_KEY_NAME", "bank-session")
    monkeypatch.setenv("POSTERN_SESSION_TOKEN_ISSUER", "https://auth.bank.example")
    monkeypatch.setenv("POSTERN_SESSION_TOKEN_AUDIENCE", "https://mcp.bank.example/mcp")
    monkeypatch.setenv("POSTERN_ALLOW_NON_URI_AUDIENCE", "true")
    monkeypatch.setenv("POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS", "1")
    monkeypatch.setenv("POSTERN_MAX_REFRESH_SESSIONS", "12")
    monkeypatch.setenv("POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS", "30")
    settings = ConfirmSettings.from_env()
    assert settings.session_key_pem_path == "/run/secrets/session.pem"
    assert settings.session_key_kid == "session-7"
    assert settings.vault_session_key_name == "bank-session"
    assert settings.session_token_issuer == "https://auth.bank.example"  # noqa: S105
    assert settings.session_token_audience == "https://mcp.bank.example/mcp"  # noqa: S105
    assert settings.allow_non_uri_audience is True
    assert settings.allow_process_local_sessions is True
    assert settings.max_refresh_sessions == 12
    assert settings.rate_limit_session_jwks == 30


def test_a_deployable_configuration_passes() -> None:
    check_session_token_settings(_deployable())


@pytest.mark.parametrize(
    "issuer",
    [
        "http://auth.bank.example",
        "https://",
        "auth.bank.example",
        "https://auth.bank.example?x=1",
        "https://auth.bank.example#x",
        "https://auth.bank.\u212aey.example",
        "https://auth.bank.exa\tmple",
        "https://auth.bank.example\n",
        " https://auth.bank.example",
        "https://auth.bank.example ",
        "https://auth.bank.example\x00",
        "https://auth.bank.example\\x",
    ],
)
def test_an_issuer_that_is_not_an_https_url_is_refused(issuer: str) -> None:
    with pytest.raises(ValueError, match="POSTERN_SESSION_TOKEN_ISSUER") as raised:
        check_session_token_settings(_deployable(session_token_issuer=issuer))
    assert repr(issuer) in str(raised.value)


def test_an_issuer_shared_with_the_write_token_is_refused() -> None:
    settings = _deployable(session_token_issuer="https://mcp-write.internal")  # noqa: S106
    with pytest.raises(ValueError, match="POSTERN_WRITE_TOKEN_ISSUER"):
        check_session_token_settings(settings)


def test_an_issuer_shared_with_the_app_assertion_is_refused() -> None:
    settings = _deployable(session_token_issuer="https://app.postern-local-dev.invalid")  # noqa: S106
    with pytest.raises(ValueError, match="POSTERN_APP_ASSERTION_ISSUER"):
        check_session_token_settings(settings)


@pytest.mark.parametrize(
    "audience",
    [
        "postern",
        "https://mcp.postern.internal",
        "HTTPS://mcp.postern.internal/mcp",
        "https://MCP.postern.internal/mcp",
        "https://mcp.postern.internal:443/mcp",
        "https://mcp.postern.internal/mcp#x",
        "http://mcp.postern.internal/mcp",
    ],
)
def test_an_audience_not_in_normal_form_is_refused_without_the_flag(audience: str) -> None:
    with pytest.raises(ValueError, match="POSTERN_SESSION_TOKEN_AUDIENCE") as raised:
        check_session_token_settings(_deployable(session_token_audience=audience))
    assert "POSTERN_ALLOW_NON_URI_AUDIENCE" in str(raised.value)


def test_the_flag_admits_a_non_uri_audience_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    settings = _deployable(session_token_audience="postern", allow_non_uri_audience=True)  # noqa: S106
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        check_session_token_settings(settings)
    assert "POSTERN_ALLOW_NON_URI_AUDIENCE" in caplog.text


def test_the_flag_does_not_warn_for_a_uri_audience(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        check_session_token_settings(_deployable(allow_non_uri_audience=True))
    assert caplog.text == ""


def test_an_audience_shared_with_the_app_assertion_is_refused() -> None:
    settings = _deployable(app_assertion_audience=URI_AUDIENCE)
    with pytest.raises(ValueError, match="POSTERN_APP_ASSERTION_AUDIENCE"):
        check_session_token_settings(settings)

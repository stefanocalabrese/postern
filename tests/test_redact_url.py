"""``redact_url``, and the one log line that used to print a Redis password.

``create_device_code_store`` logged ``POSTERN_REDIS_URL`` verbatim at INFO.
Until the compose stack gave Redis per-service ACL users the URL carried no
credential, so the line was harmless; with ``rediss://user:password@host`` it
wrote the password to the log of every process start.
"""

from __future__ import annotations

import logging

import pytest
from postern_core.auth.device_codes import RedisDeviceCodeStore, create_device_code_store
from postern_core.config import UNPARSEABLE_URL, redact_url


class TestRedactUrl:
    def test_password_is_replaced_and_everything_else_is_kept(self) -> None:
        url = "rediss://postern_api:s3cret@redis:6379/0?ssl_ca_certs=/x&ssl_check_hostname=true"
        assert redact_url(url) == (
            "rediss://postern_api:***@redis:6379/0?ssl_ca_certs=/x&ssl_check_hostname=true"
        )

    def test_no_password_is_unchanged(self) -> None:
        assert redact_url("redis://redis:6379/0") == "redis://redis:6379/0"
        assert redact_url("redis://user@redis:6379/0") == "redis://user@redis:6379/0"

    def test_password_with_special_characters(self) -> None:
        out = redact_url("redis://u:p%40ss@host:6379/0")
        assert "p%40ss" not in out
        assert out == "redis://u:***@host:6379/0"

    def test_empty_username_with_password(self) -> None:
        out = redact_url("redis://:s3cret@host:6379/0")
        assert "s3cret" not in out
        assert "host:6379" in out

    def test_ipv6_host_keeps_its_brackets(self) -> None:
        out = redact_url("rediss://u:s3cret@[::1]:6379/0")
        assert out == "rediss://u:***@[::1]:6379/0"

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "   ",
            "user:s3cret@host:6379/0",
            "rediss://u:s3cret@[::1:6379/0",
            "://",
            "\x00",
            "s3cret",
        ],
    )
    def test_malformed_input_gets_the_placeholder_and_is_never_echoed(self, bad: str) -> None:
        assert redact_url(bad) == UNPARSEABLE_URL

    def test_non_string_is_not_echoed(self) -> None:
        assert redact_url(None) == UNPARSEABLE_URL  # type: ignore[arg-type]


async def test_create_device_code_store_does_not_log_the_password(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(
        "POSTERN_REDIS_URL", "rediss://postern_confirm:s3cret@redis-host:6379/0?ssl_ca_certs=/x"
    )
    with caplog.at_level(logging.INFO):
        store = create_device_code_store()
    assert isinstance(store, RedisDeviceCodeStore)
    assert "s3cret" not in caplog.text
    assert "redis-host" in caplog.text
    assert "postern_confirm" in caplog.text
    await store.close()

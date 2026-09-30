"""``POSTERN_DEVICE_APP_LINK_URI``: the base the pairing QR encodes.

Section 3 of ``dev-docs/qr-page-spec.md``. The page and the app link are two
URIs, and the app link's host must not be the page's: a phone camera handed a
URL on the page's host opens the browser page instead of the bank app, so the
pairing could never reach ``POST /scan``. ``ConfirmSettings.from_env`` refuses
that configuration at startup.
"""

from __future__ import annotations

import pytest
from postern_core.env_inventory import INVENTORY

from services.confirm.settings import ConfirmSettings

PAGE = "POSTERN_DEVICE_VERIFICATION_URI"
LINK = "POSTERN_DEVICE_APP_LINK_URI"
DEFAULT_LINK = "https://app.postern.internal/pair"


@pytest.fixture(autouse=True)
def _unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PAGE, raising=False)
    monkeypatch.delenv(LINK, raising=False)


def test_the_field_default_is_the_local_placeholder() -> None:
    assert ConfirmSettings().device_app_link_uri == DEFAULT_LINK


def test_from_env_takes_the_same_default() -> None:
    assert ConfirmSettings.from_env().device_app_link_uri == DEFAULT_LINK


def test_from_env_reads_the_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(LINK, "https://pair.bank.test/app")
    assert ConfirmSettings.from_env().device_app_link_uri == "https://pair.bank.test/app"


def test_the_variable_is_inventoried_as_a_confirm_string() -> None:
    rows = [entry for entry in INVENTORY if entry.name == LINK]
    assert len(rows) == 1
    assert rows[0].kind == "string"
    assert rows[0].services == ("confirm",)


@pytest.mark.parametrize(
    ("page", "link"),
    [
        pytest.param("https://auth.bank.test/verify", "https://auth.bank.test/pair", id="same"),
        pytest.param(
            "https://auth.bank.test/verify", "https://AUTH.Bank.Test/pair", id="case only"
        ),
        pytest.param(
            "https://auth.bank.test/verify", "https://auth.bank.test:8443/pair", id="port only"
        ),
    ],
)
def test_a_shared_host_refuses_to_start(
    monkeypatch: pytest.MonkeyPatch, page: str, link: str
) -> None:
    monkeypatch.setenv(PAGE, page)
    monkeypatch.setenv(LINK, link)
    with pytest.raises(ValueError, match=LINK) as refused:
        ConfirmSettings.from_env()
    assert PAGE in str(refused.value)


def test_a_page_moved_onto_the_default_app_link_host_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Either variable can be the one that collides."""
    monkeypatch.setenv(PAGE, "https://app.postern.internal/verify")
    with pytest.raises(ValueError, match=LINK):
        ConfirmSettings.from_env()


def test_two_different_hosts_start(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(PAGE, "https://auth.bank.test/verify")
    monkeypatch.setenv(LINK, "https://app.bank.test/pair")
    settings = ConfirmSettings.from_env()
    assert settings.device_verification_uri == "https://auth.bank.test/verify"
    assert settings.device_app_link_uri == "https://app.bank.test/pair"

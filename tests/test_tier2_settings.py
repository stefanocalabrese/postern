"""``POSTERN_CONFIRM_IDV_VALUE``: the value a tier-2 approval's ``idv`` claim must equal.

Spec docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md,
section 10, and decision record 0023. Unset is a legitimate state that refuses
every tier-2 approval and warns once at startup; a set value is 1 to 128
characters of printable ASCII, refused otherwise both from the environment and
when built in code.
"""

import dataclasses
import logging

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices

from services.confirm.main import create_confirm_app
from services.confirm.settings import (
    MAX_VISIBLE_ASCII_LENGTH,
    ConfirmSettings,
    is_visible_ascii,
    warn_if_idv_value_unset,
)

VARIABLE = "POSTERN_CONFIRM_IDV_VALUE"

#: Each is refused at construction. The last one carries a space, so it is
#: also the value the "never echoed" test looks for in the message.
REFUSED = [
    pytest.param("", id="empty"),
    pytest.param(" ", id="a-space"),
    pytest.param("idv value", id="an-inner-space"),
    pytest.param("idv\tvalue", id="a-tab"),
    pytest.param("idv\x00value", id="a-nul"),
    pytest.param("idv\x7fvalue", id="del"),
    pytest.param("idv\x1bvalue", id="a-control-character"),
    pytest.param("idv-é", id="non-ascii"),
    pytest.param("x" * (MAX_VISIBLE_ASCII_LENGTH + 1), id="129-characters"),
    pytest.param("SENTINEL VALUE", id="sentinel"),
]


def test_the_field_defaults_to_unset() -> None:
    assert ConfirmSettings().idv_value is None
    assert ConfirmSettings.for_testing().idv_value is None


@pytest.mark.parametrize("value", REFUSED)
def test_a_value_built_in_code_is_refused_naming_the_variable(value: str) -> None:
    with pytest.raises(ValueError) as raised:
        ConfirmSettings(idv_value=value)
    message = str(raised.value)
    assert VARIABLE in message
    assert "SENTINEL" not in message


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("!", id="one-character"),
        pytest.param("~", id="the-top-of-the-range"),
        pytest.param("postern-dev-idv", id="ordinary"),
        pytest.param("x" * MAX_VISIBLE_ASCII_LENGTH, id="128-characters"),
    ],
)
def test_a_usable_value_is_stored_exactly_as_given(value: str) -> None:
    assert ConfirmSettings(idv_value=value).idv_value == value


def test_the_class_is_1_to_128_characters_from_0x21_to_0x7e() -> None:
    assert MAX_VISIBLE_ASCII_LENGTH == 128
    assert is_visible_ascii("".join(chr(code) for code in range(0x21, 0x7F)))
    assert not is_visible_ascii("")
    assert not is_visible_ascii("\x20")
    assert not is_visible_ascii("\x7f")
    assert is_visible_ascii("j" * 128)
    assert not is_visible_ascii("j" * 129)


def test_unset_in_the_environment_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(VARIABLE, raising=False)
    assert ConfirmSettings.from_env().idv_value is None


def test_empty_in_the_environment_is_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(VARIABLE, "")
    assert ConfirmSettings.from_env().idv_value is None


def test_a_value_in_the_environment_is_read_exactly(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(VARIABLE, "Postern-Dev-IDV")
    assert ConfirmSettings.from_env().idv_value == "Postern-Dev-IDV"


@pytest.mark.parametrize("value", [" ", "idv value", " idv", "idv\tvalue", "idv\x1bvalue"])
def test_a_value_in_the_environment_is_refused_naming_the_variable(
    value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(VARIABLE, value)
    with pytest.raises(ValueError, match=VARIABLE):
        ConfirmSettings.from_env()


def test_unset_warns_once(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        warn_if_idv_value_unset(ConfirmSettings())
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert VARIABLE in record.getMessage()
    assert "tier-2" in record.getMessage()


def test_set_does_not_warn(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        warn_if_idv_value_unset(ConfirmSettings(idv_value="postern-dev-idv"))
    assert caplog.records == []


@pytest.mark.parametrize(("idv_value", "warnings"), [(None, 1), ("postern-dev-idv", 0)])
def test_the_composition_root_warns_exactly_when_unset(
    idv_value: str | None, warnings: int, caplog: pytest.LogCaptureFixture
) -> None:
    key_pair = RSAKeyPair.generate()
    settings = dataclasses.replace(ConfirmSettings.for_testing(), idv_value=idv_value)
    with caplog.at_level(logging.WARNING, logger="services.confirm.settings"):
        create_confirm_app(
            settings,
            assertion_verifier=JWTVerifier(
                public_key=key_pair.public_key,
                issuer="https://app.test.invalid",
                audience="postern-confirm",
            ),
            device_key_store=no_enrolled_devices(),
        )
    found = [r for r in caplog.records if VARIABLE in r.getMessage()]
    assert len(found) == warnings

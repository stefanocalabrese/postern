"""The rotation token the pairing QR carries, checked in isolation.

``services/confirm/qr_token.py`` is pure: a secret, a pairing code and a clock
slot in, a string or a verdict out. So every property section 2 of
``dev-docs/qr-page-spec.md`` states is checked here without an app, a store or
a real clock.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

import pytest

from services.confirm.qr_token import (
    MAC_BYTES,
    SLOT_SECONDS,
    SLOTS_BACK,
    SLOTS_FORWARD,
    USER_CODE_BYTES,
    QrVerdict,
    mac_for,
    message_for,
    slot_at,
    token_for,
    verify_token,
)

SECRET = bytes(range(32))
USER_CODE = "ABC234"
NOW = 1_000_000


def test_the_constants_are_the_specs() -> None:
    assert SLOT_SECONDS == 2
    assert SLOTS_BACK == 5
    assert SLOTS_FORWARD == 1
    assert MAC_BYTES == 16
    assert USER_CODE_BYTES == 6


@pytest.mark.parametrize(
    ("unix_time", "slot"),
    [
        (0.0, 0),
        (1.999, 0),
        (2.0, 1),
        (3.5, 1),
        (4.0, 2),
        (1_790_000_001.0, 895_000_000),
    ],
)
def test_a_slot_is_two_seconds_wide(unix_time: float, slot: int) -> None:
    assert slot_at(unix_time) == slot


def test_the_message_is_six_code_bytes_then_eight_slot_bytes() -> None:
    assert message_for(USER_CODE, 0) == b"ABC234" + bytes(8)
    assert message_for(USER_CODE, 1) == b"ABC234" + (1).to_bytes(8, "big")
    assert len(message_for(USER_CODE, 2**63 - 1)) == 14


def test_no_two_pairs_share_an_encoding() -> None:
    """Fixed width is what rules out ``("ABC234", 15)`` colliding with a
    neighbouring code and slot whose concatenated digits read the same."""
    seen = {message_for(code, slot) for code in ("ABC234", "ABC235") for slot in (1, 15, 151)}
    assert len(seen) == 6


@pytest.mark.parametrize("user_code", ["ABC23", "ABC2345", "ÄBC234", ""])
def test_a_user_code_that_is_not_six_ascii_bytes_is_refused(user_code: str) -> None:
    with pytest.raises(ValueError):
        message_for(user_code, 1)


def test_the_mac_is_truncated_hmac_sha256_in_unpadded_base64url() -> None:
    digest = hmac.new(SECRET, b"ABC234" + (7).to_bytes(8, "big"), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode("ascii")
    assert mac_for(SECRET, USER_CODE, 7) == expected
    assert len(mac_for(SECRET, USER_CODE, 7)) == 22


def test_a_token_is_the_slot_a_dot_and_the_mac() -> None:
    assert token_for(SECRET, USER_CODE, 7) == f"7.{mac_for(SECRET, USER_CODE, 7)}"


@pytest.mark.parametrize("slot", [NOW - 5, NOW - 1, NOW, NOW + 1])
def test_every_slot_inside_the_window_is_valid(slot: int) -> None:
    token = token_for(SECRET, USER_CODE, slot)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.VALID


def test_one_slot_past_the_back_edge_is_stale() -> None:
    token = token_for(SECRET, USER_CODE, NOW - 6)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.STALE


@pytest.mark.parametrize("slot", [NOW + 2, NOW + 1_000])
def test_a_future_slot_is_invalid_and_not_stale(slot: int) -> None:
    token = token_for(SECRET, USER_CODE, slot)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


def test_a_tampered_mac_is_invalid() -> None:
    slot, mac = token_for(SECRET, USER_CODE, NOW).split(".")
    flipped = ("B" if mac[0] == "A" else "A") + mac[1:]
    assert verify_token(SECRET, USER_CODE, f"{slot}.{flipped}", NOW) is QrVerdict.INVALID


def test_a_mac_for_a_different_user_code_is_invalid() -> None:
    token = token_for(SECRET, "XYZ789", NOW)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


def test_a_mac_under_a_different_secret_is_invalid() -> None:
    token = token_for(secrets.token_bytes(32), USER_CODE, NOW)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


def test_an_old_slot_under_the_wrong_secret_is_invalid_not_stale() -> None:
    """``qr_stale`` is a distinct answer only for a MAC that verifies, so a
    forged token for an old slot must not reach it."""
    token = token_for(secrets.token_bytes(32), USER_CODE, NOW - 50)
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


@pytest.mark.parametrize(
    "token",
    [
        "",
        ".",
        "7",
        "7.",
        ".AAAAAAAAAAAAAAAAAAAAAA",
        "-1.AAAAAAAAAAAAAAAAAAAAAA",
        "x.AAAAAAAAAAAAAAAAAAAAAA",
        "7.AAAA",
        "7.AAAAAAAAAAAAAAAAAAAAAA==",
        "7.AAAAAAAAAAAAAAAAAAAAA$",
        "12345678901234567890.AAAAAAAAAAAAAAAAAAAAAA",
        "７.AAAAAAAAAAAAAAAAAAAAAA",
        "7.AAAAAAAAAAAAAAAAAAAAAA.7",
    ],
)
def test_a_malformed_token_is_invalid(token: str) -> None:
    assert verify_token(SECRET, USER_CODE, token, NOW) is QrVerdict.INVALID


def test_an_empty_secret_verifies_nothing() -> None:
    """A record serialized before this change has no secret, and must be
    unscannable rather than scannable with the empty key."""
    token = token_for(b"", USER_CODE, NOW)
    assert verify_token(b"", USER_CODE, token, NOW) is QrVerdict.INVALID


def test_a_stored_user_code_of_the_wrong_shape_is_invalid_not_an_exception() -> None:
    token = token_for(SECRET, USER_CODE, NOW)
    assert verify_token(SECRET, "ABC", token, NOW) is QrVerdict.INVALID


_B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def test_a_sibling_final_mac_character_is_invalid() -> None:
    """The last of 22 characters carries 2 significant bits; the other 4 are
    ignored by a decoder. Every spelling of the same 16 bytes but one must be
    refused, so a token has exactly one accepted text."""
    slot, mac = token_for(SECRET, USER_CODE, NOW).split(".")
    genuine = _B64URL.index(mac[-1])
    siblings = [c for i, c in enumerate(_B64URL) if i >> 4 == genuine >> 4 and i != genuine]
    assert len(siblings) == 15
    for sibling in siblings:
        forged = f"{slot}.{mac[:-1]}{sibling}"
        assert verify_token(SECRET, USER_CODE, forged, NOW) is QrVerdict.INVALID


@pytest.mark.parametrize("slot", [NOW, NOW - 1, 7])
def test_a_slot_with_a_leading_zero_is_invalid(slot: int) -> None:
    mac = mac_for(SECRET, USER_CODE, slot)
    assert verify_token(SECRET, USER_CODE, f"0{slot}.{mac}", NOW) is QrVerdict.INVALID
    assert verify_token(SECRET, USER_CODE, f"000{slot}.{mac}", NOW) is QrVerdict.INVALID


def test_a_slot_of_exactly_zero_still_parses() -> None:
    token = token_for(SECRET, USER_CODE, 0)
    assert token.startswith("0.")
    assert verify_token(SECRET, USER_CODE, token, 0) is QrVerdict.VALID
    assert verify_token(SECRET, USER_CODE, token, 100) is QrVerdict.STALE


def test_a_padded_zero_slot_is_invalid() -> None:
    mac = mac_for(SECRET, USER_CODE, 0)
    assert verify_token(SECRET, USER_CODE, f"00.{mac}", 0) is QrVerdict.INVALID

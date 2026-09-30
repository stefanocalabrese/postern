"""The device-code store's pairing half, on the in-memory backend.

The fields the QR page and ``POST /scan`` read, the two secondary lookups, and
the two compare-and-set writes that replaced ``update_device_code``. The Redis
backend's versions of the same properties are in
``tests/test_redis_backed_stores.py``, against the real container ``make ci``
already starts, because the two backends share a contract and no code.
"""

from __future__ import annotations

import base64
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.auth.device_codes import DeviceCode, InMemoryDeviceCodeStore

from services.confirm.qr_token import QrVerdict, token_for, verify_token

VERIFY_URI = "https://auth.test.invalid/verify"
URLSAFE = re.compile(r"[A-Za-z0-9_-]+")


async def _create(store: InMemoryDeviceCodeStore, **kwargs: Any) -> DeviceCode:
    return await store.create_device_code(
        client_id="vendor-a", scopes="accounts:read", verification_uri=VERIFY_URI, **kwargs
    )


def _bare(**overrides: Any) -> DeviceCode:
    fields: dict[str, Any] = {
        "device_code": "dc-bare",
        "user_code": "ABC234",
        "verification_uri": VERIFY_URI,
        "expires_at": datetime.now(UTC) + timedelta(minutes=15),
    }
    fields.update(overrides)
    return DeviceCode(**fields)


# ---------------------------------------------------------------------------
# The new fields.
# ---------------------------------------------------------------------------


class TestTheNewFields:
    async def test_a_new_code_carries_a_handle_a_secret_and_its_creator(self) -> None:
        code = await _create(InMemoryDeviceCodeStore(), creator_ip="203.0.113.9")

        assert len(code.display_handle) == 22
        assert URLSAFE.fullmatch(code.display_handle)
        assert len(code.qr_secret) == 32
        assert code.creator_ip == "203.0.113.9"
        assert code.scanned_by == ""
        assert code.scanned_at is None

    async def test_creator_ip_is_none_when_the_caller_names_none(self) -> None:
        code = await _create(InMemoryDeviceCodeStore())
        assert code.creator_ip is None

    async def test_no_two_codes_share_a_handle_or_a_secret(self) -> None:
        store = InMemoryDeviceCodeStore()
        codes = [await _create(store) for _ in range(50)]

        assert len({c.display_handle for c in codes}) == 50
        assert len({c.qr_secret for c in codes}) == 50

    async def test_the_handle_is_neither_credential(self) -> None:
        code = await _create(InMemoryDeviceCodeStore())
        assert code.display_handle not in (code.device_code, code.user_code)

    def test_the_secret_stays_out_of_repr(self) -> None:
        secret = bytes(range(32))
        code = _bare(qr_secret=secret)

        assert "qr_secret" not in repr(code)
        assert repr(secret) not in repr(code)


# ---------------------------------------------------------------------------
# Serialization, and the record the previous release wrote.
# ---------------------------------------------------------------------------


class TestSerialization:
    def _full(self) -> DeviceCode:
        return _bare(
            display_handle="h" * 22,
            qr_secret=bytes(range(32)),
            creator_ip="2001:db8::7",
            scanned_by="cust_7f3a",
            scanned_at=datetime.now(UTC),
        )

    def test_every_pairing_field_round_trips_through_json(self) -> None:
        code = self._full()
        back = DeviceCode.from_json(code.to_json())

        assert back.display_handle == code.display_handle
        assert back.qr_secret == code.qr_secret
        assert back.creator_ip == "2001:db8::7"
        assert back.scanned_by == "cust_7f3a"
        assert back.scanned_at is not None and code.scanned_at is not None
        assert abs((back.scanned_at - code.scanned_at).total_seconds()) < 0.001

    def test_the_secret_is_standard_base64_in_the_serialized_form(self) -> None:
        serialized = self._full().to_dict()
        assert serialized["qr_secret"] == base64.b64encode(bytes(range(32))).decode("ascii")

    def test_an_unscanned_code_serializes_its_absences_as_absences(self) -> None:
        serialized = _bare().to_dict()

        assert serialized["qr_secret"] is None
        assert serialized["display_handle"] == ""
        assert serialized["creator_ip"] is None
        assert serialized["scanned_by"] == ""
        assert serialized["scanned_at"] is None
        assert DeviceCode.from_dict(serialized).qr_secret == b""

    def test_a_secret_that_is_not_base64_is_a_corrupt_record(self) -> None:
        serialized = self._full().to_dict()
        serialized["qr_secret"] = "not base64 at all!"  # noqa: S105
        with pytest.raises(ValueError):
            DeviceCode.from_dict(serialized)

    def test_a_record_from_the_previous_release_deserializes_unscannable(self) -> None:
        """No handle, so no page finds it; no secret, so no token verifies."""
        legacy: dict[str, Any] = {
            "device_code": "legacy",
            "user_code": "ABC234",
            "verification_uri": VERIFY_URI,
            "expires_at": (datetime.now(UTC) + timedelta(minutes=15)).timestamp(),
            "interval": 5,
            "client_id": "legacy-client",
            "scopes": "accounts:read",
            "approved": False,
            "approved_at": None,
            "customer_ref": "",
            "exchanged_at": None,
            # No display_handle, qr_secret, creator_ip, scanned_by, scanned_at.
        }
        code = DeviceCode.from_dict(legacy)

        assert code.display_handle == ""
        assert code.qr_secret == b""
        assert code.creator_ip is None
        assert code.scanned_by == ""
        assert code.scanned_at is None
        forged = token_for(code.qr_secret, code.user_code, 5)
        assert verify_token(code.qr_secret, code.user_code, forged, 5) is QrVerdict.INVALID

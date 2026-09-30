"""The device-code store's pairing half, on the in-memory backend.

The fields the QR page and ``POST /scan`` read, the two secondary lookups, and
the two compare-and-set writes that replaced ``update_device_code``. The Redis
backend's versions of the same properties are in
``tests/test_redis_backed_stores.py``, against the real container ``make ci``
already starts, because the two backends share a contract and no code.
"""

from __future__ import annotations

import asyncio
import base64
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.auth import device_codes
from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreContended,
    InMemoryDeviceCodeStore,
    ScanClaim,
)

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


# ---------------------------------------------------------------------------
# The two secondary lookups.
# ---------------------------------------------------------------------------


class TestTheSecondaryLookups:
    async def test_both_lookups_find_the_code(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        assert await store.get_by_display_handle(code.display_handle) == code
        assert await store.get_by_user_code(code.user_code) == code

    async def test_an_unknown_or_empty_value_finds_nothing(self) -> None:
        store = InMemoryDeviceCodeStore()
        await _create(store)

        assert await store.get_by_display_handle("no-such-handle") is None
        assert await store.get_by_display_handle("") is None
        assert await store.get_by_user_code("") is None

    async def test_an_expired_code_is_found_by_neither(self) -> None:
        """Unlike ``get_device_code``, which must still return it so that
        ``POST /token`` can answer RFC 8628's ``expired_token``."""
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        past = datetime.now(UTC) - timedelta(seconds=1)
        store._codes[code.device_code] = replace(code, expires_at=past)

        assert await store.get_by_display_handle(code.display_handle) is None
        assert await store.get_by_user_code(code.user_code) is None
        assert await store.get_device_code(code.device_code) is not None

    async def test_an_entry_pointing_at_another_code_is_not_trusted(self) -> None:
        store = InMemoryDeviceCodeStore()
        first = await _create(store)
        second = await _create(store)
        store._by_user_code[first.user_code] = second.device_code
        store._by_handle[first.display_handle] = second.device_code

        assert await store.get_by_user_code(first.user_code) is None
        assert await store.get_by_display_handle(first.display_handle) is None

    async def test_a_revoke_clears_both_entries(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        await store.revoke_device_code(code.device_code)

        assert code.user_code not in store._by_user_code
        assert code.display_handle not in store._by_handle
        assert await store.get_by_user_code(code.user_code) is None

    async def test_a_consumed_code_still_resolves_by_both(self) -> None:
        """``POST /scan`` must still find an exchanged row, to answer
        ``conflict_exchanged`` rather than ``gone``."""
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        assert await store.consume_device_code(code.device_code) is True

        by_code = await store.get_by_user_code(code.user_code)
        assert by_code is not None and by_code.exchanged_at is not None
        assert await store.get_by_display_handle(code.display_handle) is not None

    async def test_the_expiry_sweep_clears_both_entries(self) -> None:
        store = InMemoryDeviceCodeStore()
        due = await _create(store, expires_in=0)

        await _create(store)

        assert due.device_code not in store._codes
        assert due.user_code not in store._by_user_code
        assert due.display_handle not in store._by_handle

    async def test_a_colliding_user_code_is_regenerated(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = InMemoryDeviceCodeStore()
        first = await _create(store)
        spellings = iter([first.user_code, "XYZ789"])
        monkeypatch.setattr(device_codes, "_generate_user_code", lambda: next(spellings))

        second = await _create(store)

        assert second.user_code == "XYZ789"
        assert await store.get_by_user_code(first.user_code) == first

    async def test_a_colliding_handle_is_regenerated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        store = InMemoryDeviceCodeStore()
        first = await _create(store)
        spellings = iter([first.display_handle, "fresh-handle-0000000000"])
        monkeypatch.setattr(device_codes, "_generate_display_handle", lambda: next(spellings))

        second = await _create(store)

        assert second.display_handle == "fresh-handle-0000000000"
        assert await store.get_by_display_handle(first.display_handle) == first

    async def test_a_generator_that_only_collides_is_refused_not_looped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store = InMemoryDeviceCodeStore()
        first = await _create(store)
        monkeypatch.setattr(device_codes, "_generate_user_code", lambda: first.user_code)

        with pytest.raises(DeviceCodeStoreContended):
            await _create(store)


# ---------------------------------------------------------------------------
# The two compare-and-set writes.
# ---------------------------------------------------------------------------

ALICE = "cust_a11ce"
BOB = "cust_b0b0"


class TestClaimScan:
    async def test_the_first_scan_is_claimed_and_recorded(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.CLAIMED

        stored = await store.get_device_code(code.device_code)
        assert stored is not None
        assert stored.scanned_by == ALICE
        assert stored.scanned_at is not None
        assert stored.approved is False

    async def test_a_repeat_by_the_same_customer_is_already_mine_and_writes_nothing(
        self,
    ) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)
        before = await store.get_device_code(code.device_code)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.ALREADY_MINE
        assert await store.get_device_code(code.device_code) == before

    async def test_a_repeat_after_approval_is_approved_mine(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)
        assert await store.approve_scanned(code.device_code, ALICE) is True
        before = await store.get_device_code(code.device_code)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.APPROVED_MINE
        assert await store.get_device_code(code.device_code) == before

    async def test_another_customer_on_an_unexchanged_code_revokes_it(self) -> None:
        """The session-swap defence: B scanned first, A's scan ends the pairing."""
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, BOB)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.CONFLICT_REVOKED

        assert await store.get_device_code(code.device_code) is None
        assert await store.get_by_user_code(code.user_code) is None
        assert code.display_handle not in store._by_handle

    async def test_another_customer_on_an_approved_unexchanged_code_revokes_it_too(
        self,
    ) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, BOB)
        await store.approve_scanned(code.device_code, BOB)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.CONFLICT_REVOKED
        assert await store.get_device_code(code.device_code) is None

    async def test_another_customer_on_an_exchanged_code_leaves_it_unchanged(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, BOB)
        await store.approve_scanned(code.device_code, BOB)
        await store.consume_device_code(code.device_code)
        before = await store.get_device_code(code.device_code)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.CONFLICT_EXCHANGED
        assert await store.get_device_code(code.device_code) == before

    async def test_a_missing_code_is_gone(self) -> None:
        store = InMemoryDeviceCodeStore()
        assert await store.claim_scan("never-existed", ALICE) is ScanClaim.GONE

    async def test_an_expired_code_is_gone_and_unclaimed(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        past = datetime.now(UTC) - timedelta(seconds=1)
        store._codes[code.device_code] = replace(code, expires_at=past)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.GONE
        stored = await store.get_device_code(code.device_code)
        assert stored is not None and stored.scanned_by == ""

    async def test_a_previous_release_approval_with_no_scan_is_gone(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        store._codes[code.device_code] = replace(code, approved=True, customer_ref=BOB)

        assert await store.claim_scan(code.device_code, ALICE) is ScanClaim.GONE

    async def test_two_concurrent_first_scans_claim_once(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        results = await asyncio.gather(
            store.claim_scan(code.device_code, ALICE),
            store.claim_scan(code.device_code, ALICE),
        )

        assert sorted(r.value for r in results) == ["already_mine", "claimed"]


class TestApproveScanned:
    async def test_the_scanner_approves_and_becomes_the_customer(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)

        assert await store.approve_scanned(code.device_code, ALICE) is True

        stored = await store.get_device_code(code.device_code)
        assert stored is not None
        assert stored.approved is True
        assert stored.approved_at is not None
        assert stored.customer_ref == ALICE
        assert stored.scanned_by == ALICE

    async def test_an_unscanned_code_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)

        assert await store.approve_scanned(code.device_code, ALICE) is False
        stored = await store.get_device_code(code.device_code)
        assert stored is not None and stored.approved is False

    async def test_a_code_another_customer_scanned_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, BOB)

        assert await store.approve_scanned(code.device_code, ALICE) is False
        stored = await store.get_device_code(code.device_code)
        assert stored is not None and stored.approved is False and stored.customer_ref == ""

    async def test_an_approved_code_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)
        await store.approve_scanned(code.device_code, ALICE)

        assert await store.approve_scanned(code.device_code, ALICE) is False

    async def test_an_expired_code_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)
        scanned = await store.get_device_code(code.device_code)
        assert scanned is not None
        past = datetime.now(UTC) - timedelta(seconds=1)
        store._codes[code.device_code] = replace(scanned, expires_at=past)

        assert await store.approve_scanned(code.device_code, ALICE) is False

    async def test_a_missing_code_is_refused(self) -> None:
        store = InMemoryDeviceCodeStore()
        assert await store.approve_scanned("never-existed", ALICE) is False

    async def test_two_concurrent_approvals_approve_exactly_once(self) -> None:
        store = InMemoryDeviceCodeStore()
        code = await _create(store)
        await store.claim_scan(code.device_code, ALICE)

        won = await asyncio.gather(
            store.approve_scanned(code.device_code, ALICE),
            store.approve_scanned(code.device_code, ALICE),
        )

        assert sorted(won) == [False, True]

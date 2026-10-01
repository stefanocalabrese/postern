"""``scanner_ip`` on a device code: written by the claim, on both backends, once.

Section 1 of ``dev-docs/pairing-network-signal-spec.md``. The address of the
``POST /scan`` request that claimed a pairing is written in the same
compare-and-set as ``scanned_by`` and ``scanned_at`` and in no other write, so
every ``ScanClaim`` result is driven here and the stored row read back. The
Redis half runs against the container ``make ci`` already starts, through a
second connection, because the two backends share a contract and no code.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    InMemoryDeviceCodeStore,
    RedisDeviceCodeStore,
    ScanClaim,
)

VERIFY_URI = "https://auth.test.invalid/verify"
ALICE = "cust_a11ce"
BOB = "cust_b0b0"
FIRST = "198.51.100.7"
SECOND = "203.0.113.200"


@pytest_asyncio.fixture(params=["memory", "redis"])
async def pair(request: pytest.FixtureRequest) -> AsyncIterator[tuple[Any, Any]]:
    """A writer and a reader over one backend.

    For Redis they are two connections under one fresh key prefix, so a value
    read back has crossed the server; for memory they are the same object.
    """
    if request.param == "memory":
        store = InMemoryDeviceCodeStore()
        yield store, store
        return
    url: str = request.getfixturevalue("redis_url")
    prefix = f"t{uuid4().hex[:12]}:"
    writer = RedisDeviceCodeStore(url=url, default_ttl=900, key_prefix=prefix, max_codes=10_000)
    reader = RedisDeviceCodeStore(url=url, default_ttl=900, key_prefix=prefix, max_codes=10_000)
    yield writer, reader
    await writer.close()
    await reader.close()


async def _create(store: Any) -> DeviceCode:
    code: DeviceCode = await store.create_device_code(
        client_id="vendor-a",
        scopes="accounts:read",
        verification_uri=VERIFY_URI,
        creator_ip="192.0.2.1",
    )
    return code


async def _read(store: Any, device_code: str) -> DeviceCode | None:
    code: DeviceCode | None = await store.get_device_code(device_code)
    return code


async def test_a_new_code_has_no_scanner(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    code = await _create(writer)
    assert code.scanner_ip is None
    stored = await _read(reader, code.device_code)
    assert stored is not None and stored.scanner_ip is None


async def test_the_claim_writes_the_address_with_the_scan_fields(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    code = await _create(writer)

    assert await writer.claim_scan(code.device_code, ALICE, scanner_ip=FIRST) is ScanClaim.CLAIMED

    stored = await _read(reader, code.device_code)
    assert stored is not None
    assert stored.scanned_by == ALICE
    assert stored.scanned_at is not None
    assert stored.scanner_ip == FIRST
    assert stored.creator_ip == "192.0.2.1"


async def test_a_claim_with_no_address_stores_none(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    code = await _create(writer)

    assert await writer.claim_scan(code.device_code, ALICE, scanner_ip=None) is ScanClaim.CLAIMED

    stored = await _read(reader, code.device_code)
    assert stored is not None and stored.scanned_by == ALICE and stored.scanner_ip is None


async def test_a_retry_from_another_network_does_not_move_the_address(
    pair: tuple[Any, Any],
) -> None:
    """First scan wins: ``ALREADY_MINE`` writes nothing."""
    writer, reader = pair
    code = await _create(writer)
    await writer.claim_scan(code.device_code, ALICE, scanner_ip=FIRST)
    before = await _read(reader, code.device_code)

    assert (
        await reader.claim_scan(code.device_code, ALICE, scanner_ip=SECOND)
        is ScanClaim.ALREADY_MINE
    )

    after = await _read(writer, code.device_code)
    assert after == before
    assert after is not None and after.scanner_ip == FIRST


async def test_a_repeat_after_approval_does_not_move_the_address(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    code = await _create(writer)
    await writer.claim_scan(code.device_code, ALICE, scanner_ip=FIRST)
    assert await writer.approve_scanned(code.device_code, ALICE) is True
    before = await _read(reader, code.device_code)

    assert (
        await reader.claim_scan(code.device_code, ALICE, scanner_ip=SECOND)
        is ScanClaim.APPROVED_MINE
    )
    assert await _read(writer, code.device_code) == before


async def test_a_conflict_on_an_exchanged_code_does_not_move_the_address(
    pair: tuple[Any, Any],
) -> None:
    writer, reader = pair
    code = await _create(writer)
    await writer.claim_scan(code.device_code, BOB, scanner_ip=FIRST)
    await writer.approve_scanned(code.device_code, BOB)
    await writer.consume_device_code(code.device_code, session_id="")
    before = await _read(reader, code.device_code)

    assert (
        await reader.claim_scan(code.device_code, ALICE, scanner_ip=SECOND)
        is ScanClaim.CONFLICT_EXCHANGED
    )
    after = await _read(writer, code.device_code)
    assert after == before
    assert after is not None and after.scanner_ip == FIRST


async def test_a_conflict_on_an_unexchanged_code_leaves_no_row_to_carry_it(
    pair: tuple[Any, Any],
) -> None:
    """``CONFLICT_REVOKED`` deletes the pairing, so the second customer's
    address is written nowhere."""
    writer, reader = pair
    code = await _create(writer)
    await writer.claim_scan(code.device_code, BOB, scanner_ip=FIRST)

    assert (
        await reader.claim_scan(code.device_code, ALICE, scanner_ip=SECOND)
        is ScanClaim.CONFLICT_REVOKED
    )
    assert await _read(writer, code.device_code) is None


async def test_a_missing_code_is_gone_and_nothing_is_written(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    assert await writer.claim_scan("never-existed", ALICE, scanner_ip=FIRST) is ScanClaim.GONE
    assert await _read(reader, "never-existed") is None


async def test_claim_scan_without_an_address_is_a_type_error(pair: tuple[Any, Any]) -> None:
    """Required and keyword-only, so no caller can record "no address" by omission."""
    writer, _ = pair
    code = await _create(writer)
    with pytest.raises(TypeError):
        await writer.claim_scan(code.device_code, ALICE)
    with pytest.raises(TypeError):
        await writer.claim_scan(code.device_code, ALICE, FIRST)


def test_the_abstract_signature_makes_the_address_required_and_keyword_only() -> None:
    parameter = inspect.signature(DeviceCodeStoreBase.claim_scan).parameters["scanner_ip"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


# ---------------------------------------------------------------------------
# Serialization.
# ---------------------------------------------------------------------------


def _bare(**overrides: Any) -> DeviceCode:
    fields: dict[str, Any] = {
        "device_code": "dc-bare",
        "user_code": "ABC234",
        "verification_uri": VERIFY_URI,
        "expires_at": datetime.now(UTC) + timedelta(minutes=15),
    }
    fields.update(overrides)
    return DeviceCode(**fields)


def test_the_address_round_trips_through_json() -> None:
    back = DeviceCode.from_json(_bare(scanner_ip="2001:db8::9").to_json())
    assert back.scanner_ip == "2001:db8::9"


def test_an_absent_address_is_serialized_as_null() -> None:
    serialized = _bare().to_dict()
    assert "scanner_ip" in serialized
    assert serialized["scanner_ip"] is None
    assert DeviceCode.from_dict(serialized).scanner_ip is None


def test_a_record_written_before_the_field_existed_has_no_scanner() -> None:
    legacy = _bare(scanned_by=ALICE, scanned_at=datetime.now(UTC)).to_dict()
    del legacy["scanner_ip"]

    code = DeviceCode.from_dict(legacy)

    assert code.scanner_ip is None
    assert code.scanned_by == ALICE

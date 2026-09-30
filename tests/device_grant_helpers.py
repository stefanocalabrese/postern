"""Steps the device-grant tests share now that ``POST /approve`` needs a scan.

``POST /approve`` approves only a code the same customer scanned first
(``approve_scanned`` in ``postern_core.auth.device_codes``). Most tests that
approve a pairing are about something after the approval -- the mint, the
audit row, a rate limit -- and not about the scan, so they scan through the
STORE rather than through ``POST /scan``. That keeps them free of the scan's
own ``audit_log`` row, which would change every row count they assert, and
free of the rotation token's two-second clock. The tests that are about the
scan drive ``POST /scan`` over HTTP and use ``qr_for`` for the token.

Not a test module: the name does not start with ``test_``, so pytest does not
collect it.
"""

from __future__ import annotations

import time

from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    InMemoryDeviceCodeStore,
    ScanClaim,
)
from starlette.applications import Starlette

from services.confirm.qr_token import slot_at, token_for


def stored_form(user_code: str) -> str:
    """A pairing code as the store keys it: no separator, no spaces, upper case."""
    return user_code.strip().replace("-", "").replace(" ", "").upper()


def device_store_of(app: Starlette) -> DeviceCodeStoreBase:
    """The device-code store the assembled app holds."""
    store: DeviceCodeStoreBase = app.state.device_code_store
    return store


async def stored_code(app: Starlette, user_code: str) -> DeviceCode:
    """The live pairing a displayed or stored-form ``user_code`` names."""
    code = await device_store_of(app).get_by_user_code(stored_form(user_code))
    assert code is not None, f"no live pairing holds user_code {user_code!r}"
    return code


async def scan_in_store(app: Starlette, user_code: str, customer: str) -> DeviceCode:
    """Claim the scan of a pairing for ``customer``, as ``POST /scan`` would.

    A repeat by the same customer is accepted (``ALREADY_MINE``), because
    several tests approve the same pending code more than once.
    """
    code = await stored_code(app, user_code)
    claim = await device_store_of(app).claim_scan(code.device_code, customer)
    assert claim in (ScanClaim.CLAIMED, ScanClaim.ALREADY_MINE), claim
    return code


def qr_for(code: DeviceCode, *, slot_offset: int = 0) -> str:
    """The rotation token the QR would carry now, moved by ``slot_offset`` slots."""
    return token_for(code.qr_secret, code.user_code, slot_at(time.time()) + slot_offset)


def overwrite_in_memory(app: Starlette, code: DeviceCode) -> None:
    """Replace a stored row directly, for tests that bend one out of shape.

    The in-memory backend only: its whole-snapshot writer is gone from the
    store interface on purpose (a snapshot written back undoes a
    compare-and-set), so a test that needs an expired or corrupted row
    reaches into the dict the way several already did before it went.
    """
    store = device_store_of(app)
    assert isinstance(store, InMemoryDeviceCodeStore), type(store).__name__
    store._codes[code.device_code] = code

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

import json
import re
import time
from collections.abc import Iterator
from typing import Any

from joserfc import jwt as joserfc_jwt
from joserfc.jwk import KeySet
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
    claim = await device_store_of(app).claim_scan(code.device_code, customer, scanner_ip=None)
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


#: What ``POST /token`` answers for an approved, unexpired device code since
#: 2026-09-30, byte for byte. Issuance is disabled until the layer-1 session
#: token lands: the token this endpoint used to return was a layer-2 backend
#: token (``aud=accounts.svc``, signed with the read key ``services/api``
#: publishes), which a public client must never hold.
ISSUANCE_DISABLED_BODY = {
    "error": "temporarily_unavailable",
    "error_description": "session token issuance is not enabled",
}

#: Three base64url segments joined by dots, the compact JWS shape, with the
#: first starting ``ey``: a JOSE header is a JSON object, and both ``{"`` and
#: ``{ `` encode to a leading ``ey`` in base64url (``eyJ`` and ``eyA``). The
#: anchor keeps an IP address or a dotted host name from matching. The third
#: segment may be empty, for ``alg=none``, which is still a JWT to look for.
_JWT_SHAPE = re.compile(r"ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _strings_in(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings_in(key)
            yield from _strings_in(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings_in(item)


def jwt_shaped_strings(body: str) -> list[str]:
    """Every compact-JWS-shaped run of characters in a response body.

    Read off the raw text, so a token anywhere in the body is found, and off
    every string in the parsed JSON as well, so a JSON escape inside a value
    cannot split one.
    """
    found = set(_JWT_SHAPE.findall(body))
    try:
        parsed = json.loads(body)
    except ValueError:
        parsed = None
    for string in _strings_in(parsed):
        found.update(_JWT_SHAPE.findall(string))
    return sorted(found)


def verifies_against(token: str, jwks: dict[str, Any]) -> bool:
    """Whether ``token`` carries a valid RS256 signature from a key in ``jwks``."""
    try:
        joserfc_jwt.decode(token, KeySet.import_key_set(jwks), algorithms=["RS256"])  # type: ignore[arg-type]
    except Exception:  # noqa: BLE001 -- any failure to verify is a "no"
        return False
    return True


def assert_no_body_carries_a_token_the_api_trusts(
    bodies: list[str], api_jwks: dict[str, Any]
) -> None:
    """The regression for the layer-2 token ``POST /token`` used to return.

    Checked twice, the narrower property first so a failure names it: no
    string in any body verifies against the JWKS ``services/api`` publishes,
    which is the key set Istio trusts; and no body holds anything JWT-shaped
    at all.
    """
    shaped = [s for body in bodies for s in jwt_shaped_strings(body)]
    trusted = [s for s in shaped if verifies_against(s, api_jwks)]
    assert trusted == [], "a /token response carried a token the api's JWKS verifies"
    assert shaped == [], f"a /token response carried a JWT-shaped string: {shaped!r}"

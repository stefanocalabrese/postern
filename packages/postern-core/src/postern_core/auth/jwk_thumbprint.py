"""RFC 7638 JWK thumbprints, for telling two keys apart by their public material.

Two readers, one in each service, which is why this lives in the shared
library: ``services/confirm/session_token.py`` refuses to start when the
SESSION key's public half is also the write key's, and
``services/api/session_verifier.py`` drops any key confirm publishes as a
session key that is also the api's own read key. ``.importlinter`` forbids
either service importing the other, so the function cannot live in one of
them. Moved here from ``services/confirm/session_token.py`` on 2 October 2026;
that module re-exports both names.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from collections.abc import Mapping
from typing import Any

__all__ = ["THUMBPRINT_MEMBERS", "jwk_thumbprints"]

#: RFC 7638 section 3.2's required members per ``kty`` (RFC 8037 section 2
#: for ``OKP``). The thumbprint is over these alone.
THUMBPRINT_MEMBERS: Mapping[str, tuple[str, ...]] = {
    "RSA": ("e", "kty", "n"),
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
}


def jwk_thumbprints(jwks: Mapping[str, Any]) -> set[str]:
    """The RFC 7638 SHA-256 thumbprint of every RSA, EC and OKP key in a JWKS.

    Over the ``kty``'s required members only, so the ``kid``, ``use`` and
    every private member are ignored: two sources publishing one key under
    two kids give one thumbprint. A key of another ``kty``, missing a
    required member, or with an RSA ``n`` or ``e`` that is not base64url, is
    skipped: it cannot be the same key as one that has them, and a source
    publishing it must not crash the startup check. RSA ``n`` and ``e`` are
    hashed in their minimal encoding, leading zero octets stripped.
    """
    thumbprints: set[str] = set()
    for jwk in jwks.get("keys", []):
        members = THUMBPRINT_MEMBERS.get(jwk.get("kty", ""))
        if members is None or any(member not in jwk for member in members):
            continue
        required = {member: jwk[member] for member in members}
        if required["kty"] == "RSA":
            # RFC 7638 section 3.2 hashes RFC 7518's minimal encoding, which
            # forbids leading zero octets on `n` and `e` (section 6.3.1.1).
            # A parser may still accept a padded value, so one key published
            # padded would otherwise hash as a different key (2 October 2026).
            # EC and OKP coordinates are fixed-length and are hashed as given.
            n, e = _minimal(required["n"]), _minimal(required["e"])
            if n is None or e is None:
                continue
            required |= {"n": n, "e": e}
        canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(canonical.encode()).digest()
        thumbprints.add(_b64url(digest))
    return thumbprints


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _minimal(value: Any) -> str | None:
    """A base64url big-endian integer re-encoded without leading zero octets,
    or ``None`` when ``value`` is not base64url text."""
    if not isinstance(value, str):
        return None
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None
    return _b64url(raw.lstrip(b"\x00") or b"\x00")

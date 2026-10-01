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
    two kids give one thumbprint. A key of another ``kty``, or missing a
    required member, is skipped: it cannot be the same key as one that has
    them, and a source publishing it must not crash the startup check.
    """
    thumbprints: set[str] = set()
    for jwk in jwks.get("keys", []):
        members = THUMBPRINT_MEMBERS.get(jwk.get("kty", ""))
        if members is None or any(member not in jwk for member in members):
            continue
        required = {member: jwk[member] for member in members}
        canonical = json.dumps(required, separators=(",", ":"), sort_keys=True)
        digest = hashlib.sha256(canonical.encode()).digest()
        thumbprints.add(base64.urlsafe_b64encode(digest).rstrip(b"=").decode())
    return thumbprints

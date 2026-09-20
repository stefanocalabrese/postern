"""Workload identity: signing keys, internal-token minting, and revocation.

The read/write signing-key split is the core of the Vault axis (handoff §7.2):
each service publishes only its own key at ``/.well-known/jwks.json``.

ZT-7 revocation list plugs into the token verification seam — every internal
JWT carries a ``jti`` that the revocation list checks.  Three scopes:

- **Per-session**: revoke one ``jti`` (one device, one client).
- **Per-customer + per-client**: revoke all sessions for a customer–client pair.
- **Per-client kill switch**: revoke every session from one client (all customers).

See ``postern_core.auth.revocation.RevocationList`` for the API.
"""

from postern_core.auth.keys import GeneratedKeySource, KeySource
from postern_core.auth.minter_probe import refuse_unverifiable_minter
from postern_core.auth.read_minter import ReadTokenMinter

__all__ = [
    "GeneratedKeySource",
    "KeySource",
    "PemKeySource",
    "ReadTokenMinter",
    "refuse_unverifiable_minter",
]

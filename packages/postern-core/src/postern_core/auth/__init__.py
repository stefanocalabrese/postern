"""Workload identity: signing keys, internal-token minting, and revocation.

The read/write signing-key split is the core of the Vault axis (handoff §7.2):
each service publishes only its own key at ``/.well-known/jwks.json``.

ZT-7 revocation list plugs into the token verification seam — every internal
JWT carries a ``jti`` that the revocation list checks.  Three scopes:

- **Per-session**: revoke one ``jti`` (one device, one client).
- **Per-customer + per-client**: revoke all sessions for a customer–client pair.
- **Per-client kill switch**: revoke every session from one client (all customers).

ZT-1 — Continuous authorization: ``ReadTokenMinter`` reads this call's
revocation decision and the jti replay cache on every mint. A revoked session
dies at mint, not at next refresh.

The scopes are stored in ``RevocationStoreBase`` (Redis-backed in production
via ``POSTERN_REDIS_URL``), written by ``postern_core.auth.revoke_cli``, and
enforced per call by ``services/api/middleware/revocation.py``'s
``RevocationMiddleware``. See ``postern_core.auth.revocation`` for the scopes,
the store, the decision seam, and what revoking does NOT stop.
"""

from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    InMemoryDeviceCodeStore,
)
from postern_core.auth.keys import GeneratedKeySource, KeySource
from postern_core.auth.minter_probe import refuse_unverifiable_minter
from postern_core.auth.read_minter import JtiReplayCache, ReadTokenMinter
from postern_core.auth.revocation import (
    InMemoryRevocationStore,
    RedisRevocationStore,
    RevocationList,
    RevocationSnapshot,
    RevocationStoreBase,
    RevocationStoreUnavailable,
    RevokedError,
    create_revocation_store,
)

__all__ = [
    "DeviceCode",
    "DeviceCodeStoreBase",
    "GeneratedKeySource",
    "InMemoryDeviceCodeStore",
    "InMemoryRevocationStore",
    "JtiReplayCache",
    "KeySource",
    "ReadTokenMinter",
    "RedisRevocationStore",
    "RevocationList",
    "RevocationSnapshot",
    "RevocationStoreBase",
    "RevocationStoreUnavailable",
    "RevokedError",
    "create_revocation_store",
    "refuse_unverifiable_minter",
]

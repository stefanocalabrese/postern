"""Adapts the internal minter to the TokenMinter protocol BackendClient calls.

Read audiences only. `payments.svc` is deliberately absent: asking this minter
for a write audience raises rather than minting a token with a guessed scope.
That is a second, independent barrier to the key split. Even holding the right
key, a write token from here would carry the wrong scope, and Istio matches on
claims as well as on the signature.

ZT-1 — Continuous authorization: every mint consults the revocation decision
for this call and the jti replay cache before issuing a token. A revoked
session dies at mint, not at next refresh (ZT-1 acceptance criterion).

WHAT CHANGED, AND WHY IT HAD TO. Until this commit the check here built its
own claims dict as ``{"sub": customer.value, "client_id": audience}``, so
``is_revoked`` was asked about ``"accounts.svc"``, ``"transactions.svc"`` or
``"cards.svc"`` -- backend audiences, never an OAuth client id. Per-customer
plus per-client revocation, the connected-app scope, could therefore not
match even once someone found a way to populate the list, because no operator
revokes a customer against ``accounts.svc``. The audience is not an identity
of the caller; it names which backend this hop is for.

The lookup also cannot happen here. This object is called through the
synchronous `postern_core.facade.client`'s `TokenMinter` protocol, and the
revocation store is a coroutine over Redis. So the check runs once per call
in `services/api/middleware/revocation.py`'s `RevocationMiddleware`, which has
the validated token and therefore the real ``client_id`` and ``jti``, and
publishes its answer on a `ContextVar` this minter reads synchronously.
`postern_core.auth.revocation.require_revocation_decision` is the default
provider and it REFUSES when no decision was published, because that means
the middleware did not run.

See ``postern_core.auth.revocation`` for the store, the scopes and the
decision seam.
"""

from __future__ import annotations

import time
from collections import OrderedDict

from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.revocation import (
    RevocationDecision,
    RevokedError,
    require_revocation_decision,
)
from postern_core.identity import CustomerRef

READ_SCOPES = {
    "accounts.svc": "accounts:read",
    "transactions.svc": "transactions:read",
    "cards.svc": "cards:read",
}


class JtiReplayCache:
    """In-memory jti replay cache covering the token lifetime.

    Tracks every ``jti`` minted since startup and evicts entries older than
    the token lifetime. A duplicate jti within the window raises so the
    caller can reject the request (ZT-1, A10).

    Thread-safe enough for FastMCP's in-process test client (single-threaded
    async). Not safe across processes — that requires a shared store.
    """

    def __init__(self, *, max_age_seconds: float = 60.0) -> None:
        self._cache: OrderedDict[str, float] = OrderedDict()
        self._max_age_seconds = max_age_seconds

    def add(self, jti: str) -> None:
        """Record a jti. Raises ``ValueError`` if the jti was seen recently."""
        now = time.monotonic()
        # Evict expired entries first
        while self._cache and now - next(iter(self._cache.values())) > self._max_age_seconds:
            self._cache.popitem(last=False)

        if jti in self._cache:
            raise ValueError(f"jti replay detected: {jti}")

        self._cache[jti] = now

    def clear(self) -> None:
        """Remove all entries. Useful for tests."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Number of active entries (for testing)."""
        return len(self._cache)


class ReadTokenMinter:
    """Wraps ``InternalTokenMinter`` with ZT-1 continuous authorization.

    Every call reads this request's revocation decision and the jti replay
    cache before minting. A revoked session dies at mint, not at next refresh.

    Args:
        minter: The underlying ``InternalTokenMinter`` that signs tokens.
        revocation_decision: What to ask whether this call is revoked. The
            default, ``require_revocation_decision``, reads the decision
            `RevocationMiddleware` published for this call and RAISES when
            there is none, because no decision means the middleware did not
            run. A caller with genuinely nothing to consult passes
            ``postern_core.auth.revocation.unchecked_revocation`` explicitly;
            defaulting to that instead is how a control stays inert while its
            tests stay green.
        jti_cache: Optional ``JtiReplayCache`` for A10 (token replay prevention).
            When provided, duplicate jtis within the token lifetime raise.
    """

    def __init__(
        self,
        minter: InternalTokenMinter,
        *,
        revocation_decision: RevocationDecision = require_revocation_decision,
        jti_cache: JtiReplayCache | None = None,
    ) -> None:
        self._minter = minter
        self._revocation_decision = revocation_decision
        self._jti_cache = jti_cache

    def __call__(self, customer: CustomerRef, audience: str) -> str:
        scope = READ_SCOPES[audience]

        # ZT-1: this request's revocation decision, before anything is signed.
        # All three scopes -- session, customer+client, kill switch -- were
        # already resolved against the shared store by the middleware, which
        # is the only layer holding the customer's validated token and hence
        # the real `client_id` and `jti`. The default provider raises rather
        # than answering False when no decision exists.
        if self._revocation_decision():
            raise RevokedError(f"customer {customer.value} is revoked; no token will be minted")

        token = self._minter.mint(subject=customer, audience=audience, scope=scope)

        # ZT-1 A10: check jti replay cache after mint
        if self._jti_cache is not None:
            # Extract jti from the token to check for replays.
            # We decode just enough to get the jti — the signature is already
            # verified by InternalTokenMinter's caller (minter_probe).
            from joserfc import jwt as _jwt
            from joserfc.jwk import KeySet as _KeySet

            keyset = _KeySet.import_key_set(self._minter.key_source.public_jwks())
            decoded = _jwt.decode(token, keyset, algorithms=["RS256"])
            jti: str = decoded.claims["jti"]
            self._jti_cache.add(jti)

        return token

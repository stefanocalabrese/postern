"""Adapts the internal minter to the TokenMinter protocol BackendClient calls.

Read scopes only. Every audience below maps to a `:read` scope, and an
audience with no entry raises rather than minting a token with a guessed
scope. `payments.svc` has had an entry since decision 0022, for one payee
lookup, and it maps to `payments:read`: `payments:execute` is minted by
`services/confirm` alone, with the write key. That is a second, independent
barrier to the key split. Even holding the right key, a token from here would
carry the wrong scope for a write endpoint, and Istio matches on claims as
well as on the signature.

ZT-1 — Continuous authorization: every mint consults the revocation decision
for this call before issuing a token. A revoked session dies at mint, not at
next refresh (ZT-1 acceptance criterion). That is the control on this path.

THE JTI CACHE BELOW IS NOT A SECOND ONE, WHATEVER ITS NAME SAYS. It runs
after the token is signed, on a jti this same call generated, and there is
no other writer. Read `JtiReplayCache` and
`dev-docs/decisions/0014-jti-cache-detects-randomness-not-replay.md` before
citing it as replay protection anywhere.

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
    # Decision 0022: one read, GET /payees/{ref}, for the payments producer's
    # payee lookup. `payments:read`, never `payments:execute`, which only
    # `services/confirm` mints, with the write key.
    "payments.svc": "payments:read",
}


class JtiReplayCache:
    """A collision detector on this process's own ``uuid4``, misnamed since 2026-09-20.

    THE NAME PROMISES A CONTROL THIS CLASS CANNOT HOLD. Its only writer is
    `ReadTokenMinter.__call__`, which calls `add` on a jti that
    `InternalTokenMinter.mint` produced from ``uuid.uuid4()`` two statements
    earlier. Nothing in this repository ever hands it a jti that arrived from
    outside, so the duplicate it raises on is a uuid4 that repeated inside
    one process within one token lifetime: a failure of the RNG, not a
    replayed token. `dev-docs/decisions/0014-jti-cache-detects-randomness-not-replay.md`
    works through why that is the only reachable case and why the class is
    kept anyway.

    Replay is a property the RECIPIENT of a token observes, by remembering
    jtis it has accepted. The recipient of these tokens is the Istio gateway
    and the operator's domain services, in repositories that are not this
    one. A mint-side cache cannot substitute for that at any scale, because
    it never sees the event.

    Tracks every ``jti`` minted since startup and evicts entries older than
    the token lifetime, so the window it can detect a collision in is that
    lifetime and not longer.

    Thread-safe enough for FastMCP's in-process test client (single-threaded
    async). Per process, and deliberately: a shared backend would let two
    replicas notice a uuid4 they both generated, which is the same non-control
    at higher cost on the hot path of every backend call. The RNG failure that
    would make that reachable, a cloned VM or container resuming a duplicated
    entropy state, already surfaces in `postern_core.auth.device_codes`, where
    `_generate_device_code` draws ``secrets.token_urlsafe(32)`` into a single-use
    store that is Redis-backed because correctness needs it to be. A duplicate
    there is a duplicate credential, which is worth catching; a duplicate here
    is a duplicate log line.
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

    Every call reads this request's revocation decision before minting, so a
    revoked session dies at mint and not at next refresh. The jti cache, when
    one is supplied, runs after the signature and is not part of that: see
    `JtiReplayCache` for what it does and does not detect.

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
        jti_cache: Optional ``JtiReplayCache``. When provided, a jti this
            process already minted within the token lifetime raises. That is
            a uuid4 collision, not a replay, and the class docstring says why
            the distinction is the whole of it. Optional because nothing
            depends on it: every caller in this repository except
            `services/api/main.py`'s `create_app` leaves it ``None``, and the
            device grant in `services/confirm/device_auth.py` mints from a
            bare ``InternalTokenMinter`` with no cache reachable at all.
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

        minted = self._minter.mint_with_jti(subject=customer, audience=audience, scope=scope)

        # The jti collision check, after the signature because the jti belongs
        # to a token that exists. Not a replay check: `JtiReplayCache` carries
        # why, and this ordering is itself the proof, since a token that has
        # just been signed here has by definition not been anywhere to be
        # captured from.
        #
        # WHAT USED TO BE HERE, AND WHY ITS REMOVAL IS THE POINT. Until this
        # commit these two lines were a `KeySet.import_key_set` over the
        # published JWKS plus a full RS256 `jwt.decode`, per backend call, to
        # read back the jti `mint` had drawn three statements earlier. Nothing
        # consumed the decoded token but the next line, joserfc's `decode`
        # validates no claim (no `exp`, no `aud`, no `iss`; that is a separate
        # `JWTClaimsRegistry.validate`), and the whole thing sat inside this
        # `if`, so a minter built without a cache verified nothing at all. It
        # was therefore not a self-check on the signing key: the self-check is
        # `refuse_unverifiable_minter`, which mints one token at startup and
        # verifies it against the same JWKS, unconditionally, once.
        #
        # That matters beyond the 42us it cost per call, measured against the
        # 910us the signature costs. Decision record 0014 kept this cache
        # partly because the check was "one dictionary lookup on a path already
        # paying an RSA verification". The verification was on the path only to
        # feed the cache, so the argument was circular. The lookup is 0.2us and
        # now that is the entire cost, which is what 0014 meant.
        if self._jti_cache is not None:
            self._jti_cache.add(minted.jti)

        return minted.token

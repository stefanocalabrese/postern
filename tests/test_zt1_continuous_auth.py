"""ZT-1 — Continuous authorization and revocation.

Covers the three acceptance criteria from the zero-trust plan §4:
1. Revocation check on every token mint — a revoked session dies at mint, not
   at next refresh.
2. jti replay cache (A10) — duplicate jtis within the token lifetime raise.
3. Kill switch blocks all tokens from a client across all customers.

WHAT CHANGED IN THIS FILE, AND WHY IT IS NOT A WEAKENING. Four call sites here
used to revoke with ``client_id="accounts.svc"`` and assert the next mint
raised. That passed only because `ReadTokenMinter` was asking the revocation
list about the backend AUDIENCE instead of the OAuth client, so these tests
pinned the defect rather than the behaviour: no operator revokes a customer
against ``accounts.svc``, and with the list populated by a real operator the
connected-app scope could never have matched. They now revoke against a real
client id, with every assertion unchanged, plus a new one that a different
client for the same customer is NOT caught.

A fifth test asserted that a minter built with no revocation list still
minted. That premise is gone by design: the minter's default decision
provider REFUSES when nothing published a decision for the call, because an
absent decision means `RevocationMiddleware` did not run. It is replaced by
the opposite assertion, which is the control rather than its absence.

See ``postern_core.auth.read_minter.ReadTokenMinter`` for the API and
``postern_core.auth.revocation`` for the decision seam.
"""

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, KeySetSerialization, RSAKey
from postern_core.auth.internal_jwt import _LIFETIME, InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.auth.read_minter import JtiReplayCache, ReadTokenMinter
from postern_core.auth.revocation import (
    RevocationDecision,
    RevocationList,
    RevokedError,
    unchecked_revocation,
)
from postern_core.identity import CustomerRef

ISS = "https://mcp-read.internal"
CUST_A = CustomerRef(value="cust_a")
CUST_B = CustomerRef(value="cust_b")

#: Real OAuth client ids, which is the whole correction. An audience
#: (``accounts.svc``) names which backend a hop is for; it is not an identity
#: of the caller and nothing an operator would ever revoke against.
CLIENT = "vendor-claude"
OTHER_CLIENT = "vendor-perplexity"


@pytest.fixture
def source() -> GeneratedKeySource:
    return GeneratedKeySource(kid="read-1")


@pytest.fixture
def minter(source: GeneratedKeySource) -> ReadTokenMinter:
    return ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=unchecked_revocation,
    )


def _decision(rev: RevocationList, customer: CustomerRef, client_id: str) -> RevocationDecision:
    """The decision `RevocationMiddleware` would publish for this caller.

    The middleware resolves all three scopes against the shared store and
    publishes one boolean on a ContextVar; this is that boolean, built from
    the same claim shape (``sub``, ``client_id``, and a ``jti`` when there is
    one) so these unit tests exercise the corrected input rather than the
    audience the old code substituted for it.
    """
    claims = {"sub": customer.value, "client_id": client_id}
    return lambda: rev.is_revoked(claims)


# --- Revocation check on mint (ZT-1) ---


def test_revocation_list_blocks_mint_when_customer_client_revoked(
    source: GeneratedKeySource,
) -> None:
    """Revoking a customer–client pair blocks the next token mint."""
    rev = RevocationList()
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=_decision(rev, CUST_A, CLIENT),
    )

    # Before revocation: mint succeeds
    token = minter(CUST_A, "accounts.svc")
    assert isinstance(token, str) and len(token) > 10

    # Revoke customer A through the client that is actually calling
    rev.revoke_customer_client(customer_ref="cust_a", client_id=CLIENT)

    # Next mint raises
    with pytest.raises(RevokedError, match="cust_a.*revoked"):
        minter(CUST_A, "accounts.svc")


def test_revoking_one_client_does_not_block_the_same_customer_on_another(
    source: GeneratedKeySource,
) -> None:
    """The defect this file used to pin, stated as the assertion that catches it.

    With ``client_id=audience`` the connected-app scope was keyed on
    ``accounts.svc``, so it could not distinguish two AI vendors acting for
    one customer at all: it would have cut both or neither. Cutting one vendor
    without touching the others is the entire point of the scope.
    """
    rev = RevocationList()
    rev.revoke_customer_client(customer_ref="cust_a", client_id=CLIENT)

    revoked_client = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=_decision(rev, CUST_A, CLIENT),
    )
    other_client = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=_decision(rev, CUST_A, OTHER_CLIENT),
    )

    with pytest.raises(RevokedError):
        revoked_client(CUST_A, "accounts.svc")
    token = other_client(CUST_A, "accounts.svc")
    assert isinstance(token, str) and len(token) > 10


def test_revocation_list_blocks_mint_under_kill_switch(source: GeneratedKeySource) -> None:
    """Kill switch blocks all mints for the killed client_id."""
    rev = RevocationList()
    killed = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=_decision(rev, CUST_A, CLIENT),
    )
    survivor = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=_decision(rev, CUST_A, OTHER_CLIENT),
    )

    rev.kill_switch(client_id=CLIENT)

    # Every mint for that client raises, whichever backend it was headed for.
    with pytest.raises(RevokedError, match="revoked"):
        killed(CUST_A, "accounts.svc")
    with pytest.raises(RevokedError, match="revoked"):
        killed(CUST_A, "cards.svc")

    # A different client is unaffected. The old form of this assertion used a
    # different AUDIENCE, which only passed because the audience was standing
    # in for the client id.
    token = survivor(CUST_A, "accounts.svc")
    assert isinstance(token, str) and len(token) > 10


def test_revocation_list_no_false_positive_different_customer(source: GeneratedKeySource) -> None:
    """Revoking customer A does not block customer B."""
    rev = RevocationList()
    rev.revoke_customer_client(customer_ref="cust_a", client_id=CLIENT)

    minter_b = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=_decision(rev, CUST_B, CLIENT),
    )

    # Customer B can still mint
    token = minter_b(CUST_B, "accounts.svc")
    assert isinstance(token, str) and len(token) > 10


def test_a_minter_with_no_published_decision_refuses(source: GeneratedKeySource) -> None:
    """Fail closed on the absence of the check, not open.

    This replaces a test that asserted the opposite -- that a minter built
    without a revocation list minted anyway -- which was backward compatibility
    with a control that could not be reached. An unset decision means
    `RevocationMiddleware` did not run for this call, and a token signed on
    that basis is a token signed with the ZT-7 check skipped.
    """
    default_minter = ReadTokenMinter(InternalTokenMinter(issuer=ISS, key_source=source))

    with pytest.raises(RevokedError, match="no revocation decision"):
        default_minter(CUST_A, "accounts.svc")


# --- the jti cache, which is not the A10 control it was filed as ---
#
# THESE FOUR CASES ARE WHAT SETTLED IT, and the first one settled it against
# its own name. It was called `test_jti_cache_blocks_duplicate_token` and its
# body already said, in a comment, that nothing is blocked; the name is what
# a reader greps and the name was the false half. A green test whose title
# claims replay protection is how `dev-docs/decisions/0010-dpop-sender-constraint.md`
# came to list this cache as a compensating control for a stolen token.
# `dev-docs/decisions/0014-jti-cache-detects-randomness-not-replay.md` is the
# correction.


def test_the_cache_never_fires_on_the_mint_path_it_guards(
    source: GeneratedKeySource,
) -> None:
    """Two mints of the identical request produce two tokens and no raise.

    Which is the whole finding. `InternalTokenMinter.mint` draws a fresh
    ``uuid.uuid4()`` per call, so the cache's only writer can only ever feed
    it values it has not seen. Nothing a caller does reaches the raise.
    """
    cache = JtiReplayCache(max_age_seconds=_LIFETIME.total_seconds())
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=unchecked_revocation,
        jti_cache=cache,
    )

    token1 = minter(CUST_A, "accounts.svc")
    token2 = minter(CUST_A, "accounts.svc")

    assert token1 != token2
    assert cache.size == 2


def test_a_repeated_jti_raises_and_only_a_collision_could_repeat_one(
    source: GeneratedKeySource,
) -> None:
    """The raise exists and is reachable only by writing the string twice.

    No production path can. This is the container's own behaviour under a
    hand-built input, which is worth pinning and is not evidence that a
    captured token gets stopped anywhere.
    """
    cache = JtiReplayCache(max_age_seconds=60.0)

    cache.add("uuid-1")
    with pytest.raises(ValueError, match="jti replay detected"):
        cache.add("uuid-1")


def test_jti_cache_allows_different_jtis(source: GeneratedKeySource) -> None:
    """Different jtis never collide."""
    cache = JtiReplayCache(max_age_seconds=60.0)

    cache.add("uuid-1")
    cache.add("uuid-2")  # does not raise
    assert cache.size == 2


def test_jti_cache_clear_removes_all(source: GeneratedKeySource) -> None:
    """clear() removes all entries."""
    cache = JtiReplayCache(max_age_seconds=60.0)

    cache.add("uuid-1")
    cache.add("uuid-2")
    assert cache.size == 2

    cache.clear()
    assert cache.size == 0


# --- Combined: revocation + replay cache ---


def test_revocation_checked_before_replay_cache(source: GeneratedKeySource) -> None:
    """Revocation runs first, so a revoked customer gets `RevokedError`.

    The ordering is what matters and it is the ordering the real control
    wants: nothing is signed for a revoked customer. The cache's position
    after the signature is a consequence of it needing a signed token to read
    a jti out of, and `JtiReplayCache` carries why that placement means it
    cannot see a replay.
    """
    rev = RevocationList()
    cache = JtiReplayCache(max_age_seconds=_LIFETIME.total_seconds())
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=_decision(rev, CUST_A, CLIENT),
        jti_cache=cache,
    )

    # Mint first token (jti recorded in cache)
    minter(CUST_A, "accounts.svc")

    # Revoke customer A through the client that is calling
    rev.revoke_customer_client(customer_ref="cust_a", client_id=CLIENT)

    # Next mint raises RevokedError (revocation), not ValueError (replay)
    with pytest.raises(RevokedError, match="cust_a.*revoked"):
        minter(CUST_A, "accounts.svc")


def test_mint_without_revocation_list_still_uses_jti_cache(source: GeneratedKeySource) -> None:
    """jti cache works independently of revocation."""
    cache = JtiReplayCache(max_age_seconds=60.0)
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=unchecked_revocation,
        jti_cache=cache,
    )

    # Normal mints produce unique jtis
    t1 = minter(CUST_A, "accounts.svc")
    t2 = minter(CUST_A, "accounts.svc")
    assert t1 != t2

    # Cache tracks them
    assert cache.size == 2


# --- what feeding the cache costs, which was the argument for keeping it ---
#
# Decision record 0014 kept this cache partly because "the check costs one
# dictionary lookup on a path that is already paying an RSA verification".
# The path was paying that verification only to feed this cache: the decode
# sat inside `if self._jti_cache is not None`, so a minter built without a
# cache verified nothing, and `add` itself is the dictionary lookup. Measured
# on one developer machine over 2000 calls each, at 2048 bits: the RSA
# signature `mint` performs costs 910us, importing the JWKS plus the verifying
# decode cost 42us on top of it, and `add` costs 0.2us. The clause was not
# wrong about the lookup being cheap. It was wrong about what the path pays
# for anyway, because a signature is not a verification, and the 42us it
# waved through was 181 times the lookup it was excusing.


class _CountingKeySource:
    """A `KeySource` that records the two halves of the key separately.

    `signing_key` is the mint. `public_jwks` is read for exactly one purpose
    anywhere in this repository, verifying a token, so counting them apart is
    the observable that separates "this call signed something" from "this call
    also verified what it just signed".
    """

    def __init__(self, inner: GeneratedKeySource) -> None:
        self._inner = inner
        self.signing_key_calls = 0
        self.public_jwks_calls = 0

    def signing_key(self) -> RSAKey:
        self.signing_key_calls += 1
        return self._inner.signing_key()

    def public_jwks(self) -> KeySetSerialization:
        self.public_jwks_calls += 1
        return self._inner.public_jwks()


def test_feeding_the_cache_reads_no_public_key_and_verifies_nothing(
    source: GeneratedKeySource,
) -> None:
    """One mint signs once and verifies zero times, cache installed.

    The public half of the key has no business being touched on a path whose
    job is to sign. `refuse_unverifiable_minter` already mints one token at
    startup and verifies it against the JWKS the service publishes, which is
    the self-check this per-call decode was mistaken for.
    """
    counting = _CountingKeySource(source)
    cache = JtiReplayCache(max_age_seconds=_LIFETIME.total_seconds())
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=counting),
        revocation_decision=unchecked_revocation,
        jti_cache=cache,
    )

    minter(CUST_A, "accounts.svc")

    assert counting.signing_key_calls == 1
    assert counting.public_jwks_calls == 0
    assert cache.size == 1


def test_the_cache_records_the_jti_the_token_actually_carries(
    source: GeneratedKeySource,
) -> None:
    """The value reaching `add` is the token's own jti, not a second draw.

    Without this assertion, feeding the cache any fresh unique string would
    satisfy every other case in this file, size counts included, and the cache
    would be watching values that never left the process inside a token. The
    decode that proves the pairing belongs here, once, and not on the path.
    """
    cache = JtiReplayCache(max_age_seconds=_LIFETIME.total_seconds())
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=unchecked_revocation,
        jti_cache=cache,
    )

    token = minter(CUST_A, "accounts.svc")

    signed_jti = jwt.decode(
        token, KeySet.import_key_set(source.public_jwks()), algorithms=["RS256"]
    ).claims["jti"]
    with pytest.raises(ValueError, match="jti replay detected"):
        cache.add(signed_jti)

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


# --- jti replay cache (A10) ---


def test_jti_cache_blocks_duplicate_token(source: GeneratedKeySource) -> None:
    """Minting the same token twice raises on the second call."""
    cache = JtiReplayCache(max_age_seconds=_LIFETIME.total_seconds())
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=unchecked_revocation,
        jti_cache=cache,
    )

    # First mint succeeds
    token1 = minter(CUST_A, "accounts.svc")

    # Second mint with same customer+audience generates a new jti (UUID),
    # so it does NOT raise — each mint creates a unique token.
    # The replay cache catches *actual* replays (same jti), not just
    # repeated calls. This test verifies the cache is wired but doesn't
    # trigger on normal usage.
    token2 = minter(CUST_A, "accounts.svc")
    assert token1 != token2  # different jtis


def test_jti_cache_detects_manual_replay(source: GeneratedKeySource) -> None:
    """Manually adding the same jti twice raises."""
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
    """Revocation check happens before the jti cache, so a revoked
    customer is rejected even if their previous token's jti is still in cache."""
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

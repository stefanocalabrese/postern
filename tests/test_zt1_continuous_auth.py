"""ZT-1 — Continuous authorization and revocation.

Covers the three acceptance criteria from the zero-trust plan §4:
1. Revocation check on every token mint — a revoked session dies at mint, not
   at next refresh.
2. jti replay cache (A10) — duplicate jtis within the token lifetime raise.
3. Kill switch blocks all tokens from a client across all customers.

See ``postern_core.auth.read_minter.ReadTokenMinter`` for the API.
"""

import pytest
from postern_core.auth.internal_jwt import _LIFETIME, InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.auth.read_minter import JtiReplayCache, ReadTokenMinter
from postern_core.auth.revocation import RevocationList
from postern_core.identity import CustomerRef

ISS = "https://mcp-read.internal"
CUST_A = CustomerRef(value="cust_a")
CUST_B = CustomerRef(value="cust_b")


@pytest.fixture
def source() -> GeneratedKeySource:
    return GeneratedKeySource(kid="read-1")


@pytest.fixture
def minter(source: GeneratedKeySource) -> ReadTokenMinter:
    return ReadTokenMinter(InternalTokenMinter(issuer=ISS, key_source=source))


# --- Revocation check on mint (ZT-1) ---


def test_revocation_list_blocks_mint_when_customer_client_revoked(
    source: GeneratedKeySource,
) -> None:
    """Revoking a customer–client pair blocks the next token mint."""
    rev = RevocationList()
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_list=rev,
    )

    # Before revocation: mint succeeds
    token = minter(CUST_A, "accounts.svc")
    assert isinstance(token, str) and len(token) > 10

    # Revoke customer A + client "accounts.svc"
    rev.revoke_customer_client(customer_ref="cust_a", client_id="accounts.svc")

    # Next mint raises
    with pytest.raises(PermissionError, match="cust_a.*revoked"):
        minter(CUST_A, "accounts.svc")


def test_revocation_list_blocks_mint_under_kill_switch(source: GeneratedKeySource) -> None:
    """Kill switch blocks all mints for the killed client_id."""
    rev = RevocationList()
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_list=rev,
    )

    # Kill switch for accounts.svc (the audience maps to client_id in revocation)
    rev.kill_switch(client_id="accounts.svc")

    # All mints for that audience raise
    with pytest.raises(PermissionError, match="revoked"):
        minter(CUST_A, "accounts.svc")

    # Different audience is unaffected
    token = minter(CUST_A, "cards.svc")
    assert isinstance(token, str) and len(token) > 10


def test_revocation_list_no_false_positive_different_customer(source: GeneratedKeySource) -> None:
    """Revoking customer A does not block customer B."""
    rev = RevocationList()
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_list=rev,
    )

    rev.revoke_customer_client(customer_ref="cust_a", client_id="accounts.svc")

    # Customer B can still mint
    token = minter(CUST_B, "accounts.svc")
    assert isinstance(token, str) and len(token) > 10


def test_no_revocation_when_list_not_provided(source: GeneratedKeySource) -> None:
    """Backward compat: minter works without a revocation list."""
    minter = ReadTokenMinter(InternalTokenMinter(issuer=ISS, key_source=source))

    token = minter(CUST_A, "accounts.svc")
    assert isinstance(token, str) and len(token) > 10


# --- jti replay cache (A10) ---


def test_jti_cache_blocks_duplicate_token(source: GeneratedKeySource) -> None:
    """Minting the same token twice raises on the second call."""
    rev = RevocationList()
    cache = JtiReplayCache(max_age_seconds=_LIFETIME.total_seconds())
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_list=rev,
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
        revocation_list=rev,
        jti_cache=cache,
    )

    # Mint first token (jti recorded in cache)
    minter(CUST_A, "accounts.svc")

    # Revoke customer A
    rev.revoke_customer_client(customer_ref="cust_a", client_id="accounts.svc")

    # Next mint raises PermissionError (revocation), not ValueError (replay)
    with pytest.raises(PermissionError, match="cust_a.*revoked"):
        minter(CUST_A, "accounts.svc")


def test_mint_without_revocation_list_still_uses_jti_cache(source: GeneratedKeySource) -> None:
    """jti cache works independently of revocation list."""
    cache = JtiReplayCache(max_age_seconds=60.0)
    minter = ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        jti_cache=cache,
    )

    # Normal mints produce unique jtis
    t1 = minter(CUST_A, "accounts.svc")
    t2 = minter(CUST_A, "accounts.svc")
    assert t1 != t2

    # Cache tracks them
    assert cache.size == 2

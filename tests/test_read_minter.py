import pytest
from joserfc import jwt
from joserfc.jwk import KeySet
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.auth.read_minter import READ_SCOPES, ReadTokenMinter
from postern_core.auth.revocation import unchecked_revocation
from postern_core.identity import CustomerRef

from services.confirm.minter import WRITE_SCOPES

CUST = CustomerRef(value="cust_7f3a")
ISS = "https://mcp-read.internal"


@pytest.fixture
def source() -> GeneratedKeySource:
    return GeneratedKeySource(kid="read-1")


@pytest.fixture
def minter(source: GeneratedKeySource) -> ReadTokenMinter:
    # This file measures scope derivation and the audience refusal, not ZT-7.
    # `unchecked_revocation` is the explicit opt-out the minter's refusing
    # default requires; see `postern_core.auth.revocation`'s
    # `require_revocation_decision` for why the default refuses instead.
    return ReadTokenMinter(
        InternalTokenMinter(issuer=ISS, key_source=source),
        revocation_decision=unchecked_revocation,
    )


def test_it_satisfies_the_token_minter_protocol(
    minter: ReadTokenMinter, source: GeneratedKeySource
) -> None:
    token = minter(CUST, "accounts.svc")
    keyset = KeySet.import_key_set(source.public_jwks())
    claims = jwt.decode(token, keyset, algorithms=["RS256"]).claims
    assert claims["sub"] == "cust_7f3a"
    assert claims["aud"] == "accounts.svc"


def test_the_scope_is_derived_from_the_audience(
    minter: ReadTokenMinter, source: GeneratedKeySource
) -> None:
    token = minter(CUST, "cards.svc")
    keyset = KeySet.import_key_set(source.public_jwks())
    claims = jwt.decode(token, keyset, algorithms=["RS256"]).claims
    assert claims["scope"] == "cards:read"


def test_every_derived_scope_is_a_read_scope() -> None:
    """A write scope reachable from the read minter would defeat the split
    even with the right key, because Istio matches on claims too."""
    for scope in READ_SCOPES.values():
        assert scope.endswith(":read"), scope


def test_an_unknown_audience_is_refused(minter: ReadTokenMinter) -> None:
    """Fail closed: an audience with no mapped read scope must not silently
    mint a token with an empty or guessed scope."""
    with pytest.raises(KeyError):
        minter(CUST, "ledger.svc")


def test_the_payments_audience_mints_the_read_scope_only(
    minter: ReadTokenMinter, source: GeneratedKeySource
) -> None:
    """Decision 0022. `payments:execute` is minted by `services/confirm` alone,
    with the write key."""
    token = minter(CUST, "payments.svc")
    keyset = KeySet.import_key_set(source.public_jwks())
    claims = jwt.decode(token, keyset, algorithms=["RS256"]).claims
    assert claims["aud"] == "payments.svc"
    assert claims["scope"] == "payments:read"
    assert set(READ_SCOPES.values()).isdisjoint(WRITE_SCOPES.values())

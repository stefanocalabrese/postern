"""InternalTokenMinter: RFC 8693 delegation token for one internal hop
(handoff §7.2). Customer as `sub`, service as `act.sub`, 60 second expiry, no
PII in claims because JWTs land in logs and traces.
"""

from datetime import UTC, datetime
from typing import Any

import pytest
from joserfc import jwt
from joserfc.errors import BadSignatureError, ExpiredTokenError, InvalidClaimError
from joserfc.jwk import KeySet
from joserfc.jwt import Claims
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.identity import CustomerRef

READ_ISS = "https://mcp-read.bank.internal"
CUST = CustomerRef(value="cust_7f3a")

_BASE_CLAIM_KEYS = {"iss", "sub", "act", "aud", "scope", "iat", "exp", "jti"}


@pytest.fixture
def minter() -> InternalTokenMinter:
    return InternalTokenMinter(issuer=READ_ISS, key_source=GeneratedKeySource(kid="read-1"))


def decode(minter: InternalTokenMinter, token: str) -> Claims:
    keyset = KeySet.import_key_set(minter.key_source.public_jwks())
    return jwt.decode(token, keyset, algorithms=["RS256"]).claims


def test_the_customer_is_the_subject_and_the_service_is_the_actor(
    minter: InternalTokenMinter,
) -> None:
    claims = decode(
        minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    )
    assert claims["sub"] == "cust_7f3a"
    assert claims["act"] == {"sub": "svc:postern"}


def test_the_token_carries_the_issuer_and_audience(minter: InternalTokenMinter) -> None:
    claims = decode(
        minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    )
    assert claims["iss"] == READ_ISS
    assert claims["aud"] == "accounts.svc"


def test_the_token_expires_in_sixty_seconds(minter: InternalTokenMinter) -> None:
    claims = decode(
        minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    )
    assert claims["exp"] - claims["iat"] == 60


def test_every_token_carries_an_exp(minter: InternalTokenMinter) -> None:
    """joserfc enforces exp only if present: a token without one validates
    forever. Measured. So the minter must always set it."""
    claims = decode(
        minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    )
    assert "exp" in claims


def test_each_token_has_a_unique_jti(minter: InternalTokenMinter) -> None:
    a = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    b = decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))
    assert a["jti"] != b["jti"]


def test_an_expired_token_is_rejected_by_a_claims_registry(minter: InternalTokenMinter) -> None:
    """jwt.decode checks the signature only. The registry is what enforces exp."""
    token = minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    claims = decode(minter, token)
    future = datetime.fromtimestamp(claims["exp"] + 1, tz=UTC)
    with pytest.raises(ExpiredTokenError):
        jwt.JWTClaimsRegistry(now=int(future.timestamp())).validate(claims)


def test_a_wrong_issuer_is_rejected_when_the_registry_declares_it(
    minter: InternalTokenMinter,
) -> None:
    claims = decode(
        minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    )
    with pytest.raises(InvalidClaimError):
        jwt.JWTClaimsRegistry(iss={"essential": True, "value": "https://elsewhere"}).validate(
            claims
        )


def test_optional_claims_are_absent_when_not_supplied(minter: InternalTokenMinter) -> None:
    claims = decode(
        minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    )
    assert "challenge_id" not in claims


def test_a_challenge_id_is_carried_when_supplied(minter: InternalTokenMinter) -> None:
    claims = decode(
        minter,
        minter.mint(
            subject=CUST, audience="payments.svc", scope="payments:execute", challenge_id="chg_1"
        ),
    )
    assert claims["challenge_id"] == "chg_1"


def test_no_customer_pii_reaches_the_claims(minter: InternalTokenMinter) -> None:
    """JWTs land in logs and traces (handoff §7.2). `sub` is an opaque ref."""
    claims = decode(
        minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    )
    blob = str(claims)
    assert "ES9121000418450200051332" not in blob
    assert "4111111111114417" not in blob


def test_the_header_names_the_signing_kid(minter: InternalTokenMinter) -> None:
    token = minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    keyset = KeySet.import_key_set(minter.key_source.public_jwks())
    assert jwt.decode(token, keyset, algorithms=["RS256"]).header["kid"] == "read-1"


# --- Adversarial pass ---------------------------------------------------


def test_the_same_token_is_accepted_before_expiry_and_rejected_after(
    minter: InternalTokenMinter,
) -> None:
    """`exp - iat == 60` only checks arithmetic. This proves enforcement: the
    SAME decoded claims are accepted by a registry whose injected clock sits
    before `exp`, and rejected by one whose clock sits after it."""
    claims = decode(
        minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    )
    exp = claims["exp"]

    jwt.JWTClaimsRegistry(now=exp - 1).validate(claims)  # does not raise

    with pytest.raises(ExpiredTokenError):
        jwt.JWTClaimsRegistry(now=exp + 1).validate(claims)


def test_a_token_cannot_be_verified_against_a_different_source_sharing_the_same_kid() -> None:
    """Two sources publishing the same kid is the realistic failure shape
    (a naming convention, not a shared secret). The signature must still not
    verify against the wrong key's public JWKS."""
    signing_source = GeneratedKeySource(kid="read-1")
    other_source = GeneratedKeySource(kid="read-1")
    minter = InternalTokenMinter(issuer=READ_ISS, key_source=signing_source)
    token = minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")

    wrong_keyset = KeySet.import_key_set(other_source.public_jwks())
    with pytest.raises(BadSignatureError):
        jwt.decode(token, wrong_keyset, algorithms=["RS256"])


def test_several_hundred_tokens_have_distinct_jtis(minter: InternalTokenMinter) -> None:
    """Two calls is a weak sample for uniqueness."""
    jtis = {
        decode(minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"))[
            "jti"
        ]
        for _ in range(300)
    }
    assert len(jtis) == 300


def test_a_raw_string_subject_is_not_silently_accepted(minter: InternalTokenMinter) -> None:
    """`subject` is typed `CustomerRef`, not `str`. mypy --strict rejects a
    bare string at the call site (verified separately); this proves the
    runtime path fails loudly too rather than embedding an unvalidated
    string as `sub`, for a caller that bypasses the type checker, e.g. a
    value typed `Any` at an external boundary."""
    bad_subject: Any = "cust_7f3a"
    with pytest.raises(AttributeError):
        minter.mint(subject=bad_subject, audience="accounts.svc", scope="accounts:read")


def test_the_claim_set_is_exactly_the_intended_set(minter: InternalTokenMinter) -> None:
    """Asserts the full key set so a future addition has to be deliberate,
    rather than checking individual keys and missing an extra one."""
    claims = decode(
        minter, minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
    )
    assert set(claims) == _BASE_CLAIM_KEYS


def test_the_claim_set_with_all_optional_claims_is_exactly_the_intended_set(
    minter: InternalTokenMinter,
) -> None:
    claims = decode(
        minter,
        minter.mint(
            subject=CUST,
            audience="payments.svc",
            scope="payments:execute",
            consent_id="cst_1",
            client_id="clt_1",
            challenge_id="chg_1",
        ),
    )
    assert set(claims) == _BASE_CLAIM_KEYS | {"consent_id", "client_id", "challenge_id"}


def test_joserfc_registry_aud_matches_a_list_containing_the_expected_value() -> None:
    """Characterises joserfc's own `aud` handling; it is not exercised by the
    minter, which always sets a single string audience. Recorded because a
    registry declaring one expected `aud` value still matches a token whose
    `aud` is a list that merely CONTAINS that value, so a future change that
    lets `aud` become a list would silently widen what a registry accepts."""
    claims = {"aud": ["accounts.svc", "other.svc"]}
    jwt.JWTClaimsRegistry(aud={"essential": True, "value": "accounts.svc"}).validate(
        claims
    )  # does not raise

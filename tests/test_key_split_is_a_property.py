"""The key split, tested as a capability rather than as a configuration.

Each test here asks: given everything the API process can actually produce,
does a simulated Istio write endpoint accept any of it? The answer must be no,
and it must become yes the moment someone wires the write key into the API.
"""

import pytest
from joserfc import jwt
from joserfc.errors import BadSignatureError, InvalidKeyIdError
from joserfc.jwk import KeySet, KeySetSerialization
from joserfc.jwt import Claims
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource, KeySource
from postern_core.auth.read_minter import READ_SCOPES, ReadTokenMinter
from postern_core.auth.revocation import unchecked_revocation
from postern_core.identity import CustomerRef

from services.confirm.minter import WriteTokenMinter, build_write_minter
from services.confirm.settings import ConfirmSettings

CUST = CustomerRef(value="cust_7f3a")
WRITE_ISS = "https://mcp-write.internal"


def istio_write_endpoint(token: str, write_jwks: KeySetSerialization) -> Claims:
    """What the gateway does: resolve the kid against THIS issuer's key set,
    then check the issuer claim. Both halves matter."""
    claims = jwt.decode(token, KeySet.import_key_set(write_jwks), algorithms=["RS256"]).claims
    jwt.JWTClaimsRegistry(iss={"essential": True, "value": WRITE_ISS}).validate(claims)
    return claims


@pytest.fixture
def write_service() -> tuple[WriteTokenMinter, KeySource]:
    """One `build_write_minter` call per test, shared by the minter and the
    JWKS below.

    `ConfirmSettings.for_testing()` leaves `write_key_pem_path` unset, so
    `_write_key_source` returns a `GeneratedKeySource`, which generates fresh
    2048-bit RSA material in its constructor. Two calls therefore publish two
    different keys under the same kid `write-1`, and every token here fails
    with `BadSignatureError` for a reason that has nothing to do with the
    read/write split: measured, the control test and the miswiring test both
    failed that way before this fixture existed.
    """
    return build_write_minter(ConfirmSettings.for_testing())


@pytest.fixture
def write_jwks(write_service: tuple[WriteTokenMinter, KeySource]) -> KeySetSerialization:
    return write_service[1].public_jwks()


@pytest.fixture
def api_minter() -> ReadTokenMinter:
    source = GeneratedKeySource(kid="read-1")
    return ReadTokenMinter(
        InternalTokenMinter(issuer="https://mcp-read.internal", key_source=source),
        # The key split, not ZT-7. No request, so no revocation decision.
        revocation_decision=unchecked_revocation,
    )


def test_no_token_the_api_can_mint_is_accepted_by_the_write_endpoint(
    api_minter: ReadTokenMinter, write_jwks: KeySetSerialization
) -> None:
    """Exhaustive over the API's whole mintable surface, so it survives
    someone adding a tool with a new audience."""
    for audience in READ_SCOPES:
        token = api_minter(CUST, audience)
        with pytest.raises(InvalidKeyIdError):
            istio_write_endpoint(token, write_jwks)


def test_a_matching_kid_does_not_rescue_a_token_signed_with_the_read_key(
    write_jwks: KeySetSerialization,
) -> None:
    """The split is cryptographic, not a naming convention.

    Every other rejection in this file raises `InvalidKeyIdError`: the write
    key set has no entry for kid `read-1`, so resolution fails before any
    signature is checked. Those assertions would keep passing if someone set
    `POSTERN_READ_KEY_KID` and `POSTERN_WRITE_KEY_KID` to the same string,
    which is exactly the misconfiguration worth catching. This test removes
    that escape: an API-side key labelled `write-1`, the kid the write JWKS
    does publish, resolves to the write public key and then fails on the
    signature.

    Measured against joserfc 1.7.5: `BadSignatureError('bad_signature: ')`,
    a sibling of `InvalidKeyIdError` under `JoseError` and not a subclass of
    it, so the two assertions cannot satisfy each other.
    """
    impostor = GeneratedKeySource(kid=ConfirmSettings.for_testing().write_key_kid)
    assert impostor.signing_key().kid in [key["kid"] for key in write_jwks["keys"]]

    liar = InternalTokenMinter(issuer=WRITE_ISS, key_source=impostor)
    token = liar.mint(subject=CUST, audience="payments.svc", scope="payments:execute")

    with pytest.raises(BadSignatureError):
        istio_write_endpoint(token, write_jwks)


def test_the_api_cannot_even_ask_for_a_write_audience(api_minter: ReadTokenMinter) -> None:
    with pytest.raises(KeyError):
        api_minter(CUST, "payments.svc")


def test_the_write_minter_is_accepted_by_the_write_endpoint(
    write_service: tuple[WriteTokenMinter, KeySource], write_jwks: KeySetSerialization
) -> None:
    """The control test. If this fails the others prove nothing, because a
    verifier that rejects everything would pass them all."""
    minter, _ = write_service
    token = minter.mint(
        subject_value="cust_7f3a", audience="payments.svc", scope="payments:execute"
    )
    assert istio_write_endpoint(token, write_jwks)["aud"] == "payments.svc"


def test_miswiring_the_write_key_into_the_api_is_caught(
    write_service: tuple[WriteTokenMinter, KeySource], write_jwks: KeySetSerialization
) -> None:
    """The regression this file exists for. Simulate the mistake: build the
    API's minter on the WRITE key source. The write endpoint then accepts it,
    so this test asserts the failure is detectable rather than silent."""
    _, write_source = write_service
    miswired = ReadTokenMinter(
        InternalTokenMinter(issuer=WRITE_ISS, key_source=write_source),
        revocation_decision=unchecked_revocation,
    )
    accepted = istio_write_endpoint(miswired(CUST, "accounts.svc"), write_jwks)
    assert accepted["iss"] == WRITE_ISS


def test_a_combined_key_set_would_defeat_the_split(
    api_minter: ReadTokenMinter, write_jwks: KeySetSerialization
) -> None:
    """Why there are two JWKS endpoints and not one.

    A process holding only the read key claims the write issuer and signs with
    the read key. Against a combined key set the gateway accepts it, because
    the read key is in the set that issuer resolves against. This test pins the
    reason so nobody 'simplifies' the two endpoints into one.
    """
    read_source = api_minter._minter.key_source
    liar = InternalTokenMinter(issuer=WRITE_ISS, key_source=read_source)
    token = liar.mint(subject=CUST, audience="payments.svc", scope="payments:execute")

    with pytest.raises(InvalidKeyIdError):
        istio_write_endpoint(token, write_jwks)

    combined: KeySetSerialization = {"keys": write_jwks["keys"] + read_source.public_jwks()["keys"]}
    assert istio_write_endpoint(token, combined)["iss"] == WRITE_ISS

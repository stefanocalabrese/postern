"""Signing through Vault's transit engine, with the wire mocked.

WHAT THIS FILE PROVES AND WHAT IT CANNOT. Every test here runs against an
``httpx2.MockTransport`` whose handler holds a real RSA private key and
performs a real PKCS#1 v1.5 signature, so the JWS this repository assembles is
verified by `joserfc` against a key set this repository built. That covers the
whole of the code under test: the request shape, the ``vault:vN:`` unwrapping,
the base64 conversion, the header and payload serialisation, the version
pinning, the cache, and every refusal.

It cannot prove that a real Vault accepts that request or returns that
response, because the handler below is this repository's own belief about the
transit API written down twice. `tests/test_vault_live.py` is where that belief
meets Vault 1.20.4 in a container, and it is the only file here that can settle
it.

THE HANDLER IS A FAITHFUL FAKE AND NOT A STUB, deliberately. It decodes
``input``, signs the bytes, and re-wraps the signature exactly as Vault does.
A stub returning a canned signature would pass every assertion about shape
while proving nothing about whether the bytes this module sends are the bytes
it means to sign -- which is the one mistake that produces tokens a gateway
rejects and no test catches.
"""

import base64
import json
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx2
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.auth.vault import (
    VaultTransitError,
    VaultTransitKeySource,
)
from postern_core.identity import CustomerRef

ADDRESS = "http://vault.test:8200"
TOKEN = "hvs.notarealtoken"  # noqa: S105
CUST = CustomerRef(value="cust_7f3a")

_PRIVATE_PARAMS = {"d", "p", "q", "dp", "dq", "qi"}


class FakeVault:
    """One transit mount, in Python, answering the two endpoints we call.

    ``versions`` maps a Vault key version to a real RSA private key, so
    `rotate` is genuinely a new key and not a relabelled one. ``requests``
    records every call for the shape assertions; ``fail_with`` makes the next
    call answer a status instead.
    """

    def __init__(self, *, key_name: str = "postern-read", mount: str = "transit") -> None:
        self.key_name = key_name
        self.mount = mount
        self.versions: dict[int, rsa.RSAPrivateKey] = {1: _rsa()}
        self.requests: list[httpx2.Request] = []
        self.fail_with: tuple[int, object] | None = None
        self.key_type = "rsa-2048"
        self.accepted_token = TOKEN

    def rotate(self) -> int:
        version = max(self.versions) + 1
        self.versions[version] = _rsa()
        return version

    @property
    def latest(self) -> int:
        return max(self.versions)

    def public_pem(self, version: int) -> str:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        return (
            self.versions[version]
            .public_key()
            .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            .decode()
        )

    def joserfc_key(self, version: int, kid: str) -> RSAKey:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        pem = self.versions[version].private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        return RSAKey.import_key(pem, parameters={"kid": kid, "use": "sig", "alg": "RS256"})

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.requests.append(request)
        if self.fail_with is not None:
            status, body = self.fail_with
            return httpx2.Response(status, json=body)
        if request.headers.get("X-Vault-Token") != self.accepted_token:
            return httpx2.Response(403, json={"errors": ["permission denied"]})
        path = request.url.path
        if path == f"/v1/{self.mount}/keys/{self.key_name}" and request.method == "GET":
            return httpx2.Response(
                200,
                json={
                    "data": {
                        "name": self.key_name,
                        "type": self.key_type,
                        "latest_version": self.latest,
                        "keys": {
                            str(v): {
                                "creation_time": "2026-09-29T00:00:00Z",
                                "name": self.key_type,
                                "public_key": self.public_pem(v),
                            }
                            for v in sorted(self.versions)
                        },
                    }
                },
            )
        if path == f"/v1/{self.mount}/sign/{self.key_name}" and request.method == "POST":
            body = json.loads(request.content)
            version = int(body.get("key_version", self.latest))
            signed = self.versions[version].sign(
                base64.b64decode(body["input"]), padding.PKCS1v15(), hashes.SHA256()
            )
            return httpx2.Response(
                200,
                json={
                    "data": {
                        "key_version": version,
                        "signature": f"vault:v{version}:{base64.b64encode(signed).decode()}",
                    }
                },
            )
        return httpx2.Response(404, json={"errors": ["no handler for route"]})


def _rsa() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def vault() -> FakeVault:
    return FakeVault()


class Clock:
    """A hand-wound monotonic clock, so a cache TTL is testable without sleeping."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def source(vault: FakeVault, clock: Clock) -> Iterator[VaultTransitKeySource]:
    src = VaultTransitKeySource(
        address=ADDRESS,
        key_name=vault.key_name,
        kid="read-1",
        token=TOKEN,
        public_key_ttl_seconds=300.0,
        transport=httpx2.MockTransport(vault),
        clock=clock,
    )
    yield src
    src.close()


def _segments(token: str) -> tuple[str, str, str]:
    header, payload, signature = token.split(".")
    return header, payload, signature


def _decode(segment: str) -> dict[str, object]:
    padded = segment + "=" * (-len(segment) % 4)
    result = json.loads(base64.urlsafe_b64decode(padded))
    assert isinstance(result, dict)
    return result


class TestTheTokenItProduces:
    def test_a_signed_token_verifies_against_the_key_set_it_publishes(
        self, source: VaultTransitKeySource
    ) -> None:
        """The whole contract in one assertion, and the one every other test
        in this class refines."""
        token = source.sign({"sub": CUST.value, "aud": "accounts.svc"})
        claims = jwt.decode(
            token, KeySet.import_key_set(source.public_jwks()), algorithms=["RS256"]
        ).claims
        assert claims["sub"] == CUST.value

    def test_the_header_and_payload_are_byte_identical_to_joserfcs_own(
        self, vault: FakeVault, source: VaultTransitKeySource
    ) -> None:
        """This module assembles a compact JWS by hand, because there is no
        private key to hand `joserfc.jwt.encode`. That hand assembly is the
        risk, and this is the test that removes it: the same claims, through
        `jwt.encode` on the very key the fake Vault signs with, must produce
        the same first two segments to the byte.

        If joserfc ever changes how it orders header members or serialises
        claims, this fails here rather than at a verifier that rejects the
        token for a reason it cannot describe.
        """
        claims = {"iss": "https://mcp-read.internal", "sub": CUST.value, "iat": 1790000000}
        kid = f"read-1.v{vault.latest}"
        theirs = jwt.encode(
            {"alg": "RS256", "kid": kid}, dict(claims), vault.joserfc_key(vault.latest, kid)
        )
        ours = source.sign(dict(claims))
        assert _segments(ours)[:2] == _segments(theirs)[:2]

    def test_the_whole_token_is_byte_identical_including_the_signature(
        self, vault: FakeVault, source: VaultTransitKeySource
    ) -> None:
        """PKCS#1 v1.5 is deterministic, so signing the same bytes with the
        same key twice gives the same signature. That makes the equivalence
        above testable end to end rather than only on two of three segments,
        and it is the reason this source asks Vault for ``pkcs1v15`` rather
        than ``pss``: a randomised signature would verify but could not be
        compared, and RS256 is defined as PKCS#1 v1.5 anyway.
        """
        claims = {"sub": CUST.value}
        kid = f"read-1.v{vault.latest}"
        theirs = jwt.encode(
            {"alg": "RS256", "kid": kid}, dict(claims), vault.joserfc_key(vault.latest, kid)
        )
        assert source.sign(dict(claims)) == theirs

    def test_the_header_names_the_algorithm_the_type_and_the_versioned_kid(
        self, source: VaultTransitKeySource
    ) -> None:
        header = _decode(_segments(source.sign({"sub": CUST.value}))[0])
        assert header == {"typ": "JWT", "alg": "RS256", "kid": "read-1.v1"}

    def test_the_signature_segment_carries_no_vault_prefix_and_no_padding(
        self, source: VaultTransitKeySource
    ) -> None:
        """``vault:v1:`` and standard base64 are Vault's wire format, not the
        JWS one. A token that carried either would be rejected by every
        verifier, and the failure would read as a bad signature."""
        signature = _segments(source.sign({"sub": CUST.value}))[2]
        assert "vault" not in signature
        assert "=" not in signature and "+" not in signature and "/" not in signature
        assert len(base64.urlsafe_b64decode(signature + "==")) == 256


class TestTheRequestItSends:
    def test_it_posts_the_signing_input_to_the_configured_mount_and_key(
        self, vault: FakeVault, source: VaultTransitKeySource
    ) -> None:
        token = source.sign({"sub": CUST.value})
        sign_calls = [r for r in vault.requests if r.method == "POST"]
        assert len(sign_calls) == 1
        request = sign_calls[0]
        assert request.url.path == "/v1/transit/sign/postern-read"
        body = json.loads(request.content)
        header, payload, _ = _segments(token)
        assert base64.b64decode(body["input"]) == f"{header}.{payload}".encode()

    def test_it_asks_for_rs256_by_name_rather_than_taking_vaults_default(
        self, vault: FakeVault, source: VaultTransitKeySource
    ) -> None:
        """Vault's transit default for an RSA key is PSS, which is PS256 and
        not RS256. A header claiming RS256 over a PSS signature verifies
        nowhere."""
        source.sign({"sub": CUST.value})
        body = json.loads([r for r in vault.requests if r.method == "POST"][0].content)
        assert body["signature_algorithm"] == "pkcs1v15"
        assert body["hash_algorithm"] == "sha2-256"

    def test_it_pins_the_key_version_it_published(
        self, vault: FakeVault, source: VaultTransitKeySource
    ) -> None:
        """The property that makes rotation safe. Vault signs with the latest
        version by omission, so a rotation between the key read and the sign
        would produce a token whose kid names a version it was not signed
        with."""
        source.public_jwks()
        vault.rotate()
        source.sign({"sub": CUST.value})
        body = json.loads([r for r in vault.requests if r.method == "POST"][0].content)
        assert body["key_version"] == 1

    def test_the_token_travels_in_the_vault_header_and_not_in_a_query_string(
        self, vault: FakeVault, source: VaultTransitKeySource
    ) -> None:
        source.sign({"sub": CUST.value})
        for request in vault.requests:
            assert request.headers["X-Vault-Token"] == TOKEN
            assert TOKEN not in str(request.url)

    def test_a_custom_mount_reaches_a_custom_path(self) -> None:
        vault = FakeVault(mount="postern-transit")
        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name=vault.key_name,
            kid="read-1",
            token=TOKEN,
            mount="postern-transit",
            transport=httpx2.MockTransport(vault),
        )
        src.sign({"sub": CUST.value})
        assert vault.requests[0].url.path.startswith("/v1/postern-transit/")
        src.close()


class TestThePublishedKeySet:
    def test_it_publishes_every_version_vault_holds_each_under_its_own_kid(
        self, vault: FakeVault, source: VaultTransitKeySource, clock: Clock
    ) -> None:
        """Why the kid carries the version. A rotation under ONE kid makes
        every token minted after it fail at a verifier still holding the old
        public key, as `joserfc.errors.BadSignatureError('bad_signature: ')`
        -- an empty description that reads like a forged token. Publishing
        both versions means the old tokens keep verifying and the new ones
        verify the moment the verifier refetches, and a verifier that has not
        refetched gets `InvalidKeyIdError`, which names the problem.
        """
        source.public_jwks()
        vault.rotate()
        clock.advance(301.0)
        kids = {key["kid"] for key in source.public_jwks()["keys"]}
        assert kids == {"read-1.v1", "read-1.v2"}

    def test_a_token_minted_before_a_rotation_still_verifies_after_it(
        self, vault: FakeVault, source: VaultTransitKeySource, clock: Clock
    ) -> None:
        before = source.sign({"sub": CUST.value})
        vault.rotate()
        clock.advance(301.0)
        after = source.sign({"sub": CUST.value})
        key_set = KeySet.import_key_set(source.public_jwks())
        assert jwt.decode(before, key_set, algorithms=["RS256"]).header["kid"] == "read-1.v1"
        assert jwt.decode(after, key_set, algorithms=["RS256"]).header["kid"] == "read-1.v2"

    def test_it_carries_no_private_parameters(self, source: VaultTransitKeySource) -> None:
        doc = source.public_jwks()
        assert set(doc) == {"keys"}
        for entry in doc["keys"]:
            assert set(entry) & _PRIVATE_PARAMS == set(), entry
            assert entry["alg"] == "RS256"
            assert entry["use"] == "sig"

    def test_it_is_json_serialisable(self, source: VaultTransitKeySource) -> None:
        json.dumps(source.public_jwks())


class TestTheCache:
    def test_the_public_key_is_read_once_and_then_reused(
        self, vault: FakeVault, source: VaultTransitKeySource
    ) -> None:
        """A key read per signature would double this path's Vault traffic for
        a value that changes only on rotation."""
        for _ in range(5):
            source.sign({"sub": CUST.value})
        source.public_jwks()
        assert len([r for r in vault.requests if r.method == "GET"]) == 1

    def test_the_cache_expires_and_the_next_call_reads_again(self, vault: FakeVault) -> None:
        now = [0.0]
        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name=vault.key_name,
            kid="read-1",
            token=TOKEN,
            public_key_ttl_seconds=300.0,
            transport=httpx2.MockTransport(vault),
            clock=lambda: now[0],
        )
        src.sign({"sub": CUST.value})
        now[0] = 299.0
        src.sign({"sub": CUST.value})
        assert len([r for r in vault.requests if r.method == "GET"]) == 1
        now[0] = 301.0
        src.sign({"sub": CUST.value})
        assert len([r for r in vault.requests if r.method == "GET"]) == 2
        src.close()

    def test_a_rotation_is_picked_up_one_ttl_later_and_not_before(self, vault: FakeVault) -> None:
        """The whole cost of caching, stated as a test. Between a rotation and
        the next refresh this source keeps signing with the version it
        published, which is correct but not current."""
        now = [0.0]
        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name=vault.key_name,
            kid="read-1",
            token=TOKEN,
            public_key_ttl_seconds=60.0,
            transport=httpx2.MockTransport(vault),
            clock=lambda: now[0],
        )
        src.sign({"sub": CUST.value})
        vault.rotate()
        now[0] = 30.0
        assert _decode(_segments(src.sign({"sub": CUST.value}))[0])["kid"] == "read-1.v1"
        now[0] = 61.0
        assert _decode(_segments(src.sign({"sub": CUST.value}))[0])["kid"] == "read-1.v2"
        src.close()


class TestItFailsClosed:
    def test_a_denied_sign_raises_rather_than_returning_an_unsigned_token(
        self, vault: FakeVault, source: VaultTransitKeySource
    ) -> None:
        source.public_jwks()
        vault.fail_with = (403, {"errors": ["1 error occurred:\n\t* permission denied\n\n"]})
        with pytest.raises(VaultTransitError, match="403"):
            source.sign({"sub": CUST.value})

    def test_a_refusal_names_the_path_and_vaults_own_error(
        self, vault: FakeVault, source: VaultTransitKeySource
    ) -> None:
        source.public_jwks()
        vault.fail_with = (403, {"errors": ["permission denied"]})
        with pytest.raises(VaultTransitError) as caught:
            source.sign({"sub": CUST.value})
        assert "transit/sign/postern-read" in str(caught.value)
        assert "permission denied" in str(caught.value)

    def test_no_refusal_ever_carries_the_vault_token(
        self, vault: FakeVault, source: VaultTransitKeySource, clock: Clock
    ) -> None:
        """The credential is in every request this module sends, so every
        message built around a failed one is a place it can leak. Checked on
        both endpoints, because only one of them is on the hot path and the
        other is the one nobody looks at."""
        for status in (403, 500, 503):
            vault.fail_with = (status, {"errors": ["denied"]})
            clock.advance(301.0)
            with pytest.raises(VaultTransitError) as caught:
                source.public_jwks()
            assert TOKEN not in str(caught.value)
            with pytest.raises(VaultTransitError) as caught:
                source.sign({"sub": CUST.value})
            assert TOKEN not in str(caught.value)

    def test_an_unreachable_vault_raises_rather_than_hanging(self, vault: FakeVault) -> None:
        def refuse(_: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused")

        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name="postern-read",
            kid="read-1",
            token=TOKEN,
            transport=httpx2.MockTransport(refuse),
        )
        with pytest.raises(VaultTransitError, match="unreachable"):
            src.sign({"sub": CUST.value})
        src.close()

    def test_a_non_rsa_transit_key_is_refused_by_name(self, vault: FakeVault) -> None:
        """An ed25519 transit key answers the read endpoint happily and then
        cannot produce an RS256 signature. Refusing on the declared type names
        the mistake; letting joserfc refuse the PEM names a parse error."""
        vault.key_type = "ed25519"
        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name=vault.key_name,
            kid="read-1",
            token=TOKEN,
            transport=httpx2.MockTransport(vault),
        )
        with pytest.raises(VaultTransitError, match="ed25519"):
            src.public_jwks()
        src.close()

    def test_a_signature_for_the_wrong_version_is_refused(self, vault: FakeVault) -> None:
        """Vault reports which version signed. If that is not the version this
        source pinned, the kid in the header names a key that did not make the
        signature, and every verifier would report a bad signature instead."""

        def lie(request: httpx2.Request) -> httpx2.Response:
            response = vault(request)
            if request.method == "POST":
                body = response.json()
                body["data"]["key_version"] = 99
                return httpx2.Response(200, json=body)
            return response

        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name=vault.key_name,
            kid="read-1",
            token=TOKEN,
            transport=httpx2.MockTransport(lie),
        )
        with pytest.raises(VaultTransitError, match="version"):
            src.sign({"sub": CUST.value})
        src.close()


class TestTheVaultCredential:
    def test_a_token_file_is_read_rather_than_a_literal(
        self, vault: FakeVault, tmp_path: Path
    ) -> None:
        """The Vault Agent sink shape: the agent writes the token to a file and
        rewrites it on every renewal."""
        path = tmp_path / "vault.token"
        path.write_text(f"{TOKEN}\n")
        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name=vault.key_name,
            kid="read-1",
            token_path=path,
            transport=httpx2.MockTransport(vault),
        )
        src.sign({"sub": CUST.value})
        assert vault.requests[0].headers["X-Vault-Token"] == TOKEN
        src.close()

    def test_a_rewritten_token_file_is_picked_up_on_the_next_call(
        self, vault: FakeVault, tmp_path: Path
    ) -> None:
        """Read per call and never cached, because a Vault Agent renewing a
        token writes a NEW one and a cached value would start answering 403 at
        the moment the old one expired -- on the signing path, which is every
        backend call."""
        path = tmp_path / "vault.token"
        path.write_text("stale-token")
        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name=vault.key_name,
            kid="read-1",
            token_path=path,
            transport=httpx2.MockTransport(vault),
        )
        with pytest.raises(VaultTransitError):
            src.sign({"sub": CUST.value})
        path.write_text(TOKEN)
        src.sign({"sub": CUST.value})
        src.close()

    def test_neither_a_token_nor_a_path_is_refused_at_construction(self) -> None:
        with pytest.raises(ValueError, match="POSTERN_VAULT_TOKEN"):
            VaultTransitKeySource(address=ADDRESS, key_name="postern-read", kid="read-1")

    def test_both_a_token_and_a_path_is_refused_at_construction(self, tmp_path: Path) -> None:
        """Ambiguity in a credential is worth a refusal: an operator who added
        a token file and forgot to remove the literal would be authenticating
        with whichever this module happened to prefer, which is exactly the
        state in which a revoked credential looks like it still works."""
        path = tmp_path / "vault.token"
        path.write_text(TOKEN)
        with pytest.raises(ValueError, match="both"):
            VaultTransitKeySource(
                address=ADDRESS, key_name="postern-read", kid="read-1", token=TOKEN, token_path=path
            )

    def test_a_missing_token_file_fails_loudly(self, tmp_path: Path) -> None:
        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name="postern-read",
            kid="read-1",
            token_path=tmp_path / "absent",
            transport=httpx2.MockTransport(lambda r: httpx2.Response(200)),
        )
        with pytest.raises(VaultTransitError, match="absent"):
            src.sign({"sub": CUST.value})
        src.close()


class TestTheKeyIsNotInThisProcess:
    def test_the_source_exposes_no_signing_key_method(self, source: VaultTransitKeySource) -> None:
        """The whole point of the change, asserted where a refactor would trip
        over it. `GeneratedKeySource` and `FileKeySource` keep `signing_key()`
        because they genuinely hold one; this source must not grow one, because
        there is nothing it could return that is not either a lie or a key that
        should never have left Vault.
        """
        assert not hasattr(source, "signing_key")

    def test_no_attribute_anywhere_in_the_object_holds_private_key_material(
        self, source: VaultTransitKeySource
    ) -> None:
        """A sweep rather than a named check, so a future field that cached a
        private key would be caught without anyone remembering to add a test.
        `is_private` is joserfc's own answer to the question."""
        source.sign({"sub": CUST.value})
        for name, value in vars(source).items():
            assert not isinstance(value, rsa.RSAPrivateKey), name
            if isinstance(value, RSAKey):
                assert not value.is_private, name
        for entry in source.public_jwks()["keys"]:
            assert set(entry) & _PRIVATE_PARAMS == set()

    def test_the_cached_key_set_holds_public_keys_only(self, source: VaultTransitKeySource) -> None:
        source.sign({"sub": CUST.value})
        for key in source._key_set.keys:
            assert key.is_private is False


class TestItSubstitutesForALocalKeySource:
    def test_the_minter_signs_through_it_unchanged(self, source: VaultTransitKeySource) -> None:
        """`InternalTokenMinter` is above the seam and must not know which
        implementation it holds."""
        minter = InternalTokenMinter(issuer="https://mcp-read.internal", key_source=source)
        token = minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
        claims = jwt.decode(
            token, KeySet.import_key_set(source.public_jwks()), algorithms=["RS256"]
        ).claims
        assert claims["iss"] == "https://mcp-read.internal"
        assert claims["act"] == {"sub": "svc:postern"}
        assert claims["aud"] == "accounts.svc"

    def test_the_startup_probe_passes_over_it(self, source: VaultTransitKeySource) -> None:
        """`refuse_unverifiable_minter` mints one token and verifies it against
        the published set. Over a Vault source that is two round trips at
        startup, and it is what turns an unreachable Vault into a container
        that never becomes ready rather than one that 500s every tool call."""
        from postern_core.auth.minter_probe import refuse_unverifiable_minter

        minter = InternalTokenMinter(issuer="https://mcp-read.internal", key_source=source)
        refuse_unverifiable_minter(
            lambda: minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"),
            built=minter,
            key_source=source,
            role="READ",
        )

    def test_the_startup_probe_refuses_when_vault_is_unreachable(self, vault: FakeVault) -> None:
        from postern_core.auth.minter_probe import refuse_unverifiable_minter

        def refuse(_: httpx2.Request) -> httpx2.Response:
            raise httpx2.ConnectError("connection refused")

        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name="postern-read",
            kid="read-1",
            token=TOKEN,
            transport=httpx2.MockTransport(refuse),
        )
        minter = InternalTokenMinter(issuer="https://mcp-read.internal", key_source=src)
        with pytest.raises(VaultTransitError):
            refuse_unverifiable_minter(
                lambda: minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read"),
                built=minter,
                key_source=src,
                role="READ",
            )
        src.close()

    def test_two_sources_over_two_transit_keys_produce_disjoint_key_sets(self) -> None:
        """The key split, at this seam. Same property
        `tests/test_key_sources.py` asserts for the local sources."""
        read_vault = FakeVault(key_name="postern-read")
        write_vault = FakeVault(key_name="postern-write")
        read = VaultTransitKeySource(
            address=ADDRESS,
            key_name="postern-read",
            kid="read-1",
            token=TOKEN,
            transport=httpx2.MockTransport(read_vault),
        )
        write = VaultTransitKeySource(
            address=ADDRESS,
            key_name="postern-write",
            kid="write-1",
            token=TOKEN,
            transport=httpx2.MockTransport(write_vault),
        )
        read_kids = {e["kid"] for e in read.public_jwks()["keys"]}
        write_kids = {e["kid"] for e in write.public_jwks()["keys"]}
        assert read_kids.isdisjoint(write_kids)
        read.close()
        write.close()

    def test_a_local_source_and_a_vault_source_are_interchangeable_to_the_probe(
        self, source: VaultTransitKeySource
    ) -> None:
        """Both satisfy `KeySource`, which is what "nothing above this seam
        depends on which one is in use" means when it is checked rather than
        asserted."""
        from postern_core.auth.keys import KeySource

        sources: list[KeySource] = [GeneratedKeySource(kid="read-1"), source]
        for candidate in sources:
            token = candidate.sign({"sub": CUST.value})
            assert (
                jwt.decode(
                    token, KeySet.import_key_set(candidate.public_jwks()), algorithms=["RS256"]
                ).claims["sub"]
                == CUST.value
            )


class TestClosing:
    def test_close_is_idempotent(self, vault: FakeVault) -> None:
        """`create_app`'s lifespan calls it once, but a failed startup can run
        teardown on a half-built app."""
        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name=vault.key_name,
            kid="read-1",
            token=TOKEN,
            transport=httpx2.MockTransport(vault),
        )
        src.close()
        src.close()

    def test_the_local_sources_close_without_holding_anything(self) -> None:
        GeneratedKeySource(kid="read-1").close()


class TestTheTimeoutIsBounded:
    def test_every_phase_carries_the_configured_budget(self, vault: FakeVault) -> None:
        """A bare float on `httpx2.Client(timeout=...)` applies independently
        to connect, read, write and pool, so "one second" is a worst case of
        four. Stating all four makes that arithmetic visible rather than
        accidental -- the same reading `services/api/main.py::_backend_timeout`
        already applies to the backend client."""
        src = VaultTransitKeySource(
            address=ADDRESS,
            key_name=vault.key_name,
            kid="read-1",
            token=TOKEN,
            timeout_seconds=1.5,
            transport=httpx2.MockTransport(vault),
        )
        timeout = src._client.timeout
        assert timeout.connect == 1.5
        assert timeout.read == 1.5
        assert timeout.write == 1.5
        assert timeout.pool == 1.5
        src.close()


def test_the_handler_in_this_file_is_a_faithful_fake(vault: FakeVault) -> None:
    """A control on the control. Every assertion above is only worth what this
    fake is worth, so this one checks it signs with the key it publishes
    rather than returning something shaped like a signature."""
    signing_input = b"header.payload"
    handler: Callable[[httpx2.Request], httpx2.Response] = vault
    response = handler(
        httpx2.Request(
            "POST",
            f"{ADDRESS}/v1/transit/sign/postern-read",
            headers={"X-Vault-Token": TOKEN},
            json={
                "input": base64.b64encode(signing_input).decode(),
                "signature_algorithm": "pkcs1v15",
                "hash_algorithm": "sha2-256",
            },
        )
    )
    signature = base64.b64decode(response.json()["data"]["signature"].split(":")[2])
    vault.versions[1].public_key().verify(
        signature, signing_input, padding.PKCS1v15(), hashes.SHA256()
    )

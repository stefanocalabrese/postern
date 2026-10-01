"""The transit contract, against a real Vault in a container.

WHY THIS FILE EXISTS BESIDE `tests/test_vault_transit_key_source.py`. That one
drives an `httpx2.MockTransport` whose handler is this repository's own belief
about the transit API. It can prove that the bytes sent are the bytes meant and
that the JWS assembles correctly, and it cannot prove that Vault accepts the
request or returns what the handler returns -- because both halves of that
comparison were written here. This file settles it against
``hashicorp/vault:1.20`` (1.20.4 at the time of writing), and it is also the
only place the read/write split is measured as an AUTHORIZATION property rather
than a cryptographic one.

THE SPLIT HAS TWO HALVES AND ONLY ONE OF THEM IS IN THIS REPOSITORY.
`tests/test_key_split_is_a_property.py` measures the cryptographic half: no
token the API process can produce is accepted by a verifier holding the write
key set. That holds however the key is stored. The other half is new with
transit and is a Vault ACL: the api service's Vault token carries ``update`` on
``transit/sign/postern-read`` and NOTHING on ``transit/sign/postern-write``, so
a compromised read process cannot obtain a write signature even though it knows
the key's name, the mount and the address. `TestTheReadServiceCannotSignWithTheWriteKey`
below is that measurement, and it is a measurement rather than a promise
because the policies it applies are the ones an operator writes.

WHAT IT COSTS `make ci`: one container start, measured in the module-level
comment on `vault` below. It skips, loudly, when Docker is unreachable -- the
same shape `tests/conftest.py`'s `pg_url` and `redis_url` use, and for the same
reason: a 15-frame `DockerException` per dependent test is not a useful way to
say "start Docker".
"""

import base64
import json
from collections.abc import Iterator
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any

import docker
import httpx2
import pytest
from docker.errors import DockerException
from fastmcp.server.http import StarletteWithLifespan
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError
from joserfc.jwk import KeySet, KeySetSerialization
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import choose_key_source
from postern_core.auth.revocation import decision_scope
from postern_core.auth.vault import (
    VaultSettings,
    VaultTransitError,
    VaultTransitKeySource,
)
from postern_core.identity import CustomerRef
from testcontainers.community.vault import VaultContainer

from services.api.main import create_app
from services.api.settings import Settings
from services.confirm.main import create_confirm_app
from services.confirm.minter import build_write_minter
from services.confirm.session_token import build_session_minter
from services.confirm.settings import ConfirmSettings

CUST = CustomerRef(value="cust_7f3a")
READ_KEY = "postern-read"
WRITE_KEY = "postern-write"
SESSION_KEY = "postern-session"
ROOT = "postern-live-root"  # noqa: S105 -- the dev-mode container's own token

#: What each service's Vault token is allowed to do, verbatim HCL.
#:
#: WRITTEN OUT RATHER THAN BUILT, because these two documents are the operator
#: deliverable. `dev-docs` is off limits to this change, so the thing an
#: operator copies into their Terraform lives here, where a test proves that
#: what it copies is what was measured. Note the shape: ``update`` on ONE sign
#: path and ``read`` on ONE key path. No wildcard, no ``transit/*``, and
#: nothing at all on ``transit/export/*`` -- which Vault would refuse anyway,
#: since a key created without ``exportable`` has no export to permit.
READ_POLICY = """
path "transit/sign/postern-read" { capabilities = ["update"] }
path "transit/keys/postern-read" { capabilities = ["read"] }
"""

#: The confirm service's policy: the write key and the session key, and since
#: the layer-1 session token nothing on the read key.
WRITE_POLICY = """
path "transit/sign/postern-write"   { capabilities = ["update"] }
path "transit/keys/postern-write"   { capabilities = ["read"] }
path "transit/sign/postern-session" { capabilities = ["update"] }
path "transit/keys/postern-session" { capabilities = ["read"] }
"""


@dataclass(frozen=True)
class LiveVault:
    """One dev-mode Vault, its address and the two scoped tokens in it."""

    address: str
    root_token: str
    read_token: str
    write_token: str

    def client(self, token: str) -> httpx2.Client:
        return httpx2.Client(base_url=self.address, headers={"X-Vault-Token": token}, timeout=10.0)


@pytest.fixture(scope="session")
def vault() -> Iterator[LiveVault]:
    """One Vault for the whole run, bootstrapped the way an operator does.

    SESSION-SCOPED for the reason `pg_url` and `redis_url` are: a container
    start is wall clock `make ci` pays before every commit. Measured on one
    developer machine: ~1.5s to start and ~0.4s to bootstrap the five objects
    below.

    THE FIVE STEPS ARE THE OPERATOR CHECKLIST, EXECUTED. Enable transit, create
    three RSA keys (read, write, session), write two policies, mint one token
    per policy. Nothing here
    is a test fixture's convenience: this is `docker-compose.yml`'s
    ``vault-init`` service in Python, and if the two ever disagree one of them
    is wrong about what a deployment needs.
    """
    try:
        docker.from_env().ping()
    except DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping Vault-backed tests: {exc}")
    with VaultContainer("hashicorp/vault:1.20", root_token=ROOT) as container:
        address = container.get_connection_url()
        with httpx2.Client(base_url=address, headers={"X-Vault-Token": ROOT}, timeout=30.0) as root:
            _raise_for(root.post("/v1/sys/mounts/transit", json={"type": "transit"}))
            for name in (READ_KEY, WRITE_KEY, SESSION_KEY):
                _raise_for(root.post(f"/v1/transit/keys/{name}", json={"type": "rsa-2048"}))
            tokens = {}
            for name, policy in (("postern-read", READ_POLICY), ("postern-write", WRITE_POLICY)):
                _raise_for(root.put(f"/v1/sys/policies/acl/{name}", json={"policy": policy}))
                response = root.post(
                    "/v1/auth/token/create", json={"policies": [name], "ttl": "1h"}
                )
                _raise_for(response)
                tokens[name] = response.json()["auth"]["client_token"]
        yield LiveVault(
            address=address,
            root_token=ROOT,
            read_token=tokens["postern-read"],
            write_token=tokens["postern-write"],
        )


def _raise_for(response: httpx2.Response) -> httpx2.Response:
    if response.status_code >= 400:
        raise AssertionError(f"vault bootstrap failed: {response.status_code} {response.text}")
    return response


@pytest.fixture
def read_source(vault: LiveVault) -> Iterator[VaultTransitKeySource]:
    # THROUGH `choose_key_source`, not through the constructor, because this
    # fixture is also the assertion that the branch a composition root takes
    # under ``POSTERN_VAULT_ADDR`` reaches the Vault source at all.
    source = choose_key_source(
        role="READ",
        kid="read-1",
        vault=_credentialled(vault, vault.read_token),
        vault_key_name=READ_KEY,
        pem_path=None,
        pem_env_var="POSTERN_READ_KEY_PEM_PATH",
    )
    assert isinstance(source, VaultTransitKeySource)
    yield source
    source.close()


@pytest.fixture
def write_source(vault: LiveVault) -> Iterator[VaultTransitKeySource]:
    source = VaultTransitKeySource(
        address=vault.address,
        key_name=WRITE_KEY,
        kid="write-1",
        token=vault.write_token,
    )
    yield source
    source.close()


class TestTheWireContract:
    """The half `tests/test_vault_transit_key_source.py` cannot reach."""

    def test_a_token_signed_by_vault_verifies_against_the_key_vault_publishes(
        self, read_source: VaultTransitKeySource
    ) -> None:
        """The whole of it. If this passes, the request shape, the signature
        algorithm, the ``vault:v1:`` unwrapping and the base64 conversion are
        all right against Vault 1.20.4 -- and the mocked file's belief about
        each of them was correct."""
        minter = InternalTokenMinter(issuer="https://mcp-read.internal", key_source=read_source)
        token = minter.mint(subject=CUST, audience="accounts.svc", scope="accounts:read")
        claims = jwt.decode(
            token, KeySet.import_key_set(read_source.public_jwks()), algorithms=["RS256"]
        ).claims
        assert claims["sub"] == CUST.value
        assert claims["scope"] == "accounts:read"
        assert claims["act"] == {"sub": "svc:postern"}

    def test_the_published_kid_names_the_version_that_signed(
        self, read_source: VaultTransitKeySource
    ) -> None:
        token = read_source.sign({"sub": CUST.value})
        header = json.loads(_b64(token.split(".")[0]))
        assert header["kid"] == "read-1.v1"
        assert [key["kid"] for key in read_source.public_jwks()["keys"]] == ["read-1.v1"]

    def test_pss_would_not_have_verified_which_is_why_the_algorithm_is_named(
        self, vault: LiveVault, read_source: VaultTransitKeySource
    ) -> None:
        """A control on the choice, not on the code. Vault's default signature
        algorithm for an RSA transit key is PSS; RS256 is PKCS#1 v1.5. This
        asks Vault for the default and asserts the result does NOT verify as
        RS256, which is what makes ``signature_algorithm: pkcs1v15`` in the
        request body load-bearing rather than decorative.
        """
        header, payload, _ = read_source.sign({"sub": CUST.value}).split(".")
        signing_input = f"{header}.{payload}".encode()
        with vault.client(vault.read_token) as client:
            response = client.post(
                f"/v1/transit/sign/{READ_KEY}",
                json={"input": base64.b64encode(signing_input).decode(), "key_version": 1},
            )
        _raise_for(response)
        raw = base64.b64decode(response.json()["data"]["signature"].split(":")[2])
        forged = f"{header}.{payload}.{base64.urlsafe_b64encode(raw).rstrip(b'=').decode()}"
        with pytest.raises(Exception, match="bad_signature"):
            jwt.decode(
                forged, KeySet.import_key_set(read_source.public_jwks()), algorithms=["RS256"]
            )


class TestTheKeyNeverLeavesVault:
    """The property the whole change is bought for, asserted against Vault."""

    def test_vault_refuses_to_export_the_private_key_to_its_own_root_token(
        self, vault: LiveVault
    ) -> None:
        """NOT 403 from a policy, which an operator could widen. 400, because
        a transit key created without ``exportable`` has no export to permit
        and the capability does not exist to be granted.

        This is the whole difference between transit and a Vault Agent sidecar
        rendering a PEM. Under the sidecar the private key is a file, so a
        process that can read the file has the key and a root token can fetch
        it again; under transit there is no request, at any privilege level,
        that returns it.
        """
        with vault.client(vault.root_token) as client:
            response = client.get(f"/v1/transit/export/signing-key/{READ_KEY}")
        assert response.status_code == 400
        assert "not exportable" in response.text

    def test_the_key_is_not_marked_exportable(self, vault: LiveVault) -> None:
        """The state behind the refusal above, so a reader can tell the two
        apart: a key created ``exportable=true`` would answer that export 200
        and this test is what would say so."""
        with vault.client(vault.root_token) as client:
            data = _raise_for(client.get(f"/v1/transit/keys/{READ_KEY}")).json()["data"]
        assert data["exportable"] is False
        assert data["type"] == "rsa-2048"

    def test_the_process_holds_no_private_material_after_signing(
        self, read_source: VaultTransitKeySource
    ) -> None:
        read_source.sign({"sub": CUST.value})
        for entry in read_source.public_jwks()["keys"]:
            assert set(entry) & {"d", "p", "q", "dp", "dq", "qi"} == set()
        assert not hasattr(read_source, "signing_key")


class TestTheReadServiceCannotSignWithTheWriteKey:
    """The authorization half of the split, which only a real Vault can show.

    Every test here uses the token the API service would hold and reaches for
    something only the write service may have. A 403 is Vault refusing, not
    this repository declining.
    """

    def test_signing_with_the_write_key_is_refused(self, vault: LiveVault) -> None:
        """The whole scenario in one call: the read process knows the write
        key's name, the mount and the address, and still cannot sign."""
        impostor = VaultTransitKeySource(
            address=vault.address, key_name=WRITE_KEY, kid="write-1", token=vault.read_token
        )
        with pytest.raises(VaultTransitError, match="403"):
            impostor.sign({"sub": CUST.value, "aud": "payments.svc"})
        impostor.close()

    def test_even_reading_the_write_keys_public_half_is_refused(self, vault: LiveVault) -> None:
        impostor = VaultTransitKeySource(
            address=vault.address, key_name=WRITE_KEY, kid="write-1", token=vault.read_token
        )
        with pytest.raises(VaultTransitError, match="403"):
            impostor.public_jwks()
        impostor.close()

    def test_the_refusal_is_vaults_and_names_permission_denied(self, vault: LiveVault) -> None:
        with vault.client(vault.read_token) as client:
            response = client.post(
                f"/v1/transit/sign/{WRITE_KEY}",
                json={
                    "input": base64.b64encode(b"anything").decode(),
                    "signature_algorithm": "pkcs1v15",
                    "hash_algorithm": "sha2-256",
                },
            )
        assert response.status_code == 403
        assert "permission denied" in response.text

    def test_the_write_service_can_sign_with_the_write_key(
        self, write_source: VaultTransitKeySource
    ) -> None:
        """The control test. Without it every refusal above is satisfied by a
        Vault that refuses everything."""
        token = write_source.sign({"sub": CUST.value, "aud": "payments.svc"})
        claims = jwt.decode(
            token, KeySet.import_key_set(write_source.public_jwks()), algorithms=["RS256"]
        ).claims
        assert claims["aud"] == "payments.svc"

    def test_a_read_token_is_refused_by_a_verifier_holding_the_write_key_set(
        self, read_source: VaultTransitKeySource, write_source: VaultTransitKeySource
    ) -> None:
        """The cryptographic half, re-measured over real Vault keys. Same
        assertion `tests/test_key_split_is_a_property.py` makes over generated
        ones, and the reason both exist: that file proves the property holds
        for any key source, this one proves the two transit keys really are
        two keys."""
        token = read_source.sign({"sub": CUST.value, "aud": "payments.svc"})
        with pytest.raises(InvalidKeyIdError):
            jwt.decode(
                token, KeySet.import_key_set(write_source.public_jwks()), algorithms=["RS256"]
            )

    def test_the_two_key_sets_are_disjoint(
        self, read_source: VaultTransitKeySource, write_source: VaultTransitKeySource
    ) -> None:
        read_kids = {entry["kid"] for entry in read_source.public_jwks()["keys"]}
        write_kids = {entry["kid"] for entry in write_source.public_jwks()["keys"]}
        assert read_kids.isdisjoint(write_kids)
        assert _moduli(read_source.public_jwks()).isdisjoint(_moduli(write_source.public_jwks()))


class TestTheConfirmServiceSignsSessionsAndNothingOnTheReadKey:
    """The confirm token after the layer-1 session token: SESSION yes, READ no."""

    def test_the_session_minter_signs_through_the_session_transit_key(
        self, vault: LiveVault
    ) -> None:
        settings = ConfirmSettings(
            vault=_credentialled(vault, vault.write_token),
            vault_session_key_name=SESSION_KEY,
        )
        minter, source = build_session_minter(settings)
        claims = minter.prepare(customer=CUST, client_id="c", scope="accounts:read", sid="s")
        token = minter.sign(claims)
        decoded = jwt.decode(
            token, KeySet.import_key_set(source.public_jwks()), algorithms=["RS256"]
        )
        assert decoded.claims["jti"] == claims.jti
        assert decoded.header["kid"].startswith("session-1.v")
        source.close()

    def test_the_confirm_token_cannot_sign_with_the_read_key(self, vault: LiveVault) -> None:
        impostor = VaultTransitKeySource(
            address=vault.address, key_name=READ_KEY, kid="read-1", token=vault.write_token
        )
        with pytest.raises(VaultTransitError, match="403"):
            impostor.sign({"sub": CUST.value, "aud": "accounts.svc"})
        impostor.close()

    def test_the_api_token_cannot_sign_with_the_session_key(self, vault: LiveVault) -> None:
        impostor = VaultTransitKeySource(
            address=vault.address, key_name=SESSION_KEY, kid="session-1", token=vault.read_token
        )
        with pytest.raises(VaultTransitError, match="403"):
            impostor.sign({"sub": CUST.value, "aud": "https://mcp.postern.test/mcp"})
        impostor.close()

    async def test_session_jwks_publishes_the_versioned_session_kids(
        self, vault: LiveVault
    ) -> None:
        from postern_core.auth.device_keys import no_enrolled_devices

        settings = ConfirmSettings(
            app_assertion_jwks_uri="https://issuer.test/.well-known/jwks.json",
            app_assertion_issuer="https://issuer.test",
            app_assertion_audience="postern-confirm",
            vault=_credentialled(vault, vault.write_token),
            vault_write_key_name=WRITE_KEY,
            vault_session_key_name=SESSION_KEY,
            allow_non_uri_audience=True,
            allow_process_local_sessions=True,
        )
        app = create_confirm_app(settings, device_key_store=no_enrolled_devices())
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app), base_url="http://confirm.test"
        ) as client:
            session = (await client.get("/session/jwks.json")).json()
            write = (await client.get("/.well-known/jwks.json")).json()
        kids = [entry["kid"] for entry in session["keys"]]
        assert kids and all(kid.startswith("session-1.v") for kid in kids)
        assert _moduli(session).isdisjoint(_moduli(write))
        app.state.postern_session_key_source.close()
        app.state.postern_write_key_source.close()


class TestRotation:
    """What ``vault write -f transit/keys/<name>/rotate`` does to live tokens.

    ROTATED LAST, in its own class, because it changes the shared session
    fixture's state: after this runs the read key has two versions. Every
    assertion above that names ``read-1.v1`` would still hold -- a rotation
    adds a version and does not remove one -- but a reader should know the
    order is not accidental.
    """

    def test_a_rotation_adds_a_version_and_keeps_old_tokens_verifying(
        self, vault: LiveVault
    ) -> None:
        source = VaultTransitKeySource(
            address=vault.address,
            key_name=READ_KEY,
            kid="read-1",
            token=vault.read_token,
            public_key_ttl_seconds=0.001,
        )
        before = source.sign({"sub": CUST.value})
        with vault.client(vault.root_token) as client:
            _raise_for(client.post(f"/v1/transit/keys/{READ_KEY}/rotate", json={}))
        after = source.sign({"sub": CUST.value})

        key_set = KeySet.import_key_set(source.public_jwks())
        assert jwt.decode(before, key_set, algorithms=["RS256"]).header["kid"] == "read-1.v1"
        assert jwt.decode(after, key_set, algorithms=["RS256"]).header["kid"] == "read-1.v2"
        source.close()

    def test_a_verifier_that_has_not_refetched_reports_the_kid_and_not_a_bad_signature(
        self, vault: LiveVault
    ) -> None:
        """Why the kid carries the version, measured. A verifier holding only
        the pre-rotation key set answers `InvalidKeyIdError`, which names a key
        it does not have. Under one fixed kid the same situation answers
        `BadSignatureError('bad_signature: ')`, whose empty description reads
        like a forged token -- the failure
        `docs/verification/2026-09-18-multi-replica-jwks.md` measured for the
        ephemeral-key case and the one an operator most needs told apart from
        an attack.
        """
        source = VaultTransitKeySource(
            address=vault.address,
            key_name=READ_KEY,
            kid="read-1",
            token=vault.read_token,
            public_key_ttl_seconds=0.001,
        )
        stale = source.public_jwks()
        with vault.client(vault.root_token) as client:
            _raise_for(client.post(f"/v1/transit/keys/{READ_KEY}/rotate", json={}))
        fresh_token = source.sign({"sub": CUST.value})
        with pytest.raises(InvalidKeyIdError):
            jwt.decode(fresh_token, KeySet.import_key_set(stale), algorithms=["RS256"])
        source.close()


class TestTheCompositionRoots:
    """`create_app` and `build_write_minter`, over a real Vault."""

    def test_the_api_starts_and_mints_through_vault(self, vault: LiveVault) -> None:
        """`create_app` runs `refuse_unverifiable_minter`, which mints one
        token and verifies it against the key set this same process publishes.
        Over Vault that is two round trips before uvicorn serves, and a Vault
        that is down is therefore a container that never becomes ready."""
        app = create_app(_vault_settings(vault))
        with decision_scope(False):
            token = app.state.backend_client._minter(CUST, "accounts.svc")
        published = app.state.postern_read_key_source.public_jwks()
        claims = jwt.decode(token, KeySet.import_key_set(published), algorithms=["RS256"]).claims
        assert claims["scope"] == "accounts:read"
        assert [entry["kid"] for entry in published["keys"]][0].startswith("read-1.v")

    def test_the_api_refuses_to_start_when_vault_is_unreachable(self, vault: LiveVault) -> None:
        """Fail closed, at startup, on purpose. The alternative is a pod that
        passes its readiness probe and 500s every tool call; this one never
        becomes ready, so an orchestrator keeps the previous task set serving.
        `postern_core.auth.minter_probe`'s docstring predicted this trade
        before the code existed and asked that it be taken deliberately."""
        settings = _vault_settings(vault)
        broken = VaultSettings(
            address="http://127.0.0.1:1",
            token=vault.read_token,
            token_path=None,
            mount="transit",
            timeout_seconds=1.0,
            public_key_ttl_seconds=300.0,
        )
        with pytest.raises(VaultTransitError, match="unreachable"):
            create_app(
                Settings(
                    backend_base_url=settings.backend_base_url,
                    vault=broken,
                    vault_read_key_name=READ_KEY,
                )
            )

    def test_the_jwks_route_publishes_what_vault_holds(self, vault: LiveVault) -> None:
        app = create_app(_vault_settings(vault))
        route = next(r for r in app.routes if getattr(r, "path", None) == "/.well-known/jwks.json")
        assert route is not None
        published = app.state.postern_read_key_source.public_jwks()
        with vault.client(vault.read_token) as client:
            data = _raise_for(client.get(f"/v1/transit/keys/{READ_KEY}")).json()["data"]
        assert len(published["keys"]) == len(data["keys"])

    def test_the_write_minter_is_built_over_the_write_transit_key(self, vault: LiveVault) -> None:
        settings = ConfirmSettings(
            app_assertion_jwks_uri="https://issuer.test/.well-known/jwks.json",
            app_assertion_issuer="https://issuer.test",
            app_assertion_audience="postern-confirm",
            device_keys_path="/dev/null",
            vault=_credentialled(vault, vault.write_token),
            vault_write_key_name=WRITE_KEY,
        )
        minter, key_source = build_write_minter(settings)
        token = minter.mint(
            subject_value=CUST.value, audience="payments.svc", scope="payments:execute"
        )
        claims = jwt.decode(
            token, KeySet.import_key_set(key_source.public_jwks()), algorithms=["RS256"]
        ).claims
        assert claims["scope"] == "payments:execute"
        key_source.close()


async def test_a_real_tool_call_returns_masked_data_with_every_token_signed_by_vault(
    vault: LiveVault, pg_url: str
) -> None:
    """End to end: a `tools/call` over the assembled app, a real database, and
    a backend reached with a token Vault signed.

    This is the one test in `make ci` that exercises the whole path the change
    touches at once. The backend is an `httpx2.MockTransport` -- there is no
    operator backend to call in CI -- but the handler ASSERTS on the
    ``Authorization`` header it receives and verifies that bearer against the
    key set Vault publishes, so "a token was attached" is not what is being
    measured here. What is: the token that left this process was signed inside
    Vault and verifies against what Vault publishes, and the tool's answer is
    masked.
    """
    from tests.fixtures import backend_responses as fx

    verified: list[dict[str, Any]] = []
    published: dict[str, KeySetSerialization] = {}

    def handler(request: httpx2.Request) -> httpx2.Response:
        bearer = request.headers["Authorization"].removeprefix("Bearer ")
        claims = jwt.decode(
            bearer, KeySet.import_key_set(published["read"]), algorithms=["RS256"]
        ).claims
        verified.append(dict(claims))
        return httpx2.Response(200, json=fx.ACCOUNTS)

    settings = Settings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        vault=_credentialled(vault, vault.read_token),
        vault_read_key_name=READ_KEY,
    )
    app = create_app(settings, resolver=lambda: CUST, transport=httpx2.MockTransport(handler))
    published["read"] = app.state.postern_read_key_source.public_jwks()

    async with _lifespan(app):
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/mcp",
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Mcp-Method": "tools/call",
                    "Mcp-Name": "accounts.list",
                },
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "accounts.list", "arguments": {}},
                },
            )
    assert response.status_code == 200
    body = response.json()
    assert "error" not in body
    assert body["result"]["isError"] is False

    # The token really was Vault's: the handler above decoded it against the
    # key set Vault publishes, which no in-process key could have satisfied.
    assert len(verified) == 1
    assert verified[0]["sub"] == CUST.value
    assert verified[0]["scope"] == "accounts:read"

    # And the answer is masked. `tests/test_masking_golden.py` is the gate for
    # this property in general; the assertion here is that routing every
    # signature through Vault did not change what a caller receives.
    rendered = json.dumps(body)
    assert fx.FULL_IBAN not in rendered
    assert fx.FULL_IBAN[-4:] in rendered, "the masked tail should still be there"


def _vault_settings(vault: LiveVault) -> Settings:
    return Settings(
        backend_base_url="https://backend.test",
        vault=_credentialled(vault, vault.read_token),
        vault_read_key_name=READ_KEY,
    )


def _credentialled(vault: LiveVault, token: str) -> VaultSettings:
    return VaultSettings(
        address=vault.address,
        token=token,
        token_path=None,
        mount="transit",
        timeout_seconds=10.0,
        public_key_ttl_seconds=300.0,
    )


def _b64(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _moduli(jwks: KeySetSerialization) -> set[str]:
    return {str(entry["n"]) for entry in jwks["keys"]}


def _lifespan(app: StarletteWithLifespan) -> AbstractAsyncContextManager[None]:
    """`tests/test_asgi_app.py`'s lifespan pump, reused by import.

    Neither `httpx2.ASGITransport` nor `httpx2.AsyncClient` runs the ASGI
    lifespan protocol, and this app's shutdown is where the three resources --
    the backend client, the database and, since 2026-09-29, the Vault-backed
    `KeySource` -- are closed. Imported rather than copied: one pump, one place
    it can be wrong.
    """
    from tests.test_asgi_app import _drive_lifespan

    return _drive_lifespan(app)

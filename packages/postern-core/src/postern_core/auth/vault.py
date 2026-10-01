"""A signing key that stays inside Vault.

WHAT THIS REMOVES. `postern_core.auth.keys`' other two implementations hold an
`RSAKey` with private parameters on an instance attribute, so the private key
is in this process's heap and any imported code reaches it by attribute
access. Vault's transit engine generates the key inside Vault and signs inside
Vault; the only thing that crosses the wire in either direction is a hash
input and a signature. Measured against Vault 1.20.4 on 29 September 2026: a
transit key is created with ``exportable=false`` by default, and
``GET /v1/transit/export/signing-key/<name>`` answers **HTTP 400, "private key
material is not exportable"** to the ROOT token. Not 403 from a policy an
operator could widen -- 400, because there is no request that returns it. That
is the difference between this and a Vault Agent sidecar rendering a PEM,
which is `FileKeySource`: the sidecar shape moves where the key is STORED and
leaves it in the process; this moves where the key is USED.

WHY A COMPACT JWS IS ASSEMBLED HERE rather than by `joserfc.jwt.encode`.
`encode` wants a key object to sign with, and there is no key object -- that
is the point. So `sign` below builds the two base64url segments, sends their
concatenation to Vault, and appends what comes back. The risk in that is
divergence from what joserfc would have produced, and it is closed by
measurement rather than by care:
`tests/test_vault_transit_key_source.py::TestTheTokenItProduces::test_the_whole_token_is_byte_identical_including_the_signature`
signs the same claims through `jwt.encode` on the very key the fake Vault
holds and asserts the two tokens are equal as strings. PKCS#1 v1.5 is
deterministic, which is what makes that comparison possible at all, and RS256
is defined as PKCS#1 v1.5 anyway.

WHAT THE KID MEANS HERE, AND WHY IT IS NOT THE ONE IN SETTINGS. A local key
source publishes one key under the configured kid. Vault holds a key with
VERSIONS, and ``vault write -f transit/keys/<name>/rotate`` adds one without
changing its name. Under a single kid that rotation is invisible to a
verifier: it resolves the same kid to the public key it already cached and
reports `joserfc.errors.BadSignatureError('bad_signature: ')`, an empty
description that reads like a forged token. So the published kid is
``<configured kid>.v<version>`` and `public_jwks` publishes EVERY version
Vault still holds. Tokens minted before a rotation keep verifying, tokens
minted after it verify as soon as the verifier refetches, and a verifier that
has not refetched gets `InvalidKeyIdError`, which names the problem.

THE VERSION IS PINNED ON EVERY SIGNATURE, and that is what makes the above an
invariant rather than a race. Vault signs with the latest version when the
request omits ``key_version``, so between this process reading the key and
sending a signature a rotation would produce a token whose kid names a version
that did not sign it. Both values come from ONE read: the version in the
header and the version in the request body are the same number.

WHAT IT COSTS. Measured on one developer machine against
``hashicorp/vault:1.20`` in Docker over loopback, 50 signatures each: a transit
signature is **1777us** against **926us** for the same RS256 signature computed
in process, so the signing path pays about **+850us per backend call**. A key
read is 464us and happens once per TTL rather than once per call. Both numbers
are loopback; a real deployment pays its own network on top, which is why
`timeout_seconds` exists and why the API service's request deadline grew by
its worst case.

AND WHAT IT COSTS THAT IS NOT LATENCY. `postern_core.facade.client`'s
`TokenMinter` protocol is SYNCHRONOUS -- ``(customer, audience) -> str`` -- and
`BackendClient.get_json` calls it inline, so this round trip happens on the
event loop and no other task runs during it. Today's in-process signature
already blocks the loop for its 926us, but it blocks on CPU, which nothing can
yield during anyway; this blocks on a socket, which an async client would have
yielded. Making it yield means making `TokenMinter`, `ReadTokenMinter`,
`InternalTokenMinter.mint` and `BackendClient.get_json` async, which is four
layers above this seam, so it is not done here and is written down instead.
"""

from __future__ import annotations

import base64
import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx2
from joserfc.jwk import Key, KeyParameters, KeySet, KeySetSerialization, RSAKey
from joserfc.jwt import Claims
from joserfc.util import json_b64encode, to_bytes, urlsafe_b64encode

from postern_core.config import float_from_env

__all__ = [
    "DEFAULT_PUBLIC_KEY_TTL_SECONDS",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_TRANSIT_MOUNT",
    "VaultSettings",
    "VaultTransitError",
    "VaultTransitKeySource",
    "public_key_ttl_from_env",
    "vault_from_env",
]

#: Where an operator mounts the transit engine when they do not say otherwise.
DEFAULT_TRANSIT_MOUNT = "transit"

#: Per-PHASE budget for one Vault call, in seconds.
#:
#: Applied to connect, read, write and pool independently, so the worst case
#: for one call is four times this. One second is chosen against a measured
#: 1.8ms round trip over loopback and the deployment this repository describes,
#: where Vault is a sidecar or a same-VPC service; it is generous headroom for
#: jitter, not an expected latency. `services/api/settings.py`'s
#: ``request_deadline_seconds`` carries 4x this number as a term, so an
#: operator who raises this owes that line too.
DEFAULT_TIMEOUT_SECONDS = 1.0

#: How long a public key read is reused before Vault is asked again.
#:
#: The only thing this staleness can cost is signing with the previous key
#: version for up to this long after a rotation, which is correct but not
#: current -- never a token that fails to verify, because the version signed
#: with and the version published come from the same read. Five minutes
#: against a 464us read is roughly one read per replica per five minutes; the
#: alternative, a read per signature, doubles this path's Vault traffic to
#: track a value that changes when an operator runs a command.
DEFAULT_PUBLIC_KEY_TTL_SECONDS = 300.0


class VaultTransitError(RuntimeError):
    """Vault refused, failed, or answered something this module cannot use.

    ONE EXCEPTION FOR EVERY FAILURE, because every one of them has the same
    consequence: no signature, therefore no token, therefore no backend call.
    A caller that distinguished a 403 from a timeout would have nothing
    different to do with the answer, and the operator reading the message
    already has the status in it.

    NOTHING CONSTRUCTED HERE CARRIES THE VAULT TOKEN. The credential is in
    every request this module sends, so every message built around a failed
    one is a place it can leak;
    `tests/test_vault_transit_key_source.py::TestItFailsClosed::test_no_refusal_ever_carries_the_vault_token`
    drives both endpoints across three statuses and asserts it does not.
    """


@dataclass(frozen=True, slots=True)
class _Material:
    """One read of the transit key: the version to sign with, and every
    version's public half, already in JWKS form.

    A NAMED PAIR because the two must come from the same read. Holding them
    separately is how a rotation between them produces a token whose kid names
    a key that did not sign it, and the type makes that unwritable.
    """

    version: int
    key_set: KeySet
    read_at: float


class VaultTransitKeySource:
    """Signs through ``POST /v1/<mount>/sign/<key>`` and publishes what
    ``GET /v1/<mount>/keys/<key>`` returns.

    Args:
        address: Vault's base URL, e.g. ``https://vault.internal:8200``.
        key_name: The transit key's name. The read service and the write
            service name different keys, and an operator's policies are what
            make that a separation rather than a convention.
        kid: The kid PREFIX. What is published is ``<kid>.v<version>``; the
            module docstring says why.
        token: A Vault token, for a developer poking at a local stack.
        token_path: A file holding one, which is the shape a Vault Agent sink
            writes. Read on every call and never cached, because an agent
            renewing a token writes a new one and a cached value would start
            answering 403 at the moment the old one expired -- on the signing
            path, which is every backend call. Exactly one of ``token`` and
            ``token_path`` must be given.
        mount: Where transit is mounted.
        timeout_seconds: Per-phase budget; see `DEFAULT_TIMEOUT_SECONDS`.
        public_key_ttl_seconds: See `DEFAULT_PUBLIC_KEY_TTL_SECONDS`.
        transport: A test seam. `httpx2.MockTransport` is what
            `tests/test_vault_transit_key_source.py` passes; production passes
            nothing and gets a real connection pool.
        clock: A test seam for the TTL, `time.monotonic` in production.

    Raises:
        ValueError: if neither or both of ``token`` and ``token_path`` are
            given. Refused at construction rather than at first sign, so a
            misconfigured deployment fails while the composition root is still
            assembling and not at the first customer request.

    NOTHING IS FETCHED IN THE CONSTRUCTOR. `services/api/main.py`'s
    `create_app` builds this and then runs
    `postern_core.auth.minter_probe.refuse_unverifiable_minter`, which mints
    one token and verifies it against `public_jwks`, so an unreachable Vault
    stops startup a few lines later with a message about a minter rather than
    here with one about a constructor. That is deliberate and it is a trade
    `minter_probe`'s own docstring predicted: a Vault that is down turns the
    read service into a container that never becomes ready, not one that
    serves 500s. For an orchestrator that is the better failure -- the previous
    task set keeps serving -- and for a process whose whole job is minting
    these tokens there is nothing useful it could do while it cannot.
    """

    def __init__(
        self,
        *,
        address: str,
        key_name: str,
        kid: str,
        token: str | None = None,
        token_path: Path | None = None,
        mount: str = DEFAULT_TRANSIT_MOUNT,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        public_key_ttl_seconds: float = DEFAULT_PUBLIC_KEY_TTL_SECONDS,
        transport: httpx2.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        # THE CREDENTIAL BECOMES A ZERO-ARGUMENT READER HERE, once, rather than
        # a pair of fields branched on at every call. The match is both the
        # validation and the selection, so there is exactly one place either
        # argument is examined and no unreachable "neither" branch further in;
        # and a literal token never becomes an attribute an accidental `repr`
        # of this object could print.
        self._read_token: Callable[[], str]
        match (token, token_path):
            case (str() as literal, None):
                self._read_token = lambda: literal
            case (None, Path() as path):
                self._read_token = lambda: _token_from(path)
            case _:
                raise ValueError(
                    "VaultTransitKeySource needs exactly one credential: a `token` str "
                    "(POSTERN_VAULT_TOKEN) or a `token_path` Path "
                    "(POSTERN_VAULT_TOKEN_PATH), not both and not neither. Got "
                    f"token={type(token).__name__}, token_path={type(token_path).__name__}."
                )
        self._key_name = key_name
        self._kid = kid
        self._sign_path = f"/v1/{mount}/sign/{key_name}"
        self._keys_path = f"/v1/{mount}/keys/{key_name}"
        self._ttl = public_key_ttl_seconds
        self._clock = clock
        self._cached: _Material | None = None
        self._client = httpx2.Client(
            base_url=address,
            # Four phases named rather than one float, for the reason
            # `services/api/main.py::_backend_timeout` names them: a bare float
            # applies to each independently, so "one second" is a worst case of
            # four and the arithmetic should be visible where it is paid.
            timeout=httpx2.Timeout(
                connect=timeout_seconds,
                read=timeout_seconds,
                write=timeout_seconds,
                pool=timeout_seconds,
            ),
            transport=transport,
        )

    # -- KeySource -------------------------------------------------------

    def sign(self, claims: Claims) -> str:
        """One RS256 compact JWS over ``claims``, signed inside Vault."""
        material = self._material()
        kid = f"{self._kid}.v{material.version}"
        header = json_b64encode({"typ": "JWT", "alg": "RS256", "kid": kid})
        # joserfc's `_rfc7519.claims.convert_claims` is this one line, and the
        # duplication is deliberate: importing it would reach into a private
        # module for a `json.dumps` call, and the byte-identity test above the
        # class is what pins the two together on every run. The datetime
        # coercion that function also performs is absent because
        # `InternalTokenMinter` already writes `iat` and `exp` as ints.
        payload = urlsafe_b64encode(
            to_bytes(json.dumps(claims, ensure_ascii=False, separators=(",", ":")))
        )
        signing_input = header + b"." + payload
        data = self._post(
            self._sign_path,
            {
                "input": base64.b64encode(signing_input).decode("ascii"),
                # NAMED, never Vault's default. Transit's default for an RSA
                # key is PSS, which is PS256; a header claiming RS256 over a
                # PSS signature verifies nowhere.
                "signature_algorithm": "pkcs1v15",
                "hash_algorithm": "sha2-256",
                "key_version": material.version,
            },
        )
        signed_version = data.get("key_version")
        if signed_version != material.version:
            raise VaultTransitError(
                f"{self._sign_path} signed with key version {signed_version!r} but this "
                f"process asked for {material.version} and published its public half under "
                f"kid {kid!r}. A token whose kid names a version that did not sign it is "
                f"rejected as a bad signature, which reads like forgery."
            )
        return (signing_input + b"." + urlsafe_b64encode(_unwrap(data["signature"]))).decode(
            "ascii"
        )

    def public_jwks(self) -> KeySetSerialization:
        """Every key version Vault still holds, each under its own kid."""
        return self._material().key_set.as_dict()

    def close(self) -> None:
        """Release the connection pool. Idempotent: `httpx2.Client.close` is."""
        self._client.close()

    # -- internals -------------------------------------------------------

    @property
    def _key_set(self) -> KeySet:
        """The cached key set, for the test that sweeps it for private material."""
        return self._material().key_set

    def _material(self) -> _Material:
        cached = self._cached
        if cached is not None and self._clock() - cached.read_at < self._ttl:
            return cached
        data = self._get(self._keys_path)
        key_type = data.get("type")
        if not isinstance(key_type, str) or not key_type.startswith("rsa-"):
            raise VaultTransitError(
                f"transit key {self._key_name!r} is of type {key_type!r}; this source signs "
                f"RS256 and needs an RSA key. Create it with -type=rsa-2048 or rsa-4096."
            )
        version = int(data["latest_version"])
        keys: list[Key] = [
            RSAKey.import_key(
                entry["public_key"],
                parameters=_parameters(f"{self._kid}.v{number}"),
            )
            for number, entry in sorted(data["keys"].items(), key=lambda item: int(item[0]))
        ]
        material = _Material(version=version, key_set=KeySet(keys), read_at=self._clock())
        self._cached = material
        return material

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self._read_token()}

    def _get(self, path: str) -> dict[str, Any]:
        return self._data(path, lambda: self._client.get(path, headers=self._headers()))

    def _post(self, path: str, body: dict[str, object]) -> dict[str, Any]:
        return self._data(path, lambda: self._client.post(path, json=body, headers=self._headers()))

    def _data(self, path: str, call: Callable[[], httpx2.Response]) -> dict[str, Any]:
        """One request, and every way it can fail turned into one exception.

        ``httpx2.HTTPError`` is the base of connect errors, timeouts, protocol
        errors and pool timeouts alike, so the one `except` covers the whole
        transport surface; the status check covers the rest. Neither branch
        formats a header.
        """
        try:
            response = call()
        except httpx2.HTTPError as exc:
            raise VaultTransitError(
                f"Vault is unreachable at {path}: {type(exc).__name__}. No signature means no "
                f"internal token and no backend call, which is the intended direction: this "
                f"process fails closed rather than reaching a backend unauthenticated."
            ) from exc
        if response.status_code >= 400:
            raise VaultTransitError(
                f"{path} answered HTTP {response.status_code}: {_errors(response)}"
            )
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise VaultTransitError(
                f"{path} answered HTTP {response.status_code} with no `data` object. That is "
                f"not a transit endpoint; check POSTERN_VAULT_TRANSIT_MOUNT."
            )
        return data


def _parameters(kid: str) -> KeyParameters:
    return {"kid": kid, "use": "sig", "alg": "RS256"}


def _token_from(path: Path) -> str:
    """The Vault token a sink wrote, read fresh.

    Read per call and never cached: an agent renewing a token writes a NEW
    one into this file, and a value cached at startup would start answering
    403 the moment the old one expired -- on the signing path, which is every
    backend call. A file read is single-digit microseconds against the 1.8ms
    the round trip it precedes costs.
    """
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise VaultTransitError(
            f"cannot read the Vault token from {path}: {type(exc).__name__}. "
            f"POSTERN_VAULT_TOKEN_PATH names the file a Vault Agent sink writes; without it "
            f"this process can mint no token and will reach no backend."
        ) from exc


def _unwrap(signature: object) -> bytes:
    """``vault:v1:<standard base64>`` to raw bytes.

    Vault's wire format, not the JWS one. A signature segment that carried
    either the prefix or standard base64 would be rejected by every verifier,
    and the failure would read as a bad signature rather than as a formatting
    mistake.
    """
    if not isinstance(signature, str) or signature.count(":") != 2:
        raise VaultTransitError(
            f"transit returned a signature this module cannot read: expected "
            f"'vault:v<n>:<base64>', got {type(signature).__name__}."
        )
    return base64.b64decode(signature.split(":", 2)[2])


def _errors(response: httpx2.Response) -> str:
    """Vault's own ``errors`` array, or the body, capped.

    Vault does not echo the token in an error body -- checked against 1.20.4
    for 403, 400 and 404 -- but the cap is here anyway, for the same reason
    `postern_core.facade.client`'s `_detail` caps a backend body: an error
    string that lands in a log should not be able to carry an unbounded
    response.
    """
    try:
        body = response.json()
    except ValueError:
        return response.text[:200]
    if isinstance(body, dict) and isinstance(body.get("errors"), list):
        return "; ".join(str(item) for item in body["errors"])[:200]
    return str(body)[:200]


@dataclass(frozen=True, slots=True)
class VaultSettings:
    """What both services need to know about one Vault, parsed once.

    WHY IT IS PARSED IN ``postern_core`` AND NOT TWICE IN THE SERVICES. Same
    argument `postern_core/config.py` makes for `enforce_redis_requirement`:
    `.importlinter` forbids the two services importing each other, so a value
    both composition roots must read identically either lives in the one
    library they both import or is copied and drifts. Six of the eight
    ``POSTERN_VAULT_*`` variables are about the Vault, not about the key, so
    six are read here and attributed to both services. The two that name a KEY
    -- ``POSTERN_VAULT_READ_KEY_NAME`` and ``POSTERN_VAULT_WRITE_KEY_NAME`` --
    are read in each service's own ``from_env``, because which key a process
    may name is the whole of the read/write split and does not belong in a
    shared reader.

    IT HOLDS NO KEY NAME for the same reason, and that is worth stating as a
    property rather than an omission: there is no object in this codebase from
    which a process can obtain both a read and a write signing capability, and
    this type would have been the natural place for one to appear.
    """

    address: str
    token: str | None
    token_path: str | None
    mount: str
    timeout_seconds: float
    public_key_ttl_seconds: float


def vault_from_env() -> VaultSettings | None:
    """The Vault this deployment signs through, or ``None`` for no Vault.

    ``POSTERN_VAULT_ADDR`` is the switch, and its absence is the documented
    path rather than a degraded one: this repository is a framework, an
    operator without Vault must still be able to run it, and ``docker compose``
    must come up without one. Unset means the PEM and generated branches in
    `postern_core.auth.keys.choose_key_source` behave exactly as they did
    before this module existed.

    THE CREDENTIAL IS NOT VALIDATED HERE. ``VaultTransitKeySource``'s
    constructor refuses when neither or both of the two are set, which is one
    refusal in one place; repeating it here would be a second copy to keep in
    step, and this function has nothing to add to the message.
    """
    address = os.environ.get("POSTERN_VAULT_ADDR") or None
    if address is None:
        return None
    return VaultSettings(
        address=address,
        token=os.environ.get("POSTERN_VAULT_TOKEN") or None,
        token_path=os.environ.get("POSTERN_VAULT_TOKEN_PATH") or None,
        mount=os.environ.get("POSTERN_VAULT_TRANSIT_MOUNT", DEFAULT_TRANSIT_MOUNT),
        timeout_seconds=float_from_env(
            "POSTERN_VAULT_TIMEOUT_SECONDS",
            DEFAULT_TIMEOUT_SECONDS,
            minimum=0,
            exclusive=True,
            because=(
                "It bounds each phase of every call to Vault, and every internal token is "
                "signed by one of those calls; at zero httpx2 answers every request "
                "ConnectTimeout, so this process mints nothing and reaches no backend."
            ),
        ),
        public_key_ttl_seconds=public_key_ttl_from_env(),
    )


def public_key_ttl_from_env() -> float:
    """``POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS``, read in one place for two readers.

    `vault_from_env` above, for how long a transit key read is reused, and
    ``services/api``'s settings, for how long its session-token verifier
    trusts confirm's ``/session/jwks.json`` -- read whether or not a Vault is
    configured, because the session key rotates the same way under a PEM.
    """
    return float_from_env(
        "POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS",
        DEFAULT_PUBLIC_KEY_TTL_SECONDS,
        minimum=0,
        exclusive=True,
        because=(
            "It is how long a transit key read is reused before Vault is asked again; "
            "at zero every signature costs a second round trip to re-read a public key "
            "that changes only when an operator rotates it."
        ),
    )

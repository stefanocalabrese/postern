"""Where a signing key comes from.

This is the seam Vault landed behind on 29 September 2026. Nothing above it
knows whether the key was generated in process, read from a PEM a Vault Agent
sidecar rendered, or held inside Vault and never handed over at all --
`postern_core.auth.vault.VaultTransitKeySource` is the third, and
`tests/test_vault_live.py` is the test in this repo that does touch Vault,
against a real container.

THE SEAM IS A SIGNING CAPABILITY, NOT A KEY, and that is what the third
implementation is bought with. `signing_key()` used to be on the Protocol
below, so every caller above it could reach private key material by attribute
access and the only question Vault answered was where that material was
STORED. `sign(claims)` returns a token instead, so an implementation is free
to make the signature happen somewhere this process cannot reach. The two
local implementations keep `signing_key()` as a concrete method, because they
genuinely hold one and tests read it; the Vault one does not have it, and
`tests/test_vault_transit_key_source.py::TestTheKeyIsNotInThisProcess`
asserts that a refactor cannot give it one by accident.

WHAT THAT MOVED, EXACTLY. Under `GeneratedKeySource` and `FileKeySource` the
private key is an `RSAKey` on an instance attribute: anything holding a
reference to the source, or reached through it, can export it. Under the
Vault source the same sweep finds nothing, and Vault refuses to export the
material to its own root token (measured: HTTP 400, "private key material is
not exportable"). The seam is where that difference becomes invisible to
everything above.

joserfc's `kid` is read-only and has no setter: a bare PEM import yields
`kid=None`, which cannot be recovered afterwards, so every implementation
must supply the kid at construction.
"""

import warnings
from pathlib import Path
from typing import Protocol

from joserfc import jwt
from joserfc.jwk import KeyParameters, KeySet, KeySetSerialization, RSAKey
from joserfc.jwt import Claims

from postern_core.auth.vault import VaultSettings, VaultTransitKeySource


def _parameters(kid: str) -> KeyParameters:
    return {"kid": kid, "use": "sig", "alg": "RS256"}


def warn_ephemeral_signing_key(*, role: str, kid: str, pem_env_var: str) -> None:
    """Say out loud that the process just built a signing key it cannot keep.

    `GeneratedKeySource` is silent by construction, and so is every path to
    it. Until 29 September 2026 there were three such paths, one per
    composition root, and each called this immediately after its own
    fall-through; since `choose_key_source` below absorbed all three there is
    ONE call site, still immediately after the fall-through and still with the
    key already constructed. `services/api/main.py::_read_key_source`,
    `services/confirm/minter.py::_write_key_source` and
    `services/confirm/main.py::create_confirm_app` all reach it through that
    one function now, so a fourth key added anywhere gets this warning without
    anyone remembering to add it -- which is most of why the three copies were
    worth collapsing.

    UNCONDITIONAL, deliberately. It asks nothing about the deployment,
    because there is nothing in `Settings` or `ConfirmSettings` to ask: no
    `POSTERN_ENV`, no `environment` field. The guard `d203606` deleted,
    `_refuse_stub_minter_in_production`, inferred "production" from a
    settings shape (`customer_jwks_uri` and `customer_token_issuer` both set)
    rather than from what `create_app` had built, and once the real
    `ReadTokenMinter` replaced `StubTokenMinter` it refused exactly the
    genuine deployments and nothing else. A control that never forms an
    opinion about production cannot be wrong about one. The price is that
    `Settings.for_testing()`, `ConfirmSettings.for_testing()` and the local
    docker-compose stack all warn too; that noise is the accepted cost.

    A WARNING, never a refusal. Refusing here would stop `docker compose up`
    and every test that builds an app, and the way back would be a named
    override flag, which is precisely what `POSTERN_ALLOW_STUB_TOKEN_MINTER`
    was before `d203606` removed it. `RuntimeWarning` via `warnings.warn` is
    the mechanism `postern_core.facade.client.StubTokenMinter` already uses
    for the same "must be loud, cannot be fatal" case.

    The message names the consequence rather than the state, because
    "generated an ephemeral key" tells an operator nothing they can act on.
    What it costs is measured in
    `docs/verification/2026-09-18-multi-replica-jwks.md`.
    """
    warnings.warn(
        f"{role} signing key generated in process: {pem_env_var} is unset, so this "
        f"process built a fresh 2048-bit RSA key and will discard it on exit. "
        f"Every restart and every replica signs with a different key while the "
        f"published kid stays {kid!r}, which comes from settings and never from the "
        f"key, so a token minted here fails against any other replica's JWKS as "
        f"joserfc.errors.BadSignatureError('bad_signature: ') -- an empty description "
        f"that reads like a forged token, not the InvalidKeyIdError that would name a "
        f"key mismatch. Measured in "
        f"docs/verification/2026-09-18-multi-replica-jwks.md. Set {pem_env_var} to the "
        f"private-key PEM a Vault Agent sidecar renders.",
        RuntimeWarning,
        stacklevel=2,
    )


class KeySource(Protocol):
    """Supplies one signing capability and the public JWKS for it."""

    def sign(self, claims: Claims) -> str:
        """``claims`` as an RS256 compact JWS, however this source signs."""
        ...

    def public_jwks(self) -> KeySetSerialization: ...

    def close(self) -> None:
        """Release whatever this source holds open.

        A no-op for the two local implementations, which hold nothing, and a
        connection pool for the Vault one. It is on the PROTOCOL rather than
        behind an `isinstance` check in the composition root because "nothing
        above this seam knows which implementation is in use" is the whole
        property, and a root that has to ask would be the first thing to
        break it.
        """
        ...


class GeneratedKeySource:
    """An in-process key. For tests and local development only."""

    def __init__(self, *, kid: str) -> None:
        self._key = RSAKey.generate_key(2048, parameters=_parameters(kid))

    def signing_key(self) -> RSAKey:
        return self._key

    def sign(self, claims: Claims) -> str:
        return jwt.encode({"alg": "RS256", "kid": self._key.kid}, claims, self._key)

    def public_jwks(self) -> KeySetSerialization:
        return KeySet([self._key]).as_dict()

    def close(self) -> None:
        """Nothing is open. The key is garbage when this object is."""


class FileKeySource:
    """A PEM on disk, which is the shape a Vault Agent sidecar renders.

    `RSAKey.import_key` silently accepts a PUBLIC-key PEM: it returns a key
    with `is_private is False` and raises nothing. A `KeySource` built from
    one would produce a minter that cannot sign, and that would surface only
    when the first token is minted, not when the process starts. This
    constructor instead rejects a non-private key immediately, so a
    misrendered Vault Agent secret fails at startup.
    """

    def __init__(self, path: Path, *, kid: str) -> None:
        key = RSAKey.import_key(path.read_bytes(), parameters=_parameters(kid))
        if not key.is_private:
            raise ValueError(
                f"{path} contains a public key; FileKeySource needs the private key to sign tokens."
            )
        self._key = key

    def signing_key(self) -> RSAKey:
        return self._key

    def sign(self, claims: Claims) -> str:
        return jwt.encode({"alg": "RS256", "kid": self._key.kid}, claims, self._key)

    def public_jwks(self) -> KeySetSerialization:
        return KeySet([self._key]).as_dict()

    def close(self) -> None:
        """Nothing is open. The PEM was read once, at construction."""


def choose_key_source(
    *,
    role: str,
    kid: str,
    vault: VaultSettings | None,
    vault_key_name: str,
    pem_path: str | None,
    pem_env_var: str,
) -> KeySource:
    """The one decision all three signing keys in this codebase make.

    Three call sites, one per key: `services/api/main.py`'s READ key,
    `services/confirm/minter.py`'s WRITE key, and `services/confirm/main.py`'s
    READ key for the device grant. Each passes its own key's configuration and
    gets back one source. It was three copies of an if/else until Vault landed
    and each would have grown a third branch; `postern_core/config.py`'s
    docstring carries the general form of the argument for why a decision both
    services must make identically lives in the library they both import.

    ONE KEY IN, ONE SOURCE OUT, and that signature is the control. There is no
    argument here that names two keys and no return value that carries two
    sources, so this function cannot be the place a process acquires both a
    read and a write signing capability -- which is exactly the convenience a
    shared helper attracts, and exactly what `services/api/jwks.py`'s docstring
    measured the cost of on the JWKS side.

    Args:
        role: ``"READ"`` or ``"WRITE"``, for the ephemeral-key warning only.
        kid: The configured key id. Under Vault it is a PREFIX and the
            published kid carries the version; `postern_core.auth.vault` says
            why.
        vault: `postern_core.auth.vault.vault_from_env`'s answer, or ``None``
            when ``POSTERN_VAULT_ADDR`` is unset.
        vault_key_name: The transit key this process may sign with. The read
            service and the write service name different ones, and the Vault
            policy attached to each service's token is what makes that a
            separation rather than a convention.
        pem_path: The PEM branch, unchanged.
        pem_env_var: Named in the ephemeral-key warning so the message says
            which line to edit.

    Raises:
        ValueError: when a Vault and a PEM path are both configured. Refused
            rather than ordered, because an operator who believes they have
            moved a key into Vault while a PEM path is still set would be
            running off whichever this function happened to prefer -- and the
            PEM they think is unused is still on a disk, still readable, and
            still the thing an RCE finds.
    """
    if vault is not None and pem_path is not None:
        raise ValueError(
            f"the {role} signing key is configured twice: POSTERN_VAULT_ADDR names a Vault "
            f"and {pem_env_var} names a PEM. Unset one. Signing through Vault while a "
            f"private key is still on disk keeps the asset the Vault was meant to remove."
        )
    if vault is not None:
        return VaultTransitKeySource(
            address=vault.address,
            key_name=vault_key_name,
            kid=kid,
            token=vault.token,
            token_path=Path(vault.token_path) if vault.token_path is not None else None,
            mount=vault.mount,
            timeout_seconds=vault.timeout_seconds,
            public_key_ttl_seconds=vault.public_key_ttl_seconds,
        )
    if pem_path is not None:
        return FileKeySource(Path(pem_path), kid=kid)
    # The key first, the warning second, so the warning reports something built
    # rather than something configured -- the lesson `d203606` left, and the
    # ordering both composition roots used before this function existed.
    source = GeneratedKeySource(kid=kid)
    warn_ephemeral_signing_key(role=role, kid=kid, pem_env_var=pem_env_var)
    return source

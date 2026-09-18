"""Where a signing key comes from.

This is the seam Vault lands behind. Nothing above it knows whether the key
was generated in process, read from a file rendered by a Vault Agent sidecar,
or fetched over the API, and no test in this repo touches Vault.

joserfc's `kid` is read-only and has no setter: a bare PEM import yields
`kid=None`, which cannot be recovered afterwards, so every implementation
must supply the kid at construction.
"""

import warnings
from pathlib import Path
from typing import Protocol

from joserfc.jwk import KeyParameters, KeySet, KeySetSerialization, RSAKey


def _parameters(kid: str) -> KeyParameters:
    return {"kid": kid, "use": "sig", "alg": "RS256"}


def warn_ephemeral_signing_key(*, role: str, kid: str, pem_env_var: str) -> None:
    """Say out loud that the process just built a signing key it cannot keep.

    `GeneratedKeySource` is silent by construction, and so is every path to
    it: `services/api/main.py::_read_key_source` and
    `services/confirm/minter.py::_write_key_source` both fall through to it
    when no PEM path is set, with no exception, no log line and no warning.
    Each composition root calls this immediately after that fall-through,
    with the key already constructed.

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
    """Supplies one signing key and the public JWKS for it."""

    def signing_key(self) -> RSAKey: ...

    def public_jwks(self) -> KeySetSerialization: ...


class GeneratedKeySource:
    """An in-process key. For tests and local development only."""

    def __init__(self, *, kid: str) -> None:
        self._key = RSAKey.generate_key(2048, parameters=_parameters(kid))

    def signing_key(self) -> RSAKey:
        return self._key

    def public_jwks(self) -> KeySetSerialization:
        return KeySet([self._key]).as_dict()


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

    def public_jwks(self) -> KeySetSerialization:
        return KeySet([self._key]).as_dict()

"""Where a signing key comes from.

This is the seam Vault lands behind. Nothing above it knows whether the key
was generated in process, read from a file rendered by a Vault Agent sidecar,
or fetched over the API, and no test in this repo touches Vault.

joserfc's `kid` is read-only and has no setter: a bare PEM import yields
`kid=None`, which cannot be recovered afterwards, so every implementation
must supply the kid at construction.
"""

from pathlib import Path
from typing import Protocol

from joserfc.jwk import KeyParameters, KeySet, KeySetSerialization, RSAKey


def _parameters(kid: str) -> KeyParameters:
    return {"kid": kid, "use": "sig", "alg": "RS256"}


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

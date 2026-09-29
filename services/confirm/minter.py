"""Builds the WRITE token minter for the confirm service.

`InternalTokenMinter.mint` keeps taking a `CustomerRef` unchanged (see
`postern_core.auth.internal_jwt`): that is where `CustomerRef`'s own
validation runs. This service has no `CustomerRef` yet at the point it needs
to mint -- Plan 5's approval callback is what will eventually produce one --
so `WriteTokenMinter` is a thin wrapper around the opaque subject string,
constructing a `CustomerRef` internally rather than weakening the core
minter's signature to accept a raw string.

`WRITE_SCOPES` mirrors `postern_core.auth.read_minter.READ_SCOPES`'s shape
for the write audiences the payment and card write paths will use; nothing
in this service derives a scope from it yet; Plan 5/6 is expected to.
"""

from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import KeySource, choose_key_source
from postern_core.identity import CustomerRef

from services.confirm.settings import ConfirmSettings

WRITE_SCOPES = {
    "payments.svc": "payments:execute",
    "cards.svc": "cards:write",
}


class WriteTokenMinter:
    """Adapts `InternalTokenMinter` for callers that only hold an opaque
    subject string, not a `CustomerRef`."""

    def __init__(self, minter: InternalTokenMinter) -> None:
        self._minter = minter

    def mint(
        self,
        *,
        subject_value: str,
        audience: str,
        scope: str,
        challenge_id: str = "",
    ) -> str:
        return self._minter.mint(
            subject=CustomerRef(value=subject_value),
            audience=audience,
            scope=scope,
            challenge_id=challenge_id or None,
        )


def _write_key_source(settings: ConfirmSettings) -> KeySource:
    """The WRITE signing key: inside Vault, from a PEM, or generated here.

    Mirrors `services.api.main._read_key_source` and, since 29 September 2026,
    shares its body: both call `postern_core.auth.keys.choose_key_source` and
    differ only in the arguments, which is the whole of the split expressed as
    a call. This one names a WRITE kid, the WRITE PEM variable and the WRITE
    transit key; that one names three read values and cannot name these.

    This is the half with more at stake, since this key is what will sign
    write tokens for `payments.svc` and `cards.svc` (`WRITE_SCOPES` above),
    and it is therefore the half Vault is most worth for. Under
    ``POSTERN_VAULT_ADDR`` the material that signs a payment token exists only
    inside Vault, and this process holds a token whose policy permits
    ``update`` on one transit path.

    `ConfirmSettings.for_testing()` and the local docker-compose stack leave
    both unset and get a generated key, with the same warning.
    `docs/verification/2026-09-18-multi-replica-jwks.md` measured two live
    `confirm` replicas publishing different 2048-bit moduli under the one
    `kid` `write-1`; it minted no write token, which that record's own
    unverified list states, so the divergence is measured on this side and
    the `bad_signature: ` cost of it only on the read side.
    """
    return choose_key_source(
        role="WRITE",
        kid=settings.write_key_kid,
        vault=settings.vault,
        vault_key_name=settings.vault_write_key_name,
        pem_path=settings.write_key_pem_path,
        pem_env_var="POSTERN_WRITE_KEY_PEM_PATH",
    )


def build_write_minter(settings: ConfirmSettings) -> tuple[WriteTokenMinter, KeySource]:
    """One minter, built over the WRITE key only, plus the `KeySource` behind
    it so the JWKS route can publish its public half. There is deliberately
    no function anywhere in this codebase that can hand one process both a
    read and a write key source.
    """
    key_source = _write_key_source(settings)
    minter = WriteTokenMinter(
        InternalTokenMinter(issuer=settings.write_token_issuer, key_source=key_source)
    )
    return minter, key_source

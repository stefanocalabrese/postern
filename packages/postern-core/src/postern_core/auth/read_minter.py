"""Adapts the internal minter to the TokenMinter protocol BackendClient calls.

Read audiences only. `payments.svc` is deliberately absent: asking this minter
for a write audience raises rather than minting a token with a guessed scope.
That is a second, independent barrier to the key split. Even holding the right
key, a write token from here would carry the wrong scope, and Istio matches on
claims as well as on the signature.
"""

from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.identity import CustomerRef

READ_SCOPES = {
    "accounts.svc": "accounts:read",
    "transactions.svc": "transactions:read",
    "cards.svc": "cards:read",
}


class ReadTokenMinter:
    def __init__(self, minter: InternalTokenMinter) -> None:
        self._minter = minter

    def __call__(self, customer: CustomerRef, audience: str) -> str:
        scope = READ_SCOPES[audience]
        return self._minter.mint(subject=customer, audience=audience, scope=scope)

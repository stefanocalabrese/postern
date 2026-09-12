"""Customer identity. The token is the identity (handoff §6.2).

`user_id` is never a tool argument and is never returned to the client.
Every tool resolves the customer through a `CustomerResolver`.
"""

from typing import Annotated, Protocol

from pydantic import BaseModel, ConfigDict, StringConstraints

# `cust` is the only namespace this codebase mints (handoff §7.2's example
# claim is `"sub": "cust:7f3a..."`; test fixtures across this repo use the
# underscore form `cust_7f3a`, so both separators are accepted). Anchoring on
# a literal namespace prefix rejects an IBAN, PAN, bare account number or
# national id in every fixture and test this codebase actually constructs:
# a bare `[A-Za-z0-9_:-]{4,64}` character-class guard accepts an IBAN
# outright (24 alphanumeric characters sits inside 4..64) and proves nothing
# about opacity.
#
# This is a provenance convention, not a proof of opacity: the suffix
# `[A-Za-z0-9]{1,60}` still matches `cust_ES9121000418450200051332` (an
# IBAN), `cust_12345678Z` (a Spanish DNI shape) or `cust_4111111111114417`
# (a PAN) if an issuer ever minted one of those as the suffix (security
# review, Task 3, second round). Tightening the suffix to the issuer's real
# minted-token shape needs the platform team to say what that shape is; see
# the open item next to ZT-2. The actual guarantee is that `sub` is minted
# only by the token issuer, which handoff §7.2 requires to be an opaque
# customer reference — this pattern rejects the shapes above, it does not
# prove the issuer never mints something PAN- or DNI-shaped.
_OPAQUE = r"^cust[:_][A-Za-z0-9]{1,60}$"


class CustomerRef(BaseModel):
    """An opaque reference. Never an IBAN, account number or national id (§7.2)."""

    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)

    value: Annotated[str, StringConstraints(pattern=_OPAQUE)]


class CustomerResolver(Protocol):
    """Resolves the calling customer from ambient request state.

    Production reads the validated access token. Tests inject a fake. There is
    deliberately no argument: nothing the model can set may influence this.
    """

    def __call__(self) -> CustomerRef: ...

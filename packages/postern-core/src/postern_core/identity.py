"""Customer identity. The token is the identity (handoff §6.2).

`user_id` is never a tool argument and is never returned to the client.
Every tool resolves the customer through a `CustomerResolver`.
"""

from typing import Annotated, Protocol

from pydantic import BaseModel, ConfigDict, StringConstraints

# `cust` is the only namespace this codebase mints (handoff §7.2's example
# claim is `"sub": "cust:7f3a..."`; test fixtures across this repo use the
# underscore form `cust_7f3a`, so both separators are accepted). Anchoring on
# a literal namespace prefix is what actually rejects an IBAN, PAN, bare
# account number or national id: all of those are also short alphanumeric
# strings, so a bare `[A-Za-z0-9_:-]{4,64}` character-class guard accepts an
# IBAN outright (24 alphanumeric characters sits inside 4..64) and proves
# nothing about opacity. The namespace prefix is the actual guarantee; the
# token issuer is the one place trusted to hand out `cust:`/`cust_` values.
_OPAQUE = r"^cust[:_][A-Za-z0-9]{1,60}$"


class CustomerRef(BaseModel):
    """An opaque reference. Never an IBAN, account number or national id (§7.2)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    value: Annotated[str, StringConstraints(pattern=_OPAQUE)]


class CustomerResolver(Protocol):
    """Resolves the calling customer from ambient request state.

    Production reads the validated access token. Tests inject a fake. There is
    deliberately no argument: nothing the model can set may influence this.
    """

    def __call__(self) -> CustomerRef: ...

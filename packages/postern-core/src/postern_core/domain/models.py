"""The MCP-facing contract (handoff §8.4).

Deliberately distinct from backend response shapes so tool schemas stay stable
while backends refactor. Counterparty account identifiers are absent by design
(§6.5): name only, never an account number.
"""

from collections.abc import Mapping
from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import AwareDatetime, BaseModel, ConfigDict, StringConstraints

from postern_core.domain.masking import MaskedIban, MaskedPan
from postern_core.domain.money import Money

Ref = Annotated[str, StringConstraints(pattern=r"^[a-z]{3}_[A-Za-z0-9]{1,32}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Re-validate on update, so masking cannot be bypassed (see Task 2 review)."""
        if update:
            return type(self).model_validate({**self.model_dump(), **update})
        return super().model_copy(deep=deep)


class Account(_Strict):
    ref: Ref
    label: str
    iban: MaskedIban


class Balance(_Strict):
    account_ref: Ref
    amount: Money
    as_of: AwareDatetime


class Transaction(_Strict):
    ref: Ref
    account_ref: Ref
    booked_at: AwareDatetime
    amount: Money
    direction: Literal["debit", "credit"]
    counterparty_name: str
    description: str


class Card(_Strict):
    ref: Ref
    label: str
    pan: MaskedPan
    status: Literal["active", "frozen", "cancelled"]


class ConsentSummary(_Strict):
    domain: Literal["accounts", "transactions", "cards", "payments"]
    granted: bool
    expires_at: datetime | None


class SessionInfo(_Strict):
    """Return value of the bootstrap tool (handoff §4.2)."""

    accounts: list[Account]
    consents: list[ConsentSummary]
    write_enabled: list[str]
    confirmation_note: str

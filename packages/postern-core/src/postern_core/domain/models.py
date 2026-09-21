"""The MCP-facing contract (handoff §8.4).

Deliberately distinct from backend response shapes so tool schemas stay stable
while backends refactor. Counterparty account identifiers are absent by design
(§6.5): name only, never an account number.
"""

from typing import Annotated, Literal

from pydantic import AwareDatetime, StringConstraints

from postern_core.domain.base import _Strict
from postern_core.domain.masking import FreeText, MaskedIban, MaskedPan
from postern_core.domain.money import Money

Ref = Annotated[str, StringConstraints(pattern=r"^[a-z]{3}_[A-Za-z0-9]{1,32}$")]


class Account(_Strict):
    ref: Ref
    label: FreeText
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
    counterparty_name: FreeText
    description: FreeText


class TransactionPage(_Strict):
    """Result of `transactions.list` (Task 9, handoff §6.5's row-bound gap).

    `postern_core.facade.transactions.MAX_ROWS` caps `items` in that façade,
    in this process, regardless of what the backend sends or which query
    parameters it honors. `truncated` is the only signal a model has that
    `items` is not the complete window: a raw list with rows silently
    dropped would let "how much did I spend on groceries" compute a
    confidently wrong total from a partial page. See
    `facade/transactions.py`'s module docstring for the full design note.
    """

    items: list[Transaction]
    truncated: bool


class Card(_Strict):
    ref: Ref
    label: FreeText
    pan: MaskedPan
    status: Literal["active", "frozen", "cancelled"]


class ConsentSummary(_Strict):
    domain: Literal["accounts", "transactions", "cards", "payments"]
    granted: bool
    expires_at: AwareDatetime | None


class SessionInfo(_Strict):
    """Return value of the bootstrap tool (handoff §4.2)."""

    accounts: list[Account]
    consents: list[ConsentSummary]
    write_enabled: list[str]
    confirmation_note: FreeText
    session_handle: str
    """Opaque handle identifying this session. Pass it to all subsequent
    tool calls so the server can track per-session risk budgets."""

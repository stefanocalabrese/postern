"""Project backend transaction payloads onto the MCP contract (handoff §8.6).

Two independent bounds, not one:

`days` bounds the *time window* (handoff §6.5: "Bound result sets hard.
Transactions default to 30 days, explicit widening required."). It is
enforced by the tool's own schema (`services/api/tools/transactions.py`,
`Field(ge=1, le=MAX_DAYS)`), so an out-of-range value never reaches this
module or the backend at all.

`MAX_ROWS` bounds the *row count* returned from a single call, independent
of `days`. The plan as originally drafted bounded the window and stopped
there, but a wide window on an active current account is plausibly several
thousand rows, and every one of them would land in a vendor chat history the
bank cannot recall (handoff §6.5's own framing: "One unbounded call persists
five years of history permanently, somewhere we cannot reach" -- the same
sentence that motivates the day bound motivates a row bound just as
directly, since days-bounded is not rows-bounded on an active account).

`MAX_ROWS` is enforced HERE, in this façade, after the backend response
comes back -- never by trusting a `limit`/`page_size` parameter sent to the
backend. The backend is not in this repository, may not support such a
parameter, and may ignore one it does support; nothing this module sends
upstream can be relied on to bound what comes back. `list_transactions`
slices `payload["transactions"]` to `MAX_ROWS` and sets
`TransactionPage.truncated=True` whenever the backend sent more rows than
that, regardless of `days` -- a hard cap plus a visible flag, not a `limit`
parameter the model must remember to set correctly, and not opaque-cursor
pagination (out of scope for this task; recorded as an open item in the
plan for a real follow-up task, since handoff §6.6 requires pagination on
every list-returning tool and none of the tools in this 15-task plan build
it yet).

Chosen over a `limit` argument because a hard cap needs no cooperation from
the model to be safe -- there is no parameter to omit, set too high, or get
talked into raising by injected content in a transaction description -- and
it fails safe in exactly the shape handoff §6.5 warns about: whatever the
backend sends, at most `MAX_ROWS` rows ever reach the client, every time,
with no way to disable it from the tool-call side. `MAX_ROWS = 100` is
deliberately below the "200 records" handoff §6.5 already calls out as too
many for a customer question, and well below what a very active Spanish
current account can produce in a 30-day (let alone 365-day) window, so
truncation is expected to be the common case on a wide window, not a rare
edge case the flag can afford to be an afterthought for.

Order is whatever the backend returned; this façade does not itself sort by
`booked_at` before truncating. The tool's own docstring already documents an
assumption that the backend returns newest-first (unverified against a real
backend, since none exists in this repo); if that assumption is ever wrong,
truncation would silently keep the *wrong* rows rather than the newest ones
-- recorded as an open item in the plan, not fixed here, since fixing it
without a real backend contract to test against would be guessing at a
contract this module cannot observe.

`Transaction.description` and `Transaction.counterparty_name` are `FreeText`
(Task 3, second security-review round): the fixture's `description` embeds a
full PAN and IBAN, and redaction happens on `Transaction(...)` construction,
not because this module calls a scrub function. `counterparty_iban` is read
from the backend row and never carried forward; `Transaction` has no field
for it, so a future contributor who tries gets a validation error from
`extra="forbid"` -- caught by `build_model` below, not leaked.

Typed against `BackendReader` (Task 4's minimal `Protocol`), matching Task
8's correction to the same plan section for accounts: `services/api/
server.py` only ever holds a `BackendReader | None`, so a parameter typed
`BackendClient` here would make `mypy --strict` reject the call site in
`services/api/tools/transactions.py`.
"""

from datetime import datetime
from decimal import Decimal
from typing import Any

from postern_core.domain.models import Ref, Transaction, TransactionPage
from postern_core.domain.money import Money
from postern_core.facade.projection import build_model
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef

_AUDIENCE = "transactions.svc"

MAX_DAYS = 365
"""Upper bound on the `days` time window (handoff §6.5). Schema-enforced in
`services/api/tools/transactions.py`; repeated here so the façade and the
tool's `Field(le=...)` cannot drift apart silently."""

MAX_ROWS = 100
"""Upper bound on rows returned from one call, enforced in this process
regardless of `days` or backend cooperation. See the module docstring."""


def _project(row: dict[str, Any]) -> Transaction:
    """A named function, not the loop body's lambda: see `_project_account`'s
    docstring in `facade/accounts.py` for why (`row` here is this function's
    own parameter, called once per iteration, not a captured loop variable).

    `amount` is computed once, inside the factory `build_model` calls, and
    closed over by the `Transaction(...)` call below it: both `amount<0`
    (direction) and `abs(amount)` (the reported value) must agree on the
    same parsed `Decimal`, not two independent conversions of `row["amount"]`.
    """

    def factory() -> Transaction:
        amount = Decimal(row["amount"])
        return Transaction(
            ref=row["id"],
            account_ref=row["account_id"],
            booked_at=datetime.fromisoformat(row["booked_at"]),
            amount=Money(amount=abs(amount), currency=row["currency"]),
            direction="debit" if amount < 0 else "credit",
            counterparty_name=row["counterparty_name"],
            description=row["description"],
        )

    return build_model(factory, resource="transaction")


async def list_transactions(
    backend: BackendReader, customer: CustomerRef, account_ref: Ref, days: int
) -> TransactionPage:
    payload = await backend.get_json(
        "/transactions",
        customer=customer,
        audience=_AUDIENCE,
        params={"account_id": account_ref, "days": days},
    )
    rows = payload["transactions"]
    truncated = len(rows) > MAX_ROWS
    items = [_project(row) for row in rows[:MAX_ROWS]]
    return TransactionPage(items=items, truncated=truncated)

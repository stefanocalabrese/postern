"""Project backend card payloads onto the MCP contract (handoff §8.6).

Projection is explicit and field-by-field, matching `facade/accounts.py`:
`Card` accepts only the fields the MCP contract declares (`ref`, `label`,
`pan`, `status`), so a backend field this module never names -- an `expiry`,
a `cvv`, a duplicate `full_pan`, a `cardholder_name` -- cannot reach a tool
result by construction, because `_project_card` never does `Card(**row)`.

No row cap, unlike `facade/transactions.py`'s `MAX_ROWS`/`TransactionPage`
(considered and rejected for this task; recorded here rather than silently
matched or silently skipped):

Handoff §6.5's "Bound result sets hard" motivated `transactions.list`'s cap
because that tool's result size is a product of two things a model
controls or a backend's event volume drives: a widenable time window
(`days`, up to 365) times an active account's transaction frequency, which
handoff §6.5's own "not 200 records" framing already treats as routinely
exceeding a few hundred rows. `cards.list` has neither factor -- it takes
no arguments, so there is no parameter for a model to widen or be talked
into widening, and a card row is created by the bank's own card-issuance
process (a discrete, ops-gated action), not logged once per event the way a
transaction is. That is a materially different risk shape, not the same
shape assumed safe twice.

This does not mean "a customer has few cards" is verified; it is not, and
that class of assumption about a backend this repo does not contain has
been wrong before in this project (`facade/transactions.py`'s own truncation
-order and direction-from-sign notes). It means a cap added here today would
have no anchor: `transactions.py`'s `MAX_ROWS = 100` is deliberately below a
specific number the design handoff itself names ("not 200 records");
nothing in the handoff or this repo names an equivalent figure for cards, so
a `CARD_MAX_ROWS` constant picked here would be a bare guess with no source
-- the same kind of unverified external claim this project's own standards
reject elsewhere, not a control. What would change this: evidence of a real
backend contract under which one customer can hold many cards -- a
corporate/business multi-card program, virtual-card-per-subscription or
virtual-card-per-merchant issuance, or any other pattern this repo has no
visibility into. If that turns up, `list_cards` needs the same
`MAX_ROWS`/`truncated` treatment `list_transactions` already has, sized
against whatever number that contract actually supports.

Typed against `BackendReader` (Task 4's minimal `Protocol`), matching Task
8's correction for `facade/accounts.py`: `services/api/server.py` only ever
holds a `BackendReader | None`, so a parameter typed `BackendClient` here
would make `mypy --strict` reject the call site in
`services/api/tools/cards.py`.

Handoff §6.5 prefers the backend returning pre-masked values so this server
never holds a full PAN and stays out of PCI DSS scope -- open question
§10.17. Until that is answered, `MaskedPan` masks on construction here, and
a full PAN exists in this process only for the duration of one projection.
"""

from typing import Any

from postern_core.domain.models import Card
from postern_core.facade.projection import build_model
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef

_AUDIENCE = "cards.svc"


def _project_card(row: dict[str, Any]) -> Card:
    """A named function, not the loop body's lambda: see
    `facade/accounts.py::_project_account`'s docstring for why (`row` here is
    this function's own parameter, called once per iteration, not a captured
    loop variable). Any `pydantic.ValidationError` -- a missing/null field, a
    PAN that fails `MaskedPan`'s own validator, or a `status` outside
    `Card`'s `Literal` -- is caught by `build_model`, never left to escape
    to FastMCP's own dispatcher log.
    """
    return build_model(
        lambda: Card(ref=row["id"], label=row["label"], pan=row["pan"], status=row["status"]),
        resource="card",
    )


async def list_cards(backend: BackendReader, customer: CustomerRef) -> list[Card]:
    payload = await backend.get_json("/cards", customer=customer, audience=_AUDIENCE)
    return [_project_card(row) for row in payload["cards"]]

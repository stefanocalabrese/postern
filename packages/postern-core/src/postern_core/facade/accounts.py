"""Project backend account payloads onto the MCP contract (handoff §8.6).

Projection is explicit and field-by-field, never a passthrough of the
backend dict: `Account`/`Balance` accept only the fields the MCP contract
declares, so a backend field this module never names (a stray `full_name`,
`national_id`, or the `description`-embedded PAN the fixtures carry) cannot
reach a tool result by construction, `_Strict.model_config['extra']` is
`"forbid"`. A field the backend *omits*, or sends as `null`, raises inside
this function rather than the model: `row["iban"]` is a `KeyError`,
`row["iban"] = None` is a masking-validator `ValueError` -- both are
scrubbed the same way any other façade exception is, see
`services/api/tools/accounts.py`.

Typed against `BackendReader` (Task 4's minimal `Protocol`), not the
concrete `BackendClient`: `services/api/server.py` only ever holds a
`BackendReader | None` (it fails closed before Task 6's client existed and
never imports it), so a parameter typed `BackendClient` here would make
`mypy --strict` reject `services/api/tools/accounts.py`'s call site, which
receives that same narrowed `BackendReader`.
"""

from datetime import datetime
from decimal import Decimal
from typing import Any

from postern_core.domain.models import Account, Balance, Ref
from postern_core.domain.money import Money
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef

_AUDIENCE = "accounts.svc"


async def list_accounts(backend: BackendReader, customer: CustomerRef) -> list[Account]:
    payload = await backend.get_json("/accounts", customer=customer, audience=_AUDIENCE)
    return [
        Account(ref=row["id"], label=row["label"], iban=row["iban"]) for row in payload["accounts"]
    ]


async def get_balance(backend: BackendReader, customer: CustomerRef, account_ref: Ref) -> Balance:
    payload: dict[str, Any] = await backend.get_json(
        f"/accounts/{account_ref}/balance", customer=customer, audience=_AUDIENCE
    )
    return Balance(
        account_ref=payload["account_id"],
        amount=Money(amount=Decimal(payload["amount"]), currency=payload["currency"]),
        as_of=datetime.fromisoformat(payload["as_of"]),
    )

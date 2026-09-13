"""Project backend account payloads onto the MCP contract (handoff §8.6).

Projection is explicit and field-by-field, never a passthrough of the
backend dict: `Account`/`Balance` accept only the fields the MCP contract
declares, so a backend field this module never names (a stray `full_name`,
`national_id`, or the `description`-embedded PAN the fixtures carry) cannot
reach a tool result by construction, `_Strict.model_config['extra']` is
`"forbid"`. A field the backend *omits* raises a bare `KeyError` inside this
function (safe: `KeyError.__str__` names only the missing key, a literal
from this module's own source, never a value from the payload). A field the
backend sends as `null`, or as a value that fails `MaskedIban`/`MaskedPan`'s
own validator, raises `pydantic.ValidationError` while constructing
`Account`/`Balance`; that is NOT safe on its own (see `facade/projection.py`)
and every model construction below goes through `build_model` to close it.

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
from postern_core.facade.projection import build_model
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef

_AUDIENCE = "accounts.svc"


def _project_account(row: dict[str, Any]) -> Account:
    """A named function, not a lambda inline in the loop below: a lambda
    referencing the comprehension's loop variable would need a
    `row=row`-style default binding to be safe (ruff B023), and mypy cannot
    infer a lambda's parameter type through that pattern when it is also
    passed to a generic function. `row` here is this function's own
    parameter, called once per iteration, not a captured loop variable.
    """
    return build_model(
        lambda: Account(ref=row["id"], label=row["label"], iban=row["iban"]),
        resource="account",
    )


async def list_accounts(backend: BackendReader, customer: CustomerRef) -> list[Account]:
    payload = await backend.get_json("/accounts", customer=customer, audience=_AUDIENCE)
    return [_project_account(row) for row in payload["accounts"]]


async def get_balance(backend: BackendReader, customer: CustomerRef, account_ref: Ref) -> Balance:
    payload: dict[str, Any] = await backend.get_json(
        f"/accounts/{account_ref}/balance", customer=customer, audience=_AUDIENCE
    )
    return build_model(
        lambda: Balance(
            account_ref=payload["account_id"],
            amount=Money(amount=Decimal(payload["amount"]), currency=payload["currency"]),
            as_of=datetime.fromisoformat(payload["as_of"]),
        ),
        resource="balance",
    )

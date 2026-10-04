"""The payments producer's one read: a saved payee (decision 0022).

ONE FUNCTION AND NO WRITE HELPER, which `tests/test_no_write_from_api.py`
asserts for this module as for the other three. The audience is `payments.svc`
and the read minter signs it with `payments:read` only, never
`payments:execute`.

The projection names two fields and no account number: handoff §6.5 omits
counterparty account numbers entirely, so a backend that sends an IBAN beside
the name has it dropped here by construction. A missing field raises a bare
`KeyError` naming only the key, and a value `Payee` refuses goes through
`build_model`, as in `postern_core.facade.accounts`.
"""

from typing import Any

from pydantic import TypeAdapter, ValidationError

from postern_core.domain.models import Payee, Ref
from postern_core.facade.client import BackendError
from postern_core.facade.projection import build_model
from postern_core.facade.protocol import BackendReader
from postern_core.identity import CustomerRef

_AUDIENCE = "payments.svc"
_REF = TypeAdapter(Ref)


async def get_payee(backend: BackendReader, customer: CustomerRef, payee_ref: Ref) -> Payee:
    try:
        _REF.validate_python(payee_ref)
    except ValidationError:
        # A caller bug, not a backend answer: `ValueError`, as a bad argument is
        # in Python. The message is fixed and never echoes the input, which
        # would otherwise reach the path as a query string or a traversal.
        raise ValueError("payee_ref is not a valid ref") from None
    payload: dict[str, Any] = await backend.get_json(
        f"/payees/{payee_ref}", customer=customer, audience=_AUDIENCE
    )
    payee = build_model(
        lambda: Payee(payee_ref=payload["payee_ref"], display_name=payload["name"]),
        resource="payee",
    )
    if payee.payee_ref != payee_ref:
        raise BackendError(
            502,
            "backend answered a different payee",
            "The backend returned data in an unexpected shape. Tell the customer and retry later.",
        )
    return payee

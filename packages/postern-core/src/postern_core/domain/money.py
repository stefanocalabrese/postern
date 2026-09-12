from decimal import Decimal
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, StringConstraints

CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]


def _reject_float(value: object) -> object:
    """Reject a bare Python `float` outright, before pydantic's own `Decimal`
    coercion runs.

    A JSON number decoded by `json.loads` becomes a `float`, and IEEE 754
    binary floats cannot represent most decimal fractions exactly:
    `0.1 + 0.2 == 0.30000000000000004`. `Decimal`, `str` and `int` are all
    exact and pass through unchanged to pydantic's own `Decimal` validation;
    `Field(strict=True)` was measured and rejected, since it also rejects the
    `str` wire form a backend must use to avoid this exact hazard. A backend
    sends amounts as a decimal string (or an int for a whole-number amount),
    never a bare JSON number that a client-side float already corrupted.
    """
    if isinstance(value, float):
        raise ValueError(
            "amount must not be a float: binary floating point cannot represent "
            "a decimal amount exactly; send a decimal string or a Decimal"
        )
    return value


MoneyAmount = Annotated[Decimal, BeforeValidator(_reject_float)]


class Money(BaseModel):
    """An amount is never a bare number through this channel (handoff §6.5)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    amount: MoneyAmount
    currency: CurrencyCode

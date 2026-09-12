from decimal import Decimal
from typing import Annotated

from pydantic import AfterValidator, BeforeValidator, Field, StringConstraints

from postern_core.domain.base import _Strict

CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]

# Above every real ISO 4217 minor unit (JPY is 0 decimal places, most
# currencies are 2, a few historical/crypto-adjacent ones are 3) and below
# every float artifact this module has to close (0.1 + 0.2's repr has 17
# decimal places; Decimal(0.1)'s exact binary value has 55). Chosen so this
# rejects both float-derived routes without needing a currency-exponent
# table (see "What this plan deliberately does not establish").
_MAX_DECIMAL_PLACES = 4


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

    This alone is not enough: `Decimal(str(0.1 + 0.2))` and `Decimal(0.1)`
    are both already `Decimal` by the time they reach this validator (the
    float was converted before `Money` ever saw it), so this check never
    fires for either. `_reject_imprecise_decimal` below closes those two
    routes by inspecting the resulting `Decimal`'s exponent instead of the
    input's type.
    """
    if isinstance(value, float):
        raise ValueError(
            "amount must not be a float: binary floating point cannot represent "
            "a decimal amount exactly; send a decimal string or a Decimal"
        )
    return value


def _reject_imprecise_decimal(value: Decimal) -> Decimal:
    """Reject a `Decimal` with more than `_MAX_DECIMAL_PLACES` decimal places.

    Closes `Decimal(str(0.1 + 0.2))` (17 decimal places) and `Decimal(0.1)`
    (55 decimal places, the exact binary value): both are already `Decimal`
    by the time `_reject_float` runs, so neither is caught there. A
    non-finite `Decimal` (`NaN`, `Infinity`) is rejected by
    `Field(allow_inf_nan=False)` below, which runs before this validator; the
    `isinstance` guard here is defensive, not the primary control for that
    case, and this function is never expected to observe a non-finite value.
    """
    exponent = value.as_tuple().exponent
    if not isinstance(exponent, int):
        raise ValueError("amount must be a finite decimal value")
    if exponent < -_MAX_DECIMAL_PLACES:
        raise ValueError(
            f"amount has more than {_MAX_DECIMAL_PLACES} decimal places: likely a "
            "float artifact (binary floating point rarely round-trips to a short "
            f"decimal); {_MAX_DECIMAL_PLACES} decimal places is above every real "
            "ISO 4217 minor unit"
        )
    return value


MoneyAmount = Annotated[
    Decimal,
    BeforeValidator(_reject_float),
    Field(allow_inf_nan=False),
    AfterValidator(_reject_imprecise_decimal),
]


class Money(_Strict):
    """An amount is never a bare number through this channel (handoff §6.5).

    Derives from `_Strict`, not `BaseModel`: `revalidate_instances` is read
    from a nested field's own class, not its parent's, so a `Money` typed as
    plain `BaseModel` let a bypassed amount reach `Balance`/`Transaction`
    untouched even though those parents already set
    `revalidate_instances="always"` themselves (security review, Task 3,
    second round).
    """

    amount: MoneyAmount
    currency: CurrencyCode

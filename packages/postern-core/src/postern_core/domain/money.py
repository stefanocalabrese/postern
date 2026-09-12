from decimal import Decimal
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

CurrencyCode = Annotated[str, StringConstraints(pattern=r"^[A-Z]{3}$")]


class Money(BaseModel):
    """An amount is never a bare number through this channel (handoff §6.5)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    amount: Decimal
    currency: CurrencyCode

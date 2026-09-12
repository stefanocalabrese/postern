"""The strict base for the MCP-facing domain contract (handoff §8.4).

Split out of `models.py` so `money.py` can derive `Money` from it too: a
nested field's re-validation behaviour (`revalidate_instances`) is read from
that field's own class, not the parent's, so `Money` deriving from plain
`BaseModel` left every bypass this class closes wide open the moment a
`Money` was nested inside an `Account`, `Balance` or `Transaction` (security
review, Task 3, second round).
"""

from collections.abc import Mapping
from typing import Any, Self

from pydantic import BaseModel, ConfigDict


class _Strict(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_assignment=True,
        hide_input_in_errors=True,
        revalidate_instances="always",
    )

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Re-validate on update, so masking cannot be bypassed (see Task 2 review).

        `update is not None` (not truthiness): `model_copy(update={})` must
        still take the re-validating path, not silently fall through to the
        raw, unvalidated `super().model_copy()` just because an empty dict is
        falsy (security review, Task 3, second round).

        The unvalidated copy-with-update is produced first via `super()`, so
        `deep` is honoured exactly as pydantic's own `model_copy` honours it;
        re-validating its dump afterwards is what closes the bypass, and is
        safe regardless of whether the copy was deep or shallow, since
        `model_validate` reconstructs every nested value from scratch anyway.
        """
        if update is not None:
            unvalidated = super().model_copy(update=dict(update), deep=deep)
            return type(self).model_validate(unvalidated.model_dump())
        return super().model_copy(deep=deep)

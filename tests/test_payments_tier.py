"""`postern_core.payments` is the one declaration both services read.

`services/api` stores `PAYMENT_TIER` on every payment challenge it creates and
`services/confirm` routes the approved operation at the tier it declares. Two
separate literals could drift apart silently, and a challenge would be stored
at one tier and routed at another.
"""

import inspect

from postern_core.domain.verification import VerificationTier
from postern_core.payments import (
    CREATE_PAYMENT_TOOL,
    PAYMENT_STATUS_TOOL,
    PAYMENT_TIER,
    PRODUCER_TOOL_NAMES,
)

from services.confirm import execute
from services.confirm.execute import BUILTIN_WRITE_OPERATIONS, WRITE_OPERATIONS


def test_the_payment_tier_is_app_identity_verification() -> None:
    assert PAYMENT_TIER == VerificationTier.APP_IDENTITY_VERIFICATION
    assert int(PAYMENT_TIER) == 2


def test_the_producer_registers_exactly_two_names() -> None:
    assert CREATE_PAYMENT_TOOL == "payments.create_payment"
    assert PAYMENT_STATUS_TOOL == "payments.get_payment_status"
    assert PRODUCER_TOOL_NAMES == (CREATE_PAYMENT_TOOL, PAYMENT_STATUS_TOOL)


def test_confirm_routes_create_payment_at_the_shared_tier() -> None:
    operation = WRITE_OPERATIONS[CREATE_PAYMENT_TOOL]
    assert operation.tier == PAYMENT_TIER
    assert (operation.audience, operation.path_template, operation.method) == (
        "payments.svc",
        "/payments",
        "POST",
    )


def test_the_builtin_entry_names_the_shared_declaration() -> None:
    """By source as well as by value: the literal it replaces had the same
    value, so a value check alone passes against the old code."""
    (builtin,) = [op for op in BUILTIN_WRITE_OPERATIONS if op.tool_name == CREATE_PAYMENT_TOOL]
    assert builtin.tier == PAYMENT_TIER
    source = inspect.getsource(execute)
    assert "tool_name=CREATE_PAYMENT_TOOL" in source
    assert "tier=PAYMENT_TIER" in source


def test_the_status_tool_is_not_a_write_operation() -> None:
    assert PAYMENT_STATUS_TOOL not in WRITE_OPERATIONS

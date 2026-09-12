from datetime import UTC, datetime
from decimal import Decimal

import pytest
from postern_core.domain.models import (
    Account,
    Balance,
    Card,
    ConsentSummary,
    SessionInfo,
    Transaction,
)
from postern_core.domain.money import Money
from postern_core.identity import CustomerRef
from pydantic import ValidationError


def test_money_carries_currency_and_serializes_exactly() -> None:
    m = Money(amount=Decimal("340.00"), currency="EUR")
    assert m.model_dump_json() == '{"amount":"340.00","currency":"EUR"}'


def test_money_rejects_a_non_iso_currency() -> None:
    with pytest.raises(ValidationError):
        Money(amount=Decimal("1"), currency="euros")


def test_balance_carries_account_ref_and_as_of() -> None:
    b = Balance(
        account_ref="acc_7f3a",
        amount=Money(amount=Decimal("1200.50"), currency="EUR"),
        as_of=datetime(2026, 9, 12, 10, 0, tzinfo=UTC),
    )
    assert b.account_ref == "acc_7f3a"
    assert b.as_of.tzinfo is not None


def test_balance_rejects_a_naive_timestamp() -> None:
    with pytest.raises(ValidationError):
        Balance(
            account_ref="acc_7f3a",
            amount=Money(amount=Decimal("1"), currency="EUR"),
            as_of=datetime(2026, 9, 12, 10, 0),
        )


def test_account_masks_its_iban() -> None:
    a = Account(ref="acc_7f3a", label="Joint expenses", iban="ES9121000418450200051332")
    assert a.iban == "ES•• •••• 1332"


def test_card_masks_its_pan() -> None:
    card = Card(ref="crd_1", label="Debit", pan="4111111111114417", status="active")
    assert card.pan == "•••• 4417"


def test_transaction_has_no_counterparty_account_field() -> None:
    assert "counterparty_iban" not in Transaction.model_fields
    assert "counterparty_account" not in Transaction.model_fields


def test_models_reject_unknown_fields() -> None:
    # `pan` is not a field on Account. Constructed via model_validate on a plain
    # dict, not Account(pan=...) directly: the latter is a field name mypy
    # --strict statically rejects (pydantic v2's BaseModel is a PEP 681
    # dataclass_transform, so a keyword mypy cannot see on the model is a
    # call-arg error, not just a runtime one), and the point of this test is
    # the runtime extra="forbid" behaviour, not a static-typing violation.
    with pytest.raises(ValidationError):
        Account.model_validate(
            {
                "ref": "acc_1",
                "label": "X",
                "iban": "ES9121000418450200051332",
                "pan": "4111111111114417",
            }
        )


def test_customer_ref_is_opaque() -> None:
    with pytest.raises(ValidationError):
        CustomerRef(value="ES9121000418450200051332")


def test_model_copy_update_remasks_rather_than_storing_raw() -> None:
    """model_copy(update=...) is the natural idiom for patching one field of
    a backend-derived model, and it bypasses Annotated validators even under
    frozen=True. _Strict overrides model_copy to re-validate (Task 2 review)."""
    card = Card(ref="crd_1", label="Debit", pan="4111111111114417", status="active")
    patched = card.model_copy(update={"pan": "4111111111114417"})
    assert patched.pan == "•••• 4417"
    assert "4111111111114417" not in patched.model_dump_json()


def test_validation_error_never_echoes_the_raw_identifier() -> None:
    """Pydantic's default ValidationError.__str__ embeds `input_value=...`
    for the field that failed. Without hide_input_in_errors=True on _Strict,
    the raw string below appears verbatim in str(exc)."""
    with pytest.raises(ValidationError) as exc_info:
        Card(ref="crd_1", label="Debit", pan="my card is 4111111111114417 thanks", status="active")
    assert "4111111111114417" not in str(exc_info.value)


def test_nested_model_construct_bypass_is_remasked_on_parent_construction() -> None:
    """Pydantic's default revalidate_instances="never" means a nested field
    typed as list[Account] accepts an already-Account-typed instance as-is,
    without re-running its validators -- including one built via the
    forbidden Account.model_construct(), which never masked its IBAN. This
    is not the model_copy bypass (Task 3 review of Step 6): it reaches
    through a plain SessionInfo(...) call, no model_copy involved. _Strict
    sets revalidate_instances="always" so a nested instance is re-validated
    (and thus re-masked) exactly like a nested dict would be."""
    bad_account = Account.model_construct(ref="acc_x", label="X", iban="ES9121000418450200051332")
    assert bad_account.iban == "ES9121000418450200051332"  # forbidden call, unmasked by design

    session = SessionInfo(
        accounts=[bad_account],
        consents=[ConsentSummary(domain="accounts", granted=True, expires_at=None)],
        write_enabled=[],
        confirmation_note="none",
    )
    assert session.accounts[0].iban == "ES•• •••• 1332"
    assert "9121000418450200051332" not in session.model_dump_json()

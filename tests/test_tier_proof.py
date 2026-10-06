"""The tier rule of decision record 0023 as a pure function (spec section 5).

No database and no app: every row here is built in memory and every clock is
passed in, so the bounds are tested exactly. `tests/test_tier2_approval.py`
drives the same rule through the real callback.
"""

import json
import logging
import math
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from postern_core.domain.verification import VerificationTier
from postern_core.modules.write import WriteOperation
from postern_core.payments import CREATE_PAYMENT_TOOL
from postern_core.store.models import ChallengeRecord

from services.confirm.audit import (
    DETAIL_TIER_MISMATCH,
    DETAIL_TIER_UNSUPPORTED,
    DETAIL_VERIFICATION_NOT_CONFIGURED,
    DETAIL_VERIFICATION_REQUIRED,
)
from services.confirm.execute import WRITE_OPERATIONS
from services.confirm.tier_proof import (
    TIER_MISMATCH_DESCRIPTION,
    TIER_UNSUPPORTED_DESCRIPTION,
    VERIFICATION_REQUIRED_DESCRIPTION,
    TierRefusal,
    TierVerdict,
    check_tier,
    tier_refusal,
)

IDV = "postern-dev-idv"
CHALLENGE = "t2_unit_0001"
JTI = "jti-unit-0001"
CREATED = datetime(2026, 10, 6, 12, 0, 0, tzinfo=UTC)
NOW = CREATED.timestamp() + 60
TIER_1_TOOL = "standing_orders.cancel"


def record(
    *, tier: int = 2, tool_name: str = CREATE_PAYMENT_TOOL, created_at: datetime = CREATED
) -> ChallengeRecord:
    return ChallengeRecord(
        challenge_id=CHALLENGE,
        customer_ref="cust_unit1",
        tool_name=tool_name,
        payload={},
        tier=tier,
        status="pending",
        created_at=created_at,
        expires_at=created_at + timedelta(seconds=300),
    )


def claims(**overrides: Any) -> dict[str, Any]:
    """The four claims a tier-2 approval needs, valid unless overridden."""
    base: dict[str, Any] = {
        "idv": IDV,
        "challenge_id": CHALLENGE,
        "jti": JTI,
        "auth_time": CREATED.timestamp() + 5,
    }
    base.update(overrides)
    return base


def without(name: str) -> dict[str, Any]:
    remaining = claims()
    del remaining[name]
    return remaining


def check(
    row: ChallengeRecord,
    claim_set: Mapping[str, Any],
    *,
    expected: str | None = IDV,
    now: float = NOW,
    operations: Mapping[str, WriteOperation] = WRITE_OPERATIONS,
) -> TierVerdict:
    return check_tier(
        record=row,
        challenge_id=CHALLENGE,
        claims=claim_set,
        expected_idv=expected,
        now=now,
        operations=operations,
    )


def required(claim: str) -> TierRefusal:
    return TierRefusal(
        error="verification_required",
        detail=DETAIL_VERIFICATION_REQUIRED,
        description=VERIFICATION_REQUIRED_DESCRIPTION,
        failed_claim=claim,
    )


MISMATCH = TierRefusal(
    error="tier_mismatch",
    detail=DETAIL_TIER_MISMATCH,
    description=TIER_MISMATCH_DESCRIPTION,
    failed_claim=None,
)


# -- Tier 1 is unchanged -----------------------------------------------------------


def test_a_tier_1_row_needs_no_claims() -> None:
    assert check(record(tier=1, tool_name=TIER_1_TOOL), {}) == TierVerdict(None, None)


def test_a_tier_1_row_ignores_tier_2_claims() -> None:
    assert check(record(tier=1, tool_name=TIER_1_TOOL), claims()) == TierVerdict(None, None)


def test_an_unset_value_does_not_touch_a_tier_1_row() -> None:
    row = record(tier=1, tool_name=TIER_1_TOOL)
    assert check(row, {}, expected=None) == TierVerdict(None, None)


def test_a_tier_1_row_of_an_undeclared_operation_is_left_to_the_executor() -> None:
    """`resolve_endpoint` refuses an unknown tool after the claim, as before."""
    row = record(tier=1, tool_name="test.unregistered_write")
    assert check(row, {}) == TierVerdict(None, None)


# -- Tier 2 --------------------------------------------------------------------------


def test_a_tier_2_row_with_all_four_claims_passes_and_returns_the_jti() -> None:
    assert check(record(), claims()) == TierVerdict(refusal=None, assertion_jti=JTI)


def test_an_unset_value_refuses_every_tier_2_row() -> None:
    assert check(record(), claims(), expected=None) == TierVerdict(
        refusal=TierRefusal(
            error="verification_required",
            detail=DETAIL_VERIFICATION_NOT_CONFIGURED,
            description=VERIFICATION_REQUIRED_DESCRIPTION,
            failed_claim=None,
        ),
        assertion_jti=None,
    )


@pytest.mark.parametrize(
    ("claim_set", "failed", "jti_recorded"),
    [
        pytest.param(without("idv"), "idv", False, id="idv-missing"),
        pytest.param(claims(idv=1), "idv", False, id="idv-not-a-string"),
        pytest.param(claims(idv="another-value"), "idv", False, id="idv-wrong"),
        pytest.param(claims(idv=IDV.upper()), "idv", False, id="idv-other-case"),
        pytest.param(claims(idv=f" {IDV}"), "idv", False, id="idv-padded"),
        pytest.param(claims(idv=""), "idv", False, id="idv-empty"),
        pytest.param(claims(idv=None), "idv", False, id="idv-null"),
        pytest.param(without("challenge_id"), "challenge_id", False, id="challenge-id-missing"),
        pytest.param(claims(challenge_id=1), "challenge_id", False, id="challenge-id-number"),
        pytest.param(
            claims(challenge_id="t2_unit_0002"), "challenge_id", False, id="challenge-id-other"
        ),
        pytest.param(
            claims(challenge_id=CHALLENGE[:-1]), "challenge_id", False, id="challenge-id-prefix"
        ),
        pytest.param(
            claims(challenge_id=CHALLENGE + "0"), "challenge_id", False, id="challenge-id-extended"
        ),
        pytest.param(
            claims(challenge_id=CHALLENGE + "\n"),
            "challenge_id",
            False,
            id="challenge-id-trailing-newline",
        ),
        pytest.param(
            claims(challenge_id=CHALLENGE.upper()),
            "challenge_id",
            False,
            id="challenge-id-other-case",
        ),
        pytest.param(without("jti"), "jti", False, id="jti-missing"),
        pytest.param(claims(jti=7), "jti", False, id="jti-number"),
        pytest.param(claims(jti=""), "jti", False, id="jti-empty"),
        pytest.param(claims(jti="j" * 129), "jti", False, id="jti-129-characters"),
        pytest.param(claims(jti="jti\x00x"), "jti", False, id="jti-nul"),
        pytest.param(claims(jti="jti x"), "jti", False, id="jti-space"),
        pytest.param(claims(jti="jti\x7f"), "jti", False, id="jti-del"),
        pytest.param(claims(jti="jti-é"), "jti", False, id="jti-non-ascii"),
        pytest.param(without("auth_time"), "auth_time", True, id="auth-time-missing"),
        pytest.param(claims(auth_time=True), "auth_time", True, id="auth-time-bool"),
        pytest.param(
            claims(auth_time=str(CREATED.timestamp() + 5)),
            "auth_time",
            True,
            id="auth-time-in-range-numeric-string",
        ),
        pytest.param(claims(auth_time=math.nan), "auth_time", True, id="auth-time-nan"),
        pytest.param(claims(auth_time=math.inf), "auth_time", True, id="auth-time-inf"),
        pytest.param(claims(auth_time=-math.inf), "auth_time", True, id="auth-time-minus-inf"),
        pytest.param(claims(auth_time=10**400), "auth_time", True, id="auth-time-huge-int"),
        pytest.param(
            claims(auth_time=CREATED.timestamp() - 31),
            "auth_time",
            True,
            id="auth-time-31s-before-creation",
        ),
        pytest.param(claims(auth_time=NOW + 31), "auth_time", True, id="auth-time-31s-ahead"),
    ],
)
def test_each_failed_claim_refuses_with_one_description(
    claim_set: dict[str, Any], failed: str, jti_recorded: bool
) -> None:
    verdict = check(record(), claim_set)
    assert verdict.refusal == required(failed)
    assert verdict.assertion_jti == (JTI if jti_recorded else None)


@pytest.mark.parametrize(
    "auth_time",
    [
        pytest.param(CREATED.timestamp() - 30, id="lower-bound"),
        pytest.param(NOW + 30, id="upper-bound"),
        pytest.param(int(CREATED.timestamp()), id="an-integer"),
    ],
)
def test_the_auth_time_bounds_are_inclusive(auth_time: float) -> None:
    assert check(record(), claims(auth_time=auth_time)) == TierVerdict(None, JTI)


def test_a_jti_of_exactly_128_characters_passes() -> None:
    jti = "j" * 128
    assert check(record(), claims(jti=jti)) == TierVerdict(None, jti)


def test_an_infinite_auth_time_is_refused_even_when_the_bounds_would_admit_it() -> None:
    """With ``now`` infinite the upper bound is infinite, so ``inf <= inf``
    holds and only the finiteness check refuses."""
    verdict = check(record(), claims(auth_time=math.inf), now=math.inf)
    assert verdict.refusal == required("auth_time")
    assert verdict.assertion_jti == JTI


def test_a_bool_auth_time_is_refused_where_the_integer_1_would_pass() -> None:
    """A row created one second after the epoch puts ``1`` inside the bounds,
    so the refusal of ``True`` is the bool rule and not the bounds."""
    epoch = datetime(1970, 1, 1, 0, 0, 1, tzinfo=UTC)
    row = record(created_at=epoch)
    assert check(row, claims(auth_time=1), now=1.0).refusal is None
    assert check(row, claims(auth_time=True), now=1.0).refusal == required("auth_time")


# -- The declared tier -------------------------------------------------------------


@pytest.mark.parametrize("tier", [0, 1])
def test_a_payment_row_below_its_declared_tier_is_a_mismatch(tier: int) -> None:
    assert check(record(tier=tier), claims()) == TierVerdict(MISMATCH, None)


def test_the_mismatch_reads_the_declared_tier_from_the_operations_given() -> None:
    declared = WriteOperation(
        tool_name="test.write",
        audience="payments.svc",
        path_template="/test",
        method="POST",
        tier=VerificationTier.APP_IDENTITY_VERIFICATION,
    )
    row = record(tier=1, tool_name="test.write")
    assert check(row, {}, operations={"test.write": declared}).refusal == MISMATCH
    assert check(row, {}, operations={}).refusal is None


def test_a_tier_2_row_of_a_tier_1_operation_needs_the_proof() -> None:
    row = record(tier=2, tool_name=TIER_1_TOOL)
    assert check(row, {}).refusal == required("idv")
    assert check(row, claims()) == TierVerdict(None, JTI)


def test_a_tier_0_row_of_an_undeclared_operation_is_unsupported() -> None:
    row = record(tier=0, tool_name="test.unregistered_write")
    assert check(row, claims()) == TierVerdict(
        TierRefusal(
            error="tier_unsupported",
            detail=DETAIL_TIER_UNSUPPORTED,
            description=TIER_UNSUPPORTED_DESCRIPTION,
            failed_claim=None,
        ),
        None,
    )


# -- What a refusal says -----------------------------------------------------------


def test_no_description_names_a_claim_or_the_configured_value() -> None:
    for description in (
        VERIFICATION_REQUIRED_DESCRIPTION,
        TIER_MISMATCH_DESCRIPTION,
        TIER_UNSUPPORTED_DESCRIPTION,
    ):
        assert IDV not in description
        for claim in ("idv", "challenge_id", "jti", "auth_time"):
            assert claim not in description


def test_a_claim_refusal_is_a_fixed_403_and_logs_the_claim_name(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.tier_proof"):
        response, detail = tier_refusal(CHALLENGE, required("jti"))
    assert response.status_code == 403
    assert json.loads(bytes(response.body)) == {
        "error": "verification_required",
        "error_description": VERIFICATION_REQUIRED_DESCRIPTION,
    }
    assert detail == DETAIL_VERIFICATION_REQUIRED
    (logged,) = caplog.records
    assert logged.levelno == logging.WARNING
    assert CHALLENGE in logged.getMessage()
    assert "jti claim" in logged.getMessage()


@pytest.mark.parametrize("refusal", [required("jti"), MISMATCH], ids=["claim", "row"])
def test_a_newline_in_the_challenge_id_cannot_forge_a_log_line(
    caplog: pytest.LogCaptureFixture, refusal: TierRefusal
) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.tier_proof"):
        tier_refusal("abc\nWARNING forged line", refusal)
    (logged,) = caplog.records
    assert "\n" not in logged.getMessage()


def test_a_row_refusal_logs_its_detail(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="services.confirm.tier_proof"):
        response, detail = tier_refusal(CHALLENGE, MISMATCH)
    assert response.status_code == 403
    assert json.loads(bytes(response.body))["error"] == "tier_mismatch"
    assert detail == DETAIL_TIER_MISMATCH
    (logged,) = caplog.records
    assert "tier_mismatch" in logged.getMessage()

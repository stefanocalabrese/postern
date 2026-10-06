"""The tier a challenge row needs at approval, and whether the assertion proves it.

Spec docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md,
section 5, and decision record 0023. ``services/confirm/callback.py`` calls
`check_tier` between the device-signature check and the claiming ``UPDATE``,
so every refusal here leaves the row ``pending`` and the customer can retry
inside the tier's window.

THE RULE, in the order it is applied:

1. A row whose tier is below the tier its operation declares is refused,
   ``tier_mismatch``. The declared tier is static configuration in this
   process (`services.confirm.execute`'s ``WRITE_OPERATIONS``); the row is
   not, because ``postern_app`` holds ``UPDATE`` on ``challenges`` and the api
   connects as that role.
2. Tier 1 is unchanged: no claim is read.
3. Tier 2 needs four claims of the verified banking-app assertion: ``idv``
   equal to ``POSTERN_CONFIRM_IDV_VALUE``, ``challenge_id`` equal to the
   challenge in the request path, a ``jti`` of 1 to 128 printable ASCII
   characters, and a numeric ``auth_time`` no earlier than 30 seconds before
   the row was created and no later than 30 seconds from now. With the
   setting unset every tier-2 row is refused, ``verification_not_configured``.
4. Any other tier, which in a database whose CHECK allows 0 to 2 means tier 0,
   is refused, ``tier_unsupported``. A tier-0 row of a declared operation
   never gets here: every declared tier is 1 or 2, so step 1 refuses it first.

WHAT THIS PROVES, AND WHAT IT CANNOT. The trust anchor is the operator's app
backend, which minted the assertion: the claims say "identity verification
happened for this challenge", and nothing in this repository can check the
match itself (handoff section 6.3 and section 10.8 place it in the backend
cluster). What it stops is an approval that carries no claim of verification,
and one assertion reused across challenges. It cannot see one verification
backing several assertions, an ``idv`` the backend sets without a
verification, or an ``auth_time`` it sets to whatever it likes; the mobile
app pairing contract lists what the backend must do instead.

`check_tier` is pure: no I/O, no clock, no logging. `tier_refusal` is the
one function here that logs, and it names the failed claim and never a value.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from postern_core.domain.verification import VerificationTier
from postern_core.modules.write import WriteOperation
from postern_core.store.models import ChallengeRecord
from starlette.responses import JSONResponse

from services.confirm.audit import (
    DETAIL_TIER_MISMATCH,
    DETAIL_TIER_UNSUPPORTED,
    DETAIL_VERIFICATION_NOT_CONFIGURED,
    DETAIL_VERIFICATION_REQUIRED,
)
from services.confirm.auth import ASSERTION_CLOCK_SKEW_SECONDS
from services.confirm.settings import is_visible_ascii

logger = logging.getLogger(__name__)

#: The ``error`` codes a refusal answers with. Two tier-2 failures share the
#: first; the audit ``detail`` tells them apart.
VERIFICATION_REQUIRED_ERROR = "verification_required"
TIER_MISMATCH_ERROR = "tier_mismatch"
TIER_UNSUPPORTED_ERROR = "tier_unsupported"

#: The fixed ``error_description`` of each. None names a claim or carries a
#: value: a caller cannot change the signed claims, so there is nothing for it
#: to probe, and the configured value must never be in a response.
VERIFICATION_REQUIRED_DESCRIPTION = (
    "this challenge requires proof of app identity verification, and the assertion "
    "does not carry it"
)
TIER_MISMATCH_DESCRIPTION = (
    "this challenge is stored below the verification tier its operation requires"
)
TIER_UNSUPPORTED_DESCRIPTION = "this challenge's verification tier cannot be approved"

#: The four claims a tier-2 approval reads, by name. The WARNING line names
#: whichever failed.
IDV_CLAIM = "idv"
CHALLENGE_ID_CLAIM = "challenge_id"
JTI_CLAIM = "jti"
AUTH_TIME_CLAIM = "auth_time"


@dataclass(frozen=True, slots=True)
class TierRefusal:
    """Why an approval is refused before the claim.

    ``failed_claim`` names the tier-2 claim that failed, for the operator's
    log line, and is ``None`` for the three refusals that are about the row
    or the setting rather than a claim.
    """

    error: str
    detail: str
    description: str
    failed_claim: str | None


@dataclass(frozen=True, slots=True)
class TierVerdict:
    """What `check_tier` decided.

    ``refusal`` is ``None`` when the approval may go on to the claim.
    ``assertion_jti`` is the assertion's ``jti`` once it has passed its own
    check on a tier-2 row, whether or not a later check refused, so the audit
    row can record it (spec section 8); ``None`` otherwise, and always
    ``None`` on tier 1.
    """

    refusal: TierRefusal | None
    assertion_jti: str | None


_TIER_MISMATCH = TierRefusal(
    error=TIER_MISMATCH_ERROR,
    detail=DETAIL_TIER_MISMATCH,
    description=TIER_MISMATCH_DESCRIPTION,
    failed_claim=None,
)
_TIER_UNSUPPORTED = TierRefusal(
    error=TIER_UNSUPPORTED_ERROR,
    detail=DETAIL_TIER_UNSUPPORTED,
    description=TIER_UNSUPPORTED_DESCRIPTION,
    failed_claim=None,
)
_NOT_CONFIGURED = TierRefusal(
    error=VERIFICATION_REQUIRED_ERROR,
    detail=DETAIL_VERIFICATION_NOT_CONFIGURED,
    description=VERIFICATION_REQUIRED_DESCRIPTION,
    failed_claim=None,
)


def _required(claim: str) -> TierRefusal:
    return TierRefusal(
        error=VERIFICATION_REQUIRED_ERROR,
        detail=DETAIL_VERIFICATION_REQUIRED,
        description=VERIFICATION_REQUIRED_DESCRIPTION,
        failed_claim=claim,
    )


def _auth_time_within(value: object, *, lower: float, upper: float) -> bool:
    """A finite JSON number, not a bool, inside ``[lower, upper]``.

    ``bool`` is refused by name because it is an ``int`` subclass, for the
    reason `services/confirm/auth.py`'s `_is_time` gives. Finiteness is
    checked on a ``float`` only: ``math.isfinite`` raises ``OverflowError``
    on an ``int`` too large for a float (``10**400`` is a valid JSON number),
    and every ``int`` is finite anyway, so the comparison below is exact.
    """
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    if isinstance(value, float) and not math.isfinite(value):
        return False
    return lower <= value <= upper


def check_tier(
    *,
    record: ChallengeRecord,
    challenge_id: str,
    claims: Mapping[str, Any],
    expected_idv: str | None,
    now: float,
    operations: Mapping[str, WriteOperation],
) -> TierVerdict:
    """Decide whether this approval may go on to the claim (module docstring).

    Args:
        record: the stored challenge row, as ``get_challenge`` read it.
        challenge_id: the challenge id from the request path.
        claims: every claim of the verified banking-app assertion.
        expected_idv: ``ConfirmSettings.idv_value``; ``None`` when unset.
        now: the current time, seconds since the epoch.
        operations: the declared write operations, keyed by tool name.
    """
    declared = operations.get(record.tool_name)
    if declared is not None and record.tier < declared.tier:
        return TierVerdict(refusal=_TIER_MISMATCH, assertion_jti=None)
    if record.tier == VerificationTier.APP_APPROVAL:
        return TierVerdict(refusal=None, assertion_jti=None)
    if record.tier != VerificationTier.APP_IDENTITY_VERIFICATION:
        return TierVerdict(refusal=_TIER_UNSUPPORTED, assertion_jti=None)
    if expected_idv is None:
        return TierVerdict(refusal=_NOT_CONFIGURED, assertion_jti=None)

    # Exact comparison on the stored string: no case folding, no trimming,
    # no normalisation. `isinstance` first, so a missing or null claim is
    # refused before anything is compared with it.
    idv = claims.get(IDV_CLAIM)
    if not isinstance(idv, str) or idv != expected_idv:
        return TierVerdict(refusal=_required(IDV_CLAIM), assertion_jti=None)

    # Against the PATH, which is the challenge this request is approving.
    bound = claims.get(CHALLENGE_ID_CLAIM)
    if not isinstance(bound, str) or bound != challenge_id:
        return TierVerdict(refusal=_required(CHALLENGE_ID_CLAIM), assertion_jti=None)

    # The character rule is what keeps the claiming UPDATE from raising on a
    # NUL when this value is stored as `verification_result`.
    jti = claims.get(JTI_CLAIM)
    if not isinstance(jti, str) or not is_visible_ascii(jti):
        return TierVerdict(refusal=_required(JTI_CLAIM), assertion_jti=None)

    # From here on the jti is recorded even on a refusal (spec section 8).
    if not _auth_time_within(
        claims.get(AUTH_TIME_CLAIM),
        lower=record.created_at.timestamp() - ASSERTION_CLOCK_SKEW_SECONDS,
        upper=now + ASSERTION_CLOCK_SKEW_SECONDS,
    ):
        return TierVerdict(refusal=_required(AUTH_TIME_CLAIM), assertion_jti=jti)
    return TierVerdict(refusal=None, assertion_jti=jti)


def tier_refusal(challenge_id: str, refusal: TierRefusal) -> tuple[JSONResponse, str]:
    """The 403 and the audit ``detail`` for ``refusal``, with one WARNING line.

    403 and not 401, for the reason ``services/confirm/device_signature.py``
    gives for its own refusals: the caller authenticated and is not permitted.
    The log line names the failed claim, or the refusal's detail when no claim
    failed, and never a claim value or the configured value: an operator needs
    to know which claim to take up with the app backend, and with the payments
    flag on, each refusal has already cost a customer a verification.
    """
    if refusal.failed_claim is None:
        logger.warning("challenge approve: %r refused, %s", challenge_id, refusal.detail)
    else:
        logger.warning(
            "challenge approve: %r refused, the assertion's %s claim does not prove "
            "app identity verification for this challenge",
            challenge_id,
            refusal.failed_claim,
        )
    response = JSONResponse(
        status_code=403,
        content={"error": refusal.error, "error_description": refusal.description},
    )
    return response, refusal.detail

"""The payments producer's shared declaration.

Both services import it. `services/api` stores `PAYMENT_TIER` on every
challenge it creates, and `services/confirm` routes the approved operation at
that tier, so the two cannot disagree about the tier or the name (spec
docs/superpowers/specs/2026-10-04-payments-producer-core-design.md, section 4).

NOT PART OF `postern_core.modules.write`, which is what keeps the api's import
rule untouched: `.importlinter`'s ``api-not-module-write-half`` contract
forbids that package, and this module imports nothing but the tier enum.
"""

import hashlib
import json
from collections.abc import Mapping

from postern_core.domain.verification import VerificationTier

#: The verification tier a payment requires: device approval plus server-side
#: app identity verification (handoff §7.4).
PAYMENT_TIER = VerificationTier.APP_IDENTITY_VERIFICATION

#: The tool that proposes a payment, and the write operation `services/confirm`
#: executes once the customer approves it. One name for both, because the
#: approval callback routes on the `tool_name` the producer stored.
CREATE_PAYMENT_TOOL = "payments.create_payment"

#: The tool that reports a proposal's status. Not a write operation.
PAYMENT_STATUS_TOOL = "payments.get_payment_status"

#: Every tool the producer registers, in registration order.
PRODUCER_TOOL_NAMES: tuple[str, ...] = (CREATE_PAYMENT_TOOL, PAYMENT_STATUS_TOOL)


def request_fingerprint(*, customer_ref: str, tool_name: str, payload: Mapping[str, str]) -> str:
    """Lowercase hex SHA-256 naming one request, for idempotency (spec section 5).

    JSON with sorted keys and no whitespace, rather than the fields joined by a
    separator: a separator can occur inside a value, and then two different
    requests concatenate to the same string. Key order in `payload` does not
    matter; every key and every value does.
    """
    canonical = json.dumps(
        {"customer_ref": customer_ref, "tool_name": tool_name, "payload": dict(payload)},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

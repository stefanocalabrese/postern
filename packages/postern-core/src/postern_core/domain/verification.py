"""Verification tiering and challenge models (handoff §7.4).

The three-tier verification system that gates write operations:

- **Tier 0** — Session token only. All reads. PSD2 requires SCA for AIS
  only at consent and every 180 days (§6.4).

- **Tier 1** — App approval: device-bound key (possession) + app unlock
  via PIN/passcode/device biometric (knowledge or inherence). Covers most
  writes: freeze card, set label, rename, cancel a standing order.

- **Tier 2** — Tier 1 plus server-side app identity verification
  (selfie matching with liveness detection). Covers payments, new payees,
  high value, limit increases.

Tier 1 is the default for writes, not tier 2. It satisfies SCA with two
factors from different categories, takes about a second, and triggers no
Article 9 processing event. Tier 2 costs 5–15 seconds, fails a real
percentage of the time on lighting/glasses/angle, and creates a
special-category processing event every single time.

**Terminology:** The operator's app brands its identity-verification
feature "Face ID" internally, but it is **server-side selfie matching**
running in the backend cluster — not Apple's on-device Secure Enclave
feature. Never write "Face ID" in this codebase. Use "app identity
verification"; write "device unlock biometric" when the phone's own
biometric is meant.

Challenge lifecycle:

1. ``payments.create_payment`` (or any tier-1/2 tool) persists a
   ``Challenge`` row and returns ``challenge_id`` immediately.

2. The confirmation payload is built server-side from the stored row
   (NEVER from agent input), sent to the mobile app.

3. User approves on their device (tier 1: PIN/biometric + device-bound
   key signature; tier 2: additionally selfie capture and matching).

4. Approval callback marks the challenge approved, writes the audit
   chain, and executes the backend write endpoint.

5. The agent polls ``payments.get_payment_status(challenge_id)`` until
   the challenge reaches a terminal state.

Challenges expire at 2–5 minutes; ``is_expired`` tells callers whether
to return an error or continue waiting.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

# ---------------------------------------------------------------------------
# VerificationTier — which verification gates this operation.
# ---------------------------------------------------------------------------


class VerificationTier(IntEnum):
    """Which verification gates a write operation.

    Declared on the tool definition (handoff §7.4: "Do NOT tier on the
    HTTP verb"). Runtime risk rules may escalate upward per call.

    Attributes:
        SESSION_ONLY: Read-only access, session token suffices.
        APP_APPROVAL: Device-bound key + app unlock (PIN/passcode/biometric).
        APP_IDENTITY_VERIFICATION: Tier 1 plus server-side selfie matching.
    """

    SESSION_ONLY = 0
    APP_APPROVAL = 1
    APP_IDENTITY_VERIFICATION = 2

    @property
    def requires_selfie(self) -> bool:
        """Whether this tier triggers server-side selfie matching."""
        return self == VerificationTier.APP_IDENTITY_VERIFICATION

    @property
    def requires_device_key(self) -> bool:
        """Whether this tier requires a device-bound key signature."""
        return self >= VerificationTier.APP_APPROVAL

    def __str__(self) -> str:
        return {
            VerificationTier.SESSION_ONLY: "session",
            VerificationTier.APP_APPROVAL: "app_approval",
            VerificationTier.APP_IDENTITY_VERIFICATION: "app_identity_verification",
        }[self]


# ---------------------------------------------------------------------------
# Challenge — the approval workflow state machine.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Challenge:
    """A pending approval workflow for a write operation.

    The challenge is the source of truth for what executes: the confirmation
    payload sent to the phone is built server-side from this stored row,
    never re-sent or re-specified by the agent.

    This dataclass is not used by the approval callback, which works on the
    stored ``ChallengeRecord`` row. The tier-2 rule enforced at approval is
    ``services/confirm/tier_proof.py`` (four claims of the banking-app
    assertion; decision record 0023), not the ``approve`` check below, which
    only requires a non-empty ``verification_result`` argument.

    Attributes:
        challenge_id: Opaque unique identifier. The idempotency key for
            ``create_payment`` — calling again with identical parameters
            inside a short window returns the existing pending challenge.
        customer_ref: The customer who initiated the operation (from token).
        tool_name: Which MCP tool triggered this challenge.
        payload: The full operation payload as presented to the device —
            amount, payee, account. Built server-side from stored data.
        tier: The verification tier required for this operation.
        status: Current state of the approval workflow.
        created_at: When the challenge was created (UTC).
        expires_at: When this challenge expires and can no longer be approved.
        confirming_device: Device identifier once the user approves (None until then).
        verification_result: Opaque reference to the tier-2 verification result.
            The approval callback does not use this dataclass; on a stored
            tier-2 row the value is the ``jti`` of the banking-app assertion
            that proved app identity verification (decision record 0023).
            Never stores the captured image — only the result and an audit
            reference (handoff §7.4: "never store the captured image").
        signature: Device-bound key signature over the payload, provided by
            the mobile app at approval time.
    """

    challenge_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    customer_ref: str = ""
    tool_name: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    tier: VerificationTier = VerificationTier.APP_APPROVAL
    status: str = "pending"  # pending | approved | executed | declined | expired
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = field(default=None)  # computed in __post_init__ if None.
    confirming_device: str | None = None
    verification_result: str | None = None
    signature: str | None = None

    def __post_init__(self) -> None:
        """Set expires_at from created_at + TTL based on tier, if not provided."""
        if self.expires_at is None:
            ttl_seconds = {
                VerificationTier.SESSION_ONLY: 30,
                VerificationTier.APP_APPROVAL: 180,
                VerificationTier.APP_IDENTITY_VERIFICATION: 300,
            }[self.tier]
            object.__setattr__(
                self, "expires_at", self.created_at + _dt.timedelta(seconds=ttl_seconds)
            )

    @property
    def is_expired(self) -> bool:
        """Whether this challenge has passed its expiry."""
        expires = self.expires_at
        if expires is None:
            return False  # not expired if never computed (shouldn't happen)
        return datetime.now(UTC) >= expires

    @property
    def is_terminal(self) -> bool:
        """Whether this challenge has reached a terminal state."""
        return self.status in ("approved", "executed", "declined", "expired")

    @property
    def human_summary(self) -> str:
        """A human-readable summary for relaying to the operator.

        Built from the payload and tier — what the agent shows the user
        as "check your phone to approve EUR 340 to Acme Ltd".
        """
        amount = self.payload.get("amount", "?")
        payee = self.payload.get("payee", "the recipient")
        return f"approve {amount} to {payee}"

    def approve(
        self,
        *,
        device_id: str,
        signature: str,
        verification_result: str | None = None,
    ) -> Challenge:
        """Transition this challenge to approved state.

        Args:
            device_id: The confirming device identifier.
            signature: Device-bound key signature over the payload.
            verification_result: Opaque reference recorded with the approval.
                This model is NOT what the approval callback runs: the
                callback in ``services/confirm`` enforces tier 2 through
                ``services/confirm/tier_proof.py``, which reads claims of the
                banking-app assertion and stores its ``jti`` (decision record
                0023). The check below is this dataclass's own, older rule.

        Returns:
            A new ``Challenge`` with updated state.

        Raises:
            ValueError: If the challenge is already terminal or expired.
        """
        if self.is_terminal:
            raise ValueError(f"Challenge {self.challenge_id} is already terminal ({self.status})")
        if self.is_expired:
            raise ValueError(f"Challenge {self.challenge_id} has expired")

        # Validate tier-2 requirements.
        if self.tier == VerificationTier.APP_IDENTITY_VERIFICATION:
            if not verification_result:
                raise ValueError("tier-2 challenge requires a verification result")

        updated = Challenge(
            challenge_id=self.challenge_id,
            customer_ref=self.customer_ref,
            tool_name=self.tool_name,
            payload=dict(self.payload),
            tier=self.tier,
            status="approved",
            created_at=self.created_at,
            expires_at=self.expires_at,
            confirming_device=device_id,
            verification_result=verification_result,
            signature=signature,
        )
        return updated

    def expire(self) -> Challenge:
        """Transition this challenge to expired state."""
        if self.is_terminal and not self.is_expired:
            return self  # Already terminal, don't re-transition.

        updated = Challenge(
            challenge_id=self.challenge_id,
            customer_ref=self.customer_ref,
            tool_name=self.tool_name,
            payload=dict(self.payload),
            tier=self.tier,
            status="expired",
            created_at=self.created_at,
            expires_at=self.expires_at,
            confirming_device=self.confirming_device,
            verification_result=self.verification_result,
            signature=self.signature,
        )
        return updated

    def decline(self) -> Challenge:
        """Transition this challenge to declined state."""
        updated = Challenge(
            challenge_id=self.challenge_id,
            customer_ref=self.customer_ref,
            tool_name=self.tool_name,
            payload=dict(self.payload),
            tier=self.tier,
            status="declined",
            created_at=self.created_at,
            expires_at=self.expires_at,
            confirming_device=self.confirming_device,
            verification_result=self.verification_result,
            signature=self.signature,
        )
        return updated

    def to_dict(self) -> dict[str, Any]:
        """Serialize for storage (e.g. Redis or JSON audit)."""
        return {
            "challenge_id": self.challenge_id,
            "customer_ref": self.customer_ref,
            "tool_name": self.tool_name,
            "payload": self.payload,
            "tier": int(self.tier),
            "status": self.status,
            "created_at": int(self.created_at.timestamp()),
            "expires_at": int(self.expires_at.timestamp()) if self.expires_at else 0,
            "confirming_device": self.confirming_device,
            "verification_result": self.verification_result,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Challenge:
        """Deserialize from storage."""
        created_at = _dt.datetime.fromtimestamp(data["created_at"], tz=UTC)
        expires_at_override = _dt.datetime.fromtimestamp(data["expires_at"], tz=UTC)

        obj = cls(
            challenge_id=data["challenge_id"],
            customer_ref=data["customer_ref"],
            tool_name=data["tool_name"],
            payload=data.get("payload", {}),
            tier=VerificationTier(data["tier"]),
            status=data.get("status", "pending"),
            created_at=created_at,
            expires_at=expires_at_override,  # Override the __post_init__ computed value.
            confirming_device=data.get("confirming_device"),
            verification_result=data.get("verification_result"),
            signature=data.get("signature"),
        )
        return obj


# ---------------------------------------------------------------------------
# Backwards-compatible alias.
# ---------------------------------------------------------------------------

#: Alias for ``VerificationTier.APP_APPROVAL`` — the default tier for writes.
DEFAULT_VERIFICATION_TIER = VerificationTier.APP_APPROVAL

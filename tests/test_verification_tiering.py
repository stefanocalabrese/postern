"""Verification tiering and challenge lifecycle (handoff §7.4).

Covers:
- VerificationTier enum values, properties, and string representation.
- Challenge creation with tier-specific TTLs (30s/180s/300s).
- Challenge state transitions: approve, expire, decline.
- Tier-2 requires verification_result on approval.
- Expiry detection and terminal state guards.
- Serialization round-trip (to_dict / from_dict).
- Human-readable summary generation.
"""

from datetime import UTC, datetime, timedelta

import pytest

from postern_core.domain.verification import (
    Challenge,
    DEFAULT_VERIFICATION_TIER,
    VerificationTier,
)


# ---------------------------------------------------------------------------
# VerificationTier enum.
# ---------------------------------------------------------------------------


class TestVerificationTierEnum:
    """The three-tier verification system."""

    def test_tier_values(self) -> None:
        assert int(VerificationTier.SESSION_ONLY) == 0
        assert int(VerificationTier.APP_APPROVAL) == 1
        assert int(VerificationTier.APP_IDENTITY_VERIFICATION) == 2

    def test_requires_selfie(self) -> None:
        assert VerificationTier.SESSION_ONLY.requires_selfie is False
        assert VerificationTier.APP_APPROVAL.requires_selfie is False
        assert VerificationTier.APP_IDENTITY_VERIFICATION.requires_selfie is True

    def test_requires_device_key(self) -> None:
        assert VerificationTier.SESSION_ONLY.requires_device_key is False
        assert VerificationTier.APP_APPROVAL.requires_device_key is True
        assert VerificationTier.APP_IDENTITY_VERIFICATION.requires_device_key is True

    def test_str_representation(self) -> None:
        assert str(VerificationTier.SESSION_ONLY) == "session"
        assert str(VerificationTier.APP_APPROVAL) == "app_approval"
        assert str(VerificationTier.APP_IDENTITY_VERIFICATION) == "app_identity_verification"

    def test_default_tier_is_app_approval(self) -> None:
        assert DEFAULT_VERIFICATION_TIER == VerificationTier.APP_APPROVAL


# ---------------------------------------------------------------------------
# Challenge creation and tier-specific TTLs.
# ---------------------------------------------------------------------------


class TestChallengeCreation:
    """Challenge creation with tier-specific TTLs."""

    def test_default_challenge_has_pending_status(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        assert c.status == "pending"
        assert not c.is_terminal
        assert not c.is_expired

    def test_tier_0_ttl_is_30_seconds(self) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        c = Challenge(tier=VerificationTier.SESSION_ONLY, created_at=base)
        assert c.expires_at is not None
        assert (c.expires_at - base).total_seconds() == 30

    def test_tier_1_ttl_is_180_seconds(self) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        c = Challenge(tier=VerificationTier.APP_APPROVAL, created_at=base)
        assert c.expires_at is not None
        assert (c.expires_at - base).total_seconds() == 180

    def test_tier_2_ttl_is_300_seconds(self) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        c = Challenge(tier=VerificationTier.APP_IDENTITY_VERIFICATION, created_at=base)
        assert c.expires_at is not None
        assert (c.expires_at - base).total_seconds() == 300

    def test_challenge_generates_unique_id(self) -> None:
        c1 = Challenge(tier=VerificationTier.APP_APPROVAL)
        c2 = Challenge(tier=VerificationTier.APP_APPROVAL)
        assert c1.challenge_id != c2.challenge_id

    def test_challenge_stores_payload(self) -> None:
        payload = {"amount": "EUR 340.00", "payee": "Acme Ltd", "account": "acc_123"}
        c = Challenge(
            customer_ref="cust_7f3a",
            tool_name="payments.create_payment",
            payload=payload,
            tier=VerificationTier.APP_IDENTITY_VERIFICATION,
        )
        assert c.payload == payload

    def test_challenge_stores_customer_and_tool(self) -> None:
        c = Challenge(
            customer_ref="cust_7f3a",
            tool_name="cards.freeze_card",
            tier=VerificationTier.APP_APPROVAL,
        )
        assert c.customer_ref == "cust_7f3a"
        assert c.tool_name == "cards.freeze_card"


# ---------------------------------------------------------------------------
# Challenge state transitions.
# ---------------------------------------------------------------------------


class TestChallengeApprove:
    """Transition from pending to approved."""

    def test_approve_sets_status_and_device(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        approved = c.approve(device_id="dev_abc123", signature="sig_xyz")
        assert approved.status == "approved"
        assert approved.confirming_device == "dev_abc123"
        assert approved.signature == "sig_xyz"

    def test_approve_preserves_original_fields(self) -> None:
        c = Challenge(
            customer_ref="cust_7f3a",
            tool_name="payments.create_payment",
            payload={"amount": "EUR 340.00"},
            tier=VerificationTier.APP_IDENTITY_VERIFICATION,
        )
        approved = c.approve(
            device_id="dev_abc",
            signature="sig",
            verification_result="vr_match_001",
        )
        assert approved.customer_ref == "cust_7f3a"
        assert approved.tool_name == "payments.create_payment"
        assert approved.payload == {"amount": "EUR 340.00"}
        assert approved.tier == VerificationTier.APP_IDENTITY_VERIFICATION

    def test_approve_preserves_timestamps(self) -> None:
        base = datetime(2030, 1, 1, 12, 0, 0, tzinfo=UTC)
        c = Challenge(tier=VerificationTier.APP_APPROVAL, created_at=base)
        approved = c.approve(device_id="dev", signature="sig")
        assert approved.created_at == base
        assert approved.expires_at == c.expires_at

    def test_approve_tier_2_requires_verification_result(self) -> None:
        c = Challenge(tier=VerificationTier.APP_IDENTITY_VERIFICATION)
        with pytest.raises(ValueError, match="tier-2"):
            c.approve(device_id="dev", signature="sig")

    def test_approve_tier_1_does_not_require_verification_result(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        approved = c.approve(device_id="dev", signature="sig")
        assert approved.verification_result is None

    def test_approved_challenge_cannot_be_reapproved(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        approved = c.approve(device_id="dev", signature="sig")
        with pytest.raises(ValueError, match="already terminal"):
            approved.approve(device_id="dev", signature="sig")

    def test_expired_challenge_cannot_be_approved(self) -> None:
        base = datetime(2020, 1, 1, tzinfo=UTC)
        c = Challenge(tier=VerificationTier.APP_APPROVAL, created_at=base)
        assert c.is_expired
        with pytest.raises(ValueError, match="expired"):
            c.approve(device_id="dev", signature="sig")


class TestChallengeExpire:
    """Transition to expired state."""

    def test_expire_sets_status(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        expired = c.expire()
        assert expired.status == "expired"

    def test_expire_preserves_fields(self) -> None:
        c = Challenge(
            customer_ref="cust_7f3a",
            tool_name="payments.create_payment",
            tier=VerificationTier.APP_APPROVAL,
        )
        expired = c.expire()
        assert expired.customer_ref == "cust_7f3a"
        assert expired.tool_name == "payments.create_payment"

    def test_already_terminal_challenge_returns_self(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        declined = c.decline()
        # Declined is terminal, so expire returns self.
        result = declined.expire()
        assert result is declined


class TestChallengeDecline:
    """Transition to declined state."""

    def test_decline_sets_status(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        declined = c.decline()
        assert declined.status == "declined"

    def test_decline_preserves_fields(self) -> None:
        c = Challenge(
            customer_ref="cust_7f3a",
            tool_name="payments.create_payment",
            tier=VerificationTier.APP_APPROVAL,
        )
        declined = c.decline()
        assert declined.customer_ref == "cust_7f3a"


# ---------------------------------------------------------------------------
# Expiry and terminal state.
# ---------------------------------------------------------------------------


class TestExpiryAndTerminal:
    """Challenge expiry detection and terminal state guards."""

    def test_future_challenge_is_not_expired(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        assert not c.is_expired

    def test_past_challenge_is_expired(self) -> None:
        base = datetime(2020, 1, 1, tzinfo=UTC)
        c = Challenge(tier=VerificationTier.APP_APPROVAL, created_at=base)
        assert c.is_expired

    def test_pending_challenge_is_not_terminal(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        assert not c.is_terminal

    def test_approved_challenge_is_terminal(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        approved = c.approve(device_id="dev", signature="sig")
        assert approved.is_terminal

    def test_expired_challenge_is_terminal(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        expired = c.expire()
        assert expired.is_terminal

    def test_declined_challenge_is_terminal(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        declined = c.decline()
        assert declined.is_terminal


# ---------------------------------------------------------------------------
# Serialization.
# ---------------------------------------------------------------------------


class TestSerialization:
    """to_dict / from_dict round-trip."""

    def test_round_trip_pending(self) -> None:
        c = Challenge(
            customer_ref="cust_7f3a",
            tool_name="payments.create_payment",
            payload={"amount": "EUR 340.00"},
            tier=VerificationTier.APP_IDENTITY_VERIFICATION,
        )
        d = c.to_dict()
        restored = Challenge.from_dict(d)
        assert restored.challenge_id == c.challenge_id
        assert restored.customer_ref == "cust_7f3a"
        assert restored.tool_name == "payments.create_payment"
        assert restored.payload == {"amount": "EUR 340.00"}
        assert restored.tier == VerificationTier.APP_IDENTITY_VERIFICATION
        assert restored.status == "pending"

    def test_round_trip_approved(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        approved = c.approve(
            device_id="dev_abc",
            signature="sig_xyz",
            verification_result="vr_match_001",
        )
        d = approved.to_dict()
        restored = Challenge.from_dict(d)
        assert restored.status == "approved"
        assert restored.confirming_device == "dev_abc"
        assert restored.signature == "sig_xyz"
        assert restored.verification_result == "vr_match_001"

    def test_round_trip_preserves_timestamps(self) -> None:
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        c = Challenge(tier=VerificationTier.APP_APPROVAL, created_at=base)
        d = c.to_dict()
        restored = Challenge.from_dict(d)
        assert restored.created_at == base
        # expires_at is preserved from the dict, not recomputed.
        assert restored.expires_at == c.expires_at


# ---------------------------------------------------------------------------
# Human summary.
# ---------------------------------------------------------------------------


class TestHumanSummary:
    """human_summary generation."""

    def test_summary_includes_amount_and_payee(self) -> None:
        c = Challenge(
            tool_name="payments.create_payment",
            payload={"amount": "EUR 340.00", "payee": "Acme Ltd"},
            tier=VerificationTier.APP_APPROVAL,
        )
        assert "EUR 340.00" in c.human_summary
        assert "Acme Ltd" in c.human_summary

    def test_summary_fallbacks_for_missing_fields(self) -> None:
        c = Challenge(tier=VerificationTier.APP_APPROVAL)
        assert "?" in c.human_summary  # fallback amount
        assert "the recipient" in c.human_summary  # fallback payee


# ---------------------------------------------------------------------------
# VerificationTier as int (for SQLAlchemy compatibility).
# ---------------------------------------------------------------------------


class TestVerificationTierAsInt:
    """VerificationTier can be used as int (for DB storage)."""

    def test_int_conversion(self) -> None:
        assert int(VerificationTier.SESSION_ONLY) == 0
        assert int(VerificationTier.APP_APPROVAL) == 1
        assert int(VerificationTier.APP_IDENTITY_VERIFICATION) == 2

    def test_from_int(self) -> None:
        assert VerificationTier(0) == VerificationTier.SESSION_ONLY
        assert VerificationTier(1) == VerificationTier.APP_APPROVAL
        assert VerificationTier(2) == VerificationTier.APP_IDENTITY_VERIFICATION

    def test_challenge_accepts_int_tier(self) -> None:
        c = Challenge(tier=VerificationTier(1))  # int, not enum.
        assert c.tier == VerificationTier.APP_APPROVAL

    def test_challenge_from_dict_with_int_tier(self) -> None:
        d = {
            "challenge_id": "abc123",
            "customer_ref": "cust_7f3a",
            "tool_name": "payments.create_payment",
            "payload": {},
            "tier": 2,  # int in dict.
            "status": "pending",
            "created_at": datetime(2026, 1, 1, tzinfo=UTC).timestamp(),
            "expires_at": datetime(2026, 1, 1, tzinfo=UTC).timestamp() + 300,
        }
        c = Challenge.from_dict(d)
        assert c.tier == VerificationTier.APP_IDENTITY_VERIFICATION

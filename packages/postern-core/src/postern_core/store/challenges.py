"""Challenge store — CRUD for the approval workflow (handoff §7.4).

Append-only by construction: ``create_challenge`` inserts a new row;
``update_challenge_status`` transitions the status. There is no delete —
expired rows remain for audit trail.

Usage::

    from postern_core.store.challenges import create_challenge, get_challenge
    from postern_core.domain.verification import VerificationTier

    challenge = await create_challenge(
        session,
        customer_ref="cust_7f3a",
        tool_name="payments.create_payment",
        payload={"amount": "EUR 340.00", "payee": "Acme Ltd"},
        tier=VerificationTier.APP_IDENTITY_VERIFICATION,
    )
    # challenge.challenge_id  →  "a1b2c3..."

    existing = await get_challenge(session, challenge.challenge_id)
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from postern_core.domain.verification import VerificationTier
from postern_core.store.models import ChallengeRecord


class ChallengeNotFoundError(Exception):
    """Raised when a challenge ID does not exist or has been garbage-collected."""


async def create_challenge(
    session: AsyncSession,
    *,
    challenge_id: str,
    customer_ref: str,
    tool_name: str,
    payload: dict[str, Any],
    tier: VerificationTier | int,
) -> ChallengeRecord:
    """Persist a new challenge row and return it.

    This is the entry point for ``payments.create_payment`` (and any other
    tier-1/2 tool): it writes the challenge to Postgres and returns the ID
    that the agent relays to the operator.

    The payload is stored as JSONB so an investigator can query which
    operations were proposed, at what amounts, to which payees — without
    parsing log aggregation.

    Args:
        session: Async SQLAlchemy session.
        challenge_id: Opaque unique identifier (idempotency key).
        customer_ref: The customer who initiated the operation.
        tool_name: Which MCP tool triggered this challenge.
        payload: The full operation payload (amount, payee, account).
        tier: Verification tier required for this operation.

    Returns:
        The persisted ``ChallengeRecord`` (with timestamps set).
    """
    now = datetime.now(UTC)

    # Compute expires_at based on tier.
    ttl_seconds = {
        VerificationTier.SESSION_ONLY: 30,
        VerificationTier.APP_APPROVAL: 180,
        VerificationTier.APP_IDENTITY_VERIFICATION: 300,
    }
    if isinstance(tier, int):
        tier_int = tier
    else:
        tier_int = int(tier)
    ttl = ttl_seconds.get(VerificationTier(tier_int), 180)  # default to tier-1 TTL.

    record = ChallengeRecord(
        challenge_id=challenge_id,
        customer_ref=customer_ref,
        tool_name=tool_name,
        payload=payload,
        tier=tier_int,
        status="pending",
        created_at=now,
        expires_at=now.replace() + __import__("datetime").timedelta(seconds=ttl),
    )
    session.add(record)
    await session.flush()
    return record


async def get_challenge(
    session: AsyncSession,
    challenge_id: str,
) -> ChallengeRecord | None:
    """Look up a challenge by its opaque ID.

    Returns ``None`` if the challenge does not exist (not found, or
    garbage-collected). Does NOT filter on expiry — callers should check
    ``record.expires_at`` themselves.

    Args:
        session: Async SQLAlchemy session.
        challenge_id: The opaque challenge identifier.

    Returns:
        The ``ChallengeRecord``, or ``None``.
    """
    stmt = select(ChallengeRecord).where(ChallengeRecord.challenge_id == challenge_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_active_challenge(
    session: AsyncSession,
    challenge_id: str,
) -> ChallengeRecord | None:
    """Look up a non-expired challenge by ID.

    Unlike ``get_challenge``, this filters on expiry: expired challenges
    return ``None``. Use this when you need to know whether the challenge
    is still valid for approval.

    Args:
        session: Async SQLAlchemy session.
        challenge_id: The opaque challenge identifier.

    Returns:
        The ``ChallengeRecord`` if active, or ``None`` (not found or expired).
    """
    now = datetime.now(UTC)
    record = await get_challenge(session, challenge_id)
    if record is not None and record.expires_at <= now:
        return None  # Expired — treat as absent.
    return record


async def update_challenge_status(
    session: AsyncSession,
    challenge_id: str,
    *,
    status: str,
    confirming_device: str | None = None,
    verification_result: str | None = None,
    signature: str | None = None,
) -> ChallengeRecord:
    """Transition a challenge to a new status.

    This is called by the approval callback (``services/confirm/callback.py``)
    after the user has approved on their device. It writes the confirming
    device, verification result (tier-2), and signature back to the row.

    Args:
        session: Async SQLAlchemy session.
        challenge_id: The opaque challenge identifier.
        status: New status (approved | executed | declined | expired).
        confirming_device: Device identifier from the mobile app.
        verification_result: Tier-2 verification reference (selfie match).
        signature: Device-bound key signature over the payload.

    Returns:
        The updated ``ChallengeRecord``.

    Raises:
        ChallengeNotFoundError: If the challenge does not exist.
    """
    record = await get_challenge(session, challenge_id)
    if record is None:
        raise ChallengeNotFoundError(f"Challenge {challenge_id} not found")

    record.status = status
    if confirming_device is not None:
        record.confirming_device = confirming_device
    if verification_result is not None:
        record.verification_result = verification_result
    if signature is not None:
        record.signature = signature

    await session.flush()
    return record


async def mark_expired(
    session: AsyncSession,
    challenge_id: str,
) -> ChallengeRecord | None:
    """Transition a pending challenge to expired (if still pending).

    Called by the background expiry sweep or by ``get_payment_status``
    when polling reveals an expired challenge.

    Args:
        session: Async SQLAlchemy session.
        challenge_id: The opaque challenge identifier.

    Returns:
        The updated ``ChallengeRecord``, or ``None`` if not found / already terminal.
    """
    record = await get_challenge(session, challenge_id)
    if record is None:
        return None
    if record.status != "pending":
        return None  # Already terminal.

    record.status = "expired"
    await session.flush()
    return record


async def list_customer_challenges(
    session: AsyncSession,
    customer_ref: str,
    *,
    limit: int = 50,
) -> list[ChallengeRecord]:
    """List recent challenges for a customer.

    Used by ``payments.get_payment_status`` and audit queries. Ordered
    newest-first so the agent can show "your last 3 pending payments".

    Args:
        session: Async SQLAlchemy session.
        customer_ref: The customer identifier.
        limit: Maximum rows to return (default 50).

    Returns:
        List of ``ChallengeRecord``, newest first.
    """
    stmt = (
        select(ChallengeRecord)
        .where(ChallengeRecord.customer_ref == customer_ref)
        .order_by(ChallengeRecord.created_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())

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

import datetime as _dt
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from postern_core.domain.verification import VerificationTier
from postern_core.store.models import ChallengeRecord

# What ``update_challenge_status`` asserts about the clock, alongside the
# status it asserts about the row.
#
# ``"ignore"``  -- the transition does not depend on the deadline at all.
# ``"unexpired"`` -- ``expires_at > now()``; the transition is a use of the
#     challenge and must not succeed after its deadline.
# ``"expired"`` -- ``expires_at <= now()``; the transition is the RECORDING of
#     that deadline having passed, so it must not succeed before it.
#
# Kept as a closed set rather than a pair of booleans because "unexpired and
# expired" is not a state and a signature that can express it invites someone
# to pass it.
ExpiryPredicate = Literal["ignore", "unexpired", "expired"]


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
        expires_at=now.replace() + _dt.timedelta(seconds=ttl),
    )
    session.add(record)
    await session.flush()
    return record


async def get_challenge(
    session: AsyncSession,
    challenge_id: str,
    *,
    refresh: bool = False,
) -> ChallengeRecord | None:
    """Look up a challenge by its opaque ID.

    Returns ``None`` if the challenge does not exist (not found, or
    garbage-collected). Does NOT filter on expiry — callers should check
    ``record.expires_at`` themselves.

    Args:
        session: Async SQLAlchemy session.
        challenge_id: The opaque challenge identifier.
        refresh: Overwrite the session's already-loaded copy of this row with
            what the database currently holds. Required whenever the answer
            must reflect a write made by ANOTHER connection since this session
            last read the row; see below.

    Returns:
        The ``ChallengeRecord``, or ``None``.

    WHY ``refresh`` EXISTS, measured rather than anticipated. A second call to
    this function in a session that has already loaded the row does issue the
    ``SELECT``, and under READ COMMITTED that ``SELECT`` does see another
    transaction's committed update -- but the ORM then discards the fetched
    columns in favour of the instance already in its identity map, and hands
    back the stale one. ``services/confirm/callback.py``'s
    ``_refused_transition_response`` hit exactly that: with six concurrent
    approvals of one challenge, the five that lost the race each read
    ``status='pending'`` back from the identity map after the winner had
    committed its transition, and each answered 500 instead of 409.
    ``refresh=True`` sets ``populate_existing``, which repopulates the
    instance from the result instead.
    """
    stmt = select(ChallengeRecord).where(ChallengeRecord.challenge_id == challenge_id)
    if refresh:
        stmt = stmt.execution_options(populate_existing=True)
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
    expected_status: str,
    expiry: ExpiryPredicate = "ignore",
    confirming_device: str | None = None,
    verification_result: str | None = None,
    signature: str | None = None,
) -> ChallengeRecord | None:
    """Transition a challenge from one status to another, atomically.

    One statement -- ``UPDATE challenges SET status = :status ... WHERE
    challenge_id = :id AND status = :expected_status`` -- whose rowcount is
    the answer. The row is never read, inspected and then written; the
    precondition travels inside the write, so PostgreSQL decides it under the
    row lock rather than the caller deciding it against a snapshot.

    WHY (audit finding C-03). This used to be ``get_challenge`` followed by
    attribute assignment and ``flush()``: a plain ``SELECT`` with no ``FOR
    UPDATE``, then an ``UPDATE`` carrying no predicate on the old status. Two
    concurrent approvals of one challenge both read ``pending``, both passed
    the caller's Python check, and the second ``UPDATE`` blocked on the row
    lock and then applied unconditionally -- there was nothing in it to fail.
    Both callers then executed a payment. MCP ``2026-07-28`` removed SSE
    resumability, so a client re-issuing a dropped request is the specified
    behaviour, not an unlikely one.

    With the predicate in the statement, READ COMMITTED re-evaluates it
    against the committed row version once the lock is acquired, so the
    loser's ``UPDATE`` matches zero rows and this returns ``None``.

    Args:
        session: Async SQLAlchemy session.
        challenge_id: The opaque challenge identifier.
        status: New status (approved | executed | declined | expired).
        expected_status: The status the row must currently hold. Required,
            keyword-only, and deliberately without a default -- see below.
        expiry: What the transition asserts about ``expires_at``. See
            ``ExpiryPredicate``.
        confirming_device: Device identifier from the mobile app.
        verification_result: Tier-2 verification reference (selfie match).
        signature: Device-bound key signature over the payload.

    Returns:
        The updated ``ChallengeRecord``, or ``None`` when the statement
        matched no row -- the challenge does not exist, it is not in
        ``expected_status`` (another caller won the race, or it was already
        terminal), or it failed the ``expiry`` predicate. This layer does not
        distinguish those; a caller that must (``services/confirm/callback.py``
        owes a 404, a 409 and a 410) reads the row once afterwards, which is
        safe because every reason the statement can fail is permanent: a
        terminal status has no transition back to ``pending``, and
        ``expires_at`` is immutable while the clock only moves forward. This
        function never raises for a missing row; ``ChallengeNotFoundError``
        stays exported for callers that prefer an exception.

    WHY ``expected_status`` IS REQUIRED AND NOT DEFAULTED TO ``"pending"``.
    A default is the defect this function was rewritten to remove, one layer
    up: it lets a call site say nothing about the state it believes the row is
    in, which is exactly what the old read-then-write did. Two of the three
    transitions in ``services/confirm/callback.py`` start from ``pending``
    and the third (``approved`` -> ``executed``) does not, so a ``"pending"``
    default would be silently wrong at one of the three existing callers
    today, and would fail there by returning ``None`` -- a lost-race answer
    for what is really a miswritten call. Requiring it costs one keyword at
    four call sites and makes every transition in the tree state its own
    precondition where a reader can see it.
    """
    values: dict[str, Any] = {"status": status}
    if confirming_device is not None:
        values["confirming_device"] = confirming_device
    if verification_result is not None:
        values["verification_result"] = verification_result
    if signature is not None:
        values["signature"] = signature

    conditions = [
        ChallengeRecord.challenge_id == challenge_id,
        ChallengeRecord.status == expected_status,
    ]
    # `func.now()` is PostgreSQL's `transaction_timestamp()`, so a caller that
    # issues this statement and then reads the row back to classify a zero
    # rowcount gets one instant for both, and the two cannot disagree about
    # whether the deadline had passed at decision time.
    if expiry == "unexpired":
        conditions.append(ChallengeRecord.expires_at > func.now())
    elif expiry == "expired":
        conditions.append(ChallengeRecord.expires_at <= func.now())

    stmt = (
        update(ChallengeRecord)
        .where(*conditions)
        .values(**values)
        .returning(ChallengeRecord)
        # `populate_existing` is load-bearing, not decoration: the caller has
        # usually just read this row (the ownership check does), so it is in
        # the session's identity map holding its pre-update attributes, and
        # without this the object handed back would report the OLD status
        # while the database holds the new one.
        .execution_options(synchronize_session=False, populate_existing=True)
    )

    result = await session.execute(stmt)
    return result.scalars().one_or_none()


async def mark_expired(
    session: AsyncSession,
    challenge_id: str,
) -> ChallengeRecord | None:
    """Transition a pending challenge to expired (if still pending).

    Called by the background expiry sweep or by ``get_payment_status``
    when polling reveals an expired challenge.

    Carried the same read-then-write defect as ``update_challenge_status``
    (audit finding C-03) and is fixed the same way, by delegating to it:
    its ``if record.status != "pending": return None`` guard was evaluated
    against a snapshot taken by an unlocked ``SELECT``, so two sweeps -- or a
    sweep racing an approval -- could both pass it and the ``expired`` write
    could land on top of an ``approved`` row. It now transitions
    ``pending`` -> ``expired`` conditionally or not at all.

    Deliberately ``expiry="ignore"``: this function's contract is "mark it
    expired because I have decided it is", and its callers are the sweep and
    the polling path, which own that decision. Adding ``expires_at <= now()``
    here would silently change what it does for a caller that means to retire
    a still-live challenge. ``services/confirm/callback.py`` wants the
    deadline enforced in SQL and asks for it explicitly.

    Args:
        session: Async SQLAlchemy session.
        challenge_id: The opaque challenge identifier.

    Returns:
        The updated ``ChallengeRecord``, or ``None`` if not found / already terminal.
    """
    return await update_challenge_status(
        session,
        challenge_id,
        status="expired",
        expected_status="pending",
    )


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

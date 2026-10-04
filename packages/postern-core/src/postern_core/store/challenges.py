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

from datetime import timedelta
from typing import Any, Literal

from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
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


#: How long a challenge stays approvable, by tier: 30 seconds, 3 minutes and 5
#: minutes. One table for `create_challenge` and
#: `create_pending_challenge_once`, so the two cannot stamp different deadlines
#: for one tier.
TIER_TTL_SECONDS: dict[VerificationTier, int] = {
    VerificationTier.SESSION_ONLY: 30,
    VerificationTier.APP_APPROVAL: 180,
    VerificationTier.APP_IDENTITY_VERIFICATION: 300,
}

#: The predicate of `ix_challenges_pending_fingerprint`, spelled as the index
#: spells it. ON CONFLICT infers a partial index only from a WHERE clause that
#: implies its predicate, and a bound parameter in its place does not.
_PENDING_PREDICATE = "status = 'pending'"


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
        The persisted ``ChallengeRecord``, with ``created_at`` and
        ``expires_at`` as the database stamped them (its clock, not this
        process's).
    """
    # Compute the TTL from the tier.
    if isinstance(tier, int):
        tier_int = tier
    else:
        tier_int = int(tier)
    ttl = TIER_TTL_SECONDS.get(VerificationTier(tier_int), 180)  # default to tier-1 TTL.

    # Both timestamps are SQL expressions, evaluated by the database, so
    # ``expires_at`` is stamped on the clock that ``update_challenge_status``
    # and ``get_active_challenge`` later judge it on. Taking ``now`` from
    # ``datetime.now(UTC)`` here and comparing against ``now()`` there made two
    # clocks decide one deadline, and a host and a container whose clocks
    # differ by more than the TTL disagree about whether a fresh challenge has
    # already expired.
    #
    # ``statement_timestamp()`` and not ``now()`` for the stamp: ``now()`` is
    # frozen at the transaction's first statement, so a transaction that has
    # been open for a while would take that time out of a 30-second tier-0
    # TTL before the row exists. The expiry predicates keep ``now()``: it is
    # one instant per transaction, so a caller that runs a transition and then
    # reads the row back to classify a refusal sees one verdict. The two
    # differ by the age of the transaction, always in the direction that
    # leaves a just-created challenge unexpired, so the choices do not
    # conflict.
    record = ChallengeRecord(
        challenge_id=challenge_id,
        customer_ref=customer_ref,
        tool_name=tool_name,
        payload=payload,
        tier=tier_int,
        status="pending",
        created_at=func.statement_timestamp(),
        expires_at=func.statement_timestamp() + timedelta(seconds=ttl),
    )
    session.add(record)
    await session.flush()
    # The attributes hold SQL expressions until the database has answered, so
    # read the stamped values back; without this the returned record's
    # timestamps are unloaded and touching them raises under asyncio.
    await session.refresh(record, ["created_at", "expires_at"])
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
    # Expiry is decided by the database's ``now()`` in the same statement,
    # never by comparing ``expires_at`` with this process's clock, which is not
    # the clock ``create_challenge`` stamped it on.
    stmt = select(ChallengeRecord).where(
        ChallengeRecord.challenge_id == challenge_id,
        ChallengeRecord.expires_at > func.now(),
    )
    result = await session.execute(stmt)
    record = result.scalar_one_or_none()
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


async def expire_stale_pending(
    session: AsyncSession,
    *,
    customer_ref: str,
    request_fingerprint: str,
) -> list[str]:
    """Move this customer's pending rows with this fingerprint to ``expired``
    once the database clock has passed their deadline, and name them.

    The payments producer runs this in the same transaction as, and just
    before, `create_pending_challenge_once`. Without it a row past its
    deadline that nobody has marked would still occupy the partial unique
    index, and the insert would hand the caller a challenge that can no longer
    be approved. ``now()`` is the transaction's timestamp, the clock every
    other expiry predicate in this module uses.
    """
    stmt = (
        update(ChallengeRecord)
        .where(
            ChallengeRecord.customer_ref == customer_ref,
            ChallengeRecord.request_fingerprint == request_fingerprint,
            ChallengeRecord.status == "pending",
            ChallengeRecord.expires_at <= func.now(),
        )
        .values(status="expired")
        .returning(ChallengeRecord.challenge_id)
        .execution_options(synchronize_session=False)
    )
    return list((await session.scalars(stmt)).all())


async def create_pending_challenge_once(
    session: AsyncSession,
    *,
    challenge_id: str,
    customer_ref: str,
    tool_name: str,
    payload: dict[str, Any],
    tier: VerificationTier,
    request_fingerprint: str,
    client_id: str | None,
    session_jti: str | None,
) -> ChallengeRecord | None:
    """Insert a pending challenge, or return the one already pending for this
    customer and fingerprint.

    One INSERT ... ON CONFLICT DO NOTHING against
    ``ix_challenges_pending_fingerprint``, then, when it inserted nothing, one
    SELECT of the pending row it collided with. PostgreSQL decides the
    collision under the index, so two concurrent callers produce one row: the
    second INSERT waits for the first transaction, and once that commits it
    inserts nothing and its SELECT, on a fresh READ COMMITTED snapshot, finds
    the first caller's row.

    Returns ``None`` in one case only: the row it collided with left
    ``pending`` between the two statements. The caller reports a failure and
    a retry makes a new challenge, which is correct for a row that has been
    approved or expired.

    Both timestamps are stamped by the database, as in `create_challenge`.
    """
    ttl = TIER_TTL_SECONDS[tier]
    insert_stmt = (
        pg_insert(ChallengeRecord)
        .values(
            challenge_id=challenge_id,
            customer_ref=customer_ref,
            tool_name=tool_name,
            payload=payload,
            tier=int(tier),
            status="pending",
            created_at=func.statement_timestamp(),
            expires_at=func.statement_timestamp() + timedelta(seconds=ttl),
            request_fingerprint=request_fingerprint,
            client_id=client_id,
            session_jti=session_jti,
        )
        .on_conflict_do_nothing(
            index_elements=["customer_ref", "request_fingerprint"],
            index_where=text(_PENDING_PREDICATE),
        )
        .returning(ChallengeRecord)
    )
    inserted = (await session.scalars(insert_stmt)).one_or_none()
    if inserted is not None:
        return inserted
    existing = (
        select(ChallengeRecord)
        .where(
            ChallengeRecord.customer_ref == customer_ref,
            ChallengeRecord.request_fingerprint == request_fingerprint,
            ChallengeRecord.status == "pending",
        )
        .execution_options(populate_existing=True)
    )
    return (await session.scalars(existing)).one_or_none()

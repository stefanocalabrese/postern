"""The producer's store statements and fingerprint, against Postgres.

`create_pending_challenge_once` and `expire_stale_pending` are what make a
repeated `payments.create_payment` return the challenge it already made while
that challenge is pending, and `ix_challenges_pending_fingerprint` is what
makes that hold under concurrency rather than by a read-then-write. Every test
that writes commits for real, because the property is about two connections,
and deletes its own rows by the `chal_pfp_` prefix.
"""

import asyncio
import hashlib
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from postern_core.payments import CREATE_PAYMENT_TOOL, PAYMENT_TIER, request_fingerprint
from postern_core.store import challenges
from postern_core.store.engine import Database
from postern_core.store.models import ChallengeRecord
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

CUSTOMER = "cust_7f3a"
OTHER = "cust_9b21"
PREFIX = "chal_pfp_"
PAYLOAD: dict[str, str] = {
    "from_account_ref": "acc_7f3a",
    "payee_ref": "pay_nw01",
    "payee_name": "Northwind Energy",
    "amount": "340.50",
    "currency": "EUR",
}


def _fingerprint(customer_ref: str = CUSTOMER) -> str:
    return request_fingerprint(
        customer_ref=customer_ref, tool_name=CREATE_PAYMENT_TOOL, payload=PAYLOAD
    )


async def _delete(database: Database) -> None:
    async with database.sessionmaker() as s:
        await s.execute(
            text("DELETE FROM challenges WHERE challenge_id LIKE :p"), {"p": f"{PREFIX}%"}
        )
        await s.commit()


@pytest_asyncio.fixture
async def clean(database: Database) -> AsyncIterator[None]:
    await _delete(database)
    yield
    await _delete(database)


async def _create(
    session: AsyncSession, challenge_id: str, *, customer_ref: str = CUSTOMER
) -> ChallengeRecord | None:
    return await challenges.create_pending_challenge_once(
        session,
        challenge_id=challenge_id,
        customer_ref=customer_ref,
        tool_name=CREATE_PAYMENT_TOOL,
        payload=PAYLOAD,
        tier=PAYMENT_TIER,
        request_fingerprint=_fingerprint(customer_ref),
        client_id="claude-code",
        session_jti="jti-1",
    )


async def _status(database: Database, challenge_id: str) -> str:
    async with database.sessionmaker() as s:
        row = await challenges.get_challenge(s, challenge_id)
    assert row is not None
    return row.status


async def _count(database: Database) -> int:
    async with database.sessionmaker() as s:
        result = await s.execute(
            select(func.count())
            .select_from(ChallengeRecord)
            .where(ChallengeRecord.challenge_id.like(f"{PREFIX}%"))
        )
    return int(result.scalar_one())


# -- The fingerprint ---------------------------------------------------------


def test_the_fingerprint_is_sha256_of_sorted_compact_json() -> None:
    canonical = (
        '{"customer_ref":"cust_7f3a","payload":{"amount":"340.50","currency":"EUR",'
        '"from_account_ref":"acc_7f3a","payee_name":"Northwind Energy",'
        '"payee_ref":"pay_nw01"},"tool_name":"payments.create_payment"}'
    )
    assert _fingerprint() == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert len(_fingerprint()) == 64
    assert _fingerprint() == _fingerprint().lower()


def test_the_fingerprint_does_not_depend_on_key_order() -> None:
    reordered = dict(reversed(list(PAYLOAD.items())))
    assert list(reordered) != list(PAYLOAD)
    assert (
        request_fingerprint(customer_ref=CUSTOMER, tool_name=CREATE_PAYMENT_TOOL, payload=reordered)
        == _fingerprint()
    )


@pytest.mark.parametrize("field", sorted(PAYLOAD))
def test_the_fingerprint_changes_with_every_payload_field(field: str) -> None:
    changed = {**PAYLOAD, field: PAYLOAD[field] + "0"}
    assert (
        request_fingerprint(customer_ref=CUSTOMER, tool_name=CREATE_PAYMENT_TOOL, payload=changed)
        != _fingerprint()
    )


def test_the_fingerprint_changes_with_an_added_reference() -> None:
    added = {**PAYLOAD, "reference": "Rent October"}
    assert (
        request_fingerprint(customer_ref=CUSTOMER, tool_name=CREATE_PAYMENT_TOOL, payload=added)
        != _fingerprint()
    )


def test_the_fingerprint_changes_with_the_customer_and_the_tool() -> None:
    assert _fingerprint(OTHER) != _fingerprint()
    assert (
        request_fingerprint(customer_ref=CUSTOMER, tool_name="accounts.rename", payload=PAYLOAD)
        != _fingerprint()
    )


# -- The partial unique index ---------------------------------------------------


async def test_the_unique_index_covers_pending_rows_only(database: Database) -> None:
    """Pinned here because `alembic check` compares this index's name,
    uniqueness and columns and not its WHERE clause, so a model and a
    migration that disagree on the predicate would pass the drift gate."""
    async with database.sessionmaker() as s:
        indexdef = (
            await s.execute(
                text(
                    "SELECT indexdef FROM pg_indexes WHERE tablename = 'challenges' "
                    "AND indexname = 'ix_challenges_pending_fingerprint'"
                )
            )
        ).scalar_one()
    assert indexdef.startswith(
        "CREATE UNIQUE INDEX ix_challenges_pending_fingerprint ON public.challenges"
    )
    assert "(customer_ref, request_fingerprint)" in indexdef
    assert indexdef.endswith("WHERE ((status)::text = 'pending'::text)")


# -- The insert ------------------------------------------------------------------


async def test_a_first_call_inserts_a_pending_tier_two_row(database: Database, clean: None) -> None:
    async with database.sessionmaker() as s:
        record = await _create(s, f"{PREFIX}first")
        await s.commit()
    assert record is not None
    assert (record.challenge_id, record.status, record.tier) == (f"{PREFIX}first", "pending", 2)
    assert (record.client_id, record.session_jti) == ("claude-code", "jti-1")
    assert record.request_fingerprint == _fingerprint()
    assert record.payload == PAYLOAD
    assert (record.expires_at - record.created_at).total_seconds() == 300


async def test_a_repeat_returns_the_pending_row_and_inserts_nothing(
    database: Database, clean: None
) -> None:
    async with database.sessionmaker() as s:
        first = await _create(s, f"{PREFIX}one")
        await s.commit()
    async with database.sessionmaker() as s:
        second = await _create(s, f"{PREFIX}two")
        await s.commit()
    assert first is not None and second is not None
    assert second.challenge_id == first.challenge_id
    assert second.expires_at == first.expires_at
    assert await _count(database) == 1


async def test_a_concurrent_second_insert_waits_and_returns_the_first_row(
    database: Database, clean: None
) -> None:
    async with database.sessionmaker() as winner, database.sessionmaker() as loser:
        first = await _create(winner, f"{PREFIX}winner")
        assert first is not None  # uncommitted: the index entry is held.
        contender = asyncio.create_task(_create(loser, f"{PREFIX}loser"))
        # Asserts the second INSERT is blocked on the first's index entry. If
        # it were free to insert, it would have finished by now.
        await asyncio.sleep(0.2)
        assert not contender.done(), "the second INSERT did not wait for the first"
        await winner.commit()
        second = await contender
        await loser.commit()
    assert second is not None
    assert second.challenge_id == f"{PREFIX}winner"
    assert await _count(database) == 1


async def test_a_stale_pending_row_is_expired_and_a_new_one_created(
    database: Database, clean: None
) -> None:
    async with database.sessionmaker() as s:
        await _create(s, f"{PREFIX}stale")
        await s.commit()
    async with database.sessionmaker() as s:
        await s.execute(
            text(
                "UPDATE challenges SET expires_at = now() - interval '1 second' "
                "WHERE challenge_id = :c"
            ),
            {"c": f"{PREFIX}stale"},
        )
        await s.commit()
    async with database.sessionmaker() as s:
        expired = await challenges.expire_stale_pending(
            s, customer_ref=CUSTOMER, request_fingerprint=_fingerprint()
        )
        fresh = await _create(s, f"{PREFIX}fresh")
        await s.commit()
    assert expired == [f"{PREFIX}stale"]
    assert fresh is not None and fresh.challenge_id == f"{PREFIX}fresh"
    assert await _status(database, f"{PREFIX}stale") == "expired"


async def test_expiry_touches_only_this_customers_past_deadline_rows(
    database: Database, clean: None
) -> None:
    async with database.sessionmaker() as s:
        await _create(s, f"{PREFIX}live")
        await _create(s, f"{PREFIX}other", customer_ref=OTHER)
        await s.commit()
    async with database.sessionmaker() as s:
        await s.execute(
            text(
                "UPDATE challenges SET expires_at = now() - interval '1 second' "
                "WHERE challenge_id = :c"
            ),
            {"c": f"{PREFIX}other"},
        )
        await s.commit()
    async with database.sessionmaker() as s:
        expired = await challenges.expire_stale_pending(
            s, customer_ref=CUSTOMER, request_fingerprint=_fingerprint()
        )
        await s.commit()
    assert expired == []
    assert await _status(database, f"{PREFIX}live") == "pending"
    assert await _status(database, f"{PREFIX}other") == "pending"


async def test_an_approved_row_does_not_block_a_new_proposal(
    database: Database, clean: None
) -> None:
    async with database.sessionmaker() as s:
        await _create(s, f"{PREFIX}approved")
        await s.commit()
    async with database.sessionmaker() as s:
        await challenges.update_challenge_status(
            s,
            f"{PREFIX}approved",
            status="approved",
            expected_status="pending",
            expiry="unexpired",
        )
        await s.commit()
    async with database.sessionmaker() as s:
        again = await _create(s, f"{PREFIX}again")
        await s.commit()
    assert again is not None and again.challenge_id == f"{PREFIX}again"


async def test_rows_without_a_fingerprint_never_collide(database: Database, clean: None) -> None:
    async with database.sessionmaker() as s:
        for suffix in ("nofp_a", "nofp_b"):
            await challenges.create_challenge(
                s,
                challenge_id=f"{PREFIX}{suffix}",
                customer_ref=CUSTOMER,
                tool_name=CREATE_PAYMENT_TOOL,
                payload=PAYLOAD,
                tier=PAYMENT_TIER,
            )
        await s.commit()
    assert await _count(database) == 2


async def test_the_producer_statements_run_as_the_application_role(
    app_db: Database, database: Database, clean: None
) -> None:
    """`postern_app` holds SELECT, INSERT and UPDATE on `challenges`, which is
    every privilege these two statements need: the conflict-tolerant INSERT
    with RETURNING, and the conditional UPDATE with RETURNING."""
    async with app_db.sessionmaker() as s:
        assert (
            await challenges.expire_stale_pending(
                s, customer_ref=CUSTOMER, request_fingerprint=_fingerprint()
            )
            == []
        )
        first = await _create(s, f"{PREFIX}approle")
        await s.commit()
    async with app_db.sessionmaker() as s:
        again = await _create(s, f"{PREFIX}approle_again")
        await s.commit()
    assert first is not None and again is not None
    assert again.challenge_id == first.challenge_id

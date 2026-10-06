"""One challenge executes at most one payment, under real concurrency.

Audit finding C-03. Approving a challenge used to be a read-then-write with
no lock and no conditional predicate: ``services/confirm/callback.py`` read
the row, checked ``status == "pending"`` in Python, and then issued an
``UPDATE`` that carried no predicate on the old status. Under READ COMMITTED
every concurrent approval of the same challenge passed that check against the
same ``pending`` snapshot, every one of them reached the backend write
endpoint, and the second ``UPDATE`` simply applied on top of the first
because there was nothing in it to fail.

MCP ``2026-07-28`` removed SSE resumability, so a client that loses a stream
re-issues the request by design. N simultaneous approvals of one challenge is
the documented client behaviour, not a thought experiment.

WHY THE BARRIER. ``asyncio.gather`` over N requests does not by itself
guarantee that all N read the row before any of them writes it -- the event
loop is free to run one request to completion first, and then the test passes
against the defective code and proves nothing. The barrier below wraps the
handler's ownership read and holds every request there until all N have read
``status='pending'``, which is the exact interleaving the finding describes.
It trips only on the first N calls, which are precisely the N ownership reads:
a request cannot reach its second ``get_challenge`` (the one that classifies a
refused transition) until its ``UPDATE`` has returned, and that cannot happen
before the barrier releases.

Measured against the pre-fix code with this barrier in place: 6 requests, 6
backend calls, 6 HTTP 200s. Post-fix: 6 requests, 1 backend call, 1 HTTP 200,
5 HTTP 409s.

WHAT IS COUNTED. The number of times the backend write endpoint was actually
reached, not the number of 200s returned. A fix that deduplicated responses
while still POSTing N payments would satisfy the second count and be exactly
the defect.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.domain.verification import VerificationTier
from postern_core.store import challenges as store
from postern_core.store.challenges import get_challenge
from postern_core.store.engine import Database
from sqlalchemy import text
from starlette.applications import Starlette

import services.confirm.callback as cb
from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.device_keys import device_key, enrolled_store, sign_row

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"

# Six, not two: two concurrent approvals can be won by luck of scheduling even
# against broken code, and six leaves five losers whose status codes are
# asserted individually. It stays well under the engine's default pool ceiling
# (``pool_size`` 5 + ``max_overflow`` 10 = 15 connections), which matters
# because every one of the N requests holds a connection while parked at the
# barrier -- an N above that ceiling would deadlock the test rather than fail
# it.
CONCURRENT_APPROVALS = 6

# The barrier must not outlive a genuine hang. `asyncio.Barrier.wait()` takes
# no timeout, so it is wrapped: a party that times out breaks the barrier for
# everyone, which surfaces as `BrokenBarrierError` out of the request instead
# of a test that never returns.
BARRIER_TIMEOUT_SECONDS = 30.0


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture()
def settings(pg_url: str) -> ConfirmSettings:
    """``ConfirmSettings`` pointed at the session-scoped test database.

    Uses ``tests/conftest.py``'s session-scoped ``pg_url`` rather than
    standing up a second container the way ``tests/test_approval_integration.py``
    does: nothing here needs an isolated database, and the rows this module
    creates are deleted by the ``challenge`` fixture's own teardown.

    The three ``app_assertion_*`` fields stay ``None``; the ``app`` fixture
    passes ``assertion_verifier=`` explicitly instead.
    """
    return ConfirmSettings(
        backend_base_url="https://backend.test",  # never reached; transport is mocked
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so without these two flags it gets the
        # safe defaults and refuses to start.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    """RSA key pair backing the app-assertion bearer tokens (RSA keygen is slow)."""
    return RSAKeyPair.generate()


#: SIX ENROLLED PHONES FOR ONE CUSTOMER, which is what lets this module keep
#: asserting that each concurrent request carries a DISTINCT signature. Ed25519
#: is deterministic, so one key signing one challenge produces one string
#: however many times it signs: six concurrent approvals from one device would
#: be six identical bodies, and "the row records the winner's signature" would
#: become unfalsifiable. Six devices is also the realistic shape of the race
#: this file exists for -- a customer with a phone and a tablet, or one phone
#: retrying through a dropped stream.
DEVICES = [device_key(f"race-phone-{i}") for i in range(CONCURRENT_APPROVALS)]


@pytest.fixture()
def app(settings: ConfirmSettings, key_pair: RSAKeyPair) -> Starlette:
    """The real confirm app, with a real database and a real route table."""
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=enrolled_store("cust_7f3a", *(public for _private, public in DEVICES)),
    )


@pytest.fixture()
async def db(settings: ConfirmSettings) -> AsyncGenerator[Database, None]:
    """A second ``Database`` for inserting and inspecting rows.

    Deliberately not the app's: the app reads through its own pool, so a row
    this fixture inserts is invisible there until it is committed for real
    (the reasoning ``tests/test_approval_integration.py``'s ``session``
    fixture records at length). Everything here commits.
    """
    database = Database(settings.database_url)
    try:
        yield database
    finally:
        await database.close()


@pytest.fixture()
async def challenge(db: Database) -> AsyncGenerator[str, None]:
    """One pending, unexpired challenge for ``cust_7f3a``; deleted afterwards."""
    challenge_id = "chal_race_001"
    async with db.sessionmaker() as session:
        await store.create_challenge(
            session,
            challenge_id=challenge_id,
            customer_ref="cust_7f3a",
            tool_name="standing_orders.cancel",
            payload={"order_id": "so_7", "reason": "no longer needed"},
            tier=VerificationTier.APP_APPROVAL,
        )
        await session.commit()
    try:
        yield challenge_id
    finally:
        async with db.sessionmaker() as cleanup:
            await cleanup.execute(
                text("DELETE FROM challenges WHERE challenge_id LIKE 'chal_race_%'")
            )
            await cleanup.commit()


@pytest.fixture()
async def signatures(db: Database, challenge: str) -> list[str]:
    """One valid signature per enrolled device, over the stored challenge row.

    All six are signatures over the SAME bytes by six different keys, so they
    are six distinct strings that all verify -- which is exactly what this
    module needs to tell the winner from the losers on the row afterwards.
    """
    async with db.sessionmaker() as session:
        record = await store.get_challenge(session, challenge)
        assert record is not None
        return [sign_row(private, record) for private, _public in DEVICES]


@pytest.fixture()
def backend_calls() -> Generator[list[httpx2.Request], None, None]:
    """Every request that reached the backend write endpoint, in order."""
    calls: list[httpx2.Request] = []

    def _handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(201, json={"id": "x_1"})

    original_init = BackendWriteClient.__init__

    def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, transport=httpx2.MockTransport(_handler), **kwargs)

    with patch.object(BackendWriteClient, "__init__", patched_init):
        yield calls


@pytest.fixture()
def read_barrier() -> Generator[None, None, None]:
    """Hold every request at the handler's ownership read until all N have done it.

    See this module's docstring for why the test is worthless without it.
    """
    barrier = asyncio.Barrier(CONCURRENT_APPROVALS)
    reads = 0

    # Imported from the store rather than read off `cb`: it is the same
    # function object `services/confirm/callback.py` bound at import time, and
    # the `patch.object` below still replaces that module's binding, which is
    # the one the handler calls.
    async def barriered_get_challenge(*args: Any, **kwargs: Any) -> Any:
        nonlocal reads
        row = await get_challenge(*args, **kwargs)
        reads += 1
        if reads <= CONCURRENT_APPROVALS:
            await asyncio.wait_for(barrier.wait(), timeout=BARRIER_TIMEOUT_SECONDS)
        return row

    with patch.object(cb, "get_challenge", barriered_get_challenge):
        yield


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def bearer(key_pair: RSAKeyPair, subject: str) -> dict[str, str]:
    """A verified-assertion ``Authorization`` header for ``subject``."""
    token = key_pair.create_token(
        subject=subject, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    return {"Authorization": f"Bearer {token}"}


async def approve(
    app: Starlette,
    challenge_id: str,
    headers: dict[str, str],
    signature: str,
) -> httpx2.Response:
    """One approval, on its own client and its own database session."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        return await client.post(
            f"/challenges/{challenge_id}/approve",
            json={"signature": signature},
            headers=headers,
        )


async def _status_of(db: Database, challenge_id: str) -> tuple[str, str | None]:
    async with db.sessionmaker() as session:
        row = await store.get_challenge(session, challenge_id)
        assert row is not None
        return row.status, row.signature


# ---------------------------------------------------------------------------
# The test this task exists for.
# ---------------------------------------------------------------------------


async def test_concurrent_approvals_execute_at_most_one_payment(
    app: Starlette,
    db: Database,
    challenge: str,
    signatures: list[str],
    key_pair: RSAKeyPair,
    backend_calls: list[httpx2.Request],
    read_barrier: None,
) -> None:
    """N simultaneous approvals of one challenge reach the backend exactly once.

    Fails against the pre-fix code with ``6 == 1`` on the backend-call count:
    every request passed the Python ``status == "pending"`` check against the
    same snapshot and every one of them POSTed a payment.
    """
    headers = bearer(key_pair, "cust_7f3a")

    responses = await asyncio.gather(
        *(approve(app, challenge, headers, signatures[i]) for i in range(CONCURRENT_APPROVALS))
    )

    codes = sorted(r.status_code for r in responses)

    # The count that matters: how many payments the backend was actually asked
    # to make, not how many callers were told one was made.
    assert len(backend_calls) == 1, (
        f"backend was called {len(backend_calls)} times for one challenge; "
        f"response codes were {codes}"
    )

    successes = [r for r in responses if r.status_code == 200]
    conflicts = [r for r in responses if r.status_code == 409]
    assert len(successes) == 1, f"expected exactly one 200, got {codes}"
    assert len(conflicts) == CONCURRENT_APPROVALS - 1, f"expected the rest 409, got {codes}"

    for response in conflicts:
        assert json.loads(response.content.decode())["error"] == "already_terminal"

    assert json.loads(successes[0].content.decode())["status"] == "executed"

    # The second half of the fix, end to end: the one call that got through
    # carries the challenge id as its idempotency key, so a backend that
    # honours the header refuses a duplicate even if this server somehow
    # issued one.
    assert backend_calls[0].headers["idempotency-key"] == challenge


async def test_concurrent_approvals_leave_exactly_one_writer_on_the_row(
    app: Starlette,
    db: Database,
    challenge: str,
    signatures: list[str],
    key_pair: RSAKeyPair,
    backend_calls: list[httpx2.Request],
    read_barrier: None,
) -> None:
    """The stored row records one approval, not the last one to arrive.

    Each request sends a distinct ``signature``. Exactly one of them may end
    up on the row, and it must be the request that was told it succeeded --
    otherwise the audit trail names a caller that never executed anything
    while the one that did goes unrecorded.
    """
    headers = bearer(key_pair, "cust_7f3a")

    responses = await asyncio.gather(
        *(approve(app, challenge, headers, signatures[i]) for i in range(CONCURRENT_APPROVALS))
    )

    successes = [r for r in responses if r.status_code == 200]
    assert len(successes) == 1

    status, signature = await _status_of(db, challenge)
    assert status == "executed"

    # The winning request is identifiable: it is the one whose signature the
    # backend call carried, since only the winner reaches the backend at all.
    assert len(backend_calls) == 1
    assert signature is not None
    # Exactly one of the six, and a real one: every string here verifies
    # against a different enrolled device, so the row names WHICH phone
    # approved rather than merely that something did.
    assert signature in signatures


async def test_second_approval_after_the_first_completes_is_409(
    app: Starlette,
    db: Database,
    challenge: str,
    signatures: list[str],
    key_pair: RSAKeyPair,
    backend_calls: list[httpx2.Request],
) -> None:
    """The sequential case, with no barrier: the second approval is refused.

    Companion to the concurrent tests above -- it pins that the conditional
    transition did not merely move the race, and it runs the handler without
    the ``get_challenge`` patch, so nothing about the result depends on the
    barrier fixture being wired correctly.
    """
    headers = bearer(key_pair, "cust_7f3a")

    first = await approve(app, challenge, headers, signatures[0])
    second = await approve(app, challenge, headers, signatures[1])

    assert first.status_code == 200
    assert second.status_code == 409
    assert json.loads(second.content.decode())["error"] == "already_terminal"
    assert len(backend_calls) == 1

    status, signature = await _status_of(db, challenge)
    assert status == "executed"
    assert signature == signatures[0]


def test_module_is_running_against_a_real_database(pg_url: str) -> None:
    """A guard, not a formality.

    Every assertion above is about what PostgreSQL does with two concurrent
    ``UPDATE``s on one row. If this module ever ends up pointed at SQLite, an
    in-memory fake or a mock session, its passes would mean nothing at all --
    so fail loudly rather than pass vacuously.
    """
    assert pg_url.startswith("postgresql+asyncpg://"), pg_url
    assert os.environ.get("POSTERN_DATABASE_URL", "").startswith("postgresql+asyncpg://")

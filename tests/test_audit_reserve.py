"""The audit row a pool at its ceiling used to cost, and the one connection
that now writes it.

WHAT WAS SILENT. `services/api/main.py`'s `create_app` hands one `Database` to
the consent lookup and to `AuditMiddleware`, so both draw on one
`QueuePool`. Under `dev-docs/decisions/0006-audit-write-failure.md` a failed
audit write fails the call, and `services/api/consent.py`'s check denies when
its lookup raises -- so a pool at its ceiling produced BOTH halves of the
failure and neither half reached the table. The two refusal reasons that work
added, `consent_store_unavailable` and `consent_check_faulted`, arrived at
`audit_log` only for calls whose audit write got a connection, which during
saturation is none of them. Measured here as the negative control:
`TestTheGapThisFileCloses::test_without_a_reserve_a_saturated_pool_writes_no_row`
drives a real `tools/call` against a pool with every connection held and
reads zero rows back.

WHAT THE RESERVE IS, and the three things it is not. `Database` now builds a
SECOND engine of `audit_reserve_size` connections, reached from exactly one
place -- `postern_core.store.audit`'s `append_with_reserve`, in its
`except sqlalchemy.exc.TimeoutError` branch. So it is:

  * NOT a second pool the audit path runs on. The audit write uses the
    application pool first, every time, and touches the reserve only after
    that pool has already refused. `test_the_reserve_holds_no_connection_until
    _the_pool_has_refused` measures the consequence: a healthy call leaves the
    reserve with zero connections open, because `QueuePool` opens on demand
    and the demand never came.
  * NOT reached for any other failure. A store that is down, slow, or wrong
    fails on the application pool and stays failed;
    `TestOnlyAPoolCeilingReachesTheReserve` walks the classes. Falling back on
    those would add a connect timeout to a request that was already lost,
    which is the "slower hard outage" decision 0006 refused when it refused a
    retry.
  * NOT a way out of failing closed. Every test here that writes a row also
    asserts the call still failed. The reserve changes whether the write can
    get a connection and nothing else about it.

WHY THE ORDERING MATTERS MORE THAN THE SIZE.
`dev-docs/decisions/0013-connection-pool-ceiling.md` rejected "a separate
engine or pool for audit writes" on two grounds, and the fallback shape
answers both by construction rather than by argument. Its arithmetic ground
was that two pools each keep their own `pool_size` open at the same request
concurrency; a pool that is only ever asked for a connection after the other
one refused keeps nothing open until that happens, which is the test named
above. Its symptom ground was that two independently saturating pools make
"the store is full" produce two different symptoms depending on which ran
out; the reserve cannot be the one that ran out first, because reaching it
requires the application pool to have raised, which
`test_when_the_reserve_is_also_at_its_ceiling_the_operator_sees_both_pools`
pins as a chained pair of exceptions rather than a choice between two.

WHAT IS NOT CLAIMED, and it is the case the prose around this work is most
likely to overstate: **a reserve writes no row against a store that is
down.** A second pool to an unreachable Postgres is a second way to fail to
connect. What this closes is saturation of the ceiling -- the application
pool at its limit against a store that is answering -- which is the shape
`sqlalchemy.exc.TimeoutError` names and the only shape a connection could
have been reserved for.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest
import sqlalchemy.exc as sa_exc
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan
from postern_core.store import audit
from postern_core.store.engine import Database
from postern_core.store.models import (
    REFUSAL_CONSENT_STORE_UNAVAILABLE,
    AuditEntry,
    ConsentRecord,
)
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.pool import NullPool, QueuePool
from starlette.types import Message, Scope

from services.api.main import create_app
from services.api.settings import Settings
from tests.fixtures import backend_responses as fx
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

ISSUER = "https://postern-reserve.invalid"
AUDIENCE = "postern"

#: A consent-gated tool, so a saturated pool is refused by the consent lookup
#: before the tool body exists. `services/api/tools/bootstrap.py`'s
#: `start_session` is the ungated counterpart used further down, where the
#: entry row is the one under test.
GATED_TOOL = "accounts.list"
UNGATED_TOOL = "start_session"

#: Short deliberately. A saturated call pays this wait twice before the
#: reserve is reached -- once for the consent lookup, once for the audit
#: write's own refused checkout -- and at the production default of 1.0s that
#: is two seconds per case. The number under test is which pool serves the
#: write, not how long a refusal takes;
#: `tests/test_pool_sizing.py::TestTheCeilingIsWhatRefusesAndTheWaitIsBounded`
#: is where the wait itself is measured.
POOL_TIMEOUT = 0.2

_UNREACHABLE = "postgresql+asyncpg://postern:postern@127.0.0.1:1/postern"


# ---------------------------------------------------------------------------
# Driving the real composed app. Same shape as
# `tests/test_asgi_app.py::test_end_to_end_audit_rows_are_written_for_a_real_call`,
# which is the existing precedent for a real JWT, a seeded consent row and
# rows read back through a second connection.
# ---------------------------------------------------------------------------


def _backend(request: httpx2.Request) -> httpx2.Response:
    body = {"/accounts": fx.ACCOUNTS}.get(request.url.path)
    return httpx2.Response(200, json=body) if body is not None else httpx2.Response(404, json={})


@asynccontextmanager
async def _drive_lifespan(app: StarletteWithLifespan) -> AsyncIterator[None]:
    """The ASGI lifespan by hand, copied in shape from `tests/test_asgi_app.py`.

    Required rather than convenient: `create_app` wraps FastMCP's own
    lifespan, and without startup the session manager is uninitialised and
    `/mcp` answers nothing. Its exit is also what closes the `Database`, so
    every pool this file holds connections from must be released inside the
    block.
    """
    startup = asyncio.Event()
    shutdown = asyncio.Event()
    to_app: asyncio.Queue[Message] = asyncio.Queue()

    async def receive() -> Message:
        return await to_app.get()

    async def send(message: Message) -> None:
        if message["type"] == "lifespan.startup.complete":
            startup.set()
        elif message["type"] == "lifespan.shutdown.complete":
            shutdown.set()

    scope: Scope = {"type": "lifespan"}
    task = asyncio.create_task(app(scope, receive, send))
    await to_app.put({"type": "lifespan.startup"})
    await startup.wait()
    try:
        yield
    finally:
        await to_app.put({"type": "lifespan.shutdown"})
        await shutdown.wait()
        await task


def _settings(pg_url: str, **overrides: Any) -> Settings:
    """A pool of exactly one by default, which is the sharpest probe available.

    `tests/test_pool_sizing.py` makes the same choice for the same reason: a
    pool that physically cannot serve a second checkout turns any overlap
    straight into a `sqlalchemy.exc.TimeoutError`, where a larger pool would
    only move the concurrency at which it shows.
    """
    fields: dict[str, Any] = {
        "backend_base_url": "https://backend.test",
        "database_url": pg_url,
        "database_pool_size": 1,
        "database_max_overflow": 0,
        "database_pool_timeout_seconds": POOL_TIMEOUT,
    }
    fields.update(overrides)
    return Settings(**fields)


def _app(settings: Settings, key_pair: RSAKeyPair) -> StarletteWithLifespan:
    """The real composition root, so the wiring under test is production's.

    `create_app` and not a hand-assembled `build_server`: the claim is that
    `services/api/main.py` gives its one `Database` a reserve, and a test that
    built its own `Database` would prove only that `Database` can hold one.
    """
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_app(
        settings,
        transport=httpx2.MockTransport(_backend),
        auth_override=verifier,
    )


async def _call(
    app: StarletteWithLifespan, token: str, tool: str
) -> httpx2.Response:  # pragma: no cover - wiring
    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://t") as client:
        return await client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {token}",
                "Mcp-Method": "tools/call",
                "Mcp-Name": tool,
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": tool, "arguments": {}},
            },
        )


def queue_pool(engine: AsyncEngine) -> QueuePool:
    """The engine's pool, narrowed to the class that has a ceiling.

    Same helper and the same reason as
    `tests/test_pool_sizing.py`'s `queue_pool`: an engine that had fallen back
    to a `NullPool` answers none of these and that is exactly the regression
    worth failing on.
    """
    pool = engine.pool
    assert isinstance(pool, QueuePool)
    return pool


@asynccontextmanager
async def saturated(engine: AsyncEngine) -> AsyncIterator[None]:
    """Hold every connection this pool will ever hand out.

    The honest shape of the condition under test: not a patched sessionmaker
    and not an unreachable address, but `pool_size + max_overflow`
    connections checked out against a Postgres that is answering normally.
    Anything that asks this pool for a connection inside the block waits
    `pool_timeout` and raises `sqlalchemy.exc.TimeoutError`.
    """
    pool = queue_pool(engine)
    ceiling = pool.size() + pool._max_overflow
    held = []
    try:
        for _ in range(ceiling):
            connection = await engine.connect()
            await connection.execute(text("SELECT 1"))
            held.append(connection)
        assert pool.checkedout() == ceiling, "the pool is not actually at its ceiling"
        yield
    finally:
        for connection in held:
            await connection.close()


@asynccontextmanager
async def consented(database: Database, customer: str, *domains: str) -> AsyncIterator[None]:
    """Seed this customer's consent, and take every row it caused away again.

    Committed for real through a second connection, because the app's own
    consent lookup opens its own and cannot see this file's transaction --
    the finding `tests/test_consent_enforcement.py` recorded first. Audit
    rows go out through the one sanctioned bypass, scoped to this customer,
    so nothing this file writes reaches a suite that counts rows.
    """
    async with database.sessionmaker() as session:
        for domain in domains:
            session.add(
                ConsentRecord(
                    customer_ref=customer,
                    domain=domain,
                    granted=True,
                    granted_at=datetime.now(UTC),
                    expires_at=None,
                )
            )
        await session.commit()
    try:
        yield
    finally:
        async with database.sessionmaker() as session:
            await session.execute(
                delete(ConsentRecord).where(ConsentRecord.customer_ref == customer)
            )
            await delete_audit_rows_by_bypassing_the_append_only_triggers(
                session, AuditEntry.customer_ref == customer
            )
            await session.commit()


async def rows_for(database: Database, customer: str) -> list[AuditEntry]:
    async with database.sessionmaker() as session:
        found = await session.execute(
            select(AuditEntry).where(AuditEntry.customer_ref == customer).order_by(AuditEntry.id)
        )
        return list(found.scalars().all())


def token_for(key_pair: RSAKeyPair, customer: str) -> str:
    return key_pair.create_token(subject=customer, issuer=ISSUER, audience=AUDIENCE)


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


# ---------------------------------------------------------------------------
# The gap, and the row that closes it.
# ---------------------------------------------------------------------------


class TestTheGapThisFileCloses:
    """One scenario, twice: with the reserve and without it.

    Two tests rather than one, and the pair is the point. A test that only
    asserted the row exists would pass against a build where the pool was
    never actually saturated, and a test that only asserted the row is
    missing would pass against a build where the call never ran.
    """

    async def test_without_a_reserve_a_saturated_pool_writes_no_row(
        self, pg_url: str, database: Database, key_pair: RSAKeyPair
    ) -> None:
        """Today's behaviour, measured rather than described.

        `audit_reserve_size=0` is what every `Database` in this repository
        built before this work and what `Database`'s own default still is, so
        this is the read path exactly as it shipped: the consent lookup is
        refused by the ceiling, the call is denied, the completion write is
        refused by the same ceiling, and `audit_log` never learns that the
        customer was turned away.
        """
        customer = "cust_reserveoff01"
        settings = _settings(pg_url, database_audit_reserve_size=0)
        async with consented(database, customer, "accounts"):
            app = _app(settings, key_pair)
            async with _drive_lifespan(app):
                async with saturated(app.state.postern_database.engine):
                    response = await _call(app, token_for(key_pair, customer), GATED_TOOL)

            assert response.json()["result"]["isError"] is True
            assert await rows_for(database, customer) == [], (
                "a row exists, so this test is no longer measuring the gap"
            )

    async def test_the_denial_reaches_the_audit_table_through_the_reserve(
        self,
        pg_url: str,
        database: Database,
        key_pair: RSAKeyPair,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """The property the work exists for, against a real Postgres.

        Same app, same saturated pool, same denial -- and the row is there,
        carrying the reason the consent work added. `len(rows) == 1` is not
        decoration: it is what says the reserve wrote the completion row once
        rather than twice, which is the failure a fallback gets wrong when the
        first attempt committed before it raised.
        """
        customer = "cust_reserveon01"
        settings = _settings(pg_url, database_audit_reserve_size=1)
        async with consented(database, customer, "accounts"):
            app = _app(settings, key_pair)
            with caplog.at_level("WARNING", logger="postern_core.store.audit"):
                async with _drive_lifespan(app):
                    async with saturated(app.state.postern_database.engine):
                        response = await _call(app, token_for(key_pair, customer), GATED_TOOL)

            # STILL FAILS CLOSED. The row is the only thing that changed.
            assert response.json()["result"]["isError"] is True

            rows = await rows_for(database, customer)
            assert len(rows) == 1, [(r.outcome, r.refusal_reason) for r in rows]
            assert rows[0].tool_name == GATED_TOOL
            assert rows[0].outcome == "raised"
            assert rows[0].detail == "NotFoundError"
            assert rows[0].refusal_reason == REFUSAL_CONSENT_STORE_UNAVAILABLE

            # The operator's only signal that this happened at all, and the one
            # they alert on to learn they are a pool short. The row exists and
            # the call failed for its own reason, so nothing else in the logs
            # distinguishes a saturated replica from an ordinary refusal.
            warnings = [
                record
                for record in caplog.records
                if record.name == "postern_core.store.audit" and record.levelname == "WARNING"
            ]
            assert len(warnings) == 1, [r.getMessage() for r in warnings]
            assert "reserve" in warnings[0].getMessage()
            assert "QueuePool" in warnings[0].getMessage()

    async def test_both_rows_of_an_ungated_call_survive_a_saturated_pool(
        self, pg_url: str, database: Database, key_pair: RSAKeyPair
    ) -> None:
        """The entry row too, on the one tool that reaches the backend without
        a consent lookup.

        `start_session` carries no `auth=`, so saturation does not refuse it
        before it runs. That makes this the only shape in which the
        `outcome='reaching'` row is reachable under a full pool -- and it is
        the row with a consequence attached, because
        `services/api/middleware/audit.py`'s `_PendingEntry.record` re-raises
        when it cannot be written and the backend request is then never made.
        Through the reserve the row is durable and the touch happens, which is
        the sequence the entry row exists to guarantee rather than a
        relaxation of it.
        """
        customer = "cust_reserveungated"
        settings = _settings(pg_url, database_audit_reserve_size=1)
        async with consented(database, customer):
            app = _app(settings, key_pair)
            async with _drive_lifespan(app):
                async with saturated(app.state.postern_database.engine):
                    response = await _call(app, token_for(key_pair, customer), UNGATED_TOOL)

            assert response.json()["result"]["isError"] is False, response.text

            rows = await rows_for(database, customer)
            assert [(r.tool_name, r.outcome) for r in rows] == [
                (UNGATED_TOOL, "reaching"),
                (UNGATED_TOOL, "returned"),
            ]
            assert rows[0].call_id == rows[1].call_id


class TestTheReserveCostsNothingUntilItIsNeeded:
    """The arithmetic objection, answered by measurement.

    Decision 0013 rejected a second pool partly because "each keeps its own
    `pool_size` open whether or not the other is busy". That is true of two
    pools both serving traffic and false of a pool nothing has asked yet:
    `QueuePool` opens connections on demand, so the reserve's contribution to
    `replicas x ceiling` is a ceiling and not a standing cost.
    """

    async def test_the_reserve_holds_no_connection_until_the_pool_has_refused(
        self, pg_url: str, database: Database, key_pair: RSAKeyPair
    ) -> None:
        customer = "cust_reserveidle01"
        settings = _settings(
            pg_url,
            database_pool_size=5,
            database_max_overflow=0,
            database_audit_reserve_size=1,
        )
        async with consented(database, customer, "accounts"):
            app = _app(settings, key_pair)
            async with _drive_lifespan(app):
                response = await _call(app, token_for(key_pair, customer), GATED_TOOL)
                reserve = app.state.postern_database.audit_reserve
                assert reserve is not None
                idle = queue_pool(reserve).checkedin()

            assert response.json()["result"]["isError"] is False, response.text
            assert idle == 0, (
                f"the reserve opened {idle} connection(s) on a healthy call; it is a "
                "fallback, and a fallback that connects is a second pool"
            )
            assert len(await rows_for(database, customer)) == 2

    def test_a_null_pool_database_builds_no_reserve(self) -> None:
        """`NullPool` has no ceiling to be refused by.

        Every database-backed test in `tests/conftest.py` runs on
        ``null_pool=True``, where a checkout opens its own connection and
        queues for nothing, so `sqlalchemy.exc.TimeoutError` is unreachable
        and a reserve would be a second engine that nothing can ever route
        to.
        """
        db = Database(_UNREACHABLE, null_pool=True, audit_reserve_size=4)
        assert isinstance(db.engine.pool, NullPool)
        assert db.audit_reserve is None
        assert db.audit_reserve_sessionmaker is None

    def test_the_database_default_is_no_reserve(self) -> None:
        """`Database` is built directly by 20-odd tests and by nothing in
        production, so the reserve arrives through each service's `from_env`
        and not through a changed default -- the same posture
        `tests/test_pool_sizing.py` records for `pool_size`."""
        db = Database(_UNREACHABLE)
        assert db.audit_reserve is None

    async def test_closing_the_database_disposes_the_reserve_too(self, pg_url: str) -> None:
        """A second set of sockets that shutdown forgets is a leak per restart.

        `services/api/main.py`'s `_close_resources_after_fastmcp_shutdown`
        calls `Database.close` and nothing else, so the reserve's engine is
        disposed there or never. Measured on the pool object held before the
        call, because `AsyncEngine.dispose` replaces `engine.pool` with a fresh
        one and reading the attribute afterwards would answer about a pool that
        never had a connection.
        """
        db = Database(pg_url, audit_reserve_size=1)
        reserve = db.audit_reserve
        assert reserve is not None
        pool = queue_pool(reserve)
        async with reserve.connect() as connection:
            await connection.execute(text("SELECT 1"))
        assert pool.checkedin() == 1, "the reserve never opened a connection to dispose"

        await db.close()

        assert pool.checkedin() == 0

    async def test_create_app_wires_the_reserve_from_settings(self) -> None:
        app = create_app(
            Settings(
                backend_base_url="https://backend.test",
                database_url=_UNREACHABLE,
                database_audit_reserve_size=3,
            )
        )
        reserve = app.state.postern_database.audit_reserve
        assert reserve is not None
        assert queue_pool(reserve).size() == 3
        assert queue_pool(reserve)._max_overflow == 0, (
            "overflow on the reserve would let the fallback grow without a "
            "ceiling under exactly the condition it exists for"
        )


# ---------------------------------------------------------------------------
# The routing rule, at the unit the rule lives in.
# ---------------------------------------------------------------------------


def _raising_maker(exc: BaseException) -> Callable[[], Any]:
    """A stand-in sessionmaker whose `async with` raises on entry."""

    class _Maker:
        def __call__(self) -> Any:
            @asynccontextmanager
            async def scope() -> AsyncIterator[AsyncSession]:
                raise exc
                yield  # pragma: no cover - unreachable, satisfies the generator

            return scope()

    return _Maker()


class _Write:
    """A write that actually USES its session, which is what forces a checkout.

    Worth stating because it was a bug here first: an `AsyncSession` is lazy,
    so ``async with db.sessionmaker() as s: pass`` takes no connection from
    the pool and cannot be refused by it. A stand-in write that only counted
    its calls therefore passed every case in this class against a saturated
    pool, by never touching one. `attempts` and `completed` are separate for
    the same reason the reserve exists: on the fallback path the write is
    entered twice and finishes once.
    """

    def __init__(self) -> None:
        self.attempts = 0
        self.completed = 0

    async def __call__(self, session: AsyncSession) -> None:
        self.attempts += 1
        await session.execute(text("SELECT 1"))
        self.completed += 1


class _NoOpWrite:
    """Counts, and touches nothing.

    For the one case whose session is a stand-in object rather than an
    `AsyncSession`: the guard being tested is about a `TimeoutError` arriving
    after the write returned, which needs a fake exit rather than a real pool.
    """

    def __init__(self) -> None:
        self.attempts = 0

    async def __call__(self, session: AsyncSession) -> None:
        self.attempts += 1


class TestOnlyAPoolCeilingReachesTheReserve:
    """Which exception earns the second attempt, and which does not.

    `sqlalchemy.exc.TimeoutError` alone, because it is the only failure a
    second pool can answer: it means N connections are checked out and none
    came back, and nothing about the store itself is implied. Every other
    failure is about the store or about this software, and a second attempt
    against either pays another connect budget to reach the same answer --
    the "slower hard outage" `dev-docs/decisions/0006-audit-write-failure.md`
    named when it refused a retry.
    """

    @pytest.mark.parametrize(
        "exc",
        [
            ConnectionRefusedError("nothing listening"),
            sa_exc.OperationalError("stmt", None, Exception("gone")),
            sa_exc.ProgrammingError("stmt", None, Exception("no such column")),
            RuntimeError("a bug in this repository"),
        ],
        ids=["refused", "operational", "programming", "bug"],
    )
    async def test_every_other_failure_is_left_alone(self, exc: BaseException) -> None:
        db = Database(_UNREACHABLE, audit_reserve_size=1)
        written = _Write()
        db.sessionmaker = _raising_maker(exc)  # type: ignore[assignment]
        db.audit_reserve_sessionmaker = _raising_maker(AssertionError("reserve reached"))  # type: ignore[assignment]

        with pytest.raises(type(exc)):
            await audit.append_with_reserve(db, written)

        assert written.attempts == 0
        await db.close()

    async def test_a_pool_ceiling_is_retried_on_the_reserve(self, pg_url: str) -> None:
        """The positive control for the branch above, on a real engine.

        Without it, a predicate that matched nothing would pass every case in
        the parametrize above exactly as a correct one does. `attempts == 2`
        is what says the fallback fired rather than the primary having quietly
        succeeded.
        """
        db = Database(pg_url, audit_reserve_size=1, pool_timeout_seconds=POOL_TIMEOUT)
        written = _Write()
        try:
            async with saturated(db.engine):
                await audit.append_with_reserve(db, written)
            assert (written.attempts, written.completed) == (2, 1)
        finally:
            await db.close()

    async def test_with_no_reserve_the_pool_timeout_propagates_unchanged(self, pg_url: str) -> None:
        db = Database(pg_url, pool_timeout_seconds=POOL_TIMEOUT)
        written = _Write()
        try:
            async with saturated(db.engine):
                with pytest.raises(sa_exc.TimeoutError):
                    await audit.append_with_reserve(db, written)
            assert written.completed == 0
        finally:
            await db.close()

    async def test_a_write_that_completed_is_never_run_a_second_time(self) -> None:
        """The duplicate-row guard, which is structural and not argued.

        A pooled checkout raises `sqlalchemy.exc.TimeoutError` before any
        statement reaches the server -- measured, and pinned by
        `test_the_row_the_refused_attempt_left_behind` below -- so the
        ordinary fallback cannot duplicate a row. This covers the other
        shape: a `TimeoutError` arriving from somewhere AFTER the write
        finished, where running it again would put a second row on a
        regulator-facing table.
        """
        db = Database(_UNREACHABLE, audit_reserve_size=1)
        written = _NoOpWrite()

        class _CommitsThenRaisesOnExit:
            def __call__(self) -> Any:
                @asynccontextmanager
                async def scope() -> AsyncIterator[Any]:
                    yield object()
                    raise sa_exc.TimeoutError("raised after the row was written")

                return scope()

        db.sessionmaker = _CommitsThenRaisesOnExit()  # type: ignore[assignment]
        db.audit_reserve_sessionmaker = _raising_maker(AssertionError("reserve reached"))  # type: ignore[assignment]

        with pytest.raises(sa_exc.TimeoutError):
            await audit.append_with_reserve(db, written)

        assert written.attempts == 1
        await db.close()

    async def test_the_row_the_refused_attempt_left_behind(self, pg_url: str) -> None:
        """Nothing, and that is why one fallback cannot become two rows.

        The premise the guard above complements, measured directly rather
        than reasoned from the pool's source: with the pool at its ceiling,
        the checkout raises before the INSERT is sent, so the statement the
        first attempt would have run never reached Postgres.
        """
        db = Database(pg_url, pool_timeout_seconds=POOL_TIMEOUT)
        probe = Database(pg_url, null_pool=True)
        try:
            async with probe.sessionmaker() as session:
                await session.execute(text("CREATE TABLE IF NOT EXISTS reserve_probe (x int)"))
                await session.execute(text("DELETE FROM reserve_probe"))
                await session.commit()

            async def insert(session: AsyncSession) -> None:
                await session.execute(text("INSERT INTO reserve_probe VALUES (1)"))
                await session.commit()

            async with saturated(db.engine):
                with pytest.raises(sa_exc.TimeoutError):
                    await audit.append_with_reserve(db, insert)

            async with probe.sessionmaker() as session:
                count = (await session.execute(text("SELECT count(*) FROM reserve_probe"))).scalar()
            assert count == 0
        finally:
            async with probe.sessionmaker() as session:
                await session.execute(text("DROP TABLE IF EXISTS reserve_probe"))
                await session.commit()
            await db.close()
            await probe.close()


class TestWhenTheReserveRunsOutToo:
    """The symptom question decision 0013 asked, answered on the shape that
    replaced the one it was asked about.

    The record's objection was that two pools make "the store is full"
    produce two different symptoms depending on which ran out. Under a
    fallback there is no "which": the reserve is unreachable until the
    application pool has raised, so an exhausted reserve is always the second
    half of a pair and the operator gets both halves in one traceback.
    """

    async def test_when_the_reserve_is_also_at_its_ceiling_the_operator_sees_both_pools(
        self, pg_url: str
    ) -> None:
        db = Database(pg_url, audit_reserve_size=1, pool_timeout_seconds=POOL_TIMEOUT)
        written = _Write()
        reserve = db.audit_reserve
        assert reserve is not None
        try:
            async with saturated(db.engine), saturated(reserve):
                with pytest.raises(sa_exc.TimeoutError) as caught:
                    await audit.append_with_reserve(db, written)

            assert written.completed == 0
            # The reserve's refusal is what propagates, with the application
            # pool's as its `__cause__`: an operator reading this traceback
            # learns that the pool was full AND that the reserve could not
            # take the row either, which is the whole story rather than
            # either half of it.
            assert isinstance(caught.value.__cause__, sa_exc.TimeoutError)
            assert caught.value is not caught.value.__cause__
        finally:
            await db.close()

    async def test_the_call_fails_exactly_as_it_does_today(
        self, pg_url: str, database: Database, key_pair: RSAKeyPair
    ) -> None:
        """No worse than the silence it replaces.

        Both pools full is the state the reserve cannot improve on, and the
        thing worth pinning is that it does not make it worse: the customer
        gets the same denial and `audit_log` gets the same nothing as the
        no-reserve control at the top of this file.
        """
        customer = "cust_reserveboth01"
        settings = _settings(pg_url, database_audit_reserve_size=1)
        async with consented(database, customer, "accounts"):
            app = _app(settings, key_pair)
            async with _drive_lifespan(app):
                db: Database = app.state.postern_database
                reserve = db.audit_reserve
                assert reserve is not None
                async with saturated(db.engine), saturated(reserve):
                    response = await _call(app, token_for(key_pair, customer), GATED_TOOL)

            assert response.json()["result"]["isError"] is True
            assert await rows_for(database, customer) == []

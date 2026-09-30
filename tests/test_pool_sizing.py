"""How many Postgres connections a replica may hold, and why one is enough
for a single approval.

TWO SEPARATE CLAIMS LIVE HERE and they are easy to conflate. The first is
about SHAPE: an approval takes four pooled connections one after another and
never two at once, so the pool bounds how many REQUESTS a replica serves
concurrently and not how many connections each request costs. The second is
about SIZE: `services/api/settings.py` and `services/confirm/settings.py` now
name a ceiling instead of inheriting SQLAlchemy's 5 + 10, and
`dev-docs/decisions/0013-connection-pool-ceiling.md` carries the arithmetic an
operator has to redo against their own ``max_connections``.

WHY THE SHAPE CLAIM NEEDED A TEST. ``services/confirm/callback.py`` recorded,
correctly, that an approval writes two audit rows from their own sessions
while the handler still holds the session that claimed the challenge -- and
that reading invites the conclusion that each approval pins two pooled
connections at the same time, which would make any pool deadlock at
``pool_size + max_overflow`` simultaneous approvals with every waiter holding
one connection and needing a second. It does not, and the reason is one
statement: ``_approve`` commits before it reaches the backend, and an
`AsyncSession` returns its connection to the pool at commit rather than at
close. Measured against postgres:17-alpine on 2026-09-26, at
``pool_size=1, max_overflow=0``: a session that has run a ``SELECT`` and not
committed leaves ``checkedout=1`` and a second session times out; the same
session after ``commit()`` leaves ``checkedout=0`` and a second session is
served. So the tests below drive a real approval through a pool of exactly
one. A pool of one cannot deadlock against itself in the usual sense -- it
simply refuses -- which is what makes it the sharpest available probe: any
overlap at all turns the 200 into a `sqlalchemy.exc.TimeoutError` after
``pool_timeout``.

WHAT WOULD BREAK IT, and therefore what these tests are guarding: moving
``session.commit()`` below the backend write, sharing the handler's session
with an audit row, or wrapping the handler body in ``async with
db.sessionmaker.begin()``. The first of those is the likely one, because it
reads like a safety improvement.

WHAT IS NOT CLAIMED. Nothing here measures throughput, and no number in this
repository was derived from a load test. The ceilings are budgeted against a
connection limit, not against a request rate, and the decision record says so.
"""

from __future__ import annotations

import os
import time
from collections.abc import AsyncIterator, Generator
from typing import Any

import httpx2
import pytest
import sqlalchemy.exc
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.domain.verification import VerificationTier
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool, QueuePool
from starlette.applications import Starlette

from services.api.main import create_app
from services.api.settings import Settings
from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.device_keys import approval_body, device_key, enrolled_store

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
CUSTOMER = "cust_7f3a"

#: Every challenge this module creates. Deleted at teardown by prefix, the
#: same contract ``tests/test_approval_integration.py`` uses against its own.
PREFIX = "chal_pool_"

#: Postgres' own compiled-in default, and the number every operator starts
#: from unless they or their managed service raised it.
POSTGRES_DEFAULT_MAX_CONNECTIONS = 100

#: ``superuser_reserved_connections``, also a Postgres default. Subtracted
#: because those slots are not available to an application role at all.
SUPERUSER_RESERVED = 3

DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("pool-phone")


def api_defaults() -> Settings:
    """`Settings` at its defaults. ``backend_base_url`` has none and is the
    one required field, so it is supplied and nothing else is."""
    return Settings(backend_base_url="https://backend.test")


def api_ceiling() -> int:
    """Every connection one read-path replica can hold, the reserve included.

    THE RESERVE IS IN THE SUM, and that is the point of computing it here
    rather than writing 15. `postern_core.store.engine`'s `Database` holds a
    second engine of `database_audit_reserve_size` connections so that an
    audit row can still be written when the pool is at its ceiling
    (`tests/test_audit_reserve.py`), and those connections come out of the
    same server-wide `max_connections` as the pool's. Leaving them out would
    make the arithmetic below quietly optimistic by one per replica.

    It is a CEILING and not a standing cost -- `QueuePool` opens on demand and
    the reserve is reached only after a refused checkout -- but a budget
    against `max_connections` has to be written against what a replica MAY
    hold, because the moment the reserve is needed is the moment every replica
    needs it at once.
    """
    settings = api_defaults()
    return (
        settings.database_pool_size
        + settings.database_max_overflow
        + settings.database_audit_reserve_size
    )


def confirm_ceiling() -> int:
    """Every connection one write-path replica can hold, its reserve included.

    The reserve counts here for the same reason it counts in `api_ceiling`
    above: it is a second engine against the same server-wide
    ``max_connections``. What differs between the two services is not the
    number but which rows the reserve serves -- `services/confirm/audit.py`
    keeps `ApprovalAudit`'s entry row on the pool on purpose -- and that has no
    effect on the arithmetic.
    """
    settings = ConfirmSettings()
    return (
        settings.database_pool_size
        + settings.database_max_overflow
        + settings.database_audit_reserve_size
    )


# ---------------------------------------------------------------------------
# Fixtures. Module-scoped container, matching tests/test_write_audit.py: this
# file writes audit_log rows through a real app, and those rows cannot be
# deleted (migration f1860c110112), so they must not land in the
# session-scoped container every other suite counts rows in.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_url() -> Generator[str]:
    import docker
    from testcontainers.community.postgres import PostgresContainer

    try:
        docker.from_env().ping()
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping pool sizing tests: {exc}")

    previous = os.environ.get("POSTERN_DATABASE_URL")
    with PostgresContainer("postgres:17-alpine", driver="asyncpg") as pg:
        url = pg.get_connection_url()
        os.environ["POSTERN_DATABASE_URL"] = url
        from alembic import command
        from alembic.config import Config

        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        try:
            yield url
        finally:
            if previous is None:
                os.environ.pop("POSTERN_DATABASE_URL", None)
            else:
                os.environ["POSTERN_DATABASE_URL"] = previous


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
async def fixture_db(pg_url: str) -> AsyncIterator[Database]:
    """A SECOND database handle, on a NullPool, for everything the test itself
    does.

    Deliberately not the app's: inserting a challenge or reading a row back
    through the pool under test would spend the very connection the assertion
    is about, and a leaked checkout here would read as the defect.
    """
    db = Database(pg_url, null_pool=True)
    try:
        yield db
    finally:
        async with db.sessionmaker() as cleanup:
            await cleanup.execute(
                text("DELETE FROM challenges WHERE challenge_id LIKE :p"), {"p": f"{PREFIX}%"}
            )
            await cleanup.commit()
        await db.close()


def confirm_app(
    pg_url: str,
    key_pair: RSAKeyPair,
    *,
    pool_size: int,
    max_overflow: int,
    pool_timeout_seconds: float = 1.0,
) -> Starlette:
    """The real confirm service, wired to a pool of the stated size."""
    settings = ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        database_pool_size=pool_size,
        database_max_overflow=max_overflow,
        database_pool_timeout_seconds=pool_timeout_seconds,
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=enrolled_store(CUSTOMER, DEVICE_PUBLIC),
    )


def app_engine(app: Starlette) -> AsyncEngine:
    database: Database = app.state.postern_database
    return database.engine


def queue_pool(engine: AsyncEngine) -> QueuePool:
    """The engine's pool, narrowed to the class that has a ceiling.

    ``size()``, ``checkedout()`` and ``_max_overflow`` belong to `QueuePool`
    and not to the abstract `Pool`, which is mypy's point and also the
    assertion: an engine that had fallen back to a NullPool would answer none
    of them, and that is exactly the regression these tests would otherwise
    miss.
    """
    pool = engine.pool
    assert isinstance(pool, QueuePool)
    return pool


class PoolWatch:
    """Checkouts on one engine: how many, and how many at once.

    ``peak`` is the number the nesting question turns on. ``checkouts`` is
    what an approval costs the pool over its lifetime, which is a different
    quantity and the one the pool's throughput depends on.
    """

    def __init__(self, engine: AsyncEngine) -> None:
        self.checkouts = 0
        self.live = 0
        self.peak = 0
        event.listens_for(engine.sync_engine, "checkout")(self._out)
        event.listens_for(engine.sync_engine, "checkin")(self._in)

    def _out(self, *_: Any) -> None:
        self.checkouts += 1
        self.live += 1
        self.peak = max(self.peak, self.live)

    def _in(self, *_: Any) -> None:
        self.live -= 1


def bearer(key_pair: RSAKeyPair, subject: str = CUSTOMER) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    return {"Authorization": f"Bearer {token}"}


async def insert_pending(db: Database, challenge_id: str) -> None:
    async with db.sessionmaker() as session:
        await store.create_challenge(
            session,
            challenge_id=challenge_id,
            customer_ref=CUSTOMER,
            tool_name="payments.create_payment",
            payload={"amount": "EUR 340.00"},
            tier=VerificationTier.APP_APPROVAL,
        )
        await session.commit()


async def post_approval(
    app: Starlette, challenge_id: str, body: dict[str, Any], headers: dict[str, str]
) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        return await client.post(f"/challenges/{challenge_id}/approve", json=body, headers=headers)


def backend_answering(
    handler: Any, monkeypatch: pytest.MonkeyPatch
) -> None:  # pragma: no cover - wiring
    """Route every ``BackendWriteClient`` through ``handler``.

    Same patch as ``tests/test_approval_integration.py``'s autouse fixture,
    written per test here because two tests below need the handler to observe
    the pool at the instant the backend is reached.
    """
    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, transport=httpx2.MockTransport(handler), **kwargs)

    monkeypatch.setattr(BackendWriteClient, "__init__", patched)


# ---------------------------------------------------------------------------
# The shape: one connection at a time, even through the backend write.
# ---------------------------------------------------------------------------


class TestAnApprovalNeverHoldsTwoPooledConnectionsAtOnce:
    """A pool of exactly one serves a whole approval.

    ``pool_size=1, max_overflow=0`` is the smallest pool SQLAlchemy will
    build, and any overlap between the handler's session and an audit row's
    would make these requests wait ``pool_timeout`` and then raise. The status
    code is the assertion; ``peak`` is the diagnosis.
    """

    async def test_a_successful_approval_completes_through_a_pool_of_one(
        self,
        pg_url: str,
        key_pair: RSAKeyPair,
        fixture_db: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        backend_answering(
            lambda request: httpx2.Response(200, json={"status": "accepted"}), monkeypatch
        )
        app = confirm_app(pg_url, key_pair, pool_size=1, max_overflow=0)
        watch = PoolWatch(app_engine(app))
        challenge_id = f"{PREFIX}success"
        await insert_pending(fixture_db, challenge_id)

        response = await post_approval(
            app,
            challenge_id,
            await approval_body(fixture_db, challenge_id, DEVICE_PRIVATE),
            bearer(key_pair),
        )

        assert response.status_code == 200, response.text
        assert watch.peak == 1, (
            f"the approval held {watch.peak} pooled connections at once; a nested "
            "checkout cannot be sized away, it can only be moved to a higher "
            "concurrency"
        )
        # Four, in order: the SELECT-plus-claim transaction, the entry audit
        # row, the approved -> executed transition, the completion audit row.
        # The number is what the pool's throughput divides into, and it
        # doubled on 2026-09-23 when the write path grew an audit trail.
        assert watch.checkouts == 4

    async def test_a_refusal_before_the_backend_completes_through_a_pool_of_one(
        self,
        pg_url: str,
        key_pair: RSAKeyPair,
        fixture_db: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The other half of the shape, and the half with an OPEN transaction.

        A challenge that does not exist returns from inside ``async with
        db.sessionmaker()`` with the lookup's transaction never committed, so
        the connection goes back at ``__aexit__``. The completion row is
        written after that, by ``approve_challenge`` rather than ``_approve``,
        which is the only reason this refusal does not need a second
        connection while it still holds the first.
        """
        backend_answering(
            lambda request: httpx2.Response(500, json={"detail": "never reached"}), monkeypatch
        )
        app = confirm_app(pg_url, key_pair, pool_size=1, max_overflow=0)
        watch = PoolWatch(app_engine(app))

        response = await post_approval(
            app,
            f"{PREFIX}absent",
            {"signature": "a" * 86},
            bearer(key_pair),
        )

        assert response.status_code == 404, response.text
        assert watch.peak == 1
        # The lookup and the completion row, and nothing else: no entry row,
        # because the backend was never reached.
        assert watch.checkouts == 2

    async def test_no_pooled_connection_is_held_while_the_backend_write_is_in_flight(
        self,
        pg_url: str,
        key_pair: RSAKeyPair,
        fixture_db: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The property that stops a slow backend from becoming a store outage.

        The write endpoint gets ten seconds (``BackendWriteClient``'s own
        default timeout). If the handler held a pooled connection across that
        call, a backend at its limit would pin one connection per in-flight
        approval for ten seconds each, and the pool -- whatever its size --
        would empty at the backend's latency rather than at the database's.
        """
        observed: list[int] = []
        app = confirm_app(pg_url, key_pair, pool_size=5, max_overflow=0)
        engine = app_engine(app)

        def handler(request: httpx2.Request) -> httpx2.Response:
            observed.append(queue_pool(engine).checkedout())
            return httpx2.Response(200, json={"status": "accepted"})

        backend_answering(handler, monkeypatch)
        challenge_id = f"{PREFIX}inflight"
        await insert_pending(fixture_db, challenge_id)

        response = await post_approval(
            app,
            challenge_id,
            await approval_body(fixture_db, challenge_id, DEVICE_PRIVATE),
            bearer(key_pair),
        )

        assert response.status_code == 200, response.text
        assert observed == [0], (
            "a connection was checked out while the backend write was in flight; "
            "the entry audit row must commit and close before the request is made"
        )


class TestTheCeilingIsWhatRefusesAndTheWaitIsBounded:
    """What a customer gets when the pool is full, and how long they wait for
    it."""

    async def test_a_saturated_pool_refuses_after_two_pool_timeouts(
        self,
        pg_url: str,
        key_pair: RSAKeyPair,
        fixture_db: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two waits, not one, and that is the number an operator needs.

        The handler's own lookup waits ``pool_timeout`` and raises; the
        completion audit row that records the failure is a second checkout and
        waits the same again before failing closed
        (`dev-docs/decisions/0006-audit-write-failure.md`). So a saturated
        replica does not shed at ``pool_timeout``, it sheds at twice it, and
        the second wait happens while the first has already decided the
        request is lost.
        """
        pool_timeout = 0.25
        backend_answering(
            lambda request: httpx2.Response(200, json={"status": "accepted"}), monkeypatch
        )
        app = confirm_app(
            pg_url, key_pair, pool_size=1, max_overflow=0, pool_timeout_seconds=pool_timeout
        )
        challenge_id = f"{PREFIX}saturated"
        await insert_pending(fixture_db, challenge_id)
        body = await approval_body(fixture_db, challenge_id, DEVICE_PRIVATE)

        # Hold the pool's only connection, the way a concurrent request would.
        async with app_engine(app).connect() as held:
            await held.execute(text("SELECT 1"))
            started = time.monotonic()
            with pytest.raises(sqlalchemy.exc.TimeoutError):
                await post_approval(app, challenge_id, body, bearer(key_pair))
            elapsed = time.monotonic() - started

        assert elapsed >= 2 * pool_timeout, (
            f"{elapsed:.3f}s is less than the two waits this path owes; a single "
            "wait would mean the audit row was not attempted"
        )
        assert elapsed < 6 * pool_timeout, f"{elapsed:.3f}s is not a bounded refusal"

        # Untouched: the claim never ran, so the row is still approvable once
        # the pressure clears.
        async with fixture_db.sessionmaker() as session:
            record = await store.get_challenge(session, challenge_id)
        assert record is not None
        assert record.status == "pending"


# ---------------------------------------------------------------------------
# The size: what the numbers are, where they come from, and the floors.
# ---------------------------------------------------------------------------


class TestTheCeilingIsChosenPerServiceAndReachesTheEngine:
    def test_the_database_default_is_sqlalchemys_own_so_direct_callers_are_unchanged(
        self,
    ) -> None:
        """`Database` is constructed directly by 20-odd tests and by nothing in
        production. Changing its default would have changed their behaviour
        for a reason none of them is about."""
        db = Database("postgresql+asyncpg://u:p@localhost:5432/x")
        pool = queue_pool(db.engine)
        assert pool.size() == 5
        assert pool._max_overflow == 10

    def test_the_read_path_keeps_the_ceiling_it_has_been_running(self) -> None:
        """5 + 10 is what `services/api` inherited, and raising or lowering it
        here would have been a capacity change riding along with a
        configurability change."""
        assert api_defaults().database_pool_size == 5
        assert api_defaults().database_max_overflow == 10

    def test_the_write_path_asks_for_less_than_the_read_path(self) -> None:
        """One approval is one person tapping a phone. The read path's rate is
        set by an LLM's tool-call fan-out, which nobody here controls, and the
        two services share one ``max_connections``."""
        assert ConfirmSettings().database_pool_size == 5
        assert ConfirmSettings().database_max_overflow == 5
        assert confirm_ceiling() < api_ceiling()

    def test_both_paths_reserve_one_connection_and_both_are_in_the_ceiling(self) -> None:
        """The third connection number, on both services since 2026-09-27.

        It was the read path's alone for one commit. `services/confirm` writes
        the same `audit_log` under the same fail-closed policy, and a lost row
        there is no record that a payment approval was attempted at all, so it
        got the same reserve -- serving its two completion writes and, by
        design, not `ApprovalAudit`'s entry row.
        `tests/test_audit_reserve.py` holds that argument; what belongs here is
        only that both reserves are counted.
        """
        assert api_defaults().database_audit_reserve_size == 1
        assert ConfirmSettings().database_audit_reserve_size == 1
        assert api_ceiling() == 16
        assert confirm_ceiling() == 11
        assert confirm_ceiling() < api_ceiling()

    def test_the_defaults_fit_postgres_own_max_connections_at_a_stated_replica_count(
        self,
    ) -> None:
        """The arithmetic, executable so that raising a default has to face it.

        Four API replicas and two confirm replicas is an illustration and not
        a promise about anybody's cluster;
        `dev-docs/decisions/0013-connection-pool-ceiling.md` is where an
        operator substitutes their own numbers.

        THE NUMBER MOVED TWICE ON 2026-09-27, from 80 to 84 and then to 86,
        and it still fits. Both ceilings now count an audit reserve: the read
        path holds 16 per replica rather than 15, the write path 11 rather than
        10, and the worked example leaves 11 of the default 100 where it used
        to leave 17. The headroom assertion at the bottom is what would have
        caught either step if it had not fit, and 11 is close enough to its
        floor of 10 that the next replica of either service does not fit at the
        Postgres default -- which is the fact worth carrying out of this test
        rather than the total.
        """
        api_replicas, confirm_replicas = 4, 2
        api, confirm = api_ceiling(), confirm_ceiling()
        held = api_replicas * api + confirm_replicas * confirm
        assert held + SUPERUSER_RESERVED <= POSTGRES_DEFAULT_MAX_CONNECTIONS, (
            f"{api_replicas}x{api} + {confirm_replicas}x{confirm} = {held} connections "
            f"against a default max_connections of {POSTGRES_DEFAULT_MAX_CONNECTIONS}"
        )
        # Room left for psql, alembic and whatever the operator monitors with.
        assert POSTGRES_DEFAULT_MAX_CONNECTIONS - SUPERUSER_RESERVED - held >= 10

    async def test_create_app_wires_the_read_paths_ceiling_from_settings(self) -> None:
        settings = Settings(
            backend_base_url="https://backend.test",
            database_url="postgresql+asyncpg://u:p@localhost:5432/x",
            database_pool_size=3,
            database_max_overflow=7,
        )
        app = create_app(settings)
        pool = queue_pool(app.state.postern_database.engine)
        assert pool.size() == 3
        assert pool._max_overflow == 7

    def test_create_confirm_app_wires_the_write_paths_ceiling_from_settings(
        self, pg_url: str, key_pair: RSAKeyPair
    ) -> None:
        app = confirm_app(pg_url, key_pair, pool_size=2, max_overflow=4)
        pool = queue_pool(app_engine(app))
        assert pool.size() == 2
        assert pool._max_overflow == 4


class TestTheFloorsRefuseTheOffSwitches:
    """Both variables have a value that looks like "small" and means
    "unlimited", which is why neither floor is zero-or-anything."""

    @pytest.mark.parametrize(
        ("pool_size", "max_overflow"),
        [(0, 0), (1, -1)],
        ids=["pool_size=0", "max_overflow=-1"],
    )
    async def test_the_refused_values_hold_far_more_connections_than_they_name(
        self, pg_url: str, pool_size: int, max_overflow: int
    ) -> None:
        """Measured, not argued: each of these ceilings says at most one
        connection and each one holds twelve."""
        engine = create_async_engine(
            pg_url, pool_size=pool_size, max_overflow=max_overflow, pool_timeout=1.0
        )
        connections = []
        try:
            for _ in range(12):
                connection = await engine.connect()
                await connection.execute(text("SELECT 1"))
                connections.append(connection)
            assert queue_pool(engine).checkedout() == 12
        finally:
            for connection in connections:
                await connection.close()
            await engine.dispose()

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("POSTERN_DATABASE_POOL_SIZE", "0"),
            ("POSTERN_DATABASE_MAX_OVERFLOW", "-1"),
            ("POSTERN_CONFIRM_DATABASE_POOL_SIZE", "0"),
            ("POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW", "-1"),
        ],
    )
    def test_the_service_that_reads_it_will_not_start(
        self, name: str, value: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The refusal names the variable, which is the whole point of reading
        it through `postern_core.config` rather than through a bare
        ``int()``."""
        monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
        monkeypatch.setenv(name, value)
        confirm = name.startswith("POSTERN_CONFIRM_")
        read = ConfirmSettings.from_env if confirm else Settings.from_env
        with pytest.raises(ValueError, match=name):
            read()


class TestTheNullPoolPathIsIntact:
    """`tests/conftest.py` builds every database-backed test on
    ``null_pool=True``, and NullPool takes neither of these arguments."""

    def test_a_null_pool_database_accepts_the_arguments_and_passes_neither_on(self) -> None:
        db = Database(
            "postgresql+asyncpg://u:p@localhost:5432/x",
            null_pool=True,
            pool_size=3,
            max_overflow=7,
        )
        assert isinstance(db.engine.pool, NullPool)

    @pytest.mark.parametrize("argument", ["pool_size", "max_overflow"])
    def test_create_async_engine_itself_rejects_them_under_a_null_pool(self, argument: str) -> None:
        """Why the branch exists at all, pinned the way
        ``tests/test_store_timeouts.py`` pins it for ``pool_timeout``:
        measured against SQLAlchemy 2.0.52, the whole call raises."""
        with pytest.raises(TypeError, match=argument):
            create_async_engine(
                "postgresql+asyncpg://u:p@localhost:5432/x",
                poolclass=NullPool,
                **{argument: 1},
            )

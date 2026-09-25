import os
from collections.abc import AsyncIterator, Iterator

import docker
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from docker.errors import DockerException
from fastmcp import FastMCP
from postern_core.identity import CustomerRef, CustomerResolver
from postern_core.store.engine import Database
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

from services.api.middleware.audit import AuditMiddleware
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

TEST_CUSTOMER = CustomerRef(value="cust_7f3a")


@pytest.fixture
def resolver() -> CustomerResolver:
    """Stands in for the access-token resolver (design decision D3)."""
    return lambda: TEST_CUSTOMER


@pytest.fixture(scope="session")
def pg_url() -> Iterator[str]:
    """SYNC on purpose.

    The async Alembic env.py ends in asyncio.run(), so calling
    command.upgrade from inside a coroutine raises
    `RuntimeError: asyncio.run() cannot be called from a running event loop`.

    Checks Docker reachability itself, before `PostgresContainer` gets a
    chance to: an unreachable daemon otherwise surfaces as a 15-frame
    `docker.errors.DockerException` traceback, once per test that depends on
    this fixture, rather than one clear skip.
    """
    try:
        docker.from_env().ping()
    except DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping database-backed tests: {exc}")
    with PostgresContainer("postgres:17-alpine", driver="asyncpg") as pg:
        url = pg.get_connection_url()
        os.environ["POSTERN_DATABASE_URL"] = url
        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        yield url


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    """One Redis for the whole run, for `tests/test_redis_backed_stores.py`.

    SESSION-SCOPED for the same reason `pg_url` is, and the reason is the
    container and not the data: starting one costs wall clock that `make ci`
    pays before every commit, and the three stores under test all accept a
    ``key_prefix``, so a namespace per test isolates them without a second
    container or a flush. The ``stores`` fixture in that file is where that
    happens, and its docstring is where the alternatives are priced.

    DOCKER IS PINGED HERE, before `RedisContainer` gets a chance to: an
    unreachable daemon otherwise surfaces as a 15-frame
    `docker.errors.DockerException` traceback once per dependent test rather
    than as one clear skip line, which is the same trap `pg_url` records
    above and the reason `make test` passes ``-rs``.

    IT DELIBERATELY DOES NOT SET ``POSTERN_REDIS_URL``, which is where the
    symmetry with `pg_url` stops. `pg_url` exports ``POSTERN_DATABASE_URL``
    because there is one database backend and every test wants it. Redis is
    the OPTIONAL half of three pluggable stores:
    `postern_core.risk.session.create_session_store`,
    `postern_core.auth.revocation.create_revocation_store` and
    `postern_core.auth.device_codes.create_device_code_store` all read that
    variable and switch backend when it is set. Exporting it session-wide
    would silently move every other test in the suite off the in-memory
    stores they were written against. Tests here name the URL explicitly
    instead.
    """
    try:
        docker.from_env().ping()
    except DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping Redis-backed tests: {exc}")
    with RedisContainer("redis:7-alpine") as container:
        host = container.get_container_host_ip()
        port = container.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"


@pytest_asyncio.fixture(scope="session")
async def database(pg_url: str) -> AsyncIterator[Database]:
    db = Database(pg_url, null_pool=True)
    yield db
    await db.close()


@pytest_asyncio.fixture
async def session(database: Database) -> AsyncIterator[AsyncSession]:
    """Function-scoped and rolled back, so tests cannot see each other's rows."""
    async with database.engine.connect() as conn:
        trans = await conn.begin()
        maker = async_sessionmaker(bind=conn, expire_on_commit=False)
        async with maker() as s:
            yield s
        await trans.rollback()


async def _clear_audit_log(database: Database) -> None:
    """Migration f1860c110112 makes a plain DELETE here raise, so this goes
    through the one deliberate bypass the suite is allowed --
    `tests/fixtures/append_only_bypass.py` says why that is a bypass and not
    a utility, and `tests/test_audit_append_only.py` measures what it is a
    bypass OF."""
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


@pytest_asyncio.fixture
async def audit_server(database: Database) -> AsyncIterator[FastMCP]:
    """Fresh `audit_log` state per test, before AND after.

    `AuditMiddleware` commits through `database.sessionmaker()` -- a session
    bound directly to the engine, not to this file's `session` fixture and
    its already-open, rolled-back transaction. That is deliberate in the
    middleware (an audit row for a failed call must survive regardless of
    what the rest of the request rolls back), but it also means the
    middleware's writes are real, independently committed rows in the
    session-scoped Postgres container that the `session` fixture's rollback
    cannot undo. Measured directly: without the pre-test clear, the second
    test in this file onward sees every prior test's rows too, and
    `rows(session)[0]` silently reads an *earlier* test's row instead of
    erroring. The post-`yield` clear matters separately: without it, the
    *last* test to run leaves its rows sitting in the session-scoped
    container for whatever runs against `audit_log` next, in this file or
    another. Clearing here, both ends, keeps that persistence behaviour
    intact in the middleware/production code and fixes isolation only at the
    test boundary.
    """
    await _clear_audit_log(database)

    # `strict_input_validation=True`: FastMCP defaults to lax coercion (its
    # own doc string: "providing the string '10' to an integer field will be
    # coerced to 10"), so `leaky_tool`'s digit-only PAN string is silently
    # coerced to an `int` and the call *succeeds* without this -- measured
    # directly, the intended `ValidationError` never fires on a default
    # server. This is what actually makes the coercion produce the
    # `ValidationError` the test below asserts on.
    mcp = FastMCP(name="audit-test", strict_input_validation=True)
    mcp.add_middleware(AuditMiddleware(database))

    @mcp.tool
    async def ok_tool(amount: int, memo: str = "") -> str:
        return f"ok {amount}"

    @mcp.tool
    async def boom_tool() -> str:
        raise ValueError("internal detail")

    @mcp.tool
    async def leaky_tool(pan: int) -> str:
        return "unreachable"

    yield mcp

    await _clear_audit_log(database)

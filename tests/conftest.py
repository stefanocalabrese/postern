import asyncio
import os
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import docker
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from docker.errors import DockerException
from fastmcp import FastMCP
from postern_core import log_safety
from postern_core.identity import CustomerRef, CustomerResolver
from postern_core.store.engine import Database
from sqlalchemy import make_url
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

from services.api.middleware.audit import AuditMiddleware
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

TEST_CUSTOMER = CustomerRef(value="cust_7f3a")

#: The two SQL scripts an operator runs, executed here rather than re-typed.
#:
#: That is the whole point of reading them from disk. A fixture that created
#: the roles with its own CREATE and its own GRANT list would measure the
#: fixture, and operator checklist item 11 would still be a paragraph asking
#: somebody to build something nothing checks. These are the files
#: `docker-compose.yml` mounts and runs, so what the suite measures and what
#: `docker compose up` applies cannot drift.
SQL_DIR = Path(__file__).resolve().parent.parent / "sql"
ROLES_SQL = SQL_DIR / "01-roles.sql"
GRANTS_SQL = SQL_DIR / "02-grants.sql"

#: The role that owns every table and runs `alembic upgrade head`. Not a
#: superuser, which is exactly what makes
#: `tests/test_audit_append_only.py`'s trigger-disabling bypass an OWNERSHIP
#: property rather than a superuser one when it runs as this role.
OWNER_ROLE = "postern_owner"

#: The role both services connect as: owns nothing, holds what
#: `sql/02-grants.sql` grants and nothing else.
APP_ROLE = "postern_app"

#: Not credentials. Two literals for two roles inside a throwaway container
#: bound to a random loopback port, which `sql/01-roles.sql` deliberately
#: creates with no password at all so that no repository file carries one.
#: `S105` fires on the names, which have to keep saying what the values are.
OWNER_PASSWORD = "owner-probe"  # noqa: S105
APP_PASSWORD = "app-probe"  # noqa: S105


def _as_role(url: str, role: str, password: str) -> str:
    """`url` rewritten to connect as `role`.

    `render_as_string(hide_password=False)`, never `str(url)`: `URL.__str__`
    renders a password as `***`, so the obvious spelling produces a URL that
    authenticates with the literal string "***" and fails.
    """
    return make_url(url).set(username=role, password=password).render_as_string(hide_password=False)


def _run_script(url: str, script: str) -> None:
    """Run a multi-statement SQL script, synchronously.

    THE DRIVER CONNECTION RATHER THAN SQLAlchemy'S OWN EXECUTE, and it is not
    a preference: the asyncpg dialect sends every statement through the
    extended query protocol, which carries one statement per message, so a
    script with several raises `cannot insert multiple commands into a
    prepared statement` before running any of it. asyncpg's `execute` with no
    arguments uses the simple query protocol instead -- the same one `psql -f`
    uses, and therefore the same one the operator running these two files
    gets. Splitting the file on semicolons was the alternative and is wrong:
    both scripts carry `DO $$ ... $$` blocks whose bodies contain semicolons.

    SYNCHRONOUS for the reason `tests/conftest.py`'s `pg_url` is: the async
    Alembic `env.py` ends in `asyncio.run`, so this runs beside it in a
    fixture that owns no event loop.
    """

    async def go() -> None:
        engine = create_async_engine(url, poolclass=NullPool)
        try:
            async with engine.connect() as conn:
                raw = await conn.get_raw_connection()
                driver = raw.driver_connection
                # Typed `Any | None` by SQLAlchemy because a sync dialect has
                # no separate driver connection to hand back. This engine is
                # asyncpg, so it always does; the assert is what says that to
                # mypy rather than a `cast` that would say it to nobody.
                assert driver is not None, "expected an asyncpg driver connection"
                await driver.execute(script)
        finally:
            await engine.dispose()

    asyncio.run(go())


@pytest.fixture(scope="session", autouse=True)
def _no_warning_capture_in_the_pytest_process() -> Iterator[None]:
    """`install_sql_safe_logging` also routes `warnings.warn` through logging.

    Every `create_app` in the suite calls it, inside a test, where pytest has
    already replaced the warning machinery to record warnings for its summary:
    installing ours there would send the rest of that test's warnings to the log
    and drop them from the summary. So the warning half is a no-op in this
    process. It is exercised in a fresh interpreter in
    `tests/test_sql_safe_logging_reach.py`, which calls `_showwarning` directly
    and runs `install_sql_safe_logging` in a subprocess.
    """
    patch = pytest.MonkeyPatch()
    patch.setattr(log_safety, "install_warning_capture", lambda: None)
    yield
    patch.undo()


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

    WHAT IT YIELDS HAS NOT CHANGED and that is deliberate: the container's own
    bootstrap superuser, which every other fixture and every other test in this
    suite already depends on. What changed underneath is WHO BUILT THE SCHEMA.
    The three steps below are the three an operator runs, in the order and by
    the principal they run them as -- a superuser creates the roles
    (`sql/01-roles.sql`), `postern_owner` applies the migrations and therefore
    OWNS every table they create, and `postern_owner` grants to `postern_app`
    (`sql/02-grants.sql`).

    WHY THE DEFAULT FIXTURE STAYS THE SUPERUSER. A superuser bypasses every
    privilege and ownership check, so moving the table owner out from under it
    changes nothing for the ~2780 tests that use `database`, while making
    `owner_db` and `app_db` below mean something they could not mean before:
    `postern_owner` is now genuinely an owner that is not a superuser, and
    `postern_app` is genuinely a role that owns nothing. Pointing `database`
    at the application role instead would have been the stronger claim and the
    wrong trade -- `tests/conftest.py`'s own `_clear_audit_log` reaches for the
    trigger-disabling bypass, which that role must not have.

    `POSTERN_DATABASE_URL` IS MOVED FOR THE UPGRADE AND MOVED BACK, because
    `migrations/env.py` reads that variable and overrides `sqlalchemy.url` with
    it whenever it is set. Setting only the config option would have run the
    migrations as the superuser again, silently, and every claim in
    `tests/test_audit_append_only.py` about ownership would have been measured
    against the wrong role.
    """
    try:
        docker.from_env().ping()
    except DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping database-backed tests: {exc}")
    with PostgresContainer("postgres:17-alpine", driver="asyncpg") as pg:
        url = pg.get_connection_url()
        _run_script(url, ROLES_SQL.read_text())
        _run_script(
            url,
            f"ALTER ROLE {OWNER_ROLE} PASSWORD '{OWNER_PASSWORD}';"
            f"ALTER ROLE {APP_ROLE} PASSWORD '{APP_PASSWORD}';",
        )
        owner = _as_role(url, OWNER_ROLE, OWNER_PASSWORD)
        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", owner)
        os.environ["POSTERN_DATABASE_URL"] = owner
        command.upgrade(cfg, "head")
        os.environ["POSTERN_DATABASE_URL"] = url
        _run_script(owner, GRANTS_SQL.read_text())
        yield url


@pytest.fixture(scope="session")
def owner_url(pg_url: str) -> str:
    """The role that owns every table, and is not a superuser."""
    return _as_role(pg_url, OWNER_ROLE, OWNER_PASSWORD)


@pytest.fixture(scope="session")
def app_url(pg_url: str) -> str:
    """The role both services connect as, holding only `sql/02-grants.sql`."""
    return _as_role(pg_url, APP_ROLE, APP_PASSWORD)


@pytest_asyncio.fixture
async def owner_db(owner_url: str) -> AsyncIterator[Database]:
    db = Database(owner_url, null_pool=True)
    yield db
    await db.close()


@pytest_asyncio.fixture
async def app_db(app_url: str) -> AsyncIterator[Database]:
    db = Database(app_url, null_pool=True)
    yield db
    await db.close()


@pytest.fixture(scope="session")
def redis_url() -> Iterator[str]:
    """One Redis for the whole run, shared by every test that requests it.

    Seven files do, as of 1 October 2026: `tests/test_redis_backed_stores.py`,
    which it was written for, tests/test_device_code_scanner_ip.py,
    tests/test_confirm_customer_rate_limit.py, tests/test_refresh_sessions.py,
    tests/test_customer_revoked_at.py, and the two ZT-7 files,
    tests/test_zt7_revocation_reachable.py and
    tests/test_zt7_confirm_revocation.py, whose ``shared_redis`` fixtures moved
    here from fakeredis when a customer-client revocation became a Lua script.

    SESSION-SCOPED for the same reason `pg_url` is, and the reason is the
    container and not the data: starting one costs wall clock that `make ci`
    pays before every commit, and every store under test accepts a
    ``key_prefix``, so a namespace per test isolates them without a second
    container or a flush. The ``stores`` fixture in
    `tests/test_redis_backed_stores.py` is where that first happened, and its
    docstring is where the alternatives are priced.

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
    stores they were written against. Tests name the URL explicitly instead,
    and the two ZT-7 ``shared_redis`` fixtures, which need it in the
    environment for a CLI that reads it, set it with ``monkeypatch`` for one
    test at a time.
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

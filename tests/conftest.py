import os
from collections.abc import AsyncIterator, Iterator

import docker
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from docker.errors import DockerException
from postern_core.identity import CustomerRef, CustomerResolver
from postern_core.store.engine import Database
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from testcontainers.community.postgres import PostgresContainer

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

"""Async engine and session factory (Task 1).

None of these tests connect: `create_async_engine` is lazy, so a syntactically
valid URL pointing at a host that may not even be listening is enough to
exercise construction, pool selection and disposal without a running
database.
"""

from postern_core.store.engine import Database
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker


def test_database_exposes_an_engine_and_a_sessionmaker() -> None:
    db = Database("postgresql+asyncpg://u:p@localhost:5432/x")
    assert isinstance(db.engine, AsyncEngine)
    assert isinstance(db.sessionmaker, async_sessionmaker)


async def test_database_close_disposes_the_engine() -> None:
    """`engine.dispose()` replaces the pool object rather than mutating it in
    place (confirmed directly against SQLAlchemy 2.0.52: `pool` identity
    changes across `dispose()` even though its type does not), so pool
    identity before and after `close()` is a real behavioural check. A
    `close()` with an empty body -- or one that never calls `dispose()` --
    leaves the original pool in place and this assertion catches that;
    `db.engine.pool.status() is not None` does not, because `status()`
    returns a string unconditionally regardless of whether disposal ran.
    """
    db = Database("postgresql+asyncpg://u:p@localhost:5432/x")
    pool_before_close = db.engine.pool
    await db.close()
    assert db.engine.pool is not pool_before_close


def test_database_accepts_a_null_pool_for_tests() -> None:
    from sqlalchemy.pool import NullPool

    db = Database("postgresql+asyncpg://u:p@localhost:5432/x", null_pool=True)
    assert isinstance(db.engine.pool, NullPool)

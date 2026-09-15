"""Async engine and session factory.

One `Database` per process. The composition root builds it and closes it on
ASGI shutdown; nothing else may construct one, so connections are pooled
rather than opened per request.
"""

from types import TracebackType

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool


class Database:
    def __init__(self, url: str, *, null_pool: bool = False) -> None:
        # `poolclass=None` (the `null_pool=False` branch) was checked against
        # omitting the keyword entirely: both produce the same
        # `AsyncAdaptedQueuePool` for an asyncpg URL, because `None` is
        # `create_async_engine`'s own default for `poolclass`. Passing it
        # explicitly here, rather than branching to two call shapes, keeps
        # this constructor a single call.
        self.engine: AsyncEngine = create_async_engine(
            url,
            pool_pre_ping=True,
            poolclass=NullPool if null_pool else None,
        )
        self.sessionmaker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self.engine, expire_on_commit=False
        )

    async def close(self) -> None:
        await self.engine.dispose()

    async def __aenter__(self) -> "Database":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

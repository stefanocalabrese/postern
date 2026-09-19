"""Async engine and session factory.

One `Database` per process. The composition root builds it and closes it on
ASGI shutdown; nothing else may construct one, so connections are pooled
rather than opened per request.

Every phase of reaching Postgres carries its own deadline, the shape
`docs/decisions/0003-composition-root.md` already gave the backend HTTP
client. Until this constructor took `connect_args`, the only deadline on the
whole path was asyncpg's own `connect(timeout=60)` default: a store that
completed the TCP handshake and then went silent held a request for a full
minute before the call was denied (measured, and pinned in
`tests/test_consent_check_failure_mode.py`), and a query that stalled after
the connection was up had no deadline at all -- no `command_timeout` here, no
`statement_timeout` anywhere in this repository.
"""

from types import TracebackType
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool


class Database:
    def __init__(
        self,
        url: str,
        *,
        null_pool: bool = False,
        connect_timeout_seconds: float = 2.0,
        command_timeout_seconds: float = 3.0,
        pool_timeout_seconds: float = 1.0,
    ) -> None:
        """Three deadlines, one per phase, defaulting to the production values.

        `connect_timeout_seconds` becomes asyncpg's `connect(timeout=)`: the
        TCP connect, the TLS handshake and the startup/authentication
        exchange. 2.0s is slack for jitter against a same-VPC Postgres where
        this is milliseconds, not an expected latency, and it is the same
        number `Settings.backend_connect_timeout_seconds` carries for the
        same reason.

        `command_timeout_seconds` becomes asyncpg's `command_timeout`, the
        default deadline on every statement run on the connection
        (`asyncpg/protocol/protocol.pyx:715-722`: a statement with no
        explicit timeout inherits it). This is the one this path had nothing
        for. 3.0s, not the 5.0s the backend's read phase gets: everything
        this engine runs is one indexed SELECT against a small consents table
        or one audit INSERT, single-digit milliseconds on a healthy store,
        where the backend's 5.0s was sized for a transaction export streaming
        a large body.

        `pool_timeout_seconds` becomes SQLAlchemy's `pool_timeout`, how long
        a checkout waits for a free pooled connection once the pool is at its
        limit. SQLAlchemy's default is 30 seconds, three times this whole
        budget, so it is set rather than inherited; 1.0s matches
        `Settings.backend_pool_timeout_seconds`, because a checkout that
        cannot be served in a second is queueing behind saturation that
        another second will not clear.

        Passing the values in the URL query string instead of `connect_args`
        does not work and was tried: SQLAlchemy hands asyncpg the string and
        the connect dies with `TypeError: unsupported operand type(s) for +:
        'float' and 'str'` in 0.0s, which looks like a working timeout in any
        test that only asserts an exception.

        What the command timeout costs, in the terms
        `docs/decisions/0006-audit-write-failure.md` used: a failed audit
        write fails the tool call, and `services/api/consent.py`'s check
        denies when its lookup raises, so this deadline converts "the store
        was slow" into "the call failed". A database that would have answered
        the consent SELECT in 4 seconds now fails the call at 3. That cost is
        paid deliberately, not overlooked -- the alternative is the unbounded
        wait that was here before, where every request in flight holds its
        worker until the store answers, so a store that never answers parks
        every call that arrives instead of failing one. Someone reading this after
        watching a call fail at 3 seconds against a database that would have
        answered at 4 is looking at the decision: raise
        `POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS` if that store's real p99 is
        genuinely near the budget.

        Worst case these defaults sum to, per database operation: 1.0s
        waiting for the pool, 2.0s connecting, 3.0s on the statement = 6.0s
        when the checkout has to open a connection, since SQLAlchemy skips
        the pre-ping on a connection it just created
        (`sqlalchemy/pool/base.py::_checkout` pings only when its
        `connection_is_fresh` is false). On a recycled connection the
        `pool_pre_ping=True` below is three statements, not one -- BEGIN, the
        ping itself, ROLLBACK (`sqlalchemy/dialects/postgresql/asyncpg.py::_async_ping`)
        -- each inheriting `command_timeout`, which puts that shape at 1.0 +
        3x3.0 + 3.0 = 13.0s. Both sums bound a REACHABLE store, one that
        answers late, resets, or refuses. Each of those three statements does
        inherit the deadline; the connection invalidation that follows the
        first one to expire does not, so on a path silent in both directions
        the pre-ping hangs exactly like the query and neither sum applies
        (below, and `docs/verification/2026-09-17-query-stall-deadline.md`,
        which measured both paths). Measured end to end through a real HTTP
        request, a reachable stall at these defaults returns in 3.09s.
        Multiply by the operations one tool call makes: two when the consent
        lookup succeeds (the lookup, then the audit write), because
        `services/api/consent.py` caches a successful answer on
        `request.state` and the several checks a single call evaluates share
        it. A lookup that RAISES is never cached, so a failing store is
        re-attempted once per evaluation -- that module measures 5 of them for
        one `tools/call` carrying arguments -- and this budget is paid each
        time.

        One case remains unbounded and no value here fixes it: a socket that
        goes silent in both directions mid-statement AND does not answer the
        out-of-band cancel. `command_timeout` fires on time (measured: 1.00s
        at `command_timeout=1.0` against a stalling TCP proxy, at the raw
        driver), but SQLAlchemy then invalidates the connection through
        asyncpg's graceful `close(timeout=2)`, whose first act is
        `await self.cancel_sent_waiter` with no deadline on that await
        (`asyncpg/protocol/protocol.pyx:602-613`), and that waiter resolves
        only when a second connection opened to the same dead address
        finishes (`asyncpg/connect_utils.py::_cancel` reaches that address
        through `loop.create_connection` with no timeout). Measured through
        `AsyncSession.execute`: still running at 20s with
        `command_timeout=1.0`. Measured again end to end
        through a real HTTP request, on the query path and on the pre-ping
        path both, at `command_timeout=1.0`: neither had returned within the
        60-second cap the measurement used
        (`docs/verification/2026-09-17-query-stall-deadline.md`). That is a
        cap, not a bound -- whether either request ever returns was not
        determined. A store that answers, or resets, or refuses is bounded by
        the numbers above; one that is silently dropping every packet
        including a fresh connection's is bounded by the kernel, not by this.
        """
        # `pool_timeout` is a QueuePool argument. `create_async_engine`
        # consumes it only if the pool class in use accepts it, and rejects
        # the whole call otherwise: measured against SQLAlchemy 2.0.52,
        # passing it with `poolclass=NullPool` raises `TypeError: Invalid
        # argument(s) 'pool_timeout' sent to create_engine()`. NullPool opens
        # a connection per checkout and queues nothing, so there is no wait
        # for the value to bound there -- the `null_pool=True` path (tests)
        # is left with connect and command timeouts only.
        pool_kwargs: dict[str, Any] = {} if null_pool else {"pool_timeout": pool_timeout_seconds}
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
            connect_args={
                "timeout": connect_timeout_seconds,
                "command_timeout": command_timeout_seconds,
            },
            **pool_kwargs,
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

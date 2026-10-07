"""Async engine and session factory.

One `Database` per process. The composition root builds it and closes it on
ASGI shutdown; nothing else may construct one, so connections are pooled
rather than opened per request.

Every phase of reaching Postgres carries its own deadline, the shape
`dev-docs/decisions/0003-composition-root.md` already gave the backend HTTP
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
        pool_size: int = 5,
        max_overflow: int = 10,
        audit_reserve_size: int = 0,
    ) -> None:
        """Three deadlines, one ceiling and one reserve, defaulting to the
        production values.

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

        `pool_size` and `max_overflow` are the ceiling on this process:
        ``pool_size + max_overflow`` connections at most, of which the first
        `pool_size` stay open between checkouts while the rest are opened on
        demand and closed again on return. Neither was passed until
        2026-09-26, so both services ran on SQLAlchemy's own 5 + 10, a number
        nobody in this repository had chosen. The defaults here are still 5
        and 10, so a `Database` built directly -- which is every construction
        outside the two composition roots -- behaves as it always has. Each
        service now passes its own, and
        `dev-docs/decisions/0013-connection-pool-ceiling.md` carries the
        derivation.

        `audit_reserve_size` is a SECOND engine, of that many connections and
        no overflow, which exists so that one statement can still find a
        connection when the pool above is at its ceiling.
        `postern_core.store.audit`'s `append_with_reserve` is its only reader
        and reaches it from one branch: `except sqlalchemy.exc.TimeoutError`,
        which is the pool saying N connections are checked out and none came
        back. Zero, the default, builds no second engine at all, so every
        `Database` constructed outside a composition root behaves as it always
        has.

        NOT EVERY AUDIT WRITE ROUTES THROUGH IT, which matters for sizing
        because it bounds the demand. `services/api` sends both of a call's
        rows; `services/confirm` sends its completion rows and keeps
        `ApprovalAudit`'s entry row on the pool, because that row is the last
        statement before a backend WRITE endpoint and the transition after the
        money moves is not an audit write at all. That service's own settings
        module carries the argument.

        WHY A FALLBACK AND NOT A SECOND POOL, since
        `dev-docs/decisions/0013-connection-pool-ceiling.md` rejected the
        second pool and its arithmetic still holds. That record's objection
        was that two pools each keep their own `pool_size` open at the same
        request concurrency, and it is right about two pools serving traffic.
        This one serves none: the audit write uses the pool above FIRST, every
        time, so the reserve is asked for a connection only after a checkout
        has already been refused. `QueuePool` opens on demand, measured
        against postgres:17-alpine on 2026-09-27 -- `checkedin()` is 0 before
        first use and 1 after -- so a reserve that is never reached costs a
        ceiling and not a connection. The record's other objection was that
        two pools make "the store is full" produce two symptoms depending on
        which ran out; under a fallback there is no which, because an
        exhausted reserve is reachable only through an exhausted pool and
        arrives as that exception's `__cause__`.
        `tests/test_audit_reserve.py` measures both halves.

        NOT null_pool. `NullPool` opens a connection per checkout and queues
        for nothing, so it raises no `sqlalchemy.exc.TimeoutError` and there
        is no ceiling for a reserve to be a reserve against; the branch below
        builds none, and `tests/conftest.py`'s whole suite runs there.

        THE CONSTRAINT THIS FILE CANNOT SEE, and the reason these are
        configurable rather than constants:

            replicas x (pool_size + max_overflow + audit_reserve_size)
                <= max_connections - superuser_reserved - everything else

        Both services connect to the same database, so both sides of that sum
        count against one limit. Postgres' compiled-in `max_connections` is
        100 and its `superuser_reserved_connections` is 3; a managed instance
        picks its own, usually from instance memory. Nothing in this
        repository knows the replica count -- there is no Terraform here --
        so the operator owns the arithmetic and the decision record is where
        they substitute their numbers.

        WHAT ONE REQUEST COSTS, which is the other term and is not one
        connection. An approval takes FOUR checkouts in sequence and holds ONE
        at a time: the transaction that reads and claims the challenge, the
        entry audit row, the ``approved`` -> ``executed`` transition, the
        completion audit row. So the pool bounds concurrent REQUESTS, not
        connections per request. The property under that is that an
        `AsyncSession` hands its connection back at COMMIT and not at close,
        which is why `services/confirm/callback.py`'s commit before the
        backend write keeps the audit row's own session from overlapping the
        handler's; ``tests/test_pool_sizing.py`` drives a whole approval
        through ``pool_size=1, max_overflow=0`` so that a refactor which
        nested them fails instead of merely halving the concurrency at which
        this service stops.

        NONE OF THE THREE IS BOUNDED HERE, matching the three deadlines
        above: the floor lives in each service's ``from_env``, where the
        refusal can name the environment variable an operator would have to
        edit. Two of them have a value that reads as "small" and means
        "unlimited", measured against postgres:17-alpine on 2026-09-26: at
        ``pool_size=0`` and at ``max_overflow=-1`` an engine held 25
        connections at once against a ceiling that read as one. The third's
        zero is not an off switch of that kind but a plain absence, which is
        why it is the DEFAULT here and still floored at one in BOTH services'
        ``from_env``: a direct caller wants no second engine, and a deployment
        that turned the reserve off would be choosing to lose the row
        `tests/test_audit_reserve.py` exists to prove it keeps.

        Passing the values in the URL query string instead of `connect_args`
        does not work and was tried: SQLAlchemy hands asyncpg the string and
        the connect dies with `TypeError: unsupported operand type(s) for +:
        'float' and 'str'` in 0.0s, which looks like a working timeout in any
        test that only asserts an exception.

        What the command timeout costs, in the terms
        `dev-docs/decisions/0006-audit-write-failure.md` used: a failed audit
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
        # `hide_parameters=True` on BOTH engines: a failed statement's exception
        # text then ends `[SQL parameters hidden due to hide_parameters=True]`
        # instead of `[parameters: (...)]`, which carried customer refs, assertion
        # `jti` values and signatures into whatever logged the exception. The
        # driver's own message is a second carrier, which
        # `postern_core.log_safety` withholds from uncaught-error logs.
        #
        # All three of these are QueuePool arguments. `create_async_engine`
        # consumes one only if the pool class in use accepts it, and rejects
        # the whole call otherwise: measured against SQLAlchemy 2.0.52,
        # passing any of them with `poolclass=NullPool` raises `TypeError:
        # Invalid argument(s) '...' sent to create_engine()`. NullPool opens a
        # connection per checkout, queues nothing and keeps nothing, so there
        # is neither a wait to bound nor a ceiling to set there -- the
        # `null_pool=True` path (tests) is left with connect and command
        # timeouts only, and is therefore bounded by Postgres'
        # `max_connections` rather than by anything here.
        pool_kwargs: dict[str, Any] = (
            {}
            if null_pool
            else {
                "pool_timeout": pool_timeout_seconds,
                "pool_size": pool_size,
                "max_overflow": max_overflow,
            }
        )
        # `poolclass=None` (the `null_pool=False` branch) was checked against
        # omitting the keyword entirely: both produce the same
        # `AsyncAdaptedQueuePool` for an asyncpg URL, because `None` is
        # `create_async_engine`'s own default for `poolclass`. Passing it
        # explicitly here, rather than branching to two call shapes, keeps
        # this constructor a single call.
        self.engine: AsyncEngine = create_async_engine(
            url,
            hide_parameters=True,
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
        # THE RESERVE. Same URL, same three deadlines, same `pool_pre_ping`:
        # it is the identical path to the identical database, and the only
        # thing it does not share is the queue whose exhaustion is the reason
        # to reach it.
        #
        # `max_overflow=0`, fixed here and not configurable, which is the one
        # value in this constructor an operator cannot move. Overflow exists
        # to absorb a burst by opening connections above the ceiling, and the
        # condition this engine is reached in -- the application pool refusing
        # every checkout -- is precisely when every request in flight becomes
        # such a burst. An overflow here would let the fallback open
        # connections without a bound during a saturation event, against the
        # same `max_connections` the pool it is standing in for has already
        # run out of room under. `audit_reserve_size` is therefore the whole
        # ceiling, and a deployment that wants more headroom raises that.
        #
        # Built eagerly and connected lazily, the same property
        # `services/api/main.py` relies on for the pool above: nothing here
        # opens a socket, so a reserve on a process that never saturates costs
        # one Python object.
        self.audit_reserve: AsyncEngine | None = (
            None
            if null_pool or audit_reserve_size <= 0
            else create_async_engine(
                url,
                hide_parameters=True,
                pool_pre_ping=True,
                pool_timeout=pool_timeout_seconds,
                pool_size=audit_reserve_size,
                max_overflow=0,
                connect_args={
                    "timeout": connect_timeout_seconds,
                    "command_timeout": command_timeout_seconds,
                },
            )
        )
        self.audit_reserve_sessionmaker: async_sessionmaker[AsyncSession] | None = (
            None
            if self.audit_reserve is None
            else async_sessionmaker(self.audit_reserve, expire_on_commit=False)
        )

    async def close(self) -> None:
        """Both engines, and the reserve second.

        Order is not load-bearing and is stated so nobody has to wonder:
        neither dispose touches the other's connections. What matters is that
        the reserve is disposed AT ALL -- it is a second set of sockets on the
        same database, and a composition root that closed only `engine` would
        leak `audit_reserve_size` connections per replica on every restart
        against the one `max_connections` this whole file is budgeting.
        """
        await self.engine.dispose()
        if self.audit_reserve is not None:
            await self.audit_reserve.dispose()

    async def __aenter__(self) -> "Database":
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.close()

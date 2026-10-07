"""A startup measurement of the clock skew between confirm and Postgres.

WHY. A tier-2 approval carries an ``auth_time``. `services/confirm/tier_proof.py`
checks it against the challenge row's ``created_at``, which Postgres stamps with
``statement_timestamp()``, allowing `ASSERTION_CLOCK_SKEW_SECONDS` (30 s) below
it, and against confirm's own ``time.time()``, allowing the same 30 s above it.
The skew moves that window in one direction or the other:

* Database AHEAD of confirm (positive skew): legitimate approvals start to be
  refused once the skew nears 30 s. A liveness failure.
* Database BEHIND confirm (negative skew): the lower bound ``created_at - 30``
  loosens, so an ``auth_time`` up to 30 s plus the skew older than the challenge
  is accepted. The freshness window is wider than configured.

Nothing measured the skew before this module; the Redis preflight covers confirm
against Redis only.

WHAT IT DOES. One bounded ``SELECT statement_timestamp()`` (the very clock that
stamps ``created_at``) through the app's own `Database`. The skew is the
database's reading minus confirm's clock at the MIDPOINT of the query's round
trip, read after the connection is established so connect, TLS and
authentication time do not bias it. Beyond `DATABASE_CLOCK_SKEW_WARN_SECONDS` it
logs one WARNING.

WHAT IT DOES NOT DO.

* It never blocks startup and never raises. An unreachable database, a failed,
  timed-out or stalled query, or an answer that is not a timezone-aware datetime
  logs one WARNING that the skew could not be measured and carries on. The
  exception TYPE is logged and its text is not, because a database error can
  carry the connection URL.
* THE WHOLE CHECK, CONNECT INCLUDED, IS BOUNDED BY
  `DATABASE_CLOCK_TOTAL_BOUND_SECONDS` AND THAT BOUND DOES NOT WAIT FOR CLEANUP.
  ``asyncio.wait_for`` cancels and then awaits the cancelled coroutine, and
  SQLAlchemy's cleanup of a stalled asyncpg connection opens a second connection
  with no deadline (the docstring of `postern_core.store.engine.Database` carries
  the measurement), so ``wait_for`` here stalled startup past 60 s. The check
  runs as a task that is cancelled and abandoned, held in `_ABANDONED` until it
  finishes.
* It is boot-time only: drift after startup is not detected.
* The uncertainty is half the query's round trip.
* It runs in the app's lifespan, not in `create_confirm_app`, so building an app
  (which most tests do against a URL nobody listens on) opens no connection.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime

from postern_core.store.engine import Database
from sqlalchemy import text

from services.confirm.auth import ASSERTION_CLOCK_SKEW_SECONDS

logger = logging.getLogger(__name__)

#: Beyond this many seconds either way the check warns. Far inside the 30 s
#: window it protects, so an operator hears about drift while it is still harmless.
DATABASE_CLOCK_SKEW_WARN_SECONDS = 5.0

#: The query itself, once a connection exists.
DATABASE_CLOCK_QUERY_TIMEOUT_SECONDS = 1.0

#: The whole check, connect and cleanup included: what startup can ever wait.
DATABASE_CLOCK_TOTAL_BOUND_SECONDS = 1.5

#: Checks cancelled and left to finish their own cleanup. Strong references, so
#: a task nobody awaits is not garbage-collected mid-flight.
_ABANDONED: set[asyncio.Future[None]] = set()


def _wall_clock() -> float:
    """Confirm's wall clock in epoch seconds. The one time source here, so tests
    patch this and never the database."""
    return time.time()


def _wall_clock_now() -> float:
    """Looked up at call time, so a patched `_wall_clock` is honoured."""
    return _wall_clock()


def _unmeasured(reason: str) -> None:
    logger.warning(
        "The clock skew between confirm and Postgres could not be measured (%s). Tier-2 "
        "approvals compare auth_time with the challenge's created_at within %d s, so a "
        "skew near that size either refuses legitimate approvals (database ahead) or "
        "widens the freshness window (database behind). Check NTP on both hosts by hand.",
        reason,
        ASSERTION_CLOCK_SKEW_SECONDS,
    )


async def check_database_clock(
    fetch_database_time: Callable[[], Awaitable[datetime]],
    *,
    clock: Callable[[], float] = _wall_clock,
    tolerance_seconds: float = DATABASE_CLOCK_SKEW_WARN_SECONDS,
    timeout_seconds: float = DATABASE_CLOCK_QUERY_TIMEOUT_SECONDS,
) -> float | None:
    """Measure database minus confirm, in seconds, warn past ``tolerance_seconds``.

    ``clock`` is read immediately before and after ``fetch_database_time``, so
    the caller establishes any connection first. Returns the skew, or ``None``
    when it could not be measured. Never raises for a failure of the query or of
    its answer. A timeout here awaits the fetch's own cancellation cleanup; the
    caller that must not wait for that is `run_database_clock_check`.
    """
    before = clock()
    try:
        answer = await asyncio.wait_for(fetch_database_time(), timeout=timeout_seconds)
    except TimeoutError:
        _unmeasured(f"the query did not answer within {timeout_seconds:g} s")
        return None
    except Exception as exc:
        _unmeasured(f"the query failed with {type(exc).__name__}")
        return None
    after = clock()
    try:
        if not isinstance(answer, datetime) or answer.utcoffset() is None:
            _unmeasured(
                f"the database answered with {type(answer).__name__}, not an aware datetime"
            )
            return None
        skew = answer.timestamp() - (before + after) / 2.0
    except Exception as exc:
        _unmeasured(f"the answer could not be converted, {type(exc).__name__}")
        return None
    if abs(skew) > tolerance_seconds:
        if skew > 0:
            direction = "ahead of"
            consequence = (
                "with the database ahead, legitimate tier-2 approvals may be refused as the "
                "skew nears the window"
            )
        else:
            direction = "behind"
            consequence = (
                "with the database behind, the auth_time freshness window is widened by that much"
            )
        logger.warning(
            "Postgres's clock is %+.1f s from confirm's (database %s confirm), beyond the "
            "%.1f s tolerance. Tier-2 approvals check auth_time against the challenge's "
            "created_at within a %d s window; %s. Fix NTP or chrony on the confirm and "
            "database hosts. Startup continues.",
            skew,
            direction,
            tolerance_seconds,
            ASSERTION_CLOCK_SKEW_SECONDS,
            consequence,
        )
    else:
        logger.debug("confirm and Postgres clocks differ by %+.3f s", skew)
    return skew


async def _connect_and_check(database: Database) -> None:
    """Connect first, then time only the query. Never raises an ``Exception``."""
    try:
        async with database.engine.connect() as connection:

            async def fetch() -> datetime:
                result = await connection.execute(text("SELECT statement_timestamp()"))
                answer: datetime = result.scalar_one()
                return answer

            await check_database_clock(fetch, clock=_wall_clock_now)
    except Exception as exc:
        _unmeasured(f"the check failed with {type(exc).__name__}")


def _reap(task: asyncio.Future[None]) -> None:
    _ABANDONED.discard(task)
    if not task.cancelled():
        task.exception()  # retrieved, so asyncio does not log it at garbage collection


async def run_database_clock_check(database: Database) -> None:
    """Run the check through ``database.engine``, bounded by
    `DATABASE_CLOCK_TOTAL_BOUND_SECONDS` whatever the database does. Called from
    confirm's lifespan."""
    task: asyncio.Future[None] = asyncio.ensure_future(_connect_and_check(database))
    try:
        done, _ = await asyncio.wait({task}, timeout=DATABASE_CLOCK_TOTAL_BOUND_SECONDS)
    except BaseException:
        task.cancel()
        _ABANDONED.add(task)
        task.add_done_callback(_reap)
        raise
    if task in done:
        _reap(task)
        return
    task.cancel()
    _ABANDONED.add(task)
    task.add_done_callback(_reap)
    _unmeasured(f"the check did not finish within {DATABASE_CLOCK_TOTAL_BOUND_SECONDS:g} s")

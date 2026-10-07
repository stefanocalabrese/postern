"""A startup measurement of the clock skew between confirm and Postgres.

WHY. A tier-2 approval carries an ``auth_time``. `services/confirm/tier_proof.py`
checks it against the challenge row's ``created_at``, which Postgres stamps with
``statement_timestamp()``, allowing `ASSERTION_CLOCK_SKEW_SECONDS` (30 s) below
it, and against confirm's own ``time.time()``, allowing the same 30 s above it.
If confirm's clock lags the database's by more than about 30 s, legitimate
approvals are refused: a liveness failure, not a security one. Nothing measured
that skew before this module; the Redis preflight covers confirm against Redis
only.

WHAT IT DOES. One bounded ``SELECT statement_timestamp()`` (the very clock that
stamps ``created_at``) through the app's own `Database`. The skew is the
database's reading minus confirm's clock at the MIDPOINT of the round trip, so a
slow query does not read as a skew. Beyond `DATABASE_CLOCK_SKEW_WARN_SECONDS` it
logs one WARNING.

WHAT IT DOES NOT DO.

* It never blocks startup and never raises. An unreachable database, a failed or
  timed-out query or an answer that is not a timezone-aware datetime logs one
  WARNING that the skew could not be measured and carries on. The exception TYPE
  is logged and its text is not, because a database error can carry the
  connection URL.
* It is boot-time only: drift after startup is not detected.
* The uncertainty is half the round trip, so a slow query measures less sharply.
  The bound on the query is `DATABASE_CLOCK_QUERY_TIMEOUT_SECONDS`.
* It runs in the app's lifespan, not in `create_confirm_app`, so building an app
  (which most tests do against a URL nobody listens on) opens no connection.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime

from sqlalchemy import text

from services.confirm.auth import ASSERTION_CLOCK_SKEW_SECONDS

logger = logging.getLogger(__name__)

#: Beyond this many seconds either way the check warns. Far inside the 30 s
#: window it protects, so an operator hears about drift while it is still harmless.
DATABASE_CLOCK_SKEW_WARN_SECONDS = 5.0

#: The whole query, connect included. Shorter than the engine's own 2 s connect
#: timeout on purpose: startup must not wait on a database that is not answering.
DATABASE_CLOCK_QUERY_TIMEOUT_SECONDS = 1.0


def _wall_clock() -> float:
    """Confirm's wall clock in epoch seconds. The one time source here, so tests
    patch this and never the database."""
    return time.time()


def _unmeasured(reason: str) -> None:
    logger.warning(
        "The clock skew between confirm and Postgres could not be measured (%s). Tier-2 "
        "approvals compare auth_time with the challenge's created_at within %d s, so a "
        "confirm clock more than about that far behind the database refuses legitimate "
        "approvals. Check NTP on both hosts by hand.",
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

    Returns the skew, or ``None`` when it could not be measured. Never raises
    for a failure of the query or of its answer.
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
    if not isinstance(answer, datetime) or answer.tzinfo is None:
        _unmeasured(f"the database answered with {type(answer).__name__}, not an aware datetime")
        return None
    skew = answer.timestamp() - (before + after) / 2.0
    if abs(skew) > tolerance_seconds:
        direction = "ahead of" if skew > 0 else "behind"
        logger.warning(
            "Postgres's clock is %+.1f s from confirm's (database %s confirm), beyond the "
            "%.1f s tolerance. Tier-2 approvals check auth_time against the challenge's "
            "created_at within a %d s window; a confirm clock more than about that far "
            "behind the database refuses legitimate approvals. Fix NTP or chrony on the "
            "confirm and database hosts. Startup continues.",
            skew,
            direction,
            tolerance_seconds,
            ASSERTION_CLOCK_SKEW_SECONDS,
        )
    else:
        logger.debug("confirm and Postgres clocks differ by %+.3f s", skew)
    return skew


async def run_database_clock_check(database: object) -> None:
    """Run the check through ``database.engine``. Called from confirm's lifespan."""

    async def fetch() -> datetime:
        async with database.engine.connect() as connection:  # type: ignore[attr-defined]
            result = await connection.execute(text("SELECT statement_timestamp()"))
            return result.scalar_one()  # type: ignore[no-any-return]

    try:
        await check_database_clock(fetch, clock=_wall_clock_now)
    except Exception as exc:  # belt and braces: startup must never fail on this
        _unmeasured(f"the check failed with {type(exc).__name__}")


def _wall_clock_now() -> float:
    """Looked up at call time, so a patched `_wall_clock` is honoured."""
    return _wall_clock()

"""Startup checks on the Redis both services share, refused rather than documented.

Two assumptions were operator-owned until now, written down in CLAUDE.md
(operator checklist item 6) and `docs/user-guide/components/session-store.md`:

* Confirm's wall clock and Redis ``TIME`` agree to within 2 s. Two tolerances
  compare them: `postern_core.auth.revocation.PAIR_IAT_TOLERANCE_MS` (the api's
  per-pair ``iat`` floor) and ``APPROVAL_CLOCK_TOLERANCE_MS`` in
  ``services/confirm/device_auth.py``. Beyond that skew a restore can revive
  tokens and an approval check can miss a revocation.
* ``maxmemory-policy`` is ``noeviction``. The ZT-7 revocation sets carry no TTL,
  so any evicting policy can silently drop a revocation entry.

Both are now checked once per service process, at startup, only when
``POSTERN_REDIS_URL`` is set. There is no environment variable that turns them
off, which is how Vault being unreachable at startup already behaves.

WHAT THIS DOES NOT DO, stated here because a check that sounds broader than it
is will be trusted past its reach:

* It is BOOT-TIME ONLY. A clock that drifts after the process is up, or a
  ``CONFIG SET maxmemory-policy`` issued later, is not detected. An NTP monitor
  on every host, Redis's included, is still owed by the operator.
* The eviction policy is unverifiable where the server refuses ``CONFIG``
  (managed Redis commonly does). That path logs one warning and continues. What
  managed services actually answer has not been verified here.
* Only ONE Redis client is checked, built from the same ``POSTERN_REDIS_URL``
  that the session, revocation, device-code, refresh-family and rate-limit
  stores all read, so one check on one connection speaks for the revocation
  Redis and for the others. Each service runs it for itself.

This module takes a client and does not edit any store. It imports nothing from
``services``.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from postern_core.auth.revocation import PAIR_IAT_TOLERANCE_MS
from postern_core.config import redis_url_from_env

logger = logging.getLogger(__name__)

#: Socket timeouts for the preflight connection, in seconds. A Redis that
#: accepts the connection and never answers must not hang startup for good.
_PREFLIGHT_SOCKET_TIMEOUT_SECONDS = 5.0

#: The only ``maxmemory-policy`` under which a TTL-less set is never dropped.
REQUIRED_EVICTION_POLICY = "noeviction"


class RedisPreflightError(RuntimeError):
    """Redis is reachable and measurably violates an operator contract.

    A ``RuntimeError``, like `postern_core.config.enforce_redis_requirement`:
    the values parsed and the deployment-wide contract was not met. Connection
    errors are NOT wrapped in this; they propagate as redis-py raised them.
    """


def _wall_ms() -> float:
    """This process's wall clock in milliseconds. The one time source here, so
    tests patch this and never Redis."""
    return time.time() * 1000.0


def check_clock_skew(client: Any, *, tolerance_ms: int = PAIR_IAT_TOLERANCE_MS) -> None:
    """Refuse when this host's clock and Redis ``TIME`` differ beyond ``tolerance_ms``.

    The default is `PAIR_IAT_TOLERANCE_MS` from `postern_core.auth.revocation`.
    `APPROVAL_CLOCK_TOLERANCE_MS` in ``services/confirm/device_auth.py`` is the
    same number, 2 000, kept apart because `postern_core` sits below
    ``services``; a test pins that the two are equal.

    THE RULE. Read local wall time ``t0``, call ``TIME``, read local wall time
    ``t1``. The round trip is ``rtt = t1 - t0`` and the estimate is
    ``skew = redis_ms - (t0 + t1) / 2``. Redis read its clock somewhere inside
    ``[t0, t1]``, so the true skew lies within ``skew +/- rtt / 2``. REFUSE ONLY
    WHEN THE WHOLE INTERVAL LIES BEYOND THE TOLERANCE:
    ``abs(skew) - rtt / 2 > tolerance_ms``.

    * It cannot refuse a healthy deployment on a slow round trip: a perfectly
      synchronised pair has ``abs(skew) <= rtt / 2``, so the left side is never
      positive, however slow the round trip is.
    * DETECTION IS WEAKER THAN THAT, and the exact statement is this. In the
      worst case Redis read its clock at ``t0``, so the true skew is
      ``skew + rtt / 2`` while the estimate says ``skew``. The rule therefore
      detects only a true skew GREATER THAN ``tolerance_ms + rtt``. A real 3 s
      skew can pass once ``rtt`` exceeds 1000 ms (``tolerance + rtt = 3000``),
      and nothing is detected once ``rtt`` exceeds the tolerance itself. When
      ``rtt`` exceeds ``tolerance_ms / 2`` one warning says the measurement is
      inconclusive at this round trip. The refusal rule is unchanged by it.

    Raises:
        RedisPreflightError: on a measured violation.
        redis.exceptions.RedisError: unchanged, if ``TIME`` itself fails.
    """
    before = _wall_ms()
    seconds, micros = client.time()
    after = _wall_ms()
    redis_ms = int(seconds) * 1000 + int(micros) / 1000.0
    rtt = after - before
    skew = redis_ms - (before + after) / 2.0
    if rtt > tolerance_ms / 2.0:
        logger.warning(
            "Redis clock-skew measurement is inconclusive: the TIME round trip took %.0f ms, "
            "more than half the %d ms tolerance, so a true skew up to %.0f ms can pass. Check "
            "NTP on both hosts by hand.",
            rtt,
            tolerance_ms,
            tolerance_ms + rtt,
        )
    if abs(skew) - rtt / 2.0 > tolerance_ms:
        direction = "ahead of" if skew > 0 else "behind"
        raise RedisPreflightError(
            f"Redis clock-skew check failed: Redis TIME is {abs(skew):.0f} ms {direction} this "
            f"host (round trip {rtt:.0f} ms, so at least {abs(skew) - rtt / 2.0:.0f} ms after "
            f"allowing for it), beyond the {tolerance_ms} ms the revocation and approval "
            "checks tolerate. Past that, a Redis restore can revive revoked tokens and an "
            "approval check can miss a revocation. Fix NTP or chrony on this host and on the "
            "Redis host, then restart. There is no setting that skips this check."
        )


def check_eviction_policy(client: Any) -> None:
    """Refuse unless Redis reports ``maxmemory-policy`` as exactly ``noeviction``.

    The ZT-7 revocation sets carry no TTL, so under any evicting policy Redis
    may drop a revocation entry when memory is short, and a revoked customer
    is then served again.

    When the server refuses ``CONFIG`` (a ``ResponseError``: command unknown,
    renamed, or denied by ACL, which managed Redis commonly does) the policy
    cannot be verified: one warning is logged naming what to check by hand, and
    startup continues. Connection errors are not caught.

    Raises:
        RedisPreflightError: on a policy other than ``noeviction``.
    """
    from redis.exceptions import ResponseError

    try:
        reply = client.config_get("maxmemory-policy")
    except ResponseError as exc:
        logger.warning(
            "Redis maxmemory-policy cannot be verified (CONFIG was refused: %s). The ZT-7 "
            "revocation sets carry no TTL, so check by hand that the instance runs "
            "maxmemory-policy noeviction; an evicting policy can silently drop revocations.",
            exc,
        )
        return
    policy = reply.get("maxmemory-policy") if isinstance(reply, dict) else None
    if policy is None:
        logger.warning(
            "Redis maxmemory-policy cannot be verified (CONFIG GET returned no value). Check by "
            "hand that the instance runs maxmemory-policy noeviction; an evicting policy can "
            "silently drop ZT-7 revocations."
        )
        return
    if isinstance(policy, bytes):
        policy = policy.decode()
    if policy != REQUIRED_EVICTION_POLICY:
        raise RedisPreflightError(
            f"Redis eviction-policy check failed: maxmemory-policy is {policy!r}, required "
            f"{REQUIRED_EVICTION_POLICY!r}. The ZT-7 revocation sets carry no TTL, so an "
            "evicting policy can silently drop a revocation and serve a revoked customer "
            "again. Set maxmemory-policy noeviction on the instance, then restart. There is "
            "no setting that skips this check."
        )


def _client_from_url(url: str) -> Any:
    """A synchronous client, because startup is synchronous and runs once."""
    import redis

    return redis.Redis.from_url(
        url,
        decode_responses=True,
        socket_connect_timeout=_PREFLIGHT_SOCKET_TIMEOUT_SECONDS,
        socket_timeout=_PREFLIGHT_SOCKET_TIMEOUT_SECONDS,
    )


def run_redis_preflight() -> None:
    """Run both checks against ``POSTERN_REDIS_URL``, or do nothing if it is unset.

    Both services call this once during composition, before they accept
    traffic. With no URL (in-memory dev and test mode) no client is built and no
    Redis call is made.
    """
    url = redis_url_from_env()
    if not url:
        return
    client = _client_from_url(url)
    try:
        check_clock_skew(client)
        check_eviction_policy(client)
    finally:
        client.close()

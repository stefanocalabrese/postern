"""A bound on how fast ONE CUSTOMER can approve, on the three paths that have one.

THE DEFECT THIS CLOSES, AND WHY IT IS NOT A RE-KEY OF THE OTHER LIMITER.
`services/confirm/rate_limit.py` limits ``POST /approve``,
``POST /challenges/{challenge_id}/approve`` and ``POST /scan`` per CLIENT
ADDRESS BUCKET. That is the wrong unit for these three, and the sentence that
says why is short: sixty payment approvals a minute from one customer is a
signal, and sixty from a bank's egress address is a Tuesday. Its own
settings comment already recorded the gap -- "a per-address bound is the
wrong UNIT for an authenticated path, where the meaningful one is per
customer" -- and the environment overrides
that landed with it made the wrong unit SURVIVABLE without making it right: an
operator whose banking app calls from its own backend raises the address
ceiling and thereby raises it for every customer at once.

WHY TWO LIMITERS AND NOT ONE. The customer identity comes from the verified
``sub`` on the banking-app assertion, and only `AppAssertionMiddleware`
produces it, so a limiter that reads it must run AFTER the assertion check.
The other limiter must run BEFORE it -- outermost, in front of `BodySizeLimit`
-- so that a refused request never drains a body, never triggers a JWKS fetch
and never costs a signature verification, which
``tests/test_confirm_rate_limit.py::test_a_refusal_carries_retry_after_and_never_drains_the_body``
pins by passing a ``receive`` that raises if called. Those two positions are
mutually exclusive. So these are LAYERED, not alternative:

    RateLimit          (address bucket)  outermost, before the body is read
    BodySizeLimit
    AppAssertionMiddleware               the subject appears here
    CustomerRateLimit  (verified sub)    this module, innermost

THE COST OF THE INNER POSITION, STATED PLAINLY. A refusal from this module has
already cost a JWKS fetch and a signature verification, because it happens
after authentication. That is exactly the resource the outer limiter exists to
protect, which is why the outer address-keyed limiter STAYS IN FRONT and keeps
its generous ceilings as the backstop. This module is not a replacement for it
and cannot be: it has nothing to say about an unauthenticated flood, because a
caller with no valid assertion never reaches it.

WHAT IT DOES NOT BOUND. Nothing before `AppAssertionMiddleware`, and no
request whose assertion does not verify. An attacker holding N valid
assertions for N customers gets N full allowances, and that is correct rather
than a gap: the unit is the customer, and N compromised customers is N
customers' worth of exposure however it is counted. The control against one
compromised banking-app backend minting assertions for every customer at once
is not a rate limit and is not in this repository -- it is the operator's
control over that backend's signing key.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any

from postern_core.config import redis_url_from_env
from starlette.types import ASGIApp, Receive, Scope, Send

from services.confirm.auth import ASSERTION_STATE_KEY, AppAssertion
from services.confirm.rate_limit import (
    RATE_LIMIT_WINDOW_SECONDS,
    Buckets,
    Limit,
    charge_one,
    route_key,
)

logger = logging.getLogger(__name__)


#: Per-path limits, per CUSTOMER, per window.
#:
#: THE WORKING, in the shape `services/confirm/rate_limit.py`'s
#: ``DEFAULT_LIMITS`` set: a limit tuned by guess is either useless or pages
#: someone at 3am, so each number below names what a legitimate human could
#: plausibly do in a minute and then says what multiple of that it admits.
#:
#: All three paths are ONE ACTION ON A PHONE per unit of work. That is the
#: fact that sets the scale, and it is why no number is in the hundreds.
#:
#: ``/approve`` -- 10/min. This is a device pairing: the customer opens the
#:     bank app, scans a QR, reads a six-character pairing code off the
#:     browser and taps approve. Timed as a sequence of human actions that is
#:     roughly fifteen seconds of work, so about four a minute is a person
#:     going as fast as the flow allows, and a person does this when they
#:     connect a NEW AI client -- a handful of times ever, not a handful of
#:     times an hour. 10/min is ~2.5x the frantic-human ceiling.
#:
#: ``/challenges/{id}/approve`` -- 10/min. This is a payment or card write:
#:     the push arrives, the app renders the payee and the amount FROM THE
#:     STORED CHALLENGE ROW, the customer reads them, satisfies the device
#:     unlock biometric and taps. The reading is the part that cannot be
#:     compressed and is the whole point of the confirmation -- a customer who
#:     is not reading the payee is not confirming anything -- so five to eight
#:     seconds is the floor for an attentive person, i.e. about seven a
#:     minute. 10/min is ~1.4x that.
#:
#: WHY THE SAME NUMBER FOR ALL THREE, since the derivations above are not the
#: same derivation. The first two land within a factor of two of each other,
#: and settings differing by five would claim a precision neither has; ``/scan``
#: reuses the first. What makes the sameness safe is that they are separately
#: configurable: an operator who measures a real distribution and finds one of
#: them tight raises that one.
#:
#: WHAT THIS DELIBERATELY DOES NOT TRY TO BE. 10/min is 600/hour, and 600
#: payments is a great deal of money. This limiter is not the control that
#: makes a compromised approval path safe -- the device signature
#: (`services/confirm/device_signature.py`) and the server-side-built
#: confirmation payload are, and CLAUDE.md states the second as a hard rule.
#: What this bounds is VOLUME, so that "one customer approved sixty payments
#: in a minute" becomes a refusal and a log line instead of sixty payments.
DEFAULT_CUSTOMER_LIMITS: dict[str, Limit] = {
    "/approve": Limit(requests=10, window_seconds=RATE_LIMIT_WINDOW_SECONDS),
    "/challenges/approve": Limit(requests=10, window_seconds=RATE_LIMIT_WINDOW_SECONDS),
    # The scan that precedes every pairing approval: one per pairing, the
    # same human sequence as ``/approve``'s derivation above, so the same 10.
    "/scan": Limit(requests=10, window_seconds=RATE_LIMIT_WINDOW_SECONDS),
}

#: What an authenticated path with no entry of its own gets.
#:
#: DEFAULT-DENY, AND IT MEANS SOMETHING NARROWER HERE THAN IT DOES NEXT DOOR.
#: The outer limiter limits every path, because every path is reachable
#: without a credential. This one can only limit a request that CARRIES A
#: VERIFIED ASSERTION, because that is where the customer comes from; the
#: eight entries in `services/confirm/auth.py`'s ``PUBLIC_PATHS`` have no
#: customer at the moment they are served and are the outer limiter's alone.
#: So the rule this expresses is: every request that reached here WITH a
#: verified subject is charged to that subject. A protected route added to
#: this service tomorrow is customer-limited by omission, which is the same
#: direction `PUBLIC_PATHS`, ``BodySizeLimit`` and ``DEFAULT_LIMITS`` each
#: chose for their own surface.
FALLBACK_CUSTOMER_LIMIT = Limit(requests=10, window_seconds=RATE_LIMIT_WINDOW_SECONDS)

#: The error code a per-customer refusal answers with.
#:
#: DISTINCT FROM THE OUTER LIMITER'S ``too_many_requests`` ON PURPOSE, and
#: this is the whole of decision 4. Both refusals are 429 with a
#: ``Retry-After``, because both are honestly "too many requests" and a client
#: should back off for either; if they also carried the same body, an operator
#: holding a 429 could not tell which ceiling they hit, and the two have
#: opposite remedies -- the address one is raised with
#: ``POSTERN_CONFIRM_RATE_LIMIT_APPROVE`` and means "this deployment funnels
#: customers through few addresses", the customer one is raised with
#: ``POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_APPROVE`` and means "one customer is
#: approving faster than a person can". Raising the wrong one is either a
#: no-op or a hole.
CUSTOMER_RATE_LIMITED = "customer_rate_limited"

#: The error code answered when the shared counter cannot be reached.
#: `CustomerRateLimitStoreUnavailable` below carries why this is a 503 and why
#: the request is refused rather than admitted.
STORE_UNAVAILABLE = "rate_limit_store_unavailable"

#: How many customers the in-memory backend will hold before evicting.
#:
#: IT NEEDS A CAP FOR A REASON THE OUTER LIMITER'S DOES NOT SHARE. There, the
#: map is keyed on an address and an attacker rotating addresses is the
#: expected traffic. Here the key is a verified ``sub``, so the population is
#: the operator's customer base -- except that the party minting those
#: subjects is the operator's own app backend, and
#: `postern_core.identity` already warns that a COMPROMISED issuer can put
#: anything in that claim. A compromised issuer can therefore mint unbounded
#: distinct subjects, so this map is an accumulator too, and it gets the same
#: fixed-capacity LRU for the same reason: eviction only RESETS a counter, so
#: it can never deny anyone, and an attacker who can evict entries by minting
#: subjects already controls the assertion key, against which no rate limit is
#: the relevant control.
DEFAULT_MAX_CUSTOMERS = 20_000


def customer_handle(subject: str) -> str:
    """A stable, non-reversing handle for a verified subject, for logs only.

    WHY A HANDLE AND NOT THE SUBJECT. `services/confirm/revocation.py`'s
    ``log_refusal`` states this service's rule and its reason: the customer
    reference is never logged, because `postern_core.identity` warns that a
    ``sub`` minted by a compromised issuer can be PAN-, IBAN- or DNI-shaped,
    and a log line carries whatever the issuer put there. That rule is kept
    here to the letter -- no branch below logs ``subject``.

    WHY NOT SIMPLY LOG NOTHING, which is what ``log_refusal`` does. It can
    afford to: it says "the ``audit_log`` row is where the approval refusals
    are actually counted", and a revocation refusal writes one. This module
    writes none (see `CustomerRateLimit._refuse`), and a per-customer ceiling
    an operator cannot attribute to a customer is not a signal at all -- it
    reports that SOMEBODY is approving too fast and leaves nobody to call. The
    handle restores exactly that much: two refusals carrying the same handle
    are the same customer, and counting handles ranks them.

    WHAT THIS IS NOT. It is NOT a privacy control and must not be described as
    one. A customer reference is a low-entropy identifier drawn from a set the
    operator enumerates, so an operator holding this log and their own
    customer list recovers the mapping by hashing the list -- which is the
    intended operation, and the reason a salt would be actively wrong here.
    The single property claimed is that the LOG LINE ITSELF carries no PAN,
    IBAN or DNI however the issuer behaved, which is the defect the rule
    exists for.

    Sixteen hex characters, 64 bits: short enough to read in a log line,
    wide enough that two customers colliding is not a thing an operator will
    see.
    """
    return hashlib.sha256(subject.encode("utf-8")).hexdigest()[:16]


def _counter_key(subject: str) -> str:
    """The full digest, for use as a storage key rather than a log token.

    Untruncated, because a collision here is not a cosmetic problem the way it
    would be in a log: two customers sharing a counter would share a budget,
    so one could exhaust the other's. Hashed rather than raw for the reason
    the handle is hashed -- a Redis key reaches ``MONITOR``, the slow log and
    every RDB snapshot, none of which is a place for a value that might be
    PAN-shaped.
    """
    return hashlib.sha256(subject.encode("utf-8")).hexdigest()


class CustomerRateLimitStoreUnavailable(RuntimeError):
    """The shared counter could not be reached.

    NAMED AND NOT COLLAPSED INTO "admitted", which is the whole of decision 2's
    second half. Failing OPEN would remove the control at exactly the moment a
    flood is the most plausible explanation for the store being slow or gone,
    which is the shape `postern_core.auth.revocation`'s
    ``RevocationStoreUnavailable`` refuses for the same reason one line further
    into the same three handlers.

    WHAT FAILING CLOSED COSTS, and why it costs nothing new. If the shared
    store is unreachable then the revocation store is too -- they are the same
    Redis, reached through the same ``POSTERN_REDIS_URL`` -- and
    `services/confirm/revocation.py`'s check runs in each of these three
    handlers, before any body is read. So a request this refuses would have
    been refused a few microseconds later anyway, by a control that already
    chose to fail closed and whose choice is not being relitigated here. This adds no outage that
    the deployment did not already have; failing open would have added a
    window in which it did not.
    """


class CustomerRateLimitStoreBase(ABC):
    """Where the per-customer counters live.

    One method, because a rate limiter needs exactly one operation and an
    interface with a ``get`` on it invites a caller to read a count and then
    act on it, which is a race in every backend.
    """

    @abstractmethod
    async def charge(self, key: str, route: str, limit: Limit) -> int | None:
        """Count one request, or say how many seconds until it would fit.

        Returns ``None`` when the request is admitted, otherwise the
        ``Retry-After`` value in seconds.

        Raises:
            CustomerRateLimitStoreUnavailable: if the backend could not be
                reached. Never swallowed into ``None``.
        """


class InMemoryCustomerRateLimitStore(CustomerRateLimitStoreBase):
    """Per-replica counters, for development and tests.

    THE HONEST LIMIT, and it is the reason this is NOT the production default
    the way `services/confirm/rate_limit.py`'s in-process counters are. A
    deployment running R replicas behind a round-robin balancer does not
    merely admit "up to" R times each limit under an attacker who steers
    traffic -- it admits R times each limit for EVERYBODY, always, because MCP
    ``2026-07-28`` removed protocol-level sessions and "any request can land
    on any instance", so a customer's ten requests spread evenly across four
    replicas exhaust nothing. A configured 10/min would then be a real 40/min
    and no line of configuration would say so. That is tolerable for the outer
    limiter, whose docstring says so and whose numbers are deliberately
    generous safety nets with the device-code store cap as the real bound; it
    is not tolerable for a control whose entire content IS its number.

    Use it when ``POSTERN_REDIS_URL`` is unset, which is a single-process
    ``docker compose`` or a test, and where R is 1 and the drift is zero.
    """

    def __init__(self, max_customers: int = DEFAULT_MAX_CUSTOMERS) -> None:
        self._buckets = Buckets(max_customers)

    async def charge(self, key: str, route: str, limit: Limit) -> int | None:
        """Never raises: an in-process counter cannot be unreachable.

        No ``await`` between the read and the write below, so under asyncio's
        single-threaded event loop no two requests interleave inside one
        counter -- the same argument `services/confirm/rate_limit.py` makes
        for holding no lock.
        """
        return charge_one(self._buckets.get(key), route, limit, time.monotonic())

    def __len__(self) -> int:
        return len(self._buckets)


#: The three commands one charge issues, as ONE transaction.
#:
#: ``SET key 0 EX window NX`` -- establish the window if and only if the key
#: is absent. ``INCR key`` -- count this request. ``TTL key`` -- how long the
#: window has left, which is the ``Retry-After``.
#:
#: WHY ``SET NX EX`` AND NOT ``INCR`` THEN ``EXPIRE``, which is the obvious
#: spelling. The obvious spelling has a failure that is specific and bad: if
#: the ``EXPIRE`` is lost -- a connection cut between the two, a failover --
#: the counter is left with NO TTL, so it never resets and the customer it
#: belongs to is refused for the life of the key. A permanent denial produced
#: by a transient error is the worst outcome available to a rate limiter.
#: Here the TTL is set in the same command that creates the key, so a key
#: without one cannot exist, and the ``NX`` makes a concurrent second setter a
#: no-op rather than a window reset an attacker could drive.
#:
#: ``EX`` only on creation, so the window is FIXED from the first request in
#: it: the counter keeps climbing under a flood, the deadline does not move.
#:
#: MULTI/EXEC rather than three round trips, which is redis-py's ``pipeline``
#: default. Atomic, and one round trip.
#:
#: WHY NOT A LUA ``EVAL``, which would also be atomic and which this module
#: carried first. ``fakeredis`` cannot execute one without the optional
#: ``lupa`` extra, and four existing test files drive this repository's Redis
#: code through ``fakeredis`` -- `tests/test_zt7_confirm_revocation.py` among
#: them, which builds a whole confirm app. A primitive that forces a new
#: dependency on every test that assembles this service, to buy atomicity
#: three ordinary commands already have, is the wrong trade.
_WINDOW_TTL_ABSENT = -1


class RedisCustomerRateLimitStore(CustomerRateLimitStoreBase):
    """Counters shared by every replica, which is the point of this backend.

    WHY REDIS HERE WHEN `services/confirm/rate_limit.py` REJECTED IT. That
    rejection is recorded, it is correct, and each of its three arguments is
    about a property this path does not have:

    - "A Redis round trip on a public unauthenticated endpoint makes the
      limiter an amplifier." That is an argument about the CHEAPEST request in
      the system, the one the outer limiter refuses before a body is read.
      This one runs on the most expensive: by the time it is reached the
      request has already cost a JWKS fetch and an RSA signature
      verification, and if admitted it will cost an Ed25519 verification, two
      pooled Postgres connections, an append-only INSERT and an outbound HTTPS
      call to a backend write endpoint. One round trip against that is noise.
    - "For a rate limiter both answers are bad ... An in-process counter
      cannot be unreachable, so it does not have the failure mode at all."
      True there, because that limiter is the only control on its path. Here
      the path ALREADY fails closed on this exact Redis, in
      `services/confirm/revocation.py`, on the next statement; see
      `CustomerRateLimitStoreUnavailable`.
    - "The accuracy that Redis would buy is not what bounds this service's
      memory. The store cap is." There is no other bound here. This limiter's
      number IS the control, so R-times drift is not an imprecision to note in
      a docstring, it is the number not being the number.

    Compatible with any Redis-compatible service -- AWS ElastiCache, Google
    Memorystore, Azure Cache for Redis, or a self-hosted instance -- the same
    compatibility `postern_core.auth.revocation`'s `RedisRevocationStore`
    documents, and reached through the SAME ``POSTERN_REDIS_URL`` so a
    deployment cannot end up with a shared revocation list beside per-replica
    approval counters.

    Configuration via environment variables:

    ``POSTERN_REDIS_URL``
        Redis connection string, e.g. ``redis://localhost:6379/0`` or
        ``rediss://user:pass@host:port/0`` (TLS).

    ``POSTERN_REDIS_KEY_PREFIX``
        Key prefix for multi-tenant deployments (default ``"postern:"``).
    """

    def __init__(self, url: str | None = None, key_prefix: str | None = None) -> None:
        import redis.asyncio as redis

        self._url = url or redis_url_from_env() or "redis://localhost:6379/0"
        self._prefix = key_prefix or os.environ.get("POSTERN_REDIS_KEY_PREFIX", "postern:")
        self._redis: Any = redis.from_url(  # type: ignore[no-untyped-call]
            self._url,
            decode_responses=True,
        )

    def _key(self, key: str, route: str) -> str:
        """One counter per customer PER ROUTE.

        Separate budgets rather than one shared allowance, matching the outer
        limiter's per-path counters: a customer who paired a device this
        minute must not find their payment approval refused because of it.
        The two actions are unrelated and a shared counter would couple them
        for no stated benefit.
        """
        return f"{self._prefix}ratelimit:customer:{route}:{key}"

    async def charge(self, key: str, route: str, limit: Limit) -> int | None:
        counter = self._key(key, route)
        try:
            pipe = self._redis.pipeline()
            pipe.set(counter, 0, ex=limit.window_seconds, nx=True)
            pipe.incr(counter)
            pipe.ttl(counter)
            _, count, ttl = await pipe.execute()
        except Exception as exc:
            raise CustomerRateLimitStoreUnavailable(
                f"the per-customer rate limit counter could not be reached: {type(exc).__name__}"
            ) from None

        if int(count) <= limit.requests:
            return None
        # A key with no TTL cannot be produced by the transaction above, but a
        # manual `SET` or an older deployment could leave one. Treating it as
        # a full window is the conservative direction and it self-heals on the
        # next expiry.
        remaining = int(ttl)
        if remaining <= _WINDOW_TTL_ABSENT:
            remaining = limit.window_seconds
        return max(1, remaining)


def create_customer_rate_limit_store() -> CustomerRateLimitStoreBase:
    """Redis when ``POSTERN_REDIS_URL`` is set, in-process otherwise.

    The same contract as `postern_core.risk.session`'s
    `create_session_store`, `postern_core.auth.revocation`'s
    `create_revocation_store` and `postern_core.auth.device_codes`'s
    `create_device_code_store`, so one variable configures all four and no
    deployment ends up with a shared revocation list beside per-replica
    approval counters.

    THE FAILURE MODE AN OPERATOR OWNS, and it is the price of matching that
    contract rather than requiring the variable: a multi-replica deployment
    that forgets ``POSTERN_REDIS_URL`` silently gets per-replica counters and
    therefore R times every ceiling below. That exposure is not new and not
    this module's to fix unilaterally -- the revocation list, the session
    store and the device code store all degrade the same way from the same
    omission, and the log line below is the same one they emit.

    AN OPERATOR CAN NOW REFUSE THAT, WHICH THEY COULD NOT UNTIL 2026-09-26.
    ``POSTERN_REQUIRE_REDIS=1`` refuses startup without a URL, and until that
    date it was read in `services/api/main.py` and nowhere else, so setting it
    bought the guarantee on the read path and nothing at all here -- these
    counters, the ZT-7 revocation list and the device code store all stayed per
    replica while the operator believed otherwise.
    `postern_core.config.enforce_redis_requirement` is now the one
    implementation of that contract and `services/confirm/main.py` calls it
    beside `services/api/main.py`, so "we set POSTERN_REQUIRE_REDIS" does now
    mean the approval counters are shared.

    WHAT IS STILL THE OPERATOR'S, because the guard reads two environment
    variables and nothing more: it does not check that the URL is reachable,
    and it does not check that both services point at the SAME Redis. Pointing
    them at two instances satisfies every check in this repository and gives
    the read path one revocation list and the write path another.
    """
    redis_url = redis_url_from_env()
    if redis_url:
        logger.info("Using Redis per-customer rate limit counters")
        return RedisCustomerRateLimitStore(url=redis_url)
    logger.info(
        "Using in-memory per-customer rate limit counters "
        "(set POSTERN_REDIS_URL to share them across replicas)"
    )
    return InMemoryCustomerRateLimitStore()


def customer_limits_from_settings(
    *,
    approve: int,
    challenge_approve: int,
    scan: int,
) -> dict[str, Limit]:
    """Build the per-path limit map from three per-minute request counts.

    Here rather than in `services/confirm/main.py` so the composition root
    stays assembly, and here rather than in `services/confirm/settings.py` so
    that module keeps importing nothing but ``os`` and ``dataclasses`` -- the
    same split, for the same two reasons, as
    `services/confirm/rate_limit.py`'s ``limits_from_settings``.
    """
    return {
        "/approve": Limit(approve, RATE_LIMIT_WINDOW_SECONDS),
        "/challenges/approve": Limit(challenge_approve, RATE_LIMIT_WINDOW_SECONDS),
        "/scan": Limit(scan, RATE_LIMIT_WINDOW_SECONDS),
    }


class CustomerRateLimit:
    """Refuse a verified customer beyond the configured rate on their path.

    Pure ASGI rather than a ``BaseHTTPMiddleware`` subclass, matching every
    other middleware on this service: a middleware that must answer without
    touching ``receive`` has no use for the request and streaming-response
    machinery ``BaseHTTPMiddleware`` builds.

    INNERMOST, DIRECTLY BEHIND ``AppAssertionMiddleware``. It cannot go
    further out -- the verified subject does not exist further out -- and it
    deliberately does not go further in, into the handlers, even though
    `services/confirm/revocation.py`'s check is a handler call for a reason
    this module had to weigh. That reason is the audit row, and the decision
    went the other way; ``_refuse`` below carries it.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        store: CustomerRateLimitStoreBase,
        limits: dict[str, Limit] | None = None,
        fallback_limit: Limit = FALLBACK_CUSTOMER_LIMIT,
    ) -> None:
        # THE SECOND HALF OF THE STARTUP GUARD, exactly as
        # `services/confirm/rate_limit.py`'s constructor does it and for the
        # same reason: `services/confirm/settings.py`'s `_positive_int`
        # refuses a bad value where an operator's typo enters, and this
        # refuses one however it arrives. A limit of zero refuses every
        # approval that customer attempts, which is an outage wearing a
        # control's clothes.
        resolved = DEFAULT_CUSTOMER_LIMITS if limits is None else limits
        for name, limit in [*resolved.items(), ("the fallback", fallback_limit)]:
            if limit.requests < 1:
                raise ValueError(
                    f"per-customer rate limit for {name} must admit at least one request "
                    f"per window, got {limit.requests}"
                )
        self.app = app
        self.store = store
        self.limits = resolved
        self.fallback_limit = fallback_limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        assertion = scope.get("state", {}).get(ASSERTION_STATE_KEY)
        if not isinstance(assertion, AppAssertion):
            # NO VERIFIED SUBJECT, SO NOTHING TO CHARGE, AND THIS IS NOT A
            # HOLE. Reaching here means `AppAssertionMiddleware` let the
            # request through without verifying one, which it does for
            # exactly the eight entries in its ``PUBLIC_PATHS`` -- and those
            # eight have no customer at the moment they are served, which is
            # the premise of the device grant rather than an oversight. They
            # are the outer address-keyed limiter's alone, and it limits all
            # eight. Any other route reaching here unverified would already
            # have been a 401.
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        route = route_key(path)
        limit = self.limits.get(route, self.fallback_limit)
        handle = customer_handle(assertion.subject)
        try:
            retry_after = await self.store.charge(_counter_key(assertion.subject), route, limit)
        except CustomerRateLimitStoreUnavailable as exc:
            await self._store_unavailable(path, handle, limit, exc, send)
            return

        if retry_after is not None:
            await self._refuse(path, handle, retry_after, limit, send)
            return

        await self.app(scope, receive, send)

    # --- Refusal ------------------------------------------------------------

    async def _refuse(
        self,
        path: str,
        handle: str,
        retry_after: int,
        limit: Limit,
        send: Send,
    ) -> None:
        """Answer 429 with a code that is not the other limiter's.

        WHY THIS WRITES NO ``audit_log`` ROW, which is decision 5 and the one
        this module spent the longest on. The outer limiter writes none
        because it runs before the database exists; that argument does not
        transfer, since this one runs after authentication and could reach
        ``app.state.postern_database``. The reasons it still writes none:

        1. ``audit_log`` records what happened to an APPROVAL. This refusal
           never became one -- `services/confirm/audit.py`'s ``DETAIL_*``
           vocabulary describes outcomes of an attempt that got as far as
           having a parsed body and a named challenge, and neither exists at
           this point in the stack.
        2. STRUCK 2026-09-26. This read "Only ONE of the two limited paths
           has an audit trail at all", naming `services/confirm/
           device_auth.py`'s ``approve_callback`` as writing no ``audit_log``
           row on any branch. Commit 10496a3, the same day, gave it one:
           `services/confirm/audit.py`'s ``PairingAudit`` wrote exactly one
           row per ``POST /approve`` attempt, on the grant and on each
           refusal that concludes something about a customer. Its refusal
           vocabulary has changed since (the ``DETAIL_*`` constants in that
           module are the current list), and ``POST /scan`` writes through
           the same class. All three limited paths have a trail now, so the
           undercount this reason warned against does not exist.
        3. Getting the row would cost the position, and for the pairing
           paths this is the harder case to reach, not the easier one.
           `ApprovalAudit` is built from the parsed JSON body, and
           `services/confirm/revocation.py` records why that puts it out of
           reach here: "An ASGI middleware cannot reach that body without
           draining ``receive``". `PairingAudit` is built the same way, from
           ``user_code`` in the body of ``POST /approve`` and ``POST /scan``
           -- where `services/confirm/audit.py`'s ``APPROVE_ROUTE`` shows the
           challenge carries its id in the URL instead. So a row from this
           position could at least name a challenge without draining
           anything, and could never name a pairing at all: the one
           identifier this module could reach without draining ``receive``
           is exactly the one the pairing path keeps out of the URL. Moving
           this check into the handlers to reach either identifier would put
           it behind the body read, the JSON parse and the audit
           construction -- behind most of the cost it exists to bound.

        WHAT CARRIES THE SIGNAL INSTEAD, because "no row" must not mean "no
        trace": the distinct error code above, which an operator can alert on
        at their edge without parsing a body, and the line below, which names
        the ceiling that was hit and a stable per-customer handle to rank
        offenders by. `customer_handle` carries what that handle does and
        does not claim.
        """
        body = json.dumps(
            {
                "error": CUSTOMER_RATE_LIMITED,
                "error_description": (
                    f"too many requests for this customer; retry after {retry_after} seconds"
                ),
            }
        ).encode()
        logger.warning(
            "confirm: %s refused, customer %s is over the per-customer ceiling "
            "of %d per %ds, retry after %ds",
            path,
            handle,
            limit.requests,
            limit.window_seconds,
            retry_after,
        )
        await self._send(send, 429, body, retry_after)

    async def _store_unavailable(
        self,
        path: str,
        handle: str,
        limit: Limit,
        exc: CustomerRateLimitStoreUnavailable,
        send: Send,
    ) -> None:
        """Answer 503 when the shared counter cannot be reached.

        503 AND NOT 500, and not the 429 either. The caller is not over any
        ceiling and has done nothing wrong, so a 429 would be a lie that
        teaches an operator's dashboard to attribute an infrastructure outage
        to a customer's behaviour. 503 with a ``Retry-After`` says what is
        true and what to do, and it is the code
        `services/confirm/revocation.py` already reaches for on the same
        service when the party being refused is not the party at fault --
        "the browser polling it is not the party that was revoked and an
        outage is not a denial".

        It DIVERGES from the 500 that an unreachable revocation store
        produces on these same three endpoints, and that divergence is
        deliberate rather than overlooked: these are two controls answering
        for themselves, the 500 is that control's recorded choice and is not
        being changed here, and an operator seeing both codes in one Redis
        outage learns more than one who sees a single code twice.

        The exception type is logged and its message is not echoed to the
        caller: the caller learns that the service cannot serve them, and
        nothing about the operator's infrastructure.
        """
        retry_after = limit.window_seconds
        body = json.dumps(
            {
                "error": STORE_UNAVAILABLE,
                "error_description": (
                    "the per-customer rate limit counter is unavailable; "
                    f"retry after {retry_after} seconds"
                ),
            }
        ).encode()
        logger.error(
            "confirm: %s refused, the per-customer rate limit counter is unreachable "
            "for customer %s: %s",
            path,
            handle,
            exc,
        )
        await self._send(send, 503, body, retry_after)

    async def _send(self, send: Send, status: int, body: bytes, retry_after: int) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(retry_after).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

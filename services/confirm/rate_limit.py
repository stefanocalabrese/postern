"""A bound on how fast an unauthenticated caller can reach this service.

TWO CONTROLS, AND THEY CLOSE DIFFERENT DEFECTS. This module bounds the
ARRIVAL RATE. `postern_core.auth.device_codes`'s ``DeviceCodeStoreFull``
bounds the STANDING COST. Neither substitutes for the other: a rate limit
holds nothing back once the requests have been admitted, and a store cap does
nothing about the CPU, the logging and the Redis round trips a flood spends
before it reaches the cap. Both landed together on 2026-09-24 and the
measurement that motivated them is in the store module's
``DEFAULT_MAX_DEVICE_CODES``.

WHAT THIS BUYS, AND WHAT IT DOES NOT. These two controls convert unbounded
memory growth into a bounded-memory denial of service. They do not make this
service un-DoS-able, and nothing in this repository can. An attacker holding
many address prefixes still gets one full allowance per prefix, and once the
device code store reaches its cap, new pairings are refused for everyone --
that refusal is the bounded failure this trades the unbounded one for, not an
absence of failure. Stopping a distributed flood before it arrives needs
infrastructure that is not here: a WAF with per-ASN reputation scoring, an
edge rate limit, or a proof-of-work or CAPTCHA gate on the pairing page.
Those belong to the operator, alongside the other items CLAUDE.md lists as
theirs.

WHY IN-PROCESS COUNTERS, AND WHY THERE IS NO REDIS BACKEND HERE. This is a
REJECTION, recorded as one, not a seam waiting for an implementation the way
`postern_core.auth.keys`'s ``KeySource`` waits for Vault.

- A Redis round trip on a public unauthenticated endpoint makes the limiter
  an amplifier. The cheapest request in the system -- the one this module
  refuses -- would still cost a network round trip, which is backwards for a
  control whose whole purpose is to make hostile traffic cheap to refuse.
- Every other store in this repository must choose between failing open and
  failing closed when it cannot be reached, and for a rate limiter both
  answers are bad: failing open removes the control exactly when the service
  is under stress, and failing closed turns a cache outage into a total
  outage of device pairing for every customer, which is the attack this
  module exists to prevent, self-inflicted. An in-process counter cannot be
  unreachable, so it does not have the failure mode at all. Not having it
  beats choosing a side of it.
- The accuracy that Redis would buy is not what bounds this service's
  memory. The store cap is, and that one IS shared across replicas.

THE COST OF THAT CHOICE, stated the way `postern_core.risk.session`'s
``InMemorySessionStore`` states its own: counters are per replica, so a
deployment running R replicas admits up to R times each limit below, and a
deploy resets every counter. Both are acceptable because the limits are
deliberately generous (see `DEFAULT_LIMITS`) and because the store cap, not
this, is the bound that has to hold.

THE LIMITER IS ITSELF AN ACCUMULATOR, which is the trap in fixing an
accumulation defect. A map keyed by client address grows with the number of
distinct addresses seen, and an attacker rotating addresses is exactly the
traffic this module attracts. `_Buckets` is therefore a fixed-capacity LRU:
at ``max_buckets`` the least recently used entry is dropped. Eviction, not
refusal, and the argument is the reverse of the store cap's: evicting a
limiter entry only RESETS a counter, so it can never deny anyone, and an
attacker able to evict entries by presenting more than ``max_buckets``
distinct addresses already holds more addresses than any per-address limit
could bind. The store cap is what stops them.

WHY DEFAULT-DENY ON PATHS. Every path is limited; `DEFAULT_LIMITS` names the
ones with their own number and `FALLBACK_LIMIT` covers the rest. This is the
direction `services/confirm/auth.py` set with ``PUBLIC_PATHS`` -- "a route
added to this service tomorrow is therefore authenticated by omission rather
than unauthenticated by omission" -- and `services/confirm/body_limit.py`
followed for the same reason. A route added tomorrow is rate-limited by
omission.

WHY OUTERMOST, IN FRONT OF ``BodySizeLimit``. A refused request must not
drain a body, so this middleware answers without ever calling ``receive``.
Behind the body limit it would cost a 64 KiB buffer per refusal; behind
``AppAssertionMiddleware`` it would cost a JWKS fetch and a signature
verification, which for ``POST /challenges/{id}/approve`` is the expensive
part. It reaches no store, no database and no handler, so the property
``AppAssertionMiddleware``'s docstring claims for its own placement is
preserved exactly: this module holds counters and a clock.
"""

from __future__ import annotations

import json
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass

from postern_core.net import client_ip, ip_bucket
from starlette.types import ASGIApp, Receive, Scope, Send

logger = logging.getLogger(__name__)

#: The bucket unattributable traffic is counted against.
#:
#: `postern_core.net`'s `client_ip` returns ``None`` when a deployment
#: configured for N proxy hops receives a header with fewer, when the address
#: does not parse, or when there is no socket peer. Those requests share ONE
#: budget rather than going unlimited, because "the limiter could not
#: identify you" must not be the cheapest way to avoid the limiter. The
#: literal matches `services/api/middleware/risk.py`'s ``NO_CLIENT`` so one
#: grep over both services finds both.
#:
#: The consequence an operator owns: a deployment that sets
#: ``POSTERN_CONFIRM_TRUSTED_PROXY_HOPS`` to the wrong number puts ALL of its
#: traffic in this one bucket and will start refusing at the limits below.
#: That is a loud failure on the first minute of the first deploy rather than
#: a quiet absence of the control, which is the direction this service
#: already chose when it made three assertion settings required at startup.
UNATTRIBUTED = "-"


@dataclass(frozen=True)
class Limit:
    """``requests`` admitted per ``window_seconds`` from one bucket."""

    requests: int
    window_seconds: int


#: Per-path limits, per address bucket, per replica.
#:
#: THE WORKING, because a limit tuned by guess is either useless or pages
#: someone at 3am. Each is set so that a real browser and a real bank app
#: never approach it, which makes every one of these a safety net against a
#: single-host flood rather than a control that shapes normal traffic. The
#: bound that actually holds memory is the store cap.
#:
#: ``/device_authorization`` -- 60/min. A browser starting a pairing calls
#:     this ONCE. A user reloading an expired QR page calls it a handful of
#:     times. 60/min is a sustained one per second.
#: ``/token`` -- 300/min. RFC 8628 polling at the default 5-second
#:     ``interval`` is 12 calls a minute PER PAIRING, so 300 tolerates about
#:     25 concurrent pairings from one bucket. Its per-pairing control stays
#:     the ``slow_down`` in `services/confirm/device_auth.py`; this one
#:     exists for the flood of UNKNOWN device codes, which never reaches
#:     ``slow_down`` at all because the handler returns ``invalid_grant``
#:     first, and which costs a store lookup -- a Redis round trip under
#:     ``POSTERN_REDIS_URL`` -- every time.
#: ``/approve`` -- 60/min. The operator's app calls this once per pairing.
#: ``/challenges/{id}/approve`` -- 60/min. The same party, and the most
#:     expensive request this service serves: a JWKS fetch, an assertion
#:     verification, an Ed25519 device signature check and a database write.
#:
#: WHY ALL OF THESE ARE GENEROUS, said plainly because it is the honest
#: weakness of per-address limiting on a consumer bank's public endpoint:
#: carrier-grade NAT puts thousands of subscribers behind one IPv4 address.
#: Any limit low enough to bite an attacker holding a handful of addresses is
#: low enough to hurt a real NAT pool, and there is no number that escapes
#: that trade. These are set on the side that does not break customers.
DEFAULT_LIMITS: dict[str, Limit] = {
    "/device_authorization": Limit(requests=60, window_seconds=60),
    "/token": Limit(requests=300, window_seconds=60),
    "/approve": Limit(requests=60, window_seconds=60),
    "/challenges/approve": Limit(requests=60, window_seconds=60),
}

#: What an unlisted path gets. See "WHY DEFAULT-DENY ON PATHS" above.
FALLBACK_LIMIT = Limit(requests=60, window_seconds=60)

#: How many device codes one bucket may create per device-code lifetime.
#:
#: This is the per-bucket half of the store cap, and it is a SEPARATE control
#: from the 60/min above even though it is keyed the same way. 60/min over a
#: 900-second lifetime is 900 codes from one address, which is 9% of the
#: 10,000-code store cap: eleven addresses would fill the store. At 200 it
#: takes fifty. That is one more counter on a map already being maintained,
#: for a 4.5x increase in the number of distinct prefixes an attacker must
#: hold, and on IPv6 -- where `postern_core.net`'s `ip_bucket` already costs
#: them a /64 per bucket -- that difference is the whole control.
#:
#: It counts CREATIONS over the window rather than codes currently alive,
#: which over-counts: a code approved and exchanged in ten seconds still
#: occupies its bucket's allowance for the full 900. That is deliberate. The
#: alternative is coupling this module to the store's contents, and an
#: over-count is the conservative direction for a bound.
DEFAULT_PAIRING_LIMIT = Limit(requests=200, window_seconds=900)

#: How many address buckets the limiter will hold. See "THE LIMITER IS ITSELF
#: AN ACCUMULATOR" above for why this is a hard cap with LRU eviction rather
#: than a sweep.
#:
#: Measured on 2026-09-24 at the cap, with IPv6 keys (the longest) and both
#: counters populated (the worst case, which only ``/device_authorization``
#: reaches): 8,613,126 bytes for 20,000 buckets, 431 bytes each. That is the
#: whole standing cost of this control, against the 128,990,755 bytes that
#: 2,000 unauthenticated requests could put in the device code store before
#: any of this existed.
DEFAULT_MAX_BUCKETS = 20_000


@dataclass
class _Counter:
    """One fixed window: when it started, and how many landed in it.

    ``__slots__`` because there is one of these per counter per live address
    bucket, which is the memory this module is accountable for.
    """

    __slots__ = ("count", "started")

    started: float
    count: int


#: Every counter one address bucket carries, keyed by counter name. A plain
#: dict rather than a wrapper class: one per live bucket, so the per-entry
#: cost is the point.
_Counters = dict[str, _Counter]


class _Buckets:
    """A fixed-capacity LRU map of address bucket to its counters.

    ``OrderedDict`` with ``move_to_end`` on every touch, and ``popitem`` of
    the least recently used entry once over capacity. There is no periodic
    sweep: an idle bucket costs one entry and is evicted by pressure from new
    ones, which bounds memory with no work on the request path.
    """

    def __init__(self, max_buckets: int) -> None:
        self._buckets: OrderedDict[str, _Counters] = OrderedDict()
        self._max = max_buckets
        self.evictions = 0

    def get(self, key: str) -> _Counters:
        counters = self._buckets.get(key)
        if counters is None:
            counters = {}
            self._buckets[key] = counters
            while len(self._buckets) > self._max:
                self._buckets.popitem(last=False)
                self.evictions += 1
        else:
            self._buckets.move_to_end(key)
        return counters

    def __len__(self) -> int:
        return len(self._buckets)


def route_key(path: str) -> str:
    """The `DEFAULT_LIMITS` key a request path counts against.

    Exact for the three fixed paths. ``/challenges/{challenge_id}/approve``
    collapses to one key, because the challenge id is caller-supplied and
    per-id counters would let a caller mint a fresh budget by inventing an
    id -- the same reason `services/confirm/device_auth.py` refuses to key
    anything on ``DeviceCode.client_id``.
    """
    if path.startswith("/challenges/") and path.endswith("/approve"):
        return "/challenges/approve"
    return path


class RateLimit:
    """Refuse requests from one address bucket beyond the configured rate.

    Pure ASGI rather than a ``BaseHTTPMiddleware`` subclass, matching
    `services/confirm/body_limit.py` and ``AppAssertionMiddleware``: a
    middleware that must answer without touching ``receive`` has no use for
    the request and streaming-response machinery ``BaseHTTPMiddleware``
    builds.

    No locking. Every counter update below runs to completion without an
    ``await``, so under asyncio's single-threaded event loop no two requests
    can interleave inside one. A threaded server would need a lock; this
    service runs under uvicorn.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        trusted_proxy_hops: int = 0,
        limits: dict[str, Limit] | None = None,
        fallback_limit: Limit = FALLBACK_LIMIT,
        pairing_limit: Limit = DEFAULT_PAIRING_LIMIT,
        max_buckets: int = DEFAULT_MAX_BUCKETS,
    ) -> None:
        if trusted_proxy_hops < 0:
            raise ValueError(
                f"trusted_proxy_hops must be zero or positive, got {trusted_proxy_hops}"
            )
        self.app = app
        self.trusted_proxy_hops = trusted_proxy_hops
        self.limits = DEFAULT_LIMITS if limits is None else limits
        self.fallback_limit = fallback_limit
        self.pairing_limit = pairing_limit
        self._buckets = _Buckets(max_buckets)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Not only ``websocket``: ``lifespan`` reaches every middleware
        # through the same stack, and counting it would spend a request of
        # somebody's budget at startup. The reasoning is
        # `services/confirm/body_limit.py`'s, for the same stack position.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        key = self._bucket_key(scope)
        retry_after = self._charge(key, route_key(path))
        if retry_after is not None:
            await self._refuse(path, key, retry_after, send)
            return

        await self.app(scope, receive, send)

    # --- Identity -----------------------------------------------------------

    def _bucket_key(self, scope: Scope) -> str:
        """Which bucket this request counts against.

        The derivation is `postern_core.net`'s, not this module's, and that
        is deliberate: `services/api/middleware/risk.py` reads the same
        header with the same trusted-hop rule, `.importlinter` forbids these
        two services from importing each other, and a second copy of a
        hop-counted address derivation is the shape
        `services/api/middleware/audit.py` records going wrong once already.
        """
        client = scope.get("client")
        peer_host = client[0] if client else None
        forwarded = None
        for name, value in scope.get("headers", []):
            if name.lower() == b"x-forwarded-for":
                forwarded = value.decode("latin-1")
                break
        address = client_ip(
            forwarded=forwarded,
            peer_host=peer_host,
            trusted_proxy_hops=self.trusted_proxy_hops,
        )
        if address is None:
            return UNATTRIBUTED
        return ip_bucket(address)

    # --- Counting -----------------------------------------------------------

    def _charge(self, key: str, route: str) -> int | None:
        """Count this request, or say how many seconds until it would fit.

        Returns ``None`` when the request is admitted, otherwise the
        ``Retry-After`` value. Charges every applicable counter BEFORE
        deciding, so a request refused by one limit still counts against the
        other: a caller at the pairing cap must not get an unmetered
        allowance on the per-minute one by being refused.
        """
        counters = self._buckets.get(key)
        now = time.monotonic()

        limit = self.limits.get(route, self.fallback_limit)
        wait = _charge_one(counters, route, limit, now)

        if route == "/device_authorization":
            pairing_wait = _charge_one(counters, "pairing", self.pairing_limit, now)
            if pairing_wait is not None and (wait is None or pairing_wait > wait):
                wait = pairing_wait

        return wait

    # --- Refusal ------------------------------------------------------------

    async def _refuse(self, path: str, key: str, retry_after: int, send: Send) -> None:
        """Answer the refusal, in the vocabulary the caller of this path speaks.

        ``POST /token`` gets RFC 8628 §3.5's ``slow_down`` with a 400, and
        the other paths get 429. That is not an inconsistency, it is the
        difference between a device-grant client and an HTTP client: a
        conforming RFC 8628 client already knows ``slow_down`` and responds
        by lengthening its polling interval, which is exactly the behaviour
        wanted, while a 429 is a code the device-grant polling loop has no
        defined reaction to. The token endpoint's errors are RFC 6749 §5.2
        shaped, and those carry a 400.

        THIS DOES AND DOES NOT AGREE WITH THE EXISTING ``slow_down``. They
        agree in kind and differ in what they count. The one in
        `services/confirm/device_auth.py` is per DEVICE CODE and enforces the
        5-second poll interval for one pairing; this one is per ADDRESS
        BUCKET across every pairing and every unknown code. A client
        honouring either honours both. Two gaps are worth naming rather than
        implying they do not exist: the per-code one is skipped entirely once
        a code is approved, so for an approved code this limit is the only
        one left and it is loose at 300/min; and it is never reached at all
        for a device code the store does not hold, which is the flood this
        limit is really for.

        The log line is the only durable trace, for the reason
        `services/confirm/body_limit.py::BodySizeLimit._refuse` gives: this
        middleware sits outside the authentication boundary, has no verified
        subject, and must not be handed a database, or an unauthenticated
        caller could drive an INSERT per request -- a cheaper denial of
        service than the one being closed.
        """
        if route_key(path) == "/token":
            status, error = 400, "slow_down"
        else:
            status, error = 429, "too_many_requests"
        body = json.dumps(
            {
                "error": error,
                "error_description": (
                    f"too many requests from this client; retry after {retry_after} seconds"
                ),
            }
        ).encode()
        logger.warning(
            "confirm: %s rate limited for bucket %s, retry after %ds (%d buckets held)",
            path,
            key,
            retry_after,
            len(self._buckets),
        )
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


def _charge_one(counters: _Counters, name: str, limit: Limit, now: float) -> int | None:
    """Add one to a named fixed window, or return the seconds left in it.

    ``time.monotonic``, never wall clock: a clock step backwards would extend
    a window indefinitely and a step forwards would clear every counter at
    once.

    A FIXED WINDOW, not a sliding one, and the cost is worth stating: a
    caller can spend a full allowance at the end of one window and another at
    the start of the next, so the true worst case over a 60-second span is
    twice the number configured. For limits deliberately set where no real
    client reaches them, that doubling changes nothing, and the alternative
    costs a timestamp array per bucket -- memory, in the module whose subject
    is bounding memory.
    """
    counter = counters.get(name)
    if counter is None or now - counter.started >= limit.window_seconds:
        counters[name] = _Counter(started=now, count=1)
        return None
    if counter.count >= limit.requests:
        remaining = limit.window_seconds - (now - counter.started)
        return max(1, int(remaining) + 1)
    counter.count += 1
    return None

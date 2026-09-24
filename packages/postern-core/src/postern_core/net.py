"""Which address a request came from, and which bucket that address counts in.

ONE IMPLEMENTATION, DELIBERATELY, AND THE REASON IS A FINDING THIS REPOSITORY
ALREADY PAID FOR. `services/api/middleware/audit.py` records that three
copies of ``_scrub`` existed and that the weakest of the three sat on the
money path, so a NUL-split PAN reached ``BackendWriteError.detail`` unmasked.
An audit found it; no test did, because every copy had tests and each one
passed against its own copy. Deriving a client address from a hop count is
the same kind of function: security-relevant, easy to get subtly wrong, and
invisible when one copy drifts. `.importlinter` forbids ``services.api`` and
``services.confirm`` from importing each other precisely so that shared logic
lands here instead of being written twice.

Both callers are one adapter line each. `services/api/middleware/risk.py`
reads a `starlette` ``Request`` through fastmcp's ``get_http_request``;
`services/confirm/rate_limit.py` is raw ASGI and reads the scope. Neither
holds any of the logic below.

WHAT `client_ip` DECIDES, and both halves were defects fixed on the read path
on 2026-09-22 rather than choices made fresh here:

- The address is taken from the **right** of ``X-Forwarded-For``, never the
  left. The leftmost entry is the one the caller writes. Reading it let an
  attacker pin their apparent address to defeat the diversity and
  impossible-travel checks outright, or rotate it to spend a budget at will.
  The rightmost entries are the ones infrastructure appended, so with
  ``trusted_proxy_hops = n`` the address is the n-th from the right: the
  value written by the outermost proxy this deployment trusts.
- The **default is zero**, which trusts the header for nothing and uses the
  socket peer. A deployment behind an ALB, an Istio gateway or any other
  proxy MUST set its service's trusted-hop count, or every request is
  attributed to the proxy. The opposite default would mean a deployment with
  no proxy in front of it trusting a header the caller writes, which is the
  defect being fixed.
- A header carrying fewer than ``n`` entries is not the shape the deployment
  expects and is discarded, rather than read at whatever offset it happens to
  have. Otherwise a caller who strips the header chooses which entry is
  believed.
- ``ipaddress.ip_address`` both validates and canonicalises, so
  ``::FFFF:1.2.3.4`` and ``::ffff:1.2.3.4`` cannot count as two addresses.
  Anything it refuses is dropped: the caller proceeds with one fewer address
  recorded rather than with a garbage one that would make every later
  comparison lie.

WHAT `ip_bucket` DECIDES, and this half is new. An IPv4 address is its own
bucket. An IPv6 address is bucketed to its **/64**, because a single
residential or mobile allocation is a /64 or a /56: counting a v6 address as
one identity means one customer holds 2**64 of them, and any control keyed on
the full address is free to defeat from a single allocation. Bucketing does
not make v6 rotation expensive, it makes it cost a prefix rather than nothing.
An attacker holding many prefixes still holds many buckets, which is why
`services/confirm/rate_limit.py` states plainly that a rate limit is not what
bounds this service's memory.

`ip_bucket` is NOT used on the read path. `services/api/middleware/risk.py`
records the address itself, because impossible travel and address diversity
are questions about the address; bucketing there would make two addresses in
one prefix look like one caller and weaken the A4 control. Bucketing is a
rate-limiting decision and lives at the rate limiter.
"""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)

#: The prefix an IPv6 address is bucketed to by default. A /64 is the
#: smallest allocation an end site is normally given, so it is the smallest
#: unit that corresponds to one subscriber rather than to one interface.
IPV6_BUCKET_PREFIX_BITS = 64


def client_ip(
    *,
    forwarded: str | None,
    peer_host: str | None,
    trusted_proxy_hops: int,
) -> str | None:
    """The client address to attribute this request to, or ``None``.

    Args:
        forwarded: The raw ``X-Forwarded-For`` header value, or ``None`` when
            the request carries none.
        peer_host: The socket peer's address, or ``None`` when the transport
            has no peer (an in-process test client has none, and nothing
            about that is an error).
        trusted_proxy_hops: How many proxies in front of this process append
            to ``X-Forwarded-For``. Zero means trust the header for nothing.

    Returns:
        A canonical address string, or ``None`` to record nothing.

    Raises:
        ValueError: if ``trusted_proxy_hops`` is negative, which would index
            the header from the wrong end. Callers validate this when they
            are constructed so the failure lands at assembly rather than at
            the first request; this is the backstop for one that does not.
    """
    if trusted_proxy_hops < 0:
        raise ValueError(f"trusted_proxy_hops must be zero or positive, got {trusted_proxy_hops}")

    if trusted_proxy_hops > 0:
        if not forwarded:
            return None
        parts = [part.strip() for part in forwarded.split(",") if part.strip()]
        if len(parts) < trusted_proxy_hops:
            logger.warning(
                "X-Forwarded-For carries %d entries, fewer than the %d trusted hops "
                "configured; recording no client IP for this request",
                len(parts),
                trusted_proxy_hops,
            )
            return None
        candidate = parts[-trusted_proxy_hops]
    else:
        if peer_host is None:
            return None
        candidate = peer_host

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        logger.warning("discarding unparseable client address for this request")
        return None


def ip_bucket(address: str, *, ipv6_prefix_bits: int = IPV6_BUCKET_PREFIX_BITS) -> str:
    """The rate-limiting identity an address counts against.

    IPv4 buckets to the address itself. IPv6 buckets to its network prefix,
    ``/64`` by default, so that rotating inside one allocation does not reset
    a counter.

    The return value is a string rather than an `ipaddress` object because it
    is a dict key and a log field, and because ``str`` of a canonical network
    already round-trips. An address this cannot parse is returned unchanged:
    callers pass values `client_ip` already validated, so this cannot happen
    through either wiring, and inventing a second discard path here would
    mean an address dropped in two places for two different reasons.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:  # pragma: no cover - callers pass validated addresses
        return address
    if parsed.version == 4:
        return str(parsed)
    network = ipaddress.ip_network(f"{parsed}/{ipv6_prefix_bits}", strict=False)
    return str(network)

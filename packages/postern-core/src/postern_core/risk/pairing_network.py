"""Where a pairing was created, against where it was scanned.

PURE, AND THAT IS THE CONTRACT. This module imports ``ipaddress``, ``enum``,
``dataclasses``, ``typing`` and ``postern_core.risk.types``, reads no
environment, performs no I/O and holds no state. The one thing here that
could reach a network, an enricher, is a Protocol: this module says what one
must look like and ``postern_core.modules.enrichers`` finds the installed one.

WHAT THE RELATION IS FOR. The two phishing forms ``dev-docs/qr-page-spec.md``
names -- the consent lure and the live relay -- create the pairing on the
attacker's network and scan it on the victim's. The only server-side trace
either leaves is that the two networks differ, so ``POST /scan`` records the
comparison on every successful scan. It refuses nothing: a legitimate laptop
on home Wi-Fi paired with a phone on mobile data is ``different`` too, and
``dev-docs/pairing-network-signal-spec.md`` lists the other benign causes.

/24 AND /48, NOT ``postern_core.net``'s /64. That function answers "which
rate-limit counter does this address spend"; this one answers "could these
two requests plausibly be the same site". A /48 is the allocation commonly
given to one end site and a /64 is one link inside it, so a laptop on
Ethernet and a phone on Wi-Fi in one house can sit in two /64s of one /48.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol

from postern_core.risk.types import RiskSignal, Severity

__all__ = [
    "IPV4_SITE_PREFIX_BITS",
    "IPV6_SITE_PREFIX_BITS",
    "MAX_ASN",
    "SIGNAL_CODE",
    "MatchResult",
    "NetworkEnricher",
    "NetworkFacts",
    "NetworkRelation",
    "classify",
    "compare_facts",
    "pairing_network_signal",
    "sanitised",
]

#: The prefix two IPv4 addresses must share to be ``same_prefix``.
IPV4_SITE_PREFIX_BITS = 24

#: The prefix two IPv6 addresses must share to be ``same_prefix``.
IPV6_SITE_PREFIX_BITS = 48

#: The largest autonomous system number: ASNs are 32-bit (RFC 6793).
MAX_ASN = 4_294_967_295

#: The ``code`` of the one signal ``POST /scan`` records, upper case like the
#: read path's ``IMPOSSIBLE_TRAVEL``.
SIGNAL_CODE = "PAIRING_NETWORK"

#: Ranges whose /48 is shared by unrelated hosts, so an address inside one has
#: no truthful classification here and is ``unknown``. Each was measured on
#: CPython 3.12.13 with ``ipaddress``, and none is unwrapped by ``ipv4_mapped``
#: (``None`` for all of them):
#:
#: * ``64:ff9b::/96``, RFC 6052's well-known NAT64 prefix. It names the gateway,
#:   not a subscriber.
#: * ``64:ff9b:1::/48``, RFC 8215's local-use NAT64 prefix, the same flaw. It
#:   is not inside ``64:ff9b::/96`` (``64:ff9b:1::1 in ::/48`` is ``False``).
#: * ``::/96`` minus ``::`` and ``::1``, the deprecated IPv4-compatible
#:   addresses. ``::1.2.3.4`` and ``::a00:1`` both parse as plain IPv6 with
#:   ``ipv4_mapped is None`` and both lie in ``::/48``, so any two unrelated
#:   hosts would be ``same_prefix``.
#: * ``2001::/32``, Teredo. ``.teredo`` returns ``(server, client)`` and the
#:   embedded client is behind a tunnel, not the peer's network; the /48 is
#:   the relay's, shared by every client.
_UNKNOWN_RANGES = (
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("64:ff9b:1::/48"),
    ipaddress.IPv6Network("::/96"),
    ipaddress.IPv6Network("2001::/32"),
)

#: Inside ``::/96`` but not IPv4-compatible: the unspecified address and
#: loopback. They stay classified as they were.
_NOT_COMPATIBLE = frozenset({ipaddress.IPv6Address("::"), ipaddress.IPv6Address("::1")})

type _Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class NetworkRelation(StrEnum):
    """How the creator's address relates to the scanner's. Four values, closed."""

    SAME_IP = "same_ip"
    SAME_PREFIX = "same_prefix"
    DIFFERENT = "different"
    UNKNOWN = "unknown"


#: ``True``, ``False`` or the string ``"unknown"``, so that
#: ``details->>'asn_match'`` reads back as the text ``true``, ``false`` or
#: ``unknown`` uniformly.
type MatchResult = bool | Literal["unknown"]


@dataclass(frozen=True)
class NetworkFacts:
    """What an enricher knows about one address. Either field may be ``None``."""

    asn: int | None = None
    country: str | None = None


class NetworkEnricher(Protocol):
    """An installed provider of ASN and country facts for an address.

    ``None`` means "no data for this address", which is the normal answer for
    a private or reserved range. ASYNC, AND ALL I/O THROUGH ASYNC CLIENTS: a
    ``lookup`` that never yields, or that calls blocking I/O inside
    ``async def``, holds the event loop for every request on the replica, and
    the time budget ``POST /scan`` puts around it cannot stop that.
    """

    async def lookup(self, ip: str) -> NetworkFacts | None: ...


def _normalised(raw: str | None) -> _Address | None:
    """Parse ``raw``, drop an IPv6 zone and unwrap an IPv4-mapped address, or ``None``.

    A ZONE IS NOT PART OF THE ADDRESS. ``ip_address('fe80::1%eth0')`` has
    ``scope_id == 'eth0'`` and compares unequal to ``ip_address('fe80::1')``
    (measured), as does a different zone on the same address, so the zone is
    dropped by rebuilding the address from its packed bytes.

    UNWRAPPED BEFORE ANYTHING IS COMPARED, because every IPv4-mapped address
    has 80 zero bits before its ``ffff`` and so falls in ``::/48``: left
    mapped, any two unrelated IPv4 clients reaching a dual-stack socket would
    classify as ``same_prefix``, the benign-looking answer, which is the one
    direction this signal must not err in.
    """
    if raw is None:
        return None
    try:
        address = ipaddress.ip_address(raw)
    except (ValueError, TypeError):
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.scope_id is not None:
            address = ipaddress.IPv6Address(address.packed)
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
    return address


def _is_unknown_range(address: _Address) -> bool:
    if not isinstance(address, ipaddress.IPv6Address) or address in _NOT_COMPATIBLE:
        return False
    return any(address in network for network in _UNKNOWN_RANGES)


def _site(address: _Address) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    bits = IPV4_SITE_PREFIX_BITS if address.version == 4 else IPV6_SITE_PREFIX_BITS
    return ipaddress.ip_network(f"{address}/{bits}", strict=False)


def classify(creator_ip: str | None, scanner_ip: str | None) -> NetworkRelation:
    """The relation between two addresses. Total: it never raises.

    ``unknown`` when either is ``None``, either will not parse, or either lies
    in a range ``_UNKNOWN_RANGES`` lists (NAT64, IPv4-compatible, Teredo) after
    normalisation. An unparsable string is
    ``unknown`` rather than an exception because ``creator_ip`` is read back
    out of a store, and a corrupted value must not fail a scan. Mixed families
    are always ``different``.
    """
    creator = _normalised(creator_ip)
    scanner = _normalised(scanner_ip)
    if creator is None or scanner is None:
        return NetworkRelation.UNKNOWN
    for address in (creator, scanner):
        if _is_unknown_range(address):
            return NetworkRelation.UNKNOWN
    if creator == scanner:
        return NetworkRelation.SAME_IP
    if creator.version != scanner.version:
        return NetworkRelation.DIFFERENT
    if _site(creator) == _site(scanner):
        return NetworkRelation.SAME_PREFIX
    return NetworkRelation.DIFFERENT


def sanitised(facts: NetworkFacts) -> tuple[NetworkFacts, bool]:
    """``facts`` with every field that fails validation set to ``None``.

    Returns the cleaned facts and whether anything was discarded. ``asn`` must
    be an ``int`` that is not a ``bool`` and lies in 0 to ``MAX_ASN``;
    ``country`` must be two ASCII letters. A discarded value is never stored
    and never logged: the caller learns only that something was dropped.
    """
    asn = facts.asn
    country = facts.country
    asn_ok = asn is None or (
        isinstance(asn, int) and not isinstance(asn, bool) and 0 <= asn <= MAX_ASN
    )
    country_ok = country is None or (
        isinstance(country, str) and len(country) == 2 and country.isascii() and country.isalpha()
    )
    cleaned = NetworkFacts(
        asn=asn if asn_ok else None,
        country=country if country_ok else None,
    )
    return cleaned, not (asn_ok and country_ok)


def _match(creator: object, scanner: object) -> MatchResult:
    if creator is None or scanner is None:
        return "unknown"
    return creator == scanner


def compare_facts(
    creator: NetworkFacts | None, scanner: NetworkFacts | None
) -> tuple[MatchResult, MatchResult]:
    """``(asn_match, country_match)`` for two enricher answers.

    Per field: ``True`` when both sides carry a value and they are equal,
    ``False`` when both carry one and they differ, ``"unknown"`` otherwise.
    Country codes are compared after ``str.upper()``. For ``same_ip`` the
    caller passes the one answer as both arguments, so a returned field is
    ``True`` and a missing one ``"unknown"``.
    """
    if creator is None or scanner is None:
        return "unknown", "unknown"
    creator_country = creator.country.upper() if creator.country is not None else None
    scanner_country = scanner.country.upper() if scanner.country is not None else None
    return _match(creator.asn, scanner.asn), _match(creator_country, scanner_country)


def pairing_network_signal(
    relation: NetworkRelation,
    proxy_hops: int,
    asn_match: MatchResult | None = None,
    country_match: MatchResult | None = None,
) -> RiskSignal:
    """The one ``RiskSignal`` a successful scan records.

    ``severity`` is always ``LOW``, the severity whose ``RiskAction`` is to
    log: grading ``different`` higher would announce a policy nobody has
    decided. A match argument of ``None`` means no enricher is installed and
    omits its key, which a reader tells apart from ``"unknown"`` (an enricher
    was installed and could not answer) with ``details ? 'asn_match'``.

    NO ADDRESS, ASN OR COUNTRY IN ANY VALUE. The details carry only
    comparisons and a closed vocabulary chosen by this code, so nothing in
    them comes from a caller or a provider.
    """
    details: dict[str, object] = {"relation": relation.value, "proxy_hops": proxy_hops}
    if asn_match is not None:
        details["asn_match"] = asn_match
    if country_match is not None:
        details["country_match"] = country_match
    return RiskSignal(
        code=SIGNAL_CODE,
        description=f"pairing creator and scanner network relation: {relation.value}",
        severity=Severity.LOW,
        details=details,
    )

"""RFC 8707 resource indicators: the one normal form both services compare.

A layer-1 session token names the MCP server it is for in ``aud``, and RFC
8707 section 2 says what that value must be: "an absolute URI" that "MUST NOT
include a fragment component". Two places compare such a value with a
configured one: ``POST /token`` in `services/confirm`, against a ``resource``
parameter a client sends, and `services/api`'s startup refusal, against its
own ``POSTERN_AUDIENCE``. Both import this module so the two cannot disagree
about what "the same resource" means; ``.importlinter`` forbids either
service from importing the other.

THE NORMALIZATION IS RFC 3986 SECTIONS 6.2.2.1 AND 6.2.3 AND NOTHING ELSE.
The scheme and the host are lower-cased, an empty port or the scheme's default
port is removed, and an empty path becomes ``/``. The path stays
case-sensitive, percent-encoding is compared exactly as sent, and a trailing
slash on a non-empty path is significant, so ``https://mcp.example/mcp`` and
``https://mcp.example/mcp/`` are two resources. A configured audience is
required to be in this form already, so the string an operator types into both
services is the string compared.
"""

from __future__ import annotations

from urllib.parse import urlsplit

#: The ports RFC 3986 section 6.2.3 lets a normalizer drop, by scheme.
_DEFAULT_PORTS = {"https": 443, "http": 80}


def normalize_resource(value: str) -> str | None:
    """``value`` in the normal form above, or ``None`` when it cannot name a resource.

    ``None`` for an empty value, a value carrying ``#`` anywhere (a fragment,
    empty or not), a relative reference, a value with no host, and a port
    that does not parse. The caller answers each ``invalid_target``.
    """
    if not value or "#" in value:
        return None
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return None
    hostname = parts.hostname
    if not parts.scheme or not hostname:
        return None
    scheme = parts.scheme.lower()
    host = f"[{hostname}]" if ":" in hostname else hostname
    authority = host if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    userinfo, at, _ = parts.netloc.rpartition("@")
    if at:
        authority = f"{userinfo}@{authority}"
    query = f"?{parts.query}" if "?" in value else ""
    return f"{scheme}://{authority}{parts.path or '/'}{query}"


def is_normal_https_resource(value: str) -> bool:
    """Whether ``value`` is an absolute ``https`` URI with a host, already in normal form."""
    return value.startswith("https://") and normalize_resource(value) == value

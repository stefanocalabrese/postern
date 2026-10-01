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

ONE RESOURCE HAS EXACTLY ONE NORMAL FORM, AND TWO RESOURCES NEVER SHARE ONE.
Anything that could break either half is refused (``None``), never repaired.
The refusals added on 1 October 2026:

- A value that is not pure ASCII, or that carries a control character (tab,
  CR, LF and NUL included), a space, a backslash or ``%00``, checked on the
  raw string before ``urlsplit`` sees it. ``urlsplit`` deletes tab, CR and LF
  anywhere and whitespace at the start, and ``str.lower`` maps U+212A KELVIN
  SIGN to ASCII ``k``; each of those merged a different value into a real one.
  Lower-casing happens only after this check, so only on ASCII.
- The host is taken from the raw netloc, never from ``SplitResult.hostname``,
  so brackets survive, and a bracketed host with no ``:`` (an IPvFuture
  literal such as ``[v1.mcp.example]``) is refused.
- Any ``@`` in the netloc. RFC 9110 section 4.2.4: "A sender MUST NOT
  generate the userinfo subcomponent (and its "@" delimiter) when an "http"
  or "https" URI reference is generated within a message as a target URI or
  field value."
- Port 0, and a ``;`` or a ``%`` in the host.

NOT CANONICALISED, SO THESE FAIL CLOSED: IPv6 spellings and a trailing dot on
a host. ``[2001:db8:0::1]`` and ``[2001:db8::1]`` are one address with two
normal forms here, and so are ``mcp.example.`` and ``mcp.example`` for one DNS
name. That splits one resource in two and never merges two, so a client that
spells it differently from the configuration is refused, and an operator must
configure the exact string the client sends.
"""

from __future__ import annotations

from urllib.parse import urlsplit

#: The ports RFC 3986 section 6.2.3 lets a normalizer drop, by scheme.
_DEFAULT_PORTS = {"https": 443, "http": 80}

#: The highest TCP port; 0 is refused separately.
_MAX_PORT = 65535


def is_plain_ascii_uri_text(value: str) -> bool:
    """Whether ``value`` is pure ASCII with no control character, space, backslash or ``%00``.

    The check a URI compared by this package passes on its raw string, before
    any parser sees it. `services/confirm` applies it to the session issuer.
    """
    if not value.isascii() or "%00" in value:
        return False
    return not any(char <= " " or char == "\x7f" or char == "\\" for char in value)


def _split_host_port(netloc: str) -> tuple[str, str] | None:
    """The raw host and raw port text of ``netloc``, or ``None`` when it is malformed."""
    if netloc.startswith("["):
        close = netloc.find("]")
        if close == -1:
            return None
        host, rest = netloc[: close + 1], netloc[close + 1 :]
        if ":" not in host or (rest and not rest.startswith(":")):
            return None
        return host, rest[1:]
    if "[" in netloc or "]" in netloc:
        return None
    host, _, port = netloc.partition(":")
    return host, port


def normalize_resource(value: str) -> str | None:
    """``value`` in the normal form above, or ``None`` when it cannot name a resource.

    ``None`` for an empty value, a value carrying ``#`` anywhere (a fragment,
    empty or not), a relative reference, a value with no host, a port that
    does not parse or is 0, and every refusal the module docstring lists. The
    caller answers each ``invalid_target``.
    """
    if not value or "#" in value or not is_plain_ascii_uri_text(value):
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    netloc = parts.netloc
    if not parts.scheme or not netloc or "@" in netloc:
        return None
    split = _split_host_port(netloc)
    if split is None:
        return None
    raw_host, raw_port = split
    if not raw_host or ";" in raw_host or "%" in raw_host:
        return None
    if raw_port and not raw_port.isdigit():
        return None
    port = int(raw_port) if raw_port else None
    if port is not None and not 0 < port <= _MAX_PORT:
        return None
    scheme = parts.scheme.lower()
    host = raw_host.lower()
    authority = host if port is None or port == _DEFAULT_PORTS.get(scheme) else f"{host}:{port}"
    query = f"?{parts.query}" if "?" in value else ""
    return f"{scheme}://{authority}{parts.path or '/'}{query}"


def is_normal_https_resource(value: str) -> bool:
    """Whether ``value`` is an absolute ``https`` URI with a host, already in normal form."""
    return value.startswith("https://") and normalize_resource(value) == value

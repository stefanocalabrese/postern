"""The layer-1 session token's time bounds, shared by the service that mints it
and the one that verifies it.

``services/confirm/session_token.py`` stamps ``exp = iat + ACCESS_TOKEN_LIFETIME_SECONDS``
on every access token, and ``services/api/session_verifier.py`` refuses one
whose ``exp`` lies further ahead than that plus ``SESSION_CLOCK_SKEW_SECONDS``.
One constant in the shared library, because ``.importlinter`` forbids either
service importing the other, and two copies of a number are two numbers.
Moved here from ``services/confirm/session_token.py`` on 2 October 2026; that
module re-exports it.
"""

from __future__ import annotations

__all__ = ["ACCESS_TOKEN_LIFETIME_SECONDS", "SESSION_CLOCK_SKEW_SECONDS"]

#: How long an access token lives, in seconds. A code constant rather than a
#: setting: the family's absolute lifetime is one hour and this is a tenth of
#: it, and decision record 0010's amendment counts on the number.
ACCESS_TOKEN_LIFETIME_SECONDS = 600

#: How far the verifier lets ``exp``, ``iat`` and ``nbf`` run ahead of its own
#: clock, in seconds. The value ``services/confirm/auth.py`` allows app
#: assertions, for the same reason: two hosts' clocks, not an attacker.
SESSION_CLOCK_SKEW_SECONDS = 30

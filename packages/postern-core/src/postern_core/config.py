"""Bounded readers for the numeric settings both services take from the environment.

WHY THIS EXISTS. Every number in `services/api/settings.py` and
`services/confirm/settings.py` was read with a bare ``int()`` or ``float()``
until 2026-09-25, which accepts two classes of value the services cannot run
on:

- AN EMPTY STRING. ``POSTERN_CACHE_TTL_SECONDS=`` is how this repository's
  ``docker-compose.yml`` and `services/api/settings.py`'s `from_env`
  already spell "unset" for the string fields (``os.environ.get(...) or
  None``). Through a bare ``int()`` it is instead ``ValueError: invalid
  literal for int() with base 10: ''`` -- a message that names neither the
  variable nor the service.
- ZERO AND NEGATIVES, silently. Measured on 2026-09-25, each against the
  real dependency rather than argued: ``connect``/``read``/``write`` at 0.0
  or below make httpx2 2.12.0 raise ``ConnectTimeout``/``ReadTimeout``/
  ``WriteTimeout`` against a local server that answers in a millisecond;
  asyncpg refuses ``command_timeout=0`` with its own ``ValueError`` at the
  first connect, and ``connect(timeout=0)`` raises ``TimeoutError`` against a
  reachable Postgres; ``InMemoryDeviceCodeStore(max_codes=0)`` raises
  ``DeviceCodeStoreFull`` on the first pairing.

WHAT THE HELPERS BELOW ADD, and it is only these three things: an empty
string means unset, a value outside the bound raises, and the message names
the variable so the operator knows which line to edit. They do not pick
bounds. Each caller states its own, with its own reason, at the call site.

WHY IN ``postern_core`` AND NOT IN EACH SERVICE. `.importlinter` forbids
``services.api`` and ``services.confirm`` from importing each other in either
direction, so a helper either lives in the one library both already import or
is copied twice and drifts. `postern_core.net`'s ``client_ip`` is the
existing precedent: one implementation of a decision both services must make
identically, imported by each service's own middleware. Nothing here reads
the environment on its own behalf or holds state, so it adds no coupling
beyond the function call.

WHY AT PARSE TIME RATHER THAN AT FIRST USE. Three of these values already
had a bound somewhere further in -- ``RequestDeadline.__init__`` refuses a
non-positive deadline, ``RiskMiddleware.__init__`` and ``client_ip`` refuse
negative hops, and FastMCP 4.0.3's ``build_cache_hints`` refuses a
``cache_ttl`` at or below zero -- and every one of those messages names the
PARAMETER, not the environment variable that set it. An operator reading
``cache_ttl must be a positive integer, got 0`` has to find which of this
repository's variables reaches that argument. Moving the refusal to
``from_env`` keeps the same values legal and makes the message actionable;
the inner guards stay where they are, as the backstop for a caller that does
not come from ``from_env`` at all.
"""

from __future__ import annotations

import math
import os

__all__ = ["float_from_env", "int_from_env"]


def _int_phrase(minimum: int) -> str:
    """How the message names the bound.

    ``minimum=1`` produces "a positive integer", which is verbatim what
    `services/confirm/settings.py`'s `_positive_int` said before it was
    rewired through this function -- the two rate-limit messages it raises
    are unchanged to the byte, which
    ``tests/test_settings_bounds.py::TestPositiveIntMessagesAreUnchanged``
    pins.
    """
    if minimum == 1:
        return "a positive integer"
    if minimum == 0:
        return "zero or a positive integer"
    return f"an integer of at least {minimum}"


def _float_phrase(minimum: float, exclusive: bool) -> str:
    if minimum == 0:
        return "a number greater than zero" if exclusive else "zero or a positive number"
    comparison = "greater than" if exclusive else "of at least"
    return f"a number {comparison} {minimum}"


def int_from_env(name: str, default: int, *, minimum: int, because: str) -> int:
    """Read ``name`` as an integer of at least ``minimum``, or refuse to start.

    Args:
        name: The environment variable, echoed in every refusal so the
            operator learns which line to edit rather than which parameter
            was unhappy.
        default: Returned when the variable is unset OR set to an empty
            string. Never returned for a value that was set and rejected.
        minimum: The smallest value the caller can run on, INCLUSIVE.
        because: One sentence saying what the number is and why the bound
            exists. Appended to both refusals, so an operator gets the reason
            in the failure and not only in a comment they would have to go
            and find.

    Returns:
        The parsed value, or ``default``.

    Raises:
        ValueError: if the value is not an integer, or is below ``minimum``.

    WHY AN EMPTY STRING IS "UNSET" AND NOT AN ERROR. It is already this
    repository's convention for "off": `services/api/settings.py`'s
    `from_env` collapses ``""`` to ``None`` for five string fields and its
    docstring records why (an unset variable and ``POSTERN_JWKS_URI=`` must
    reach the same branch), and ``docker-compose.yml`` sets variables it
    means to leave unset to the empty string. A numeric reader that treated
    it as a typo would make the two halves of one convention disagree.

    WHY A REJECTED VALUE RAISES RATHER THAN FALLING BACK TO ``default``, in
    the words `services/confirm/settings.py`'s `_positive_int` put it in
    first: a value an operator typed and got wrong must fail when the app is
    assembled, because silently keeping the default means the variable they
    set to fix an outage did nothing, and they find out from the same alert
    they were already looking at.

    The offending value is echoed. That is an operator's own environment,
    not caller input -- the opposite of the rule
    `services/confirm/device_auth.py` follows for a malformed customer
    reference, which is attacker-reachable and never logged.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    phrase = _int_phrase(minimum)
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be {phrase}, got {raw!r}. {because}") from None
    if value < minimum:
        raise ValueError(f"{name} must be {phrase}, got {value}. {because}")
    return value


def float_from_env(
    name: str,
    default: float,
    *,
    minimum: float,
    exclusive: bool = False,
    because: str,
) -> float:
    """Read ``name`` as a finite float at or above ``minimum``, or refuse to start.

    Args:
        name: The environment variable, echoed in every refusal.
        default: Returned when the variable is unset or empty.
        minimum: The bound, inclusive unless ``exclusive``.
        exclusive: ``True`` when ``minimum`` itself is out of range. Every
            deadline in this repository except the two pool timeouts passes
            ``minimum=0, exclusive=True``, because zero seconds is not a
            short wait but no wait at all.
        because: One sentence, appended to both refusals.

    Returns:
        The parsed value, or ``default``.

    Raises:
        ValueError: if the value is not a number, is not finite, or is out of
            range.

    WHY ``math.isfinite`` IS CHECKED SEPARATELY, and this is the case a
    ``value <= 0`` test alone does not catch. ``float()`` accepts ``nan``,
    ``inf``, ``Infinity`` and any overflowing literal such as ``1e400``, and
    measured on 2026-09-25 ``nan <= 0`` and ``nan < 0`` are BOTH ``False``,
    so a NaN passes a lower bound written either way and reaches the
    dependency. Infinity passes too, and a timeout of infinity is the off
    switch these bounds exist to deny -- ``POSTERN_REQUEST_DEADLINE_SECONDS=inf``
    would leave `services/api/asgi/request_deadline.py`'s `RequestDeadline`
    installed, past its own ``seconds <= 0`` guard, and bounding nothing.
    """
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    phrase = _float_phrase(minimum, exclusive)
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"{name} must be {phrase}, got {raw!r}. {because}") from None
    if not math.isfinite(value):
        raise ValueError(f"{name} must be {phrase}, got {raw!r}. {because}")
    if value < minimum or (exclusive and value == minimum):
        raise ValueError(f"{name} must be {phrase}, got {value}. {because}")
    return value

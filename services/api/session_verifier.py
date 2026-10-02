"""The api's verifier for layer-1 session tokens, with a JWKS cache that is bounded.

``services/api`` accepts the access tokens ``services/confirm`` issues at
``POST /token``: signed by the SESSION key and published at confirm's
``/session/jwks.json``, which this service fetches from ``POSTERN_JWKS_URI``.
FastMCP 4.0.3's ``JWTVerifier`` already checks the signature against the key
the token's ``kid`` names, ``exp`` when present, ``iss`` and ``aud``; what it
does not do is bound its JWKS fetches, require ``exp``, or read ``iat`` or
``nbf``.

WHAT THE PARENT DOES, read in the installed ``fastmcp/server/auth/providers/jwt.py``
rather than recalled: its constructor sets a one-hour cache TTL, and its
``_get_jwks_key`` serves from the cache only while the cache is younger than
that AND the ``kid`` is in it. Any other case fetches, with a fresh
``httpx2.AsyncClient`` unless one was injected. There is no floor on refetches
and no negative cache, so every token carrying an unseen ``kid`` causes one
outbound fetch -- an unauthenticated caller can drive them at the api's full
request rate -- and a key removed from the published set stays trusted for up
to an hour. Its ``load_access_token`` refuses ``exp`` only when the claim is
present (``exp is not None and exp < time.time()``), and joserfc validates no
claim, so a token minted without ``exp`` verified forever.

WHAT THIS CHANGES, and nothing else:

- the cache lives ``cache_ttl_seconds`` (``POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS``,
  300 by default), so a removed key stops verifying within that;
- a ``kid`` the cache has never held is fetched for at most once per
  `MIN_REFETCH_INTERVAL_SECONDS`, and refused without a fetch in between: the
  negative cache;
- one fetch at a time, under an ``asyncio.Lock``, and callers that waited on
  it read its result instead of fetching again;
- a fetch is bounded by `FETCH_TIMEOUT_SECONDS` (2 October 2026), so an
  endpoint that accepts the connection and drips, or never answers, holds the
  lock for that long and no longer;
- a fetch that FAILS leaves the cache as it was and holds every further fetch
  to the same floor, so an unreachable JWKS endpoint is asked at most once per
  interval rather than once per request. FAILS means any of them: an HTTP
  error, the bound above, a body that is not JSON, a 200 whose JSON is not
  ``{"keys": [...]}``, and a key set that yields no usable key where the
  previous one had some. Until 2 October 2026 the 200s erased the cache,
  because the parent empties it before it parses;
- a fetched key whose RFC 7638 thumbprint equals one of this service's own
  READ key is dropped before it is cached, with one fixed WARNING per fetch
  (2 October 2026). Startup cannot fetch confirm's key set, so this holds at
  fetch time, and the read key is re-read on every fetch, so a version Vault
  publishes after startup is covered: a misconfigured ``POSTERN_JWKS_URI``
  that points at this service's own ``/.well-known/jwks.json``, or a session
  key that is the read key, fails closed instead of accepting read-key tokens
  as sessions;
- after the parent accepts a token, ``exp`` must be a number no further ahead
  than ``ACCESS_TOKEN_LIFETIME_SECONDS`` plus ``SESSION_CLOCK_SKEW_SECONDS``,
  and ``iat`` and ``nbf``, when present, numbers no further ahead than the
  skew (2 October 2026).

AVAILABILITY DEPENDS ON CONFIRM'S KEY SET, BY DESIGN. Once the cache is older
than its TTL, no session token verifies until a fetch succeeds; a failed
refresh keeps the old set but does not serve it as fresh. So the grace after
confirm's ``/session/jwks.json`` becomes unreachable is what is left of one
TTL, and then the api refuses every customer. Failing closed is the intent: a
key set that cannot be re-read cannot show that a key was not withdrawn.

IT OVERRIDES TWO PRIVATE METHODS of a pinned dependency (``fastmcp>=4.0.3,<5``),
``_get_jwks_key`` and ``_fetch_jwks``.
``tests/test_session_verifier.py`` pins both signatures and drives a
counting JWKS server through the assembled app, because a signature that
still matches does not prove the override is still called. Re-run that test,
not only keep it green, on every ``fastmcp`` version bump.

PER PROCESS. The floor and the coalescing live on one object, so "one fetch per
30 seconds on a miss plus one per TTL" is per api worker process; the
Dockerfile's ``api`` target runs one uvicorn worker per container today.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Callable, Iterable
from typing import Any, TypeGuard

from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.jwt import JWTVerifier
from postern_core.auth.jwk_thumbprint import jwk_thumbprints
from postern_core.auth.session_lifetime import (
    ACCESS_TOKEN_LIFETIME_SECONDS,
    SESSION_CLOCK_SKEW_SECONDS,
)

logger = logging.getLogger(__name__)

#: The floor under fetches for a ``kid`` the cache has never held, in seconds.
MIN_REFETCH_INTERVAL_SECONDS = 30.0

#: The bound on one JWKS fetch, in seconds, connect to parsed body. Below the
#: parent's own 10-second client timeout, which bounds each phase and not the
#: whole, so a server dripping one byte a second never trips it. A caller
#: waits on the lock behind this fetch only when the fresh cache cannot answer
#: it: an unknown kid, or any kid once the cache is past its TTL. A caller whose
#: kid the fresh cache holds is served without the lock (2 October 2026).
FETCH_TIMEOUT_SECONDS = 5.0

#: Logged once per fetch that dropped a key, and fixed: no kid, no key bytes.
READ_KEY_PUBLISHED_WARNING = (
    "The session key set at POSTERN_JWKS_URI publishes a key that is this "
    "service's own READ key (equal RFC 7638 thumbprint). It was dropped and no "
    "token signed by it will verify. POSTERN_JWKS_URI must name "
    "services/confirm's /session/jwks.json, and the session key must be a "
    "different key from the read key."
)


def _no_thumbprints() -> Iterable[str]:
    return ()


def _is_time(value: Any) -> TypeGuard[int | float]:
    """A finite JSON number; ``bool`` excluded, as ``services/confirm/auth.py`` does."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return math.isfinite(value)


def _time_claim_refusal(claims: dict[str, Any], now: float) -> str | None:
    """Why a token the parent accepted must still be refused, or ``None``.

    The returned string goes into a log line and never a claim value.
    """
    exp = claims.get("exp")
    if not _is_time(exp):
        return "token carries no numeric exp"
    if exp - now > ACCESS_TOKEN_LIFETIME_SECONDS + SESSION_CLOCK_SKEW_SECONDS:
        return "token exp is beyond the session token lifetime"
    for name in ("iat", "nbf"):
        if name in claims:
            value = claims[name]
            if not _is_time(value) or value - now > SESSION_CLOCK_SKEW_SECONDS:
                return f"token {name} is not a number or is in the future"
    return None


class SessionTokenVerifier(JWTVerifier):
    """``JWTVerifier`` with a bounded JWKS cache; see the module docstring."""

    def __init__(
        self,
        *,
        cache_ttl_seconds: float,
        min_refetch_interval_seconds: float = MIN_REFETCH_INTERVAL_SECONDS,
        forbidden_thumbprints: Callable[[], Iterable[str]] = _no_thumbprints,
        fetch_timeout_seconds: float = FETCH_TIMEOUT_SECONDS,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._session_ttl = cache_ttl_seconds
        self._refetch_floor = min_refetch_interval_seconds
        self._forbidden_thumbprints = forbidden_thumbprints
        self._fetch_timeout = fetch_timeout_seconds
        # The parent serves from its cache while `now - _jwks_cache_time <
        # _cache_ttl`; at zero that never holds on a clock that does not run
        # backwards, so `super()._get_jwks_key` always fetches. Every cache
        # decision is this class's, in `_get_jwks_key` below.
        self._cache_ttl = 0
        self._last_fetch = float("-inf")
        self._last_fetch_failed = False
        self._fetch_lock = asyncio.Lock()

    async def load_access_token(self, token: str) -> AccessToken | None:
        access = await super().load_access_token(token)
        if access is None:
            return None
        refusal = _time_claim_refusal(access.claims, time.time())
        if refusal is not None:
            logger.info("Session token rejected: %s", refusal)
            return None
        return access

    async def _fetch_jwks(self) -> dict[str, Any]:
        """The parent's fetch, refused unless it is a key set, minus every key
        whose thumbprint is the read key's.

        Here and not after the parent's parse, because the parent caches and
        returns a key in one step: a key dropped here never reaches the cache,
        so a token naming its kid is an unknown kid, held to the floor like
        any other. An entry whose ``kty`` is not a string is kept, for the
        parent to skip. The read key is read here, on every fetch, and any
        exception from reading it fails the fetch.
        """
        data = await super()._fetch_jwks()
        if not (isinstance(data, dict) and isinstance(data.get("keys"), list)):
            raise ValueError('JWKS answer is not a {"keys": [...]} object')
        try:
            forbidden = frozenset(self._forbidden_thumbprints())
        except Exception as error:
            raise ValueError(
                f"the read key's thumbprints could not be read ({type(error).__name__})"
            ) from error
        if not forbidden:
            return data
        keys = data["keys"]
        kept = [jwk for jwk in keys if not self._is_forbidden(jwk, forbidden)]
        if len(kept) != len(keys):
            logger.warning(READ_KEY_PUBLISHED_WARNING)
        return {**data, "keys": kept}

    @staticmethod
    def _is_forbidden(jwk: Any, forbidden: frozenset[str]) -> bool:
        if not isinstance(jwk, dict) or not isinstance(jwk.get("kty"), str):
            return False
        return bool(jwk_thumbprints({"keys": [jwk]}) & forbidden)

    def _cached(self, kid: str | None, now: float) -> str | None:
        """The cached key for ``kid`` while the cache is fresh, else ``None``."""
        if now - self._jwks_cache_time >= self._session_ttl:
            return None
        if kid:
            return self._jwks_cache.get(kid)
        if len(self._jwks_cache) == 1:
            return next(iter(self._jwks_cache.values()))
        return None

    def _known(self, kid: str | None) -> bool:
        """Whether the last fetch published ``kid``, however long ago."""
        if kid:
            return kid in self._jwks_cache
        return len(self._jwks_cache) == 1

    async def _get_jwks_key(self, kid: str | None) -> str:
        key = self._cached(kid, time.time())
        if key is not None:
            return key
        async with self._fetch_lock:
            now = time.time()
            # A caller that waited on the lock reads what the fetch it waited
            # for found, instead of fetching again.
            key = self._cached(kid, now)
            if key is not None:
                return key
            too_soon = now - self._last_fetch < self._refetch_floor
            if too_soon and (self._last_fetch_failed or not self._known(kid)):
                # THE NEGATIVE CACHE: this kid was not published at the last
                # fetch, or that fetch failed, and it is too recent to repeat.
                raise ValueError(f"Key ID {kid!r} not found in JWKS")
            self._last_fetch = now
            previous = self._jwks_cache_time
            # The parent REBINDS `_jwks_cache` to an empty dict before it
            # parses the answer, so a 200 whose body is not a key set used to
            # erase every cached key (2 October 2026). Holding the old dict
            # here is enough to put it back: the parent never mutates it.
            previous_keys = self._jwks_cache
            # The parent's own cache check cannot serve: `__init__` set its
            # TTL to zero, so it fetches whenever it is called. The shared
            # cache time is NOT zeroed here, which it was until 2 October
            # 2026: that made every concurrent caller whose kid the fresh
            # cache held find it stale and queue on this lock behind the fetch.
            try:
                async with asyncio.timeout(self._fetch_timeout):
                    return await super()._get_jwks_key(kid)
            except TimeoutError as error:
                # A `ValueError`, because the parent's `load_access_token`
                # turns only that family into a refusal: a bare
                # `TimeoutError` would surface as a 500.
                raise ValueError("JWKS fetch timed out") from error
            finally:
                # Zero usable keys where there were some is a failure too: a
                # key set confirm meant to empty still expires with the TTL.
                # The parent stamps the cache time, with the clock it read
                # before fetching, only after a fetch that parsed. That stamp
                # cannot equal `previous`: a refetch comes at least the floor
                # after the last fetch, or once the cache is past its TTL.
                emptied = bool(previous_keys) and not self._jwks_cache
                stamped = self._jwks_cache_time != previous
                self._last_fetch_failed = not stamped or emptied
                if self._last_fetch_failed:
                    self._jwks_cache = previous_keys
                    self._jwks_cache_time = previous

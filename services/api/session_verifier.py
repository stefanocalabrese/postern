"""The api's verifier for layer-1 session tokens, with a JWKS cache that is bounded.

``services/api`` accepts the access tokens ``services/confirm`` issues at
``POST /token``: signed by the SESSION key and published at confirm's
``/session/jwks.json``, which this service fetches from ``POSTERN_JWKS_URI``.
FastMCP 4.0.3's ``JWTVerifier`` already checks the signature against the key
the token's ``kid`` names, ``exp``, ``iss`` and ``aud``; what it does not do
is bound its JWKS fetches.

WHAT THE PARENT DOES, read in the installed ``fastmcp/server/auth/providers/jwt.py``
rather than recalled: its constructor sets a one-hour cache TTL, and its
``_get_jwks_key`` serves from the cache only while the cache is younger than
that AND the ``kid`` is in it. Any other case fetches, with a fresh
``httpx2.AsyncClient`` unless one was injected. There is no floor on refetches
and no negative cache, so every token carrying an unseen ``kid`` causes one
outbound fetch -- an unauthenticated caller can drive them at the api's full
request rate -- and a key removed from the published set stays trusted for up
to an hour.

WHAT THIS CHANGES, and nothing else:

- the cache lives ``cache_ttl_seconds`` (``POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS``,
  300 by default), so a removed key stops verifying within that;
- a ``kid`` the cache has never held is fetched for at most once per
  `MIN_REFETCH_INTERVAL_SECONDS`, and refused without a fetch in between: the
  negative cache;
- one fetch at a time, under an ``asyncio.Lock``, and callers that waited on
  it read its result instead of fetching again;
- a fetch that FAILS leaves the cache as it was and holds every further fetch
  to the same floor, so an unreachable JWKS endpoint is asked at most once per
  interval rather than once per request.

IT OVERRIDES A PRIVATE METHOD of a pinned dependency (``fastmcp>=4.0.3,<5``).
``tests/test_session_verifier.py`` pins the parent's signature and drives a
counting JWKS server through the assembled app, because a signature that
still matches does not prove the override is still called. Re-run that test,
not only keep it green, on every ``fastmcp`` version bump.

PER PROCESS. The floor and the coalescing live on one object, so "one fetch per
30 seconds on a miss plus one per TTL" is per api worker process; the
Dockerfile's ``api`` target runs one uvicorn worker per container today.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from fastmcp.server.auth.providers.jwt import JWTVerifier

#: The floor under fetches for a ``kid`` the cache has never held, in seconds.
MIN_REFETCH_INTERVAL_SECONDS = 30.0


class SessionTokenVerifier(JWTVerifier):
    """``JWTVerifier`` with a bounded JWKS cache; see the module docstring."""

    def __init__(
        self,
        *,
        cache_ttl_seconds: float,
        min_refetch_interval_seconds: float = MIN_REFETCH_INTERVAL_SECONDS,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._session_ttl = cache_ttl_seconds
        self._refetch_floor = min_refetch_interval_seconds
        self._last_fetch = float("-inf")
        self._last_fetch_failed = False
        self._fetch_lock = asyncio.Lock()

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
            # Force the parent past its own cache check, whose TTL is an hour:
            # this method has already decided a fetch is owed. The parent
            # stamps the cache time only after a fetch that succeeded.
            self._jwks_cache_time = 0
            try:
                return await super()._get_jwks_key(kid)
            finally:
                self._last_fetch_failed = self._jwks_cache_time == 0
                if self._last_fetch_failed:
                    self._jwks_cache_time = previous

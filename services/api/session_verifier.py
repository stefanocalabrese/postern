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
  interval rather than once per request. FAILS means any of them: an HTTP
  error, a timeout, a body that is not JSON, and a 200 whose JSON is not a key
  set, which until 2 October 2026 erased the cache because the parent empties
  it before it parses;
- a fetched key whose RFC 7638 thumbprint equals one of this service's own
  READ key is dropped before it is cached, with one fixed WARNING per fetch
  (2 October 2026). Startup cannot fetch confirm's key set, so this holds at
  fetch time: a misconfigured ``POSTERN_JWKS_URI`` that points at this
  service's own ``/.well-known/jwks.json``, or a session key that is the read
  key, fails closed instead of accepting read-key tokens as sessions.

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
import time
from collections.abc import Iterable
from typing import Any

from fastmcp.server.auth.providers.jwt import JWTVerifier
from postern_core.auth.jwk_thumbprint import jwk_thumbprints

logger = logging.getLogger(__name__)

#: The floor under fetches for a ``kid`` the cache has never held, in seconds.
MIN_REFETCH_INTERVAL_SECONDS = 30.0

#: Logged once per fetch that dropped a key, and fixed: no kid, no key bytes.
READ_KEY_PUBLISHED_WARNING = (
    "The session key set at POSTERN_JWKS_URI publishes a key that is this "
    "service's own READ key (equal RFC 7638 thumbprint). It was dropped and no "
    "token signed by it will verify. POSTERN_JWKS_URI must name "
    "services/confirm's /session/jwks.json, and the session key must be a "
    "different key from the read key."
)


class SessionTokenVerifier(JWTVerifier):
    """``JWTVerifier`` with a bounded JWKS cache; see the module docstring."""

    def __init__(
        self,
        *,
        cache_ttl_seconds: float,
        min_refetch_interval_seconds: float = MIN_REFETCH_INTERVAL_SECONDS,
        forbidden_thumbprints: Iterable[str] = (),
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._session_ttl = cache_ttl_seconds
        self._refetch_floor = min_refetch_interval_seconds
        self._forbidden = frozenset(forbidden_thumbprints)
        self._last_fetch = float("-inf")
        self._last_fetch_failed = False
        self._fetch_lock = asyncio.Lock()

    async def _fetch_jwks(self) -> dict[str, Any]:
        """The parent's fetch, minus every key whose thumbprint is forbidden.

        Here and not after the parent's parse, because the parent caches and
        returns a key in one step: a key dropped here never reaches the cache,
        so a token naming its kid is an unknown kid, held to the floor like
        any other. An answer that is not a ``{"keys": [...]}`` object is
        returned untouched, for the parent to fail on; an entry whose ``kty``
        is not a string is kept, for the parent to skip.
        """
        data = await super()._fetch_jwks()
        if not self._forbidden or not isinstance(data, dict):
            return data
        keys = data.get("keys")
        if not isinstance(keys, list):
            return data
        kept = [jwk for jwk in keys if not self._is_forbidden(jwk)]
        if len(kept) != len(keys):
            logger.warning(READ_KEY_PUBLISHED_WARNING)
        return {**data, "keys": kept}

    def _is_forbidden(self, jwk: Any) -> bool:
        if not isinstance(jwk, dict) or not isinstance(jwk.get("kty"), str):
            return False
        return bool(jwk_thumbprints({"keys": [jwk]}) & self._forbidden)

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
            # Force the parent past its own cache check, whose TTL is an hour:
            # this method has already decided a fetch is owed. The parent
            # stamps the cache time only after a fetch that succeeded.
            self._jwks_cache_time = 0
            try:
                return await super()._get_jwks_key(kid)
            finally:
                self._last_fetch_failed = self._jwks_cache_time == 0
                if self._last_fetch_failed:
                    self._jwks_cache = previous_keys
                    self._jwks_cache_time = previous

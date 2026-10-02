"""``services/api``'s session-token verifier and its bounded JWKS cache (spec section 8).

Three layers. The private method this subclass overrides is pinned against
the installed FastMCP. The cache's rules are driven directly, with an
injected client counting fetches. And the whole thing is driven through the
assembled ``build_server`` app against a real HTTP JWKS server that counts
the requests it receives, because a signature pin does not prove the
override is called: if an upgrade stops routing through ``_get_jwks_key``,
the last test sees FastMCP's unbounded refetch and fails. Re-run it on every
``fastmcp`` version bump.
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import logging
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey
from postern_core.auth.jwk_thumbprint import jwk_thumbprints
from postern_core.auth.session_lifetime import (
    ACCESS_TOKEN_LIFETIME_SECONDS,
    SESSION_CLOCK_SKEW_SECONDS,
)

from services.api.main import create_app
from services.api.server import build_server
from services.api.session_verifier import (
    FETCH_TIMEOUT_SECONDS,
    MIN_REFETCH_INTERVAL_SECONDS,
    READ_KEY_PUBLISHED_WARNING,
    SessionTokenVerifier,
)
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER

ISSUER = "https://auth.postern.test"
AUDIENCE = "https://mcp.postern.test/mcp"
JWKS_URI = "https://auth.postern.test/session/jwks.json"


def _key(kid: str) -> RSAKey:
    return RSAKey.generate_key(2048, parameters={"kid": kid, "use": "sig", "alg": "RS256"})


def _jwks(*keys: RSAKey) -> dict[str, Any]:
    return dict(KeySet(list(keys)).as_dict(private=False))


def _token(key: RSAKey, *, kid: str | None = None) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "cust_7f3a",
        "client_id": "claude-code",
        "jti": f"j-{now}",
        "iat": now,
        "exp": now + 600,
    }
    return jwt.encode({"alg": "RS256", "kid": kid or str(key.kid)}, claims, key)


class CountingJwks:
    """An httpx2 handler that serves a mutable key set and counts requests."""

    def __init__(self, jwks: dict[str, Any], *, delay: float = 0.0, fail: bool = False) -> None:
        self.jwks = jwks
        self.delay = delay
        self.fail = fail
        # When set, answers every request in place of the key set: a
        # malformed 200, or an exception such as a timeout.
        self.answer: Callable[[httpx2.Request], Any] | None = None
        self.fetches = 0

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.fetches += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.answer is not None:
            answered = self.answer(request)
            response: httpx2.Response = (
                await answered if inspect.isawaitable(answered) else answered
            )
            return response
        if self.fail:
            return httpx2.Response(503, json={})
        return httpx2.Response(200, json=self.jwks)


def _verifier(
    handler: CountingJwks,
    *,
    ttl: float = 300.0,
    forbidden: frozenset[str] | Callable[[], Iterable[str]] = frozenset(),
    fetch_timeout: float = FETCH_TIMEOUT_SECONDS,
) -> SessionTokenVerifier:
    return SessionTokenVerifier(
        jwks_uri=JWKS_URI,
        issuer=ISSUER,
        audience=AUDIENCE,
        required_scopes=None,
        cache_ttl_seconds=ttl,
        forbidden_thumbprints=forbidden if callable(forbidden) else (lambda: forbidden),
        fetch_timeout_seconds=fetch_timeout,
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
    )


def _signed(key: RSAKey, **overrides: Any) -> str:
    """A token over ``_claims()`` with ``overrides`` applied; ``None`` deletes."""
    claims = _claims()
    for name, value in overrides.items():
        if value is None:
            claims.pop(name, None)
        else:
            claims[name] = value
    return jwt.encode({"alg": "RS256", "kid": str(key.kid)}, claims, key)


async def _never(request: httpx2.Request) -> httpx2.Response:
    """A JWKS endpoint that accepts the request and never answers."""
    await asyncio.Event().wait()
    raise AssertionError("unreachable")


def _padded(jwks: dict[str, Any]) -> dict[str, Any]:
    """``jwks`` with a zero octet prefixed to every RSA ``n``: the same key,
    encoded the way RFC 7518 section 6.3.1.1 forbids and a parser may accept."""
    keys = []
    for jwk in jwks["keys"]:
        raw = base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4))
        padded = base64.urlsafe_b64encode(b"\x00" + raw).rstrip(b"=").decode()
        keys.append({**jwk, "n": padded})
    return {"keys": keys}


def _claims() -> dict[str, Any]:
    now = int(time.time())
    return {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "cust_7f3a",
        "client_id": "claude-code",
        "jti": f"j-{now}",
        "iat": now,
        "exp": now + 600,
    }


def _timeout(request: httpx2.Request) -> httpx2.Response:
    raise httpx2.ReadTimeout("timed out", request=request)


#: Every way a fetch can fail after the transport answered, or instead of it.
#: The 200s reach the parent's parser after it has emptied its cache, and the
#: last two of them parse into zero usable keys after a non-empty set.
MALFORMED_ANSWERS = [
    pytest.param(lambda _r: httpx2.Response(200, json={"keys": 5}), id="keys-not-a-list"),
    pytest.param(lambda _r: httpx2.Response(200, json=[]), id="a-json-list"),
    pytest.param(lambda _r: httpx2.Response(200, json={}), id="an-empty-object"),
    pytest.param(lambda _r: httpx2.Response(200, json={"error": "x"}), id="an-error-object"),
    pytest.param(lambda _r: httpx2.Response(200, json={"keys": "abc"}), id="keys-a-string"),
    pytest.param(lambda _r: httpx2.Response(200, json={"keys": {"a": 1}}), id="keys-an-object"),
    pytest.param(lambda _r: httpx2.Response(200, json={"keys": []}), id="no-keys"),
    pytest.param(lambda _r: httpx2.Response(200, json={"keys": [5]}), id="no-usable-keys"),
    pytest.param(lambda _r: httpx2.Response(200, text="<html>"), id="not-json"),
    pytest.param(lambda _r: httpx2.Response(503, json={}), id="http-503"),
    pytest.param(_timeout, id="timeout"),
]


class Clock:
    """``time.time`` moved by hand, for both this subclass and its parent."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.now = time.time()
        monkeypatch.setattr(time, "time", lambda: self.now)

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestThePinnedParent:
    def test_the_overridden_private_method_keeps_its_signature(self) -> None:
        """The annotations are strings because the parent module uses
        ``from __future__ import annotations``; measured against fastmcp 4.0.3."""
        signature = str(inspect.signature(JWTVerifier._get_jwks_key))
        assert signature == "(self, kid: 'str | None') -> 'str'"

    def test_the_second_overridden_private_method_keeps_its_signature(self) -> None:
        """``_fetch_jwks`` is where the read-key guard drops keys, before the
        parent's parser caches them; measured against fastmcp 4.0.3."""
        signature = str(inspect.signature(JWTVerifier._fetch_jwks))
        assert signature == "(self) -> 'dict[str, Any]'"

    def test_the_parent_caches_for_an_hour_which_is_why_this_exists(self) -> None:
        parent = JWTVerifier(jwks_uri=JWKS_URI, issuer=ISSUER, audience=AUDIENCE)
        assert parent._cache_ttl == 3600


class TestTheCache:
    async def test_a_published_key_verifies_with_one_fetch(self) -> None:
        key = _key("session-1.v1")
        handler = CountingJwks(_jwks(key))
        verifier = _verifier(handler)
        for _ in range(5):
            assert await verifier.verify_token(_token(key)) is not None
        assert handler.fetches == 1

    async def test_a_burst_with_one_unknown_kid_fetches_once_per_floor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        key, stranger = _key("session-1.v1"), _key("forged-1")
        handler = CountingJwks(_jwks(key))
        verifier = _verifier(handler)
        for _ in range(20):
            assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 1
        clock.advance(MIN_REFETCH_INTERVAL_SECONDS - 1)
        assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 1
        clock.advance(2)
        assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 2
        assert MIN_REFETCH_INTERVAL_SECONDS == 30.0

    async def test_concurrent_misses_share_one_fetch(self) -> None:
        key, stranger = _key("session-1.v1"), _key("forged-1")
        handler = CountingJwks(_jwks(key), delay=0.05)
        verifier = _verifier(handler)
        results = await asyncio.gather(
            *(verifier.verify_token(_token(stranger)) for _ in range(5)),
            *(verifier.verify_token(_token(key)) for _ in range(5)),
        )
        assert handler.fetches == 1
        assert [r is None for r in results] == [True] * 5 + [False] * 5

    async def test_a_removed_key_stops_verifying_within_the_ttl(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        old, new = _key("session-1.v1"), _key("session-1.v2")
        handler = CountingJwks(_jwks(old, new))
        verifier = _verifier(handler, ttl=300.0)
        assert await verifier.verify_token(_token(old)) is not None
        handler.jwks = _jwks(new)
        clock.advance(299)
        assert await verifier.verify_token(_token(old)) is not None, "inside the TTL"
        clock.advance(2)
        assert await verifier.verify_token(_token(old)) is None
        assert await verifier.verify_token(_token(new)) is not None

    async def test_a_rotated_kid_is_picked_up_after_the_floor_and_the_ttl_refetches(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        old, new = _key("session-1.v1"), _key("session-1.v2")
        handler = CountingJwks(_jwks(old))
        verifier = _verifier(handler, ttl=300.0)
        assert await verifier.verify_token(_token(old)) is not None
        handler.jwks = _jwks(old, new)
        clock.advance(MIN_REFETCH_INTERVAL_SECONDS - 1)
        assert await verifier.verify_token(_token(new)) is None, "inside the floor"
        assert handler.fetches == 1
        clock.advance(2)
        assert await verifier.verify_token(_token(new)) is not None, "after the floor"
        assert handler.fetches == 2
        clock.advance(299)
        assert await verifier.verify_token(_token(old)) is not None
        assert handler.fetches == 2, "inside the TTL"
        clock.advance(2)
        assert await verifier.verify_token(_token(old)) is not None
        assert handler.fetches == 3, "the TTL expired and the known kid refetched"

    async def test_a_failing_endpoint_is_asked_once_per_floor_and_the_cache_survives(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        key, stranger = _key("session-1.v1"), _key("forged-1")
        handler = CountingJwks(_jwks(key))
        verifier = _verifier(handler)
        assert await verifier.verify_token(_token(key)) is not None
        handler.fail = True
        clock.advance(MIN_REFETCH_INTERVAL_SECONDS + 1)
        for _ in range(10):
            assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 2
        assert await verifier.verify_token(_token(key)) is not None, "the fresh cache survived"


class TestAFailedFetchKeepsTheCache:
    """Any failed fetch leaves the cache as it was (2 October 2026).

    The parent empties its cache BEFORE it parses the answer, so until this
    date a 200 whose body was not a key set erased every cached key, and a
    genuine token was refused until the floor allowed another fetch.
    """

    @pytest.mark.parametrize("answer", MALFORMED_ANSWERS)
    async def test_a_genuine_token_verifies_right_after_a_failed_fetch(
        self, answer: Callable[[httpx2.Request], httpx2.Response], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        key, stranger = _key("session-1.v1"), _key("forged-1")
        handler = CountingJwks(_jwks(key))
        verifier = _verifier(handler)
        assert await verifier.verify_token(_token(key)) is not None
        handler.answer = answer
        clock.advance(MIN_REFETCH_INTERVAL_SECONDS + 1)
        assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 2
        assert await verifier.verify_token(_token(key)) is not None, "the cache was erased"
        for _ in range(5):
            assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 2, "a failed fetch is held to the floor"

    @pytest.mark.parametrize("answer", MALFORMED_ANSWERS)
    async def test_a_failed_refetch_at_ttl_expiry_keeps_the_stale_set_and_the_floor(
        self, answer: Callable[[httpx2.Request], httpx2.Response], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The stale set is kept as it was, and it is not served as fresh:
        once the floor passes and the endpoint answers again, it is refetched."""
        clock = Clock(monkeypatch)
        key = _key("session-1.v1")
        handler = CountingJwks(_jwks(key))
        verifier = _verifier(handler, ttl=300.0)
        assert await verifier.verify_token(_token(key)) is not None
        handler.answer = answer
        clock.advance(301)
        assert await verifier.verify_token(_token(key)) is None, "a stale set is not fresh"
        assert handler.fetches == 2
        handler.answer = None
        clock.advance(MIN_REFETCH_INTERVAL_SECONDS + 1)
        assert await verifier.verify_token(_token(key)) is not None
        assert handler.fetches == 3


class TestTheReadKeyGuard:
    """No key the api signs its own read tokens with is ever trusted as a
    session key, whatever ``POSTERN_JWKS_URI`` publishes (2 October 2026)."""

    async def test_a_published_read_key_is_dropped_and_the_session_key_still_verifies(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        read, session = _key("read-1"), _key("session-1.v1")
        handler = CountingJwks(_jwks(read, session))
        verifier = _verifier(handler, forbidden=frozenset(jwk_thumbprints(_jwks(read))))
        with caplog.at_level(logging.WARNING, logger="services.api.session_verifier"):
            for _ in range(5):
                assert await verifier.verify_token(_token(read)) is None
            assert await verifier.verify_token(_token(session)) is not None
        assert handler.fetches == 1, "the dropped kid is held to the floor like any unknown kid"
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert warnings[0].getMessage() == READ_KEY_PUBLISHED_WARNING
        assert str(_jwks(read)["keys"][0]["n"]) not in caplog.text

    async def test_the_same_key_under_another_kid_is_still_dropped(self) -> None:
        """The thumbprint ignores the kid, so renaming the key changes nothing."""
        read = _key("read-1")
        renamed = RSAKey.import_key(
            read.as_pem(private=True), parameters={"kid": "session-1.v9", "alg": "RS256"}
        )
        handler = CountingJwks(_jwks(renamed))
        verifier = _verifier(handler, forbidden=frozenset(jwk_thumbprints(_jwks(read))))
        assert await verifier.verify_token(_token(renamed)) is None

    async def test_no_forbidden_thumbprint_drops_nothing(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        session = _key("session-1.v1")
        verifier = _verifier(CountingJwks(_jwks(session)))
        with caplog.at_level(logging.WARNING):
            assert await verifier.verify_token(_token(session)) is not None
        assert READ_KEY_PUBLISHED_WARNING not in caplog.text


class TestAnAnswerThatIsNotAKeySet:
    """Refused by the fetch itself, on a first fetch too, where there is no
    cached set for the zero-usable-keys rule to compare against."""

    @pytest.mark.parametrize(
        "body", [{}, {"error": "x"}, {"keys": "abc"}, {"keys": {"a": 1}}, [], "keys"]
    )
    async def test_the_fetch_raises(self, body: Any) -> None:
        verifier = _verifier(CountingJwks(body))
        with pytest.raises(ValueError, match="not a"):
            await verifier._fetch_jwks()

    async def test_a_key_set_with_no_keys_is_still_a_key_set(self) -> None:
        verifier = _verifier(CountingJwks({"keys": []}))
        assert await verifier._fetch_jwks() == {"keys": []}


class TestTheBoundedFetch:
    """A JWKS endpoint that never answers holds the lock for at most the
    fetch timeout, then counts as a failed fetch (2 October 2026)."""

    def test_the_bound_is_five_seconds(self) -> None:
        assert FETCH_TIMEOUT_SECONDS == 5.0

    async def test_a_silent_endpoint_is_a_failed_fetch_and_the_cache_survives(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        key, stranger = _key("session-1.v1"), _key("forged-1")
        handler = CountingJwks(_jwks(key))
        verifier = _verifier(handler, fetch_timeout=0.2)
        assert await verifier.verify_token(_token(key)) is not None
        handler.answer = _never
        clock.advance(MIN_REFETCH_INTERVAL_SECONDS + 1)
        started = asyncio.get_running_loop().time()
        assert await verifier.verify_token(_token(stranger)) is None
        assert asyncio.get_running_loop().time() - started < 2.0
        assert await verifier.verify_token(_token(key)) is not None, "the cache was erased"
        for _ in range(5):
            assert await verifier.verify_token(_token(stranger)) is None
        assert handler.fetches == 2, "a timed-out fetch is held to the floor"

    async def test_build_server_uses_the_bound(self) -> None:
        settings = Settings(
            backend_base_url="https://backend.test",
            customer_jwks_uri=JWKS_URI,
            customer_token_issuer=ISSUER,
            audience=AUDIENCE,
        )
        server = build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)
        assert isinstance(server.auth, SessionTokenVerifier)
        assert server.auth._fetch_timeout == FETCH_TIMEOUT_SECONDS


class TestTheClaims:
    """``exp`` is required and bounded, ``iat`` and ``nbf`` are not in the
    future (2 October 2026). The parent checks ``exp`` only when present and
    reads neither of the others."""

    LIMIT = ACCESS_TOKEN_LIFETIME_SECONDS + SESSION_CLOCK_SKEW_SECONDS

    @pytest.fixture()
    def key(self) -> RSAKey:
        return _key("session-1.v1")

    @pytest.fixture()
    def verifier(self, key: RSAKey) -> SessionTokenVerifier:
        return _verifier(CountingJwks(_jwks(key)))

    def test_the_bounds_are_confirms(self) -> None:
        from services.confirm import session_token

        assert session_token.ACCESS_TOKEN_LIFETIME_SECONDS is ACCESS_TOKEN_LIFETIME_SECONDS
        assert ACCESS_TOKEN_LIFETIME_SECONDS == 600
        assert SESSION_CLOCK_SKEW_SECONDS == 30

    async def test_a_genuine_token_verifies(
        self, key: RSAKey, verifier: SessionTokenVerifier
    ) -> None:
        assert await verifier.verify_token(_signed(key)) is not None

    @pytest.mark.parametrize(
        "overrides",
        [
            pytest.param({"exp": None}, id="no-exp"),
            pytest.param({"exp": "9999999999"}, id="exp-a-string"),
            pytest.param({"exp": True}, id="exp-a-bool"),
            pytest.param({"iat": "now"}, id="iat-a-string"),
            pytest.param({"nbf": "now"}, id="nbf-a-string"),
        ],
    )
    async def test_a_malformed_time_claim_is_refused(
        self, key: RSAKey, verifier: SessionTokenVerifier, overrides: dict[str, Any]
    ) -> None:
        assert await verifier.verify_token(_signed(key, **overrides)) is None

    async def test_an_expired_session_token_is_refused(
        self, key: RSAKey, verifier: SessionTokenVerifier
    ) -> None:
        """Past ``exp`` by one second: refused. The same token one minute
        ahead verifies, so expiry is the only difference."""
        now = int(time.time())
        assert await verifier.verify_token(_signed(key, exp=now - 1)) is None
        assert await verifier.verify_token(_signed(key, exp=now + 60)) is not None

    async def test_exp_beyond_the_lifetime_and_skew_is_refused(
        self, key: RSAKey, verifier: SessionTokenVerifier
    ) -> None:
        now = int(time.time())
        assert await verifier.verify_token(_signed(key, exp=now + self.LIMIT - 5)) is not None
        assert await verifier.verify_token(_signed(key, exp=now + self.LIMIT + 5)) is None

    @pytest.mark.parametrize("claim", ["iat", "nbf"])
    async def test_a_future_iat_or_nbf_beyond_the_skew_is_refused(
        self, key: RSAKey, verifier: SessionTokenVerifier, claim: str
    ) -> None:
        now = int(time.time())
        inside = {claim: now + SESSION_CLOCK_SKEW_SECONDS - 5}
        beyond = {claim: now + SESSION_CLOCK_SKEW_SECONDS + 5}
        assert await verifier.verify_token(_signed(key, **inside)) is not None
        assert await verifier.verify_token(_signed(key, **beyond)) is None

    async def test_a_past_nbf_and_an_absent_iat_are_accepted(
        self, key: RSAKey, verifier: SessionTokenVerifier
    ) -> None:
        now = int(time.time())
        assert await verifier.verify_token(_signed(key, nbf=now - 60, iat=None)) is not None


class TestTheReadKeyGuardFollowsTheKey:
    """The guard hashes RSA ``n`` and ``e`` in their minimal encoding, and
    re-reads the read key on every fetch (2 October 2026)."""

    async def test_a_padded_encoding_of_the_read_key_is_still_dropped(self) -> None:
        read, session = _key("read-1"), _key("session-1.v1")
        published = {"keys": [*_padded(_jwks(read))["keys"], *_jwks(session)["keys"]]}
        control = _verifier(CountingJwks(published))
        assert await control.verify_token(_token(read)) is not None, (
            "the parent accepts the padded key, so the guard is what refuses it"
        )
        guarded = _verifier(
            CountingJwks(published), forbidden=frozenset(jwk_thumbprints(_jwks(read)))
        )
        assert await guarded.verify_token(_token(read)) is None
        assert await guarded.verify_token(_token(session)) is not None

    async def test_a_read_key_version_published_after_startup_is_guarded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        v1, v2, session = _key("read-1.v1"), _key("read-1.v2"), _key("session-1.v1")
        read_set = [v1]
        handler = CountingJwks(_jwks(session))
        verifier = _verifier(handler, forbidden=lambda: jwk_thumbprints(_jwks(*read_set)))
        assert await verifier.verify_token(_token(session)) is not None
        read_set.append(v2)  # the read key rotates after startup
        handler.jwks = _jwks(session, v2)  # and is published as a session key
        clock.advance(301)
        assert await verifier.verify_token(_token(v2)) is None
        assert await verifier.verify_token(_token(session)) is not None
        assert handler.fetches == 2

    async def test_a_read_key_that_cannot_be_read_fails_the_fetch_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = Clock(monkeypatch)
        session, stranger = _key("session-1.v1"), _key("forged-1")
        broken = [False]

        def read_thumbprints() -> set[str]:
            if broken[0]:
                raise ConnectionError("vault unreachable")
            return set()

        handler = CountingJwks(_jwks(session))
        verifier = _verifier(handler, forbidden=read_thumbprints)
        assert await verifier.verify_token(_token(session)) is not None
        broken[0] = True
        clock.advance(MIN_REFETCH_INTERVAL_SECONDS + 1)
        assert await verifier.verify_token(_token(stranger)) is None
        assert await verifier.verify_token(_token(session)) is not None, "the cache was erased"
        assert handler.fetches == 2


class TestTheSettings:
    def test_the_ttl_is_read_without_a_vault(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
        monkeypatch.delenv("POSTERN_VAULT_ADDR", raising=False)
        monkeypatch.setenv("POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS", "42")
        settings = Settings.from_env()
        assert settings.vault is None
        assert settings.customer_jwks_ttl_seconds == 42.0

    def test_build_server_builds_the_bounded_verifier(self) -> None:
        settings = Settings(
            backend_base_url="https://backend.test",
            customer_jwks_uri=JWKS_URI,
            customer_token_issuer=ISSUER,
            audience=AUDIENCE,
            customer_jwks_ttl_seconds=42.0,
        )
        server = build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)
        assert isinstance(server.auth, SessionTokenVerifier)
        assert server.auth._session_ttl == 42.0

    @pytest.mark.parametrize(
        "audience", ["postern", "https://mcp.postern.test", "https://MCP.postern.test/mcp"]
    )
    def test_a_non_uri_audience_refuses_to_start(self, audience: str) -> None:
        settings = Settings(
            backend_base_url="https://backend.test",
            customer_jwks_uri=JWKS_URI,
            customer_token_issuer=ISSUER,
            audience=audience,
        )
        with pytest.raises(ValueError, match="POSTERN_ALLOW_NON_URI_AUDIENCE"):
            build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)

    def test_the_flag_admits_it_and_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        settings = Settings(
            backend_base_url="https://backend.test",
            customer_jwks_uri=JWKS_URI,
            customer_token_issuer=ISSUER,
            allow_non_uri_audience=True,
        )
        build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)
        assert "POSTERN_ALLOW_NON_URI_AUDIENCE is set" in caplog.text

    def test_no_customer_authentication_needs_no_uri(self) -> None:
        build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=None)

    def test_the_flag_is_read_from_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
        monkeypatch.setenv("POSTERN_ALLOW_NON_URI_AUDIENCE", "true")
        assert Settings.from_env().allow_non_uri_audience is True


class _Served:
    """A real HTTP JWKS endpoint on 127.0.0.1 that publishes ``key`` and counts GETs."""

    def __init__(self, key: RSAKey) -> None:
        self.key = key
        self.jwks = _jwks(key)
        self.fetches = 0
        served = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802 -- the stdlib's name
                served.fetches += 1
                body = json.dumps(served.jwks).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                return None

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/session/jwks.json"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)


@pytest.fixture()
def served() -> Iterator[_Served]:
    endpoint = _Served(_key("session-1.v1"))
    endpoint.thread.start()
    yield endpoint
    endpoint.server.shutdown()
    endpoint.server.server_close()


async def _tools_list(app: Any, token: str) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://api.test"
    ) as client:
        return await client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "Mcp-Method": "tools/list",
                "MCP-Protocol-Version": "2026-07-28",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientCapabilities": {},
                    }
                },
            },
        )


async def test_the_assembled_app_fetches_only_what_the_override_allows(served: _Served) -> None:
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri=served.url,
        customer_token_issuer=ISSUER,
        audience=AUDIENCE,
    )
    server = build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)
    app = server.http_app(path="/mcp")
    stranger = _key("forged-1")

    async with app.router.lifespan_context(app):
        first = await _tools_list(app, _token(stranger))
        second = await _tools_list(app, _token(stranger))
        genuine = await _tools_list(app, _token(served.key))

    assert first.status_code == 401
    assert second.status_code == 401
    assert served.fetches == 1, "the second miss inside 30 seconds fetched again"
    assert genuine.status_code == 200, genuine.text
    assert served.fetches == 1, "a published kid on a fresh cache fetched again"


def _api_settings(served: _Served, **overrides: Any) -> Settings:
    return Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri=served.url,
        customer_token_issuer=ISSUER,
        audience=AUDIENCE,
        **overrides,
    )


async def _assert_the_read_key_is_never_a_session_key(app: Any, served: _Served) -> None:
    """``served`` publishes the api's own read public key beside a genuine
    session key; a token the read key signs is refused, the session one is not."""
    read_source = app.state.postern_read_key_source
    served.jwks = {"keys": [*read_source.public_jwks()["keys"], *_jwks(served.key)["keys"]]}
    verifier = app.state.postern_server.auth
    assert isinstance(verifier, SessionTokenVerifier)
    forged = read_source.sign(_claims())
    for _ in range(3):
        assert await verifier.verify_token(forged) is None
    assert await verifier.verify_token(_token(served.key)) is not None
    assert served.fetches == 1


class TestCreateAppWiresTheReadKeyGuard:
    """``create_app`` hands its own read key source's thumbprints to the verifier.

    Startup cannot fetch confirm's key set, so the guard holds at fetch time;
    these drive it against a real HTTP endpoint publishing the api's read key.
    """

    async def test_the_generated_read_key(self, served: _Served) -> None:
        app = create_app(_api_settings(served))
        await _assert_the_read_key_is_never_a_session_key(app, served)

    async def test_a_read_key_from_a_pem_file(self, served: _Served, tmp_path: Path) -> None:
        pem = tmp_path / "read.pem"
        pem.write_bytes(_key("read-1").as_pem(private=True))
        app = create_app(_api_settings(served, read_key_pem_path=str(pem)))
        await _assert_the_read_key_is_never_a_session_key(app, served)

    async def test_a_read_key_published_after_startup_is_guarded(
        self, served: _Served, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``create_app`` hands the verifier a reader, not a snapshot: a read
        key the source starts publishing after startup (a Vault rotation) is
        dropped by the next fetch."""
        app = create_app(_api_settings(served))
        rotated = _key("read-1.v2")
        monkeypatch.setattr(
            app.state.postern_read_key_source, "public_jwks", lambda: _jwks(rotated)
        )
        served.jwks = {"keys": [*_jwks(rotated)["keys"], *_jwks(served.key)["keys"]]}
        verifier = app.state.postern_server.auth
        assert await verifier.verify_token(_token(rotated)) is None
        assert await verifier.verify_token(_token(served.key)) is not None
        assert served.fetches == 1

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
import inspect
import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from services.api.server import build_server
from services.api.session_verifier import MIN_REFETCH_INTERVAL_SECONDS, SessionTokenVerifier
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
        self.fetches = 0

    async def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.fetches += 1
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.fail:
            return httpx2.Response(503, json={})
        return httpx2.Response(200, json=self.jwks)


def _verifier(handler: CountingJwks, *, ttl: float = 300.0) -> SessionTokenVerifier:
    return SessionTokenVerifier(
        jwks_uri=JWKS_URI,
        issuer=ISSUER,
        audience=AUDIENCE,
        required_scopes=None,
        cache_ttl_seconds=ttl,
        http_client=httpx2.AsyncClient(transport=httpx2.MockTransport(handler)),
    )


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

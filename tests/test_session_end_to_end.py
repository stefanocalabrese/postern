"""The layer-1 session across both services, and the audit counts it leaves.

``services/confirm`` issues a session; ``services/api``, configured as spec
section 8 says -- its customer JWKS is confirm's ``/session/jwks.json``, its
issuer confirm's session issuer, its audience the same resource URI -- accepts
it on ``tools/list`` and ``tools/call``, and after a refresh accepts the new
one. Both services share one Redis, so a recall at confirm's ``POST /scan``,
or a refresh token presented twice, is refused on the api's next call, counted
in backend touches the way ``tests/test_zt7_revocation_reachable.py`` counts
them.

The api is assembled by ``create_app`` with no verifier override: the
``SessionTokenVerifier`` here is the one ``build_server`` builds from
settings, read-key guard included. Its JWKS fetch is pointed at the confirm
app over an in-process ASGI transport by setting the client the parent
``JWTVerifier`` already accepts, so no socket is opened and every other line
is the two composition roots.

A refusal is told apart by its shape, not by "not a 500": an access token the
verifier rejects is HTTP 401 with ``invalid_token`` and never reaches a tool;
a revoked one passes the verifier and is refused by ``RevocationMiddleware``,
HTTP 200 carrying a top-level JSON-RPC ``error``. The backend touch count
decides both.

The last two tests pin spec section 9's reading of the table: each count
predicate is asked of a table holding one pairing, one exchange and one
refresh, and ``minted()`` is only ever reached for ``device_grant.token`` and
``device_grant.refresh``.
"""

from __future__ import annotations

import ast
import asyncio
import base64
import dataclasses
import json
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import RSAKey
from postern_core.auth import refresh_sessions
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.revocation import RevocationStoreBase, decision_scope
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, OUTCOME_RETURNED, AuditEntry
from sqlalchemy import select, text
from starlette.applications import Starlette

from services.api.main import create_app
from services.api.session_verifier import READ_KEY_PUBLISHED_WARNING, SessionTokenVerifier
from services.api.settings import Settings
from services.confirm import device_auth
from services.confirm.audit import (
    DETAIL_REFRESH_REUSED,
    DETAIL_SCAN_CONFLICT,
    DETAIL_SESSION_REVOKED,
    RECALL_TOOL_NAME,
    REFRESH_TOOL_NAME,
    SCAN_TOOL_NAME,
    TOKEN_TOOL_NAME,
    PairingAudit,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import qr_for, scan_in_store, session_claims, stored_code
from tests.fixtures import backend_responses as fx
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_device_grant import AUDIENCE as APP_AUDIENCE
from tests.test_device_grant import ISSUER as APP_ISSUER
from tests.test_device_grant import bearer
from tests.test_zt7_revocation_reachable import _consent

RESOURCE = "https://mcp.postern.test/mcp"
CUSTOMER = "cust_e2e0b"
VICTIM = "cust_e2e0a"
OTHER = "cust_e2e0c"
CLIENT = "claude-code"
REPO = Path(__file__).resolve().parent.parent
SESSION_JWKS_URI = "https://confirm.test/session/jwks.json"

#: The envelope MCP 2026-07-28 requires on every request.
_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


class Backend:
    """Records every backend request: the path, and the ``sub`` of the
    layer-2 token the api sent, read without verifying (the api signed it)."""

    def __init__(self) -> None:
        self.paths: list[str] = []
        self.subjects: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(request.url.path)
        token = request.headers["Authorization"].removeprefix("Bearer ")
        payload = token.split(".")[1]
        claims = json.loads(_b64url_decode(payload))
        self.subjects.append(claims["sub"])
        return httpx2.Response(200, json=fx.ACCOUNTS)


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    yield database


@pytest.fixture()
def shared_redis(monkeypatch: pytest.MonkeyPatch, redis_url: str) -> str:
    """One Redis key space for both services, as a deployment shares one."""
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"e2e{uuid4().hex[:12]}:")
    return redis_url


@pytest.fixture()
def confirm(pg_url: str, key_pair: RSAKeyPair, shared_redis: str) -> Starlette:
    settings = dataclasses.replace(
        ConfirmSettings.for_testing(),
        database_url=pg_url,
        session_token_audience=RESOURCE,
        allow_non_uri_audience=False,
        allow_process_local_sessions=False,
    )
    return create_confirm_app(
        settings,
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=APP_ISSUER, audience=APP_AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


def _api(
    pg_url: str,
    backend: Backend,
    *,
    issuer: str,
    jwks_uri: str = SESSION_JWKS_URI,
    jwks_app: Any | None,
    **overrides: Any,
) -> Any:
    """``services/api`` as ``create_app`` builds it from settings, per spec section 8.

    No ``auth_override``: the verifier is the ``SessionTokenVerifier``
    ``build_server`` constructs, with its read-key guard. Only its HTTP
    client is replaced, by one whose transport is ``jwks_app`` in process;
    with ``jwks_app=None`` the app serves its own key set to itself.
    """
    settings = Settings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        customer_jwks_uri=jwks_uri,
        customer_token_issuer=issuer,
        audience=RESOURCE,
        **overrides,
    )
    app = create_app(settings, transport=httpx2.MockTransport(backend))
    verifier = app.state.postern_server.auth
    assert isinstance(verifier, SessionTokenVerifier)
    assert verifier.jwks_uri == jwks_uri
    assert verifier._http_client is None
    verifier._http_client = httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app if jwks_app is None else jwks_app)
    )
    return app


def _confirm_api(confirm: Starlette, pg_url: str, backend: Backend) -> Any:
    return _api(
        pg_url,
        backend,
        issuer=confirm.state.settings.session_token_issuer,
        jwks_app=confirm,
    )


@asynccontextmanager
async def _serving(app: Any) -> AsyncIterator[httpx2.AsyncClient]:
    """One api, one lifespan, many calls."""
    transport = httpx2.ASGITransport(app=app, client=("127.0.0.1", 5555))
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=transport, base_url="http://t") as client:
            yield client


async def _mcp(
    client: httpx2.AsyncClient, method: str, token: str, *, name: str = ""
) -> httpx2.Response:
    params: dict[str, Any] = {"_meta": _META}
    if method == "tools/call":
        params |= {"name": name, "arguments": {}}
    return await client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Mcp-Method": method,
            "Mcp-Name": name,
            "MCP-Protocol-Version": "2026-07-28",
        },
        json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
    )


async def _list(client: httpx2.AsyncClient, token: str) -> set[str]:
    """The tool names a ``tools/list`` the api ACCEPTED returns."""
    response = await _mcp(client, "tools/list", token)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "error" not in payload, payload
    return {tool["name"] for tool in payload["result"]["tools"]}


async def _accounts(client: httpx2.AsyncClient, token: str) -> dict[str, Any]:
    """``accounts.list`` the api ACCEPTED and served; the tool result."""
    response = await _mcp(client, "tools/call", token, name="accounts.list")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "error" not in payload, payload
    result: dict[str, Any] = payload["result"]
    assert result["isError"] is False, result
    return result


def _assert_unauthenticated(response: httpx2.Response) -> None:
    """Refused by the verifier: 401 ``invalid_token``, no JSON-RPC dispatch at all."""
    assert response.status_code == 401, response.text
    assert response.json()["error"] == "invalid_token", response.text
    assert 'error="invalid_token"' in response.headers["www-authenticate"]


def _assert_revoked(response: httpx2.Response) -> None:
    """Accepted by the verifier, refused after it: HTTP 200, a JSON-RPC
    ``error`` and no ``result``, as ``RevocationMiddleware`` answers."""
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "result" not in payload, payload
    assert payload["error"]["code"] == -32603, payload


async def _confirm_post(app: Starlette, path: str, **kwargs: Any) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="https://confirm.test"
    ) as client:
        return await client.post(path, **kwargs)


async def _refresh(confirm: Starlette, refresh_token: str) -> httpx2.Response:
    return await _confirm_post(
        confirm,
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": refresh_token},
    )


async def _pair_and_exchange(
    confirm: Starlette, key_pair: RSAKeyPair, approver: str
) -> tuple[Any, dict[str, Any]]:
    """A pairing approved by ``approver`` and exchanged; the code and the session."""
    started = await _confirm_post(confirm, "/device_authorization", json={"client_id": CLIENT})
    device = started.json()
    code = await stored_code(confirm, device["user_code"])
    await scan_in_store(confirm, device["user_code"], approver)
    approved = await _confirm_post(
        confirm,
        "/approve",
        json={"user_code": device["user_code"]},
        headers=bearer(key_pair, approver),
    )
    assert approved.status_code == 200, approved.text
    exchanged = await _confirm_post(
        confirm, "/token", data={"grant_type": "device_code", "device_code": device["device_code"]}
    )
    assert session_claims(exchanged, confirm)["sub"] == approver
    return code, exchanged.json()


def _jti(access_token: str) -> str:
    claims = json.loads(_b64url_decode(access_token.split(".")[1]))
    jti: str = claims["jti"]
    return jti


async def _device_grant_rows(database: Database) -> list[AuditEntry]:
    async with database.sessionmaker() as s:
        rows = (await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars()
        return [r for r in rows if r.tool_name.startswith("device_grant.")]


async def test_the_api_accepts_the_session_and_the_refreshed_one(
    confirm: Starlette, pg_url: str, database: Database, key_pair: RSAKeyPair, clean: Database
) -> None:
    backend = Backend()
    api = _confirm_api(confirm, pg_url, backend)
    _, session = await _pair_and_exchange(confirm, key_pair, CUSTOMER)

    async with _consent(database, CustomerRef(value=CUSTOMER)):
        async with _serving(api) as client:
            assert "accounts.list" in await _list(client, session["access_token"])
            first = await _accounts(client, session["access_token"])

            refreshed = await _refresh(confirm, session["refresh_token"])
            renewed = refreshed.json()
            claims = session_claims(refreshed, confirm)
            assert claims["sub"] == CUSTOMER
            assert renewed["refresh_token"] != session["refresh_token"]
            assert renewed["access_token"] != session["access_token"]
            assert "accounts.list" in await _list(client, renewed["access_token"])
            second = await _accounts(client, renewed["access_token"])

    # The customer the backend was asked about is the one who approved, taken
    # from the session token and from nothing the client sent.
    assert backend.paths == ["/accounts", "/accounts"]
    assert backend.subjects == [CUSTOMER, CUSTOMER]
    assert first["structuredContent"] == second["structuredContent"]


async def test_a_token_for_another_audience_is_refused_by_the_api(
    confirm: Starlette, pg_url: str, database: Database, clean: Database
) -> None:
    """A layer-2-shaped token signed with the SESSION key but for a domain
    service's audience: right key, wrong audience, refused. The same claims
    with the MCP server's audience, signed the same way, are served, so the
    audience is the only thing the refusal can be about."""
    backend = Backend()
    api = _confirm_api(confirm, pg_url, backend)
    minter = confirm.state.session_minter
    claims = minter.prepare(
        customer=CustomerRef(value=CUSTOMER), client_id=CLIENT, scope="accounts:read", sid="x"
    )
    foreign = dataclasses.replace(claims, aud="accounts.svc")
    async with _consent(database, CustomerRef(value=CUSTOMER)):
        async with _serving(api) as client:
            _assert_unauthenticated(await _mcp(client, "tools/list", minter.sign(foreign)))
            _assert_unauthenticated(
                await _mcp(client, "tools/call", minter.sign(foreign), name="accounts.list")
            )
            assert backend.paths == []
            await _accounts(client, minter.sign(claims))
    assert backend.paths == ["/accounts"]


async def test_tokens_are_not_interchangeable_across_the_two_endpoints(
    confirm: Starlette, pg_url: str, key_pair: RSAKeyPair, clean: Database
) -> None:
    """A refresh token is not a bearer at the api, and an access token is not
    a refresh token at confirm: each is refused with no row written."""
    backend = Backend()
    api = _confirm_api(confirm, pg_url, backend)
    _, session = await _pair_and_exchange(confirm, key_pair, CUSTOMER)
    before = await _device_grant_rows(clean)

    async with _serving(api) as client:
        _assert_unauthenticated(await _mcp(client, "tools/list", session["refresh_token"]))

    as_refresh = await _refresh(confirm, session["access_token"])
    assert as_refresh.status_code == 400
    assert as_refresh.json()["error"] == "invalid_grant"
    assert [r.id for r in await _device_grant_rows(clean)] == [r.id for r in before]
    assert backend.paths == []


@pytest.fixture()
def read_key_pem(tmp_path: Path) -> tuple[str, RSAKey]:
    """The api's READ key on disk, and the same key in hand to sign with."""
    key = RSAKey.generate_key(2048, parameters={"kid": "read-1", "use": "sig", "alg": "RS256"})
    pem = tmp_path / "read.pem"
    pem.write_bytes(key.as_pem(private=True))
    return str(pem), key


async def test_a_layer_2_token_is_never_a_session_at_the_api(
    confirm: Starlette,
    pg_url: str,
    database: Database,
    read_key_pem: tuple[str, RSAKey],
    caplog: pytest.LogCaptureFixture,
    clean: Database,
) -> None:
    """Two forms of the regression this whole change exists for.

    First, the api correctly configured: the delegation token its own read
    minter signs for the backend is presented as a customer token, and is
    refused. Second, the api MISCONFIGURED so its customer JWKS is its own
    ``/.well-known/jwks.json``, the set Istio trusts, and a token signed by
    the READ key carrying every claim a session token carries: refused too,
    by the read-key guard alone, which the WARNING proves fired.
    """
    pem_path, read_key = read_key_pem
    session_issuer = confirm.state.settings.session_token_issuer

    backend = Backend()
    api = _confirm_api(confirm, pg_url, backend)
    with decision_scope(False):
        layer_2 = api.state.backend_client._minter(CustomerRef(value=CUSTOMER), "accounts.svc")

    misconfigured_backend = Backend()
    misconfigured = _api(
        pg_url,
        misconfigured_backend,
        issuer=session_issuer,
        jwks_uri="http://api.test/.well-known/jwks.json",
        jwks_app=None,
        read_key_pem_path=pem_path,
    )
    now = int(time.time())
    forged = joserfc_jwt.encode(
        {"alg": "RS256", "kid": "read-1"},
        {
            "iss": session_issuer,
            "aud": RESOURCE,
            "sub": CUSTOMER,
            "client_id": CLIENT,
            "client_id_verified": False,
            "scope": "accounts:read",
            "sid": "x",
            "jti": str(uuid4()),
            "iat": now,
            "exp": now + 600,
        },
        read_key,
    )

    async with _consent(database, CustomerRef(value=CUSTOMER)):
        async with _serving(api) as client:
            _assert_unauthenticated(await _mcp(client, "tools/list", layer_2))
            _assert_unauthenticated(await _mcp(client, "tools/call", layer_2, name="accounts.list"))
        with caplog.at_level(logging.WARNING, logger="services.api.session_verifier"):
            async with _serving(misconfigured) as client:
                published = (await client.get("/.well-known/jwks.json")).json()
                assert [k["kid"] for k in published["keys"]] == ["read-1"]
                _assert_unauthenticated(await _mcp(client, "tools/list", forged))
                _assert_unauthenticated(
                    await _mcp(client, "tools/call", forged, name="accounts.list")
                )

    assert READ_KEY_PUBLISHED_WARNING in [r.getMessage() for r in caplog.records]
    assert backend.paths == []
    assert misconfigured_backend.paths == []


async def test_a_reused_refresh_token_revokes_the_family_and_its_live_access_token(
    confirm: Starlette, pg_url: str, database: Database, key_pair: RSAKeyPair, clean: Database
) -> None:
    """RFC 9700 section 4.14.2 reuse detection, as the api sees it: a thief
    presents the refresh token the client already rotated, the family is
    revoked, and the access token the CLIENT holds stops working at the api
    on its next call, refused after the verifier accepted it."""
    backend = Backend()
    api = _confirm_api(confirm, pg_url, backend)
    _, first = await _pair_and_exchange(confirm, key_pair, CUSTOMER)
    revocations: RevocationStoreBase = confirm.state.postern_revocation_store

    async with _consent(database, CustomerRef(value=CUSTOMER)):
        async with _serving(api) as client:
            rotated = await _refresh(confirm, first["refresh_token"])
            second = rotated.json()
            assert session_claims(rotated, confirm)["sub"] == CUSTOMER
            await _accounts(client, second["access_token"])
            assert backend.paths == ["/accounts"]

            reused = await _refresh(confirm, first["refresh_token"])
            assert reused.status_code == 400, reused.text
            assert reused.json()["error"] == "invalid_grant"

            _assert_revoked(
                await _mcp(client, "tools/call", second["access_token"], name="accounts.list")
            )
            _assert_revoked(await _mcp(client, "tools/list", second["access_token"]))
            _assert_revoked(await _mcp(client, "tools/list", first["access_token"]))

            current = await _refresh(confirm, second["refresh_token"])
            assert current.status_code == 400, current.text
            assert current.json()["error"] == "invalid_grant"

    assert backend.paths == ["/accounts"], "a revoked access token reached the backend"
    for access in (first["access_token"], second["access_token"]):
        claims = {"sub": CUSTOMER, "client_id": CLIENT, "jti": _jti(access)}
        assert await revocations.is_revoked(claims) is True
    family = await confirm.state.refresh_session_store.get(first["refresh_token"].split(".")[1])
    assert family is not None
    assert family.revoked_reason == "reuse"
    refreshes = [
        (r.outcome, r.detail)
        for r in await _device_grant_rows(clean)
        if r.tool_name == REFRESH_TOOL_NAME
    ]
    assert refreshes == [
        (OUTCOME_RETURNED, None),
        (OUTCOME_RAISED, DETAIL_REFRESH_REUSED),
        (OUTCOME_RAISED, DETAIL_SESSION_REVOKED),
    ]


async def test_a_recalled_session_is_refused_at_the_api_before_the_backend(
    confirm: Starlette, pg_url: str, database: Database, key_pair: RSAKeyPair, clean: Database
) -> None:
    """Spec section 7: B approved A's pairing, A's client holds B's session,
    A's scan recalls it, and A's client's next call reaches no backend, nor
    can the family refresh."""
    backend = Backend()
    api = _confirm_api(confirm, pg_url, backend)
    code, session = await _pair_and_exchange(confirm, key_pair, CUSTOMER)

    async with _consent(database, CustomerRef(value=CUSTOMER)):
        async with _serving(api) as client:
            await _accounts(client, session["access_token"])
            assert backend.paths == ["/accounts"]

            conflict = await _confirm_post(
                confirm,
                "/scan",
                json={"user_code": code.user_code_display, "qr": qr_for(code)},
                headers=bearer(key_pair, VICTIM),
            )
            assert conflict.status_code == 400, conflict.text
            assert conflict.json()["error"] == "scan_conflict"

            _assert_revoked(
                await _mcp(client, "tools/call", session["access_token"], name="accounts.list")
            )
            _assert_revoked(await _mcp(client, "tools/list", session["access_token"]))
            after = await _refresh(confirm, session["refresh_token"])

    assert backend.paths == ["/accounts"], "the recalled session reached the backend"
    assert after.status_code == 400, after.text
    assert after.json()["error"] == "invalid_grant"

    rows = await _device_grant_rows(clean)
    recall = [r for r in rows if r.tool_name == RECALL_TOOL_NAME]
    conflicts = [
        r for r in rows if r.tool_name == SCAN_TOOL_NAME and r.detail == DETAIL_SCAN_CONFLICT
    ]
    assert [(r.outcome, r.detail, r.customer_ref) for r in recall] == [
        (OUTCOME_RETURNED, None, CUSTOMER)
    ]
    assert [r.customer_ref for r in conflicts] == [VICTIM]
    assert recall[0].call_id is not None
    assert recall[0].call_id == conflicts[0].call_id
    assert recall[0].arguments["session_id"] == session["refresh_token"].split(".")[1]
    assert [(r.outcome, r.detail) for r in rows if r.tool_name == REFRESH_TOOL_NAME] == [
        (OUTCOME_RAISED, DETAIL_SESSION_REVOKED)
    ]


async def test_the_family_ends_an_hour_after_the_exchange(
    confirm: Starlette,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    clean: Database,
) -> None:
    """The family's absolute lifetime, on the real Redis: the key's TTL is one
    hour, and a refresh token that is still current is refused once the hour
    has passed on the clock both modules read, with no row (spec discrepancy 3:
    an expired family is not found)."""
    _, session = await _pair_and_exchange(confirm, key_pair, CUSTOMER)
    sid = session["refresh_token"].split(".")[1]
    store = confirm.state.refresh_session_store
    assert isinstance(store, refresh_sessions.RedisRefreshSessionStore)
    # The key's own expiry, read back from the suite's Redis container.
    ttl = await store._redis.ttl(store._key(sid))
    assert 3590 <= ttl <= 3600, ttl

    rotated = await _refresh(confirm, session["refresh_token"])
    current = rotated.json()["refresh_token"]
    assert session_claims(rotated, confirm)["sid"] == sid

    class _AnHourLater(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]
            return datetime.now(tz) + timedelta(hours=1, seconds=1)

    monkeypatch.setattr(refresh_sessions, "datetime", _AnHourLater)
    monkeypatch.setattr(device_auth, "datetime", _AnHourLater)
    rows_before = len(await _device_grant_rows(clean))
    expired = await _refresh(confirm, current)
    assert expired.status_code == 400, expired.text
    assert expired.json()["error"] == "invalid_grant"
    assert "access_token" not in expired.json()
    assert len(await _device_grant_rows(clean)) == rows_before


async def test_two_concurrent_refreshes_of_one_token_revoke_the_family_at_the_api(
    confirm: Starlette, pg_url: str, database: Database, key_pair: RSAKeyPair, clean: Database
) -> None:
    """Spec section 4's atomicity: two presentations of one current refresh
    token race, one rotates and the other is reuse, which revokes the family.

    THE RACE IS FORCED INTO THE COMPARE-AND-SET. Left to ``gather`` alone,
    the loser always read the record after the winner committed and took
    step 4's reuse branch, so the ``WATCH`` was never contested (a mutation
    that reported a lost ``WATCH`` as a win survived). Here each request's
    first read of the family inside ``rotate`` waits at a barrier until the
    other has made its own, so both decide ``ROTATED`` from one record and
    exactly one ``EXEC`` lands; the other gets ``WatchError``, re-reads, and
    is ``REUSED``. The third read of the key is that retry, and is counted.
    Only this store instance's pipeline is wrapped; no production code is.

    Either request may win, so the assertions are on the outcome set. Against
    one competitor the loser retries once, so the contended answer
    (``RefreshSessionStoreContended``, not a store outage, hence a 500)
    cannot occur. The winner's 200 carries an access token whose ``jti`` the
    family recorded before the loser revoked it, so the api refuses it.
    """
    backend = Backend()
    api = _confirm_api(confirm, pg_url, backend)
    _, original = await _pair_and_exchange(confirm, key_pair, CUSTOMER)
    store = confirm.state.refresh_session_store
    assert isinstance(store, refresh_sessions.RedisRefreshSessionStore)
    family_key = store._key(original["refresh_token"].split(".")[1])
    both_read = asyncio.Barrier(2)
    reads: list[str] = []
    real_pipeline = store._redis.pipeline

    def pipeline(*args: Any, **kwargs: Any) -> Any:
        pipe = real_pipeline(*args, **kwargs)
        real_get = pipe.get

        async def get(key: str) -> Any:
            value = await real_get(key)
            if key == family_key:
                reads.append(key)
                if len(reads) <= 2:
                    await asyncio.wait_for(both_read.wait(), timeout=5)
            return value

        pipe.get = get
        return pipe

    store._redis.pipeline = pipeline
    try:
        raced = await asyncio.gather(
            _refresh(confirm, original["refresh_token"]),
            _refresh(confirm, original["refresh_token"]),
        )
    finally:
        store._redis.pipeline = real_pipeline
    assert len(reads) == 3, "both decided from one record, and the loser re-read once"
    assert sorted(r.status_code for r in raced) == [200, 400], [r.text for r in raced]
    (winner,) = [r for r in raced if r.status_code == 200]
    (loser,) = [r for r in raced if r.status_code == 400]
    assert loser.json() == {
        "error": "invalid_grant",
        "error_description": "refresh token cannot be redeemed",
    }
    won = winner.json()
    assert session_claims(winner, confirm)["sub"] == CUSTOMER

    async with _consent(database, CustomerRef(value=CUSTOMER)):
        async with _serving(api) as client:
            for token in (won["access_token"], original["access_token"]):
                _assert_revoked(await _mcp(client, "tools/call", token, name="accounts.list"))
                _assert_revoked(await _mcp(client, "tools/list", token))
    assert backend.paths == []

    current = await _refresh(confirm, won["refresh_token"])
    assert current.status_code == 400, current.text
    assert current.json()["error"] == "invalid_grant"

    family = await confirm.state.refresh_session_store.get(original["refresh_token"].split(".")[1])
    assert family is not None
    assert family.revoked_reason == "reuse"
    assert family.generation == 1
    refreshes = [
        (r.outcome, r.detail)
        for r in await _device_grant_rows(clean)
        if r.tool_name == REFRESH_TOOL_NAME
    ]
    assert sorted(refreshes[:2], key=str) == sorted(
        [(OUTCOME_RETURNED, None), (OUTCOME_RAISED, DETAIL_REFRESH_REUSED)], key=str
    )
    assert refreshes[2:] == [(OUTCOME_RAISED, DETAIL_SESSION_REVOKED)]


async def test_an_expired_session_token_is_refused_at_the_api(
    confirm: Starlette, pg_url: str, database: Database, clean: Database
) -> None:
    """A token confirm's own minter signed with the real SESSION key, whose
    ``exp`` passed 100 seconds ago: 401 before any tool runs. A fresh one from
    the same minter is served, so the time is the only difference."""
    backend = Backend()
    api = _confirm_api(confirm, pg_url, backend)
    minter = confirm.state.session_minter
    fresh = minter.prepare(
        customer=CustomerRef(value=CUSTOMER), client_id=CLIENT, scope="accounts:read", sid="x"
    )
    stale = dataclasses.replace(fresh, iat=int(time.time()) - 700)
    assert stale.exp < time.time() - 90
    async with _consent(database, CustomerRef(value=CUSTOMER)):
        async with _serving(api) as client:
            _assert_unauthenticated(await _mcp(client, "tools/list", minter.sign(stale)))
            _assert_unauthenticated(
                await _mcp(client, "tools/call", minter.sign(stale), name="accounts.list")
            )
            assert backend.paths == []
            await _accounts(client, minter.sign(fresh))
    assert backend.paths == ["/accounts"]


def _edited(token: str, **changes: str) -> str:
    """``token`` with its payload re-encoded under ``changes``, header and
    signature kept byte for byte."""
    header, payload, signature = token.split(".")
    claims = json.loads(_b64url_decode(payload)) | changes
    raw = json.dumps(claims, separators=(",", ":")).encode()
    edited = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
    assert edited != payload
    return f"{header}.{edited}.{signature}"


async def test_a_session_token_with_an_edited_payload_is_refused(
    confirm: Starlette, pg_url: str, database: Database, key_pair: RSAKeyPair, clean: Database
) -> None:
    """A genuine session token with its ``jti`` changed (to slip a revocation)
    or its ``sub`` changed (to read another customer) and the original
    signature kept: 401 for both. Both customers hold an ``accounts`` consent,
    so a missed signature check would be served, not refused for consent."""
    backend = Backend()
    api = _confirm_api(confirm, pg_url, backend)
    _, session = await _pair_and_exchange(confirm, key_pair, CUSTOMER)
    genuine = session["access_token"]
    forgeries = [_edited(genuine, jti=str(uuid4())), _edited(genuine, sub=VICTIM)]

    async with (
        _consent(database, CustomerRef(value=CUSTOMER)),
        _consent(database, CustomerRef(value=VICTIM)),
    ):
        async with _serving(api) as client:
            for forged in forgeries:
                _assert_unauthenticated(await _mcp(client, "tools/list", forged))
                _assert_unauthenticated(
                    await _mcp(client, "tools/call", forged, name="accounts.list")
                )
            assert backend.paths == []
            await _accounts(client, genuine)
    assert backend.paths == ["/accounts"]
    assert backend.subjects == [CUSTOMER]


async def test_a_refresh_token_with_another_familys_sid_is_refused(
    confirm: Starlette, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture, clean: Database
) -> None:
    """Spec section 4's integrity rule: ``sid`` only selects a record. A's
    secret grafted onto B's ``sid``, and B's onto A's, prove possession of
    neither family: ``_refresh_grant`` answers the one ``invalid_grant`` body,
    writes NO row, logs one warning naming the selected ``sid`` and never the
    presented value, and changes nothing, so a legitimate refresh of each
    family still rotates it afterwards."""
    _, first = await _pair_and_exchange(confirm, key_pair, CUSTOMER)
    _, second = await _pair_and_exchange(confirm, key_pair, OTHER)
    _, sid_a, secret_a = first["refresh_token"].split(".")
    _, sid_b, secret_b = second["refresh_token"].split(".")
    grafts = [f"prt1.{sid_b}.{secret_a}", f"prt1.{sid_a}.{secret_b}"]
    store = confirm.state.refresh_session_store
    rows_before = [r.id for r in await _device_grant_rows(clean)]

    with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
        for grafted in grafts:
            refused = await _refresh(confirm, grafted)
            assert refused.status_code == 400, refused.text
            assert refused.json() == {
                "error": "invalid_grant",
                "error_description": "refresh token cannot be redeemed",
            }
    assert [r.id for r in await _device_grant_rows(clean)] == rows_before
    warnings = [r.getMessage() for r in caplog.records if r.name == "services.confirm.device_auth"]
    assert sorted(w.rsplit(" ", 1)[-1] for w in warnings) == sorted([sid_a, sid_b]), warnings
    assert not any(secret_a in w or secret_b in w for w in warnings)
    for sid in (sid_a, sid_b):
        family = await store.get(sid)
        assert family is not None
        assert (family.generation, family.revoked_at) == (0, None)

    for refresh_token, customer in (
        (first["refresh_token"], CUSTOMER),
        (second["refresh_token"], OTHER),
    ):
        renewed = await _refresh(confirm, refresh_token)
        assert session_claims(renewed, confirm)["sub"] == customer
    after = (await _device_grant_rows(clean))[len(rows_before) :]
    assert [(r.tool_name, r.outcome, r.detail, r.customer_ref) for r in after] == [
        (REFRESH_TOOL_NAME, OUTCOME_RETURNED, None, CUSTOMER),
        (REFRESH_TOOL_NAME, OUTCOME_RETURNED, None, OTHER),
    ]


PREDICATES = {
    "pairings granted": (
        "tool_name = 'device_grant.approve' AND outcome = 'returned' AND detail IS NULL",
        1,
    ),
    "repeat approvals": (
        "tool_name = 'device_grant.approve' AND outcome = 'returned' "
        "AND detail = 'already_approved'",
        0,
    ),
    "pairings scanned": (
        "tool_name = 'device_grant.scan' AND outcome = 'returned' AND detail IS NULL",
        1,
    ),
    "repeat scans": (
        "tool_name = 'device_grant.scan' AND outcome = 'returned' "
        "AND detail IN ('already_scanned','already_approved')",
        0,
    ),
    "sessions issued": (
        "tool_name = 'device_grant.token' AND outcome = 'returned' AND detail IS NULL",
        1,
    ),
    "refreshes issued": (
        "tool_name = 'device_grant.refresh' AND outcome = 'returned' AND detail IS NULL",
        1,
    ),
    "recalls completed": ("tool_name = 'device_grant.recall' AND outcome = 'returned'", 0),
}


async def test_each_count_predicate_counts_one_endpoint(
    confirm: Starlette, key_pair: RSAKeyPair, clean: Database
) -> None:
    """One pairing (scanned over HTTP), one exchange, one refresh: every
    predicate of spec section 9 counts exactly its own event, and the naive
    ``LIKE 'device_grant.%'`` one counts four."""
    started = await _confirm_post(confirm, "/device_authorization", json={"client_id": CLIENT})
    code = await stored_code(confirm, started.json()["user_code"])
    scanned = await _confirm_post(
        confirm,
        "/scan",
        json={"user_code": code.user_code_display, "qr": qr_for(code)},
        headers=bearer(key_pair, CUSTOMER),
    )
    assert scanned.status_code == 200, scanned.text
    approved = await _confirm_post(
        confirm,
        "/approve",
        json={"user_code": code.user_code_display},
        headers=bearer(key_pair, CUSTOMER),
    )
    assert approved.status_code == 200
    exchanged = await _confirm_post(
        confirm, "/token", data={"grant_type": "device_code", "device_code": code.device_code}
    )
    refreshed = await _refresh(confirm, exchanged.json()["refresh_token"])
    assert refreshed.status_code == 200

    async with clean.sessionmaker() as s:
        for name, (predicate, expected) in PREDICATES.items():
            # The predicates are this file's own constants, not input.
            query = "SELECT count(*) FROM audit_log WHERE " + predicate  # noqa: S608
            found = (await s.execute(text(query))).scalar()
            assert found == expected, name
        naive = (
            await s.execute(
                text(
                    "SELECT count(*) FROM audit_log WHERE tool_name LIKE 'device_grant.%' "
                    "AND outcome = 'returned' AND detail IS NULL"
                )
            )
        ).scalar()
    assert naive == 4


def test_minted_is_reached_only_for_the_two_grants() -> None:
    """Every function in the device grant that calls ``minted()`` builds its
    ``PairingAudit`` with ``TOKEN_TOOL_NAME`` or ``REFRESH_TOOL_NAME``."""
    tree = ast.parse((REPO / "services/confirm/device_auth.py").read_text())
    allowed = {"TOKEN_TOOL_NAME", "REFRESH_TOOL_NAME"}
    callers = 0
    for function in (n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)):
        calls = [n for n in ast.walk(function) if isinstance(n, ast.Call)]
        mints = [c for c in calls if isinstance(c.func, ast.Attribute) and c.func.attr == "minted"]
        if not mints:
            continue
        callers += 1
        built = [
            kw.value.id
            for c in calls
            if isinstance(c.func, ast.Name) and c.func.id == PairingAudit.__name__
            for kw in c.keywords
            if kw.arg == "tool_name" and isinstance(kw.value, ast.Name)
        ]
        assert built and set(built) <= allowed, (function.name, built)
    assert callers == 2
    assert {TOKEN_TOOL_NAME, REFRESH_TOOL_NAME} == {"device_grant.token", "device_grant.refresh"}

"""Driving the api over HTTP with a real signed token, for the payments producer.

The producer's tools are consent-gated in every configuration, and
`Client(transport=server)` carries no access token, so `services/api/consent.py`
refuses them there and an in-process call proves nothing about them. These
helpers go through `create_app` with a `JWTVerifier` over an in-process key
pair, the harness `tests/test_audit_refusal_reason.py` built, and reach
`stub/backend.py` over ASGI, so every backend read is answered by the stub's
own scoping on the real internal token's `sub`.

ONE APP PER CALL, for the reason that file's `call` gives: `create_app` closes
its backend client when the lifespan exits, so a second call on one app fails
inside the tool.
"""

import json
from datetime import UTC, datetime
from typing import Any

import httpx2
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan
from postern_core.identity import TokenClaims
from postern_core.store.engine import Database
from postern_core.store.models import ConsentRecord
from sqlalchemy import delete, text

from services.api.main import create_app
from services.api.settings import Settings
from services.api.tools.payments import PaymentsRuntime
from stub import backend as stub

ISSUER = "https://postern-test.invalid"
AUDIENCE = "postern"

#: The two customers `stub/backend.py` holds fixtures for.
OWNER = "cust_7f3a"
OTHER = "cust_9b21"

_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


def token_for(
    key_pair: RSAKeyPair,
    subject: str,
    *,
    client_id: str | None = "claude-code",
    jti: str | None = "jti-test-1",
) -> str:
    """A customer token for `subject`, carrying `client_id` and `jti` unless
    told not to. Without a `client_id` claim, `JWTVerifier` falls back to
    `azp` and then to `sub` for `AccessToken.client_id`."""
    claims: dict[str, Any] = {}
    if client_id is not None:
        claims["client_id"] = client_id
    if jti is not None:
        claims["jti"] = jti
    return key_pair.create_token(
        subject=subject, issuer=ISSUER, audience=AUDIENCE, additional_claims=claims or None
    )


def producer_app(
    pg_url: str, key_pair: RSAKeyPair, *, payments_enabled: bool = True, **overrides: Any
) -> StarletteWithLifespan:
    """`create_app` with customer auth, the stub as backend, and the flag as given."""
    settings = Settings(
        backend_base_url="http://backend-stub",
        database_url=pg_url,
        customer_jwks_uri=None,
        customer_token_issuer=None,
        payments_enabled=payments_enabled,
        **overrides,
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_app(
        settings, transport=httpx2.ASGITransport(app=stub.app), auth_override=verifier
    )


async def post_rpc(
    app: StarletteWithLifespan, token: str, method: str, params: dict[str, Any]
) -> httpx2.Response:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
        "Mcp-Method": method,
    }
    if method == "tools/call":
        headers["Mcp-Name"] = params["name"]
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {**params, "_meta": _META}}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        async with app.router.lifespan_context(app):
            return await client.post("/mcp", headers=headers, json=body)


async def post_tool(
    app: StarletteWithLifespan, token: str, name: str, arguments: dict[str, Any] | None = None
) -> httpx2.Response:
    return await post_rpc(app, token, "tools/call", {"name": name, "arguments": arguments or {}})


async def call_tool(
    pg_url: str,
    key_pair: RSAKeyPair,
    token: str,
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    payments_enabled: bool = True,
    **overrides: Any,
) -> httpx2.Response:
    """One `tools/call` against a freshly built app, returned unparsed."""
    app = producer_app(pg_url, key_pair, payments_enabled=payments_enabled, **overrides)
    return await post_tool(app, token, name, arguments)


async def list_tool_names(
    pg_url: str, key_pair: RSAKeyPair, token: str, *, payments_enabled: bool = True
) -> set[str]:
    app = producer_app(pg_url, key_pair, payments_enabled=payments_enabled)
    response = await post_rpc(app, token, "tools/list", {})
    return {tool["name"] for tool in json.loads(response.text)["result"]["tools"]}


def result_of(response: httpx2.Response) -> dict[str, Any]:
    body: dict[str, Any] = json.loads(response.text)
    return dict(body["result"])


async def grant(database: Database, customer: str, *domains: str) -> None:
    async with database.sessionmaker() as session:
        for domain in domains:
            session.add(
                ConsentRecord(
                    customer_ref=customer,
                    domain=domain,
                    granted=True,
                    granted_at=datetime.now(UTC),
                    expires_at=None,
                )
            )
        await session.commit()


async def revoke_all_consents(database: Database) -> None:
    async with database.sessionmaker() as session:
        await session.execute(delete(ConsentRecord))
        await session.commit()


async def delete_produced_challenges(database: Database) -> None:
    """Every row the producer made: it is the only writer that sets a fingerprint."""
    async with database.sessionmaker() as session:
        await session.execute(text("DELETE FROM challenges WHERE request_fingerprint IS NOT NULL"))
        await session.commit()


#: A database nothing connects to: port 9 on loopback, which refuses. Building
#: a server and listing its tools opens no connection, and a consent check
#: with no token refuses before it reaches the store.
OFFLINE_DATABASE_URL = "postgresql+asyncpg://postern:postern@127.0.0.1:9/postern"


def no_claims() -> TokenClaims:
    return TokenClaims(client_id=None, jti=None)


def offline_runtime() -> PaymentsRuntime:
    """A runtime over `OFFLINE_DATABASE_URL`. Close it with `runtime.db.close()`."""
    return PaymentsRuntime(
        db=Database(OFFLINE_DATABASE_URL, null_pool=True, connect_timeout_seconds=0.5),
        claims=no_claims,
    )

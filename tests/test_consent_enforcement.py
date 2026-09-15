"""Consent must FILTER the catalogue and REJECT the call.

Filtering alone is not enforcement: a hidden tool is still callable by name.
Every test here runs over HTTP because get_access_token() is None under the
in-process Client, which would make these assertions pass vacuously.
"""

import json
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan
from postern_core.store.engine import Database
from postern_core.store.models import ConsentRecord
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.main import create_app
from services.api.settings import Settings

ISSUER = "https://postern-test.invalid"
AUDIENCE = "postern"
_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


@pytest.fixture(scope="session")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest_asyncio.fixture
async def session(database: Database) -> AsyncIterator[AsyncSession]:
    """Shadows `tests/conftest.py`'s own `session` fixture for this module.

    That fixture binds an `AsyncSession` to one externally-managed
    transaction, so `session.commit()` never reaches Postgres -- correct for
    its own fast rollback-based isolation, where every reader is the same
    test. Consent enforcement needs the opposite: the seed written here must
    be visible to a *second, independent* connection --
    `services/api/consent.py`'s own `Database(settings.database_url)` inside
    the running ASGI app. Verified directly against this database: seeding
    through conftest's `session` and calling `await session.commit()` left
    the row invisible from a fresh connection, because Postgres's default
    READ COMMITTED isolation only exposes a transaction's writes to other
    connections once that transaction's own commit has actually reached the
    database, not the ORM session bound on top of an already-open one. This
    fixture commits for real against `database`'s own engine and deletes its
    own rows afterward instead of relying on a rollback.
    """
    async with database.sessionmaker() as s:
        yield s
        await s.execute(delete(ConsentRecord))
        await s.commit()


def token_for(key_pair: RSAKeyPair, subject: str) -> str:
    return key_pair.create_token(subject=subject, issuer=ISSUER, audience=AUDIENCE)


async def seed(session: AsyncSession, customer: str, *domains: str) -> None:
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


def app_for(
    pg_url: str,
    key_pair: RSAKeyPair,
    backend_handler: Callable[[httpx2.Request], httpx2.Response],
) -> StarletteWithLifespan:
    settings = Settings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        customer_jwks_uri=None,
        customer_token_issuer=None,
        allow_stub_token_minter=True,
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_app(
        settings,
        transport=httpx2.MockTransport(backend_handler),
        auth_override=verifier,
    )


async def rpc(
    app: StarletteWithLifespan, token: str, method: str, params: dict[str, Any]
) -> dict[str, Any]:
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
    ) as c:
        async with app.router.lifespan_context(app):
            r = await c.post("/mcp", headers=headers, json=body)
    return dict(json.loads(r.text))


def backend(request: httpx2.Request) -> httpx2.Response:
    return httpx2.Response(200, json={"cards": [], "accounts": [], "transactions": []})


async def test_catalogue_is_filtered_by_consent(
    pg_url: str, key_pair: RSAKeyPair, session: AsyncSession
) -> None:
    await seed(session, "cust_7f3a", "accounts")
    app = app_for(pg_url, key_pair, backend)
    out = await rpc(app, token_for(key_pair, "cust_7f3a"), "tools/list", {})
    names = {t["name"] for t in out["result"]["tools"]}
    assert "accounts.list" in names
    assert "cards.list" not in names


async def test_a_filtered_tool_is_also_uncallable(
    pg_url: str, key_pair: RSAKeyPair, session: AsyncSession
) -> None:
    """The one that matters. A hidden tool must not be callable by name."""
    await seed(session, "cust_7f3a", "accounts")
    app = app_for(pg_url, key_pair, backend)
    out = await rpc(
        app,
        token_for(key_pair, "cust_7f3a"),
        "tools/call",
        {"name": "cards.list", "arguments": {}},
    )
    assert out["result"]["isError"] is True
    assert "cards.list" not in json.dumps(out["result"]).replace("Unknown tool: 'cards.list'", "")


async def test_a_consented_tool_is_callable(
    pg_url: str, key_pair: RSAKeyPair, session: AsyncSession
) -> None:
    await seed(session, "cust_7f3a", "accounts")
    app = app_for(pg_url, key_pair, backend)
    out = await rpc(
        app,
        token_for(key_pair, "cust_7f3a"),
        "tools/call",
        {"name": "accounts.list", "arguments": {}},
    )
    assert out["result"]["isError"] is False


async def test_two_customers_see_different_catalogues(
    pg_url: str, key_pair: RSAKeyPair, session: AsyncSession
) -> None:
    await seed(session, "cust_7f3a", "accounts")
    await seed(session, "cust_9b21", "accounts", "cards")
    app = app_for(pg_url, key_pair, backend)
    a = await rpc(app, token_for(key_pair, "cust_7f3a"), "tools/list", {})
    b = await rpc(app, token_for(key_pair, "cust_9b21"), "tools/list", {})
    assert {t["name"] for t in a["result"]["tools"]} != {t["name"] for t in b["result"]["tools"]}


async def test_a_customer_with_no_consent_sees_only_the_bootstrap_tool(
    pg_url: str, key_pair: RSAKeyPair, session: AsyncSession
) -> None:
    app = app_for(pg_url, key_pair, backend)
    out = await rpc(app, token_for(key_pair, "cust_7f3a"), "tools/list", {})
    assert {t["name"] for t in out["result"]["tools"]} == {"banking_start_session"}


async def test_a_malformed_subject_yields_no_error_and_no_consent_gated_tool(
    pg_url: str, key_pair: RSAKeyPair, session: AsyncSession
) -> None:
    """An uncaught exception in the auth check becomes JSON-RPC -32603.

    Corrected from the plan's original `tools == []`: `banking_start_session`
    deliberately carries no consent check at all (Step 4 -- "Do NOT attach a
    check to banking_start_session", and `bootstrap.py` is out of this
    task's scope), so FastMCP's `list_tools` never evaluates any check
    against it and it is unconditionally listed regardless of whether the
    token's subject parses as a customer. Measured directly against this
    implementation: it is the only tool that survives. The property this
    test actually guards -- a malformed subject degrades to a clean, empty
    *consent-gated* catalogue rather than surfacing `error` (JSON-RPC
    -32603) -- holds without requiring the bootstrap tool to disappear too.
    """
    out = await rpc(
        app_for(pg_url, key_pair, backend),
        token_for(key_pair, "ES9121000418450200051332"),
        "tools/list",
        {},
    )
    assert "error" not in out
    assert {t["name"] for t in out["result"]["tools"]} == {"banking_start_session"}

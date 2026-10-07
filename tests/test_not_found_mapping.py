"""A backend 404 on a caller-chosen account ref reads as one fixed sentence.

With `mask_error_details=True` a backend failure reaches the model as ``Error
calling tool 'x'`` and nothing more, so a mistyped or foreign ref and a backend
outage looked the same. `services/api/tools/not_found.py` maps a 404 (and only a
404) to ``ToolError("not found")`` for the tools that take a ref:
`accounts.get_balance` and `transactions.list`. Everything else stays masked.

The cross-customer property is asserted on bytes: the backend answers 404 for an
account that is another customer's exactly as for one that does not exist
(`tests/test_stub_subject_scoping.py` drives the stub's four routes), and the
reply to the model must not tell the two apart.
"""

from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.store.engine import Database

from services.api.main import create_app
from services.api.tools.not_found import NOT_FOUND
from tests.test_audit_reserve import (
    AUDIENCE,
    ISSUER,
    _drive_lifespan,
    _settings,
    consented,
    token_for,
)

CUSTOMER = "cust_notfound01"


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def _tool_call(tool: str, ref: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"account_ref": ref}},
    }


async def _call(app: Any, token: str, tool: str, ref: str) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        return await client.post(
            "/mcp",
            headers={
                "Accept": "application/json, text/event-stream",
                "Authorization": f"Bearer {token}",
                "Mcp-Method": "tools/call",
                "Mcp-Name": tool,
            },
            json=_tool_call(tool, ref),
        )


def _text(response: httpx2.Response) -> str:
    body = response.json()
    assert body["result"]["isError"] is True, body
    return str(body["result"]["content"][0]["text"])


@pytest.fixture
async def serving(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> AsyncIterator[Callable[[Callable[[httpx2.Request], httpx2.Response]], Any]]:
    """Builds the real app over a backend answering as the given handler does."""
    opened: list[Any] = []
    managers: list[Any] = []

    async def build(handler: Callable[[httpx2.Request], httpx2.Response]) -> Any:
        verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
        app = create_app(
            _settings(pg_url, database_pool_size=5, database_max_overflow=5),
            transport=httpx2.MockTransport(handler),
            auth_override=verifier,
        )
        manager = _drive_lifespan(app)
        await manager.__aenter__()
        managers.append(manager)
        opened.append(app)
        return app

    consent = consented(database, CUSTOMER, "accounts", "transactions")
    await consent.__aenter__()
    yield build
    for manager in reversed(managers):
        await manager.__aexit__(None, None, None)
    await consent.__aexit__(None, None, None)


def _answering(status: int) -> Callable[[httpx2.Request], httpx2.Response]:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, json={"detail": "zzsentinel_backend_body_8841"})

    return handler


def _unreachable(request: httpx2.Request) -> httpx2.Response:
    raise httpx2.ConnectError("zzsentinel_backend_body_8841 host:6379")


@pytest.mark.parametrize("tool", ["accounts.get_balance", "transactions.list"])
async def test_a_backend_404_is_the_fixed_not_found_sentence(
    serving: Any, key_pair: RSAKeyPair, tool: str
) -> None:
    app = await serving(_answering(404))

    response = await _call(app, token_for(key_pair, CUSTOMER), tool, "acc_unknown1")

    assert _text(response) == NOT_FOUND
    assert "zzsentinel_backend_body_8841" not in response.text


@pytest.mark.parametrize("tool", ["accounts.get_balance", "transactions.list"])
@pytest.mark.parametrize("status", [400, 401, 403, 500, 503])
async def test_every_other_backend_status_stays_masked(
    serving: Any, key_pair: RSAKeyPair, tool: str, status: int
) -> None:
    app = await serving(_answering(status))

    response = await _call(app, token_for(key_pair, CUSTOMER), tool, "acc_unknown1")

    assert _text(response) == f"Error calling tool '{tool}'"
    assert "zzsentinel_backend_body_8841" not in response.text


@pytest.mark.parametrize("tool", ["accounts.get_balance", "transactions.list"])
async def test_a_transport_failure_stays_masked(
    serving: Any, key_pair: RSAKeyPair, tool: str
) -> None:
    app = await serving(_unreachable)

    response = await _call(app, token_for(key_pair, CUSTOMER), tool, "acc_unknown1")

    assert _text(response) == f"Error calling tool '{tool}'"
    assert "zzsentinel_backend_body_8841" not in response.text


@pytest.mark.parametrize("tool", ["accounts.get_balance", "transactions.list"])
async def test_a_foreign_ref_and_an_unknown_ref_get_byte_identical_replies(
    serving: Any, key_pair: RSAKeyPair, tool: str
) -> None:
    """The backend 404s for both (ZT-2); the reply must not distinguish them."""
    app = await serving(_answering(404))
    token = token_for(key_pair, CUSTOMER)

    foreign = await _call(app, token, tool, "acc_ofsomeoneelse")
    unknown = await _call(app, token, tool, "acc_neverexisted")

    assert foreign.content == unknown.content
    assert _text(foreign) == NOT_FOUND

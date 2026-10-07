"""A backend 404 on a caller-chosen account ref reads as one fixed sentence.

With `mask_error_details=True` a backend failure reaches the model as ``Error
calling tool 'x'`` and nothing more, so a mistyped or foreign ref and a backend
outage looked the same. `services/api/tools/not_found.py` maps a 404 and a 403
(and no other status) to ``ToolError("not found")`` for the tools that take a
ref: `accounts.get_balance` and `transactions.list`. Everything else stays
masked, which is `Error calling tool 'x'` for a 400, 401, 500 or 503.

A 403 is mapped too although the contract is 404
(`dev-docs/postern-zero-trust-plan.md` section 3.2, `stub/backend.py`): a backend
that answers 403 for a foreign ref and 404 for an unknown one would otherwise
hand the model an existence oracle (A5), because the two would read differently
here.

The cross-customer property is asserted on bytes, twice: against the real stub
(`stub/backend.py` over ASGI, a second customer's ref and an invented ref) and
against a non-conforming backend that answers 403 for the foreign ref.
"""

from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.store.engine import Database

from services.api.main import create_app
from services.api.tools.not_found import NOT_FOUND
from stub import backend as stub
from tests.test_audit_reserve import (
    AUDIENCE,
    ISSUER,
    _drive_lifespan,
    _settings,
    consented,
    token_for,
)

CUSTOMER = "cust_notfound01"
#: A customer the stub knows: it owns `acc_7f3a`; `acc_9b21` is `cust_9b21`'s.
STUB_CUSTOMER = "cust_7f3a"
FOREIGN_REF = "acc_9b21"
UNKNOWN_REF = "acc_neverexisted"


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


async def _call_ok(app: Any, token: str, tool: str, ref: str) -> str:
    response = await _call(app, token, tool, ref)
    body = response.json()
    assert body["result"].get("isError") is not True, body
    return response.text


def _text(response: httpx2.Response) -> str:
    body = response.json()
    assert body["result"]["isError"] is True, body
    return str(body["result"]["content"][0]["text"])


@pytest.fixture
async def serving(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> AsyncIterator[Callable[[Any], Any]]:
    """Builds the real app over a backend: a handler function, or a ready transport."""
    opened: list[Any] = []
    managers: list[Any] = []

    async def build(backend: Any) -> Any:
        transport: httpx2.AsyncBaseTransport = (
            backend
            if isinstance(backend, httpx2.AsyncBaseTransport)
            else httpx2.MockTransport(backend)
        )
        verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
        app = create_app(
            _settings(pg_url, database_pool_size=5, database_max_overflow=5),
            transport=transport,
            auth_override=verifier,
        )
        manager = _drive_lifespan(app)
        await manager.__aenter__()
        managers.append(manager)
        opened.append(app)
        return app

    consents = [
        consented(database, who, "accounts", "transactions") for who in (CUSTOMER, STUB_CUSTOMER)
    ]
    for consent in consents:
        await consent.__aenter__()
    yield build
    for manager in reversed(managers):
        await manager.__aexit__(None, None, None)
    for consent in reversed(consents):
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
@pytest.mark.parametrize("status", [400, 401, 500, 503])
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
async def test_a_backend_403_is_the_same_fixed_not_found_sentence(
    serving: Any, key_pair: RSAKeyPair, tool: str
) -> None:
    app = await serving(_answering(403))

    response = await _call(app, token_for(key_pair, CUSTOMER), tool, "acc_unknown1")

    assert _text(response) == NOT_FOUND
    assert "zzsentinel_backend_body_8841" not in response.text


async def test_against_the_real_stub_a_foreign_ref_and_an_unknown_ref_are_byte_identical(
    serving: Any, key_pair: RSAKeyPair
) -> None:
    """`stub/backend.py` answers 404 for both (ZT-2); the reply must not tell them apart.

    Only `accounts.get_balance`: the stub's `transactions` route ignores the ref
    and returns the caller's own rows, so it has no not-found branch to drive.
    """
    app = await serving(httpx2.ASGITransport(app=stub.app))
    token = token_for(key_pair, STUB_CUSTOMER)

    own = await _call_ok(app, token, "accounts.get_balance", "acc_7f3a")
    foreign = await _call(app, token, "accounts.get_balance", FOREIGN_REF)
    unknown = await _call(app, token, "accounts.get_balance", UNKNOWN_REF)

    assert "1200.50" in own, "the stub did answer this customer's own account"
    assert _text(foreign) == NOT_FOUND
    assert foreign.content == unknown.content
    assert FOREIGN_REF not in foreign.text and UNKNOWN_REF not in unknown.text


@pytest.mark.parametrize("tool", ["accounts.get_balance", "transactions.list"])
async def test_a_backend_that_answers_403_for_a_foreign_ref_is_indistinguishable_from_404(
    serving: Any, key_pair: RSAKeyPair, tool: str
) -> None:
    """A non-conforming backend: 403 for the foreign ref, 404 for the unknown one."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        status = 403 if FOREIGN_REF in str(request.url) else 404
        return httpx2.Response(status, json={"detail": "zzsentinel_backend_body_8841"})

    app = await serving(handler)
    token = token_for(key_pair, CUSTOMER)

    foreign = await _call(app, token, tool, FOREIGN_REF)
    unknown = await _call(app, token, tool, UNKNOWN_REF)

    assert foreign.content == unknown.content
    assert _text(foreign) == NOT_FOUND

"""A consent denial and a mistyped tool name must differ in the AUDIT ROW and
nowhere else.

Before `audit_log.refusal_reason`, the two were the same row. FastMCP's
`_get_tool` returns no tool both for a name it does not know and for a tool
whose `auth=` check denied the caller (`fastmcp/server/server.py:886-915`),
and the dispatch turns both into one `NotFoundError`, so `AuditMiddleware`
recorded `outcome='raised'`, `detail='NotFoundError'` for each and an
investigator reading the table could not tell a refused `cards.list` from a
misspelled one. One of those rows is a consent record; the other is noise.

The wire response is the half that must NOT change, and one test here exists
solely to keep it that way. Telling an agent "you may not call cards.list"
confirms that the tool exists and that this customer holds cards, which is
the enumeration oracle `services/api/consent.py` and
`tests/test_consent_enforcement.py` were built to close.

Every test runs over real HTTP with a real signed token, like
`tests/test_consent_enforcement.py` and for the same reason: `get_access_token()`
is None under the in-process `Client`, so consent never denies anything there
and an assertion about a denial would pass vacuously. The harness below is a
deliberate copy of that module's, not an import: sharing it would mean
editing the file whose job is to prove the catalogue-filtering behaviour this
change must leave untouched.
"""

import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan
from postern_core.store.engine import Database
from postern_core.store.models import (
    REFUSAL_DOMAIN_NOT_CONSENTED,
    REFUSAL_NO_CUSTOMER_REF,
    AuditEntry,
    ConsentRecord,
)
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.main import create_app
from services.api.settings import Settings
from tests.fixtures import backend_responses as fx

ISSUER = "https://postern-test.invalid"
AUDIENCE = "postern"
CUSTOMER = "cust_7f3a"

# An IBAN, used as a token subject. `CustomerRef` rejects it (identity.py),
# so `services/api/consent.py`'s `_customer` finds no customer to look
# consent up for -- the second, distinct refusal this column records. Same
# value `tests/test_consent_enforcement.py` uses for the catalogue half of
# this behaviour.
NOT_A_CUSTOMER_REF = "ES9121000418450200051332"

_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}

# `cards.lost` is a typo of `cards.list`, chosen the same LENGTH as the tool
# it misspells. The wire test below then compares two whole response bodies
# byte for byte after substituting the name, with no allowance for a
# different `Content-Length`: a name the server echoes back is already known
# to whoever sent it, so the echo is not the leak, but a response that
# differed in any other byte would be.
DENIED_TOOL = "cards.list"
UNKNOWN_TOOL = "cards.lost"


@pytest.fixture(scope="session")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest_asyncio.fixture
async def consent_session(database: Database) -> AsyncIterator[AsyncSession]:
    """Commits for real, against the engine's own connection.

    `tests/conftest.py`'s `session` fixture binds to one externally-managed
    transaction, so its `commit()` never reaches Postgres -- correct for
    reading rows back inside a single test, useless for seeding a row that a
    SECOND connection must see, which is what `services/api/consent.py`
    inside the running ASGI app is. Deletes its own rows afterwards, since
    there is no rollback to undo them.
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


def _backend(request: httpx2.Request) -> httpx2.Response:
    routes = {
        "/accounts": fx.ACCOUNTS,
        f"/accounts/{fx.BALANCE['account_id']}/balance": fx.BALANCE,
        "/cards": fx.CARDS,
    }
    body = routes.get(request.url.path)
    return httpx2.Response(200, json=body) if body is not None else httpx2.Response(404, json={})


def _app(pg_url: str, key_pair: RSAKeyPair) -> StarletteWithLifespan:
    settings = Settings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        customer_jwks_uri=None,
        customer_token_issuer=None,
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_app(
        settings,
        transport=httpx2.MockTransport(_backend),
        auth_override=verifier,
    )


async def call(
    pg_url: str,
    key_pair: RSAKeyPair,
    token: str,
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    protocol_version_header: bool = False,
) -> httpx2.Response:
    """One `tools/call` against a freshly built app, returned unparsed.

    A fresh app per call, not one shared across a test: `create_app` wires
    `BackendClient.aclose()` and `Database.close()` into the ASGI lifespan
    (`_close_resources_after_fastmcp_shutdown`), so exiting the lifespan
    context closes the backend client, and a second call on the same app
    reaches its tool and dies inside it with `RuntimeError: Cannot send a
    request, as the client has been closed` -- an `isError` result that
    would pass a careless assertion about a call being refused. Measured,
    2026-09-17. Each app opens its own `Database` against the same
    container, so the audit rows all land in one table regardless.

    The response object, not its parsed body: the wire test compares whole
    response TEXT, and `json.loads` would hide exactly the byte-level
    difference it exists to rule out.

    `MCP-Protocol-Version` is opt-in because it changes how many consent
    checks run. With it present and non-empty arguments on the call, the MCP
    SDK dispatches a full internal `tools/list` to validate Mcp-Param
    headers (`mcp/server/_streamable_http_modern.py:285-359`, gated in
    `mcp/server/streamable_http_manager.py:191-196`), which evaluates EVERY
    consent-gated tool's check, not just the one being called.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
    }
    if protocol_version_header:
        headers["MCP-Protocol-Version"] = "2026-07-28"
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}, "_meta": _META},
    }
    app = _app(pg_url, key_pair)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        async with app.router.lifespan_context(app):
            return await client.post("/mcp", headers=headers, json=body)


async def rows(session: AsyncSession) -> list[AuditEntry]:
    result = await session.execute(select(AuditEntry).order_by(AuditEntry.id))
    return list(result.scalars().all())


async def test_a_denial_and_a_typo_are_now_distinguishable_in_the_audit_log(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    consent_session: AsyncSession,
    session: AsyncSession,
) -> None:
    """The measurement this change exists for. `cust_7f3a` consented to
    `accounts` only, so `cards.list` is refused; `cards.lost` does not
    exist. Both produce `outcome='raised'`, `detail='NotFoundError'` -- that
    part is unchanged and is asserted, because it is what made the rows
    identical -- and `refusal_reason` is now the field that tells them
    apart.

    `audit_server` is requested for its clear-`audit_log`-before-and-after
    behaviour (see its docstring in `tests/conftest.py`), not for the server
    object: these calls go through a real ASGI app instead. Rows are read
    back out of Postgres through `session`, a connection whose identity map
    never held the middleware's objects, so a value that only ever existed
    in SQLAlchemy memory cannot pass this test.

    The two-row unpack below also pins something the entry row could have
    changed and does not: two calls, two rows. A refused call and an unknown
    tool each still produce exactly ONE row, because neither reaches the
    backend and the `reaching` row records a touch rather than an attempt.
    """
    await seed(consent_session, CUSTOMER, "accounts")
    token = token_for(key_pair, CUSTOMER)
    await call(pg_url, key_pair, token, DENIED_TOOL)
    await call(pg_url, key_pair, token, UNKNOWN_TOOL)

    denied, unknown = await rows(session)
    assert (denied.tool_name, denied.outcome, denied.detail) == (
        DENIED_TOOL,
        "raised",
        "NotFoundError",
    )
    assert (unknown.outcome, unknown.detail) == (denied.outcome, denied.detail)
    assert denied.refusal_reason == REFUSAL_DOMAIN_NOT_CONSENTED
    assert unknown.refusal_reason is None


async def test_the_caller_still_cannot_tell_a_denial_from_a_typo(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    consent_session: AsyncSession,
) -> None:
    """The test that stops someone "improving" the error message later.

    Naming the refusal on the wire would tell an agent that `cards.list`
    exists and that this customer holds cards -- the enumeration oracle
    `services/api/consent.py` closes by returning `Unknown tool` for a
    refusal, and the property `tests/test_consent_enforcement.py` guards for
    the catalogue. The audit row gained a distinction; the response must not
    have.

    Asserted on the raw response text, not a parsed body, with the two tool
    names substituted for one placeholder and nothing else changed: the
    names differ because the caller chose them, are the same length here so
    even `Content-Length` matches, and any other differing byte fails this.
    """
    await seed(consent_session, CUSTOMER, "accounts")
    token = token_for(key_pair, CUSTOMER)
    denied = await call(pg_url, key_pair, token, DENIED_TOOL)
    unknown = await call(pg_url, key_pair, token, UNKNOWN_TOOL)

    assert denied.status_code == unknown.status_code == 200
    assert f"Unknown tool: '{DENIED_TOOL}'" in denied.text
    assert f"Unknown tool: '{UNKNOWN_TOOL}'" in unknown.text
    assert denied.text.replace(DENIED_TOOL, "X") == unknown.text.replace(UNKNOWN_TOOL, "X")
    assert denied.headers["content-type"] == unknown.headers["content-type"]
    assert denied.headers["content-length"] == unknown.headers["content-length"]
    # The refused call is an `isError` result, exactly as the unknown name
    # is, and carries nothing beyond the name it was given.
    assert json.loads(denied.text)["result"]["isError"] is True


async def test_a_subject_that_is_not_a_customer_reference_records_its_own_reason(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    consent_session: AsyncSession,
    session: AsyncSession,
) -> None:
    """The second refusal, and the one that proves this column is not a
    boolean. The token is valid and signed; its `sub` is an IBAN, which
    `CustomerRef` refuses, so the check never gets as far as asking what
    this caller consented to. `no_customer_ref` says exactly that and
    nothing about the token itself.

    `customer_ref` on the same row is NULL, because the middleware validates
    the subject the same way. That column answers a different question from
    this one and cannot replace it: it is NULL on plenty of rows nobody
    refused.
    """
    token = token_for(key_pair, NOT_A_CUSTOMER_REF)
    response = await call(pg_url, key_pair, token, "accounts.list")

    entry = (await rows(session))[0]
    assert entry.tool_name == "accounts.list"
    assert entry.outcome == "raised"
    assert entry.detail == "NotFoundError"
    assert entry.refusal_reason == REFUSAL_NO_CUSTOMER_REF
    assert entry.customer_ref is None
    assert "Unknown tool: 'accounts.list'" in response.text
    assert NOT_A_CUSTOMER_REF not in response.text


# -- One call, several tools' checks -----------------------------------------
#
# A `tools/call` carrying non-empty arguments, sent with a real
# `MCP-Protocol-Version` header, makes the MCP SDK dispatch an internal
# `tools/list` before the real call, and that pass evaluates EVERY
# consent-gated tool's check, not just the one being called. Measured
# 2026-09-17 for `accounts.get_balance` on a customer consented to `accounts`
# only: accounts.list=True, accounts.get_balance=True,
# transactions.list=False, cards.list=False, then accounts.get_balance=True
# again for the dispatch itself -- two denials, for tools nobody called,
# during one call that was allowed.
#
# The two tests below are the two ways that could reach the wrong row, and
# they are separate because two different pieces of code stop them: the
# returned path writes NULL as a constant (a call that returned was not
# refused), while the raised path does look a refusal up and is kept honest
# only by the decision being filed per tool name. A single "last refusal"
# slot passes the first test and fails the second.


async def test_a_permitted_call_that_succeeds_records_no_refusal_reason(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    consent_session: AsyncSession,
    session: AsyncSession,
) -> None:
    """`accounts.get_balance` is consented and returns a balance, while
    `transactions.list` and `cards.list` are denied inside the same HTTP
    request. The row is a successful call and must read as one."""
    await seed(consent_session, CUSTOMER, "accounts")
    response = await call(
        pg_url,
        key_pair,
        token_for(key_pair, CUSTOMER),
        "accounts.get_balance",
        {"account_ref": str(fx.BALANCE["account_id"])},
        protocol_version_header=True,
    )
    assert json.loads(response.text)["result"]["isError"] is False

    entries = await rows(session)
    # Two rows, because this call reached the backend: the entry row committed
    # before it did and the completion row after it answered. Both carry NULL
    # here, and the entry row's NULL is the stronger statement of the two --
    # it is written from below the consent check, so it can only exist on a
    # call consent allowed.
    assert [(e.tool_name, e.outcome) for e in entries] == [
        ("accounts.get_balance", "reaching"),
        ("accounts.get_balance", "returned"),
    ]
    assert [e.refusal_reason for e in entries] == [None, None]


async def test_a_permitted_call_that_fails_is_not_stamped_with_another_tools_denial(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    consent_session: AsyncSession,
    session: AsyncSession,
) -> None:
    """The test that pins the per-tool keying, and the only one that fails
    if the decision is filed in one slot per request.

    Same consented call as above, against an account the stub backend has no
    balance for, so the tool itself fails and the row is written by
    `on_call_tool`'s raised branch -- the branch that asks
    `consent.refusal_for`. Two other tools were denied inside this same HTTP
    request. `accounts.get_balance` was not one of them, so the row must
    carry NULL: a tool that failed on its own must never be recorded as a
    consent refusal, which would put a consent event a regulator can act on
    into a row where none happened.
    """
    await seed(consent_session, CUSTOMER, "accounts")
    response = await call(
        pg_url,
        key_pair,
        token_for(key_pair, CUSTOMER),
        "accounts.get_balance",
        {"account_ref": "acc_9b21"},
        protocol_version_header=True,
    )
    assert json.loads(response.text)["result"]["isError"] is True

    # The COMPLETION row, which is the second one: this tool reached the
    # backend (and got a 404 back), so an entry row was committed first.
    entries = await rows(session)
    assert [e.outcome for e in entries] == ["reaching", "raised"]
    entry = entries[1]
    assert entry.tool_name == "accounts.get_balance"
    assert entry.outcome == "raised"
    # Not `NotFoundError`: the tool was found and consented, and failed
    # inside itself. That is the row a single-slot design corrupts.
    assert entry.detail != "NotFoundError"
    assert entry.refusal_reason is None

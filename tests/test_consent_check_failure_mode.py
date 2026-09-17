"""What a consent check that RAISES does. Characterisation, not endorsement.

`services/api/consent.py`'s `check()` reaches Postgres at line 190
(`if domain in await _domains(db, customer)`). A store outage is not an
exotic condition, and nothing in this repository had ever established what
the check does when that line raises instead of returning a decision:
`docs/decisions/0006-audit-write-failure.md` made that call deliberately for
audit writes and wrote the cost down, but consent never had the equivalent.
These tests pin the answer measured on 2026-09-17, so it is a fact in the
repository before anyone changes it. They assert what IS, not what should
be; if the policy is ever chosen deliberately, these are the tests to
rewrite, and their names say so.

MEASURED ANSWER: it fails CLOSED, on both halves and in both failure shapes.

The mechanism is FastMCP's, not this project's.
`fastmcp/utilities/authorization.py:236-250` (`_evaluate_check`) catches
`Exception` around every auth check, logs "Auth check ... raised an
unexpected exception", and returns `False` -- its own docstring: "it is
logged and treated as a denial so a broken check fails closed". Both places
that consult `auth=` go through it (`run_auth_checks`, called from
`fastmcp/server/server.py:879` for `list_tools` and `:910` for `_get_tool`),
which is why the catalogue and the call agree. The HTTP status stays 200
because a denial is `CallToolResult(is_error=True)` inside a 200, never a
status -- CLAUDE.md's "Version traps" records that `ToolError` cannot
produce one either.

Two failure shapes, because they are not the same event and could have had
opposite answers:

  - REFUSED CONNECTION (nothing listening). `ConnectionRefusedError`, an
    `OSError`, in about 0.0s.
  - BLACKHOLE (the TCP handshake completes and the server never speaks --
    the shape a hung database or a dropping network path actually has).
    Measured against a real listener that accepts and stays silent:
    `TimeoutError` after **60.0 seconds**, which was asyncpg's own default
    `connect(timeout=60)` and, as measured on 2026-09-17, the ONLY
    deadline anywhere on this path -- no `command_timeout`, no
    `statement_timeout`, no pool timeout, with every configured timeout in
    the repository belonging to the backend HTTP client
    (`services/api/main.py:_backend_timeout`), a different dependency. So a
    hung store held the request for a minute and only then denied it.
    `Database.__init__` now sets all three itself (2.0s connect, 3.0s per
    statement, 1.0s pool, each configurable), which changes how long that
    minute is and nothing else: still `Exception`, still caught, still
    denied, and the backend still never reached. That invariance is the
    point of keeping this test.

`test_a_blackholed_consent_store_...` below passes 1s through that
constructor so CI does not spend even the 2; the 60s figure above is the
driver default this path actually ran on, measured, not an estimate.
Passing the timeout in the URL query string does NOT work
and was tried: SQLAlchemy hands asyncpg the string "1" and the connect dies
with `TypeError: unsupported operand type(s) for +: 'float' and 'str'` in
0.0s, which would have made the test pass for entirely the wrong reason.

Everything runs over real HTTP with a real signed token, for the reason
`tests/test_consent_enforcement.py` states: `get_access_token()` is None
under the in-process `Client`, so consent denies nothing there and any
assertion about a denial passes vacuously.

Consent and audit get SEPARATE `Database` objects here, which production
does not do (`create_app` builds one and hands it to both). That is
deliberate and is what makes these measurements attributable: with one dead
database, the audit write fails too, and a call denied by consent cannot be
told apart from a call refused because it could not be recorded. Giving
audit a healthy store isolates the consent question. The faithful
whole-outage case was measured separately and reaches the same wire answer --
`isError: true`, `Unknown tool`, backend untouched -- with the audit row
additionally lost (`audit write failed for tool 'accounts.list' after it
raised NotFoundError`), so an outage denies the call AND loses the record
that it denied it.
"""

import asyncio
import json
import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from fastmcp.server.http import StarletteWithLifespan
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.auth.keys import GeneratedKeySource
from postern_core.auth.read_minter import ReadTokenMinter
from postern_core.facade.client import BackendClient
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ConsentRecord
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware import Middleware

from services.api.asgi.header_validation import HeaderBodyValidation
from services.api.middleware.audit import AuditMiddleware
from services.api.server import build_server, token_customer_resolver
from services.api.settings import Settings

ISSUER = "https://postern-test.invalid"
AUDIENCE = "postern"
CUSTOMER = "cust_7f3a"
GATED_TOOL = "accounts.list"

# Nothing listens on port 1, so asyncpg's connect is refused immediately.
REFUSED_URL = "postgresql+asyncpg://postern:postern@127.0.0.1:1/postern"

# Every consent-gated tool registered by `build_server`. `start_session`
# is deliberately NOT in this set: `bootstrap.py` carries no `auth=` at all, so
# `list_tools` never evaluates a check against it and it survives every
# condition in this file. That is existing behaviour, asserted in
# `tests/test_consent_enforcement.py`, not something a store outage changes.
GATED_TOOLS = frozenset(
    {"accounts.list", "accounts.get_balance", "transactions.list", "cards.list"}
)

_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


@pytest.fixture(scope="session")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest_asyncio.fixture
async def consent_session(database: Database) -> AsyncIterator[AsyncSession]:
    """Commits for real, then deletes its own rows.

    `tests/conftest.py`'s `session` fixture binds to one externally-managed
    transaction whose `commit()` never reaches Postgres, so a row seeded
    through it is invisible to the second, independent connection that the
    consent check inside the running ASGI app opens. Same reasoning, and the
    same shape, as `tests/test_consent_enforcement.py`'s own override.
    """
    async with database.sessionmaker() as s:
        yield s
        await s.execute(delete(ConsentRecord))
        await s.commit()


@pytest_asyncio.fixture
async def blackhole_port() -> AsyncIterator[int]:
    """A TCP listener that completes the handshake and then never speaks.

    This is the honest "hung database" shape. A refused connection raises at
    once; a blackhole lets asyncpg finish connecting at the socket level and
    then wait for a server greeting that never arrives, which is what a
    wedged Postgres or a path that silently drops packets looks like from the
    client. Simulating it with `asyncio.sleep` in a fake sessionmaker would
    prove only that sleeping delays things.
    """
    stop = asyncio.Event()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await stop.wait()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port: int = server.sockets[0].getsockname()[1]
    yield port
    stop.set()
    server.close()
    await server.wait_closed()


class RecordingBackend:
    """Did the tool's BODY run? The decisive signal in this file.

    A denial and a successful call both arrive as HTTP 200, so the wire
    envelope alone cannot separate "refused" from "ran and returned nothing".
    Every read tool's work is a backend request, so a backend that records
    its calls answers the question the status code cannot: if this stays
    empty, no customer data was reached.
    """

    def __init__(self) -> None:
        self.paths: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(request.url.path)
        return httpx2.Response(200, json={"accounts": [], "transactions": [], "cards": []})


def _settings(pg_url: str) -> Settings:
    """Both customer-auth fields stay None on purpose.

    `_app` below passes its own `JWTVerifier` as `auth_override`, which is
    what actually puts a validated token in front of the consent check; the
    JWKS URI and issuer would only build a second verifier this test cannot
    mint for. They are not a no-auth switch here.

    No minter flag: `_app` constructs the real `ReadTokenMinter` itself and
    never routes through `create_app`, so the deleted
    `allow_stub_token_minter` was inert on this path even before d203606
    removed it (and doubly so, since the guard it fed only fired when both
    fields above were set).
    """
    return Settings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        customer_jwks_uri=None,
        customer_token_issuer=None,
    )


def _app(
    consent_db: Database,
    audit_db: Database,
    key_pair: RSAKeyPair,
    backend_handler: Callable[[httpx2.Request], httpx2.Response],
    settings: Settings,
) -> StarletteWithLifespan:
    """`create_app`'s assembly, with consent and audit on separate databases.

    Mirrors `services/api/main.py:create_app` -- same `build_server`, same
    `AuditMiddleware`, same `http_app` and `HeaderBodyValidation` -- except
    that production passes ONE `Database` to both and this takes two, for the
    attribution reason in the module docstring. `_close_resources_after_
    fastmcp_shutdown` is deliberately not wired: it closes the backend client
    on lifespan exit, which would make a second call on the same app fail
    inside the tool with `RuntimeError: Cannot send a request, as the client
    has been closed` -- an `isError` result that would satisfy a careless
    assertion about a refusal.
    """
    backend = BackendClient(
        settings.backend_base_url,
        ReadTokenMinter(
            InternalTokenMinter(
                issuer=settings.read_token_issuer,
                key_source=GeneratedKeySource(kid=settings.read_key_kid),
            )
        ),
        transport=httpx2.MockTransport(backend_handler),
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    server = build_server(
        settings,
        token_customer_resolver,
        backend,
        db=consent_db,
        auth_override=verifier,
    )
    server.add_middleware(AuditMiddleware(audit_db))
    return server.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        middleware=[
            Middleware(
                HeaderBodyValidation,
                strict=settings.strict_headers,
                max_body_bytes=settings.max_body_bytes,
            )
        ],
    )


def _token(key_pair: RSAKeyPair, subject: str = CUSTOMER) -> str:
    return key_pair.create_token(subject=subject, issuer=ISSUER, audience=AUDIENCE)


async def _seed(session: AsyncSession, customer: str, *domains: str) -> None:
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


async def _rpc(
    app: StarletteWithLifespan, token: str, method: str, params: dict[str, Any]
) -> httpx2.Response:
    """One JSON-RPC call over the real ASGI stack.

    `MCP-Protocol-Version` is sent because production clients send it, and it
    is what makes a `tools/call` with arguments trigger the MCP SDK's own
    internal `tools/list` pass (`services/api/consent.py`'s module docstring
    measures this at 5 evaluations of `check()` for one call). Sending it
    means these measurements cover the path where the check runs many times,
    not the quieter one where it runs twice.
    """
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": f"Bearer {token}",
        "Mcp-Method": method,
        "MCP-Protocol-Version": "2026-07-28",
    }
    if method == "tools/call":
        headers["Mcp-Name"] = str(params["name"])
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": {**params, "_meta": _META}}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        async with app.router.lifespan_context(app):
            return await client.post("/mcp", headers=headers, json=body)


def _tool_names(response: httpx2.Response) -> set[str]:
    payload = json.loads(response.text)
    assert "error" not in payload, payload
    return {tool["name"] for tool in payload["result"]["tools"]}


def _result(response: httpx2.Response) -> dict[str, Any]:
    payload = json.loads(response.text)
    assert "error" not in payload, payload
    return dict(payload["result"])


async def _audit_rows(session: AsyncSession) -> list[AuditEntry]:
    rows = await session.execute(select(AuditEntry).order_by(AuditEntry.id))
    return list(rows.scalars().all())


async def test_control_a_healthy_consent_check_lists_and_runs_the_consented_tool(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
) -> None:
    """The control, so the difference below is attributable to the outage.

    Same harness, same customer, same tool; only the consent database's
    health changes between this test and the next two.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    backend = RecordingBackend()
    app = _app(database, database, key_pair, backend, _settings(pg_url))

    listed = _tool_names(await _rpc(app, _token(key_pair), "tools/list", {}))
    assert GATED_TOOL in listed

    called = _result(
        await _rpc(app, _token(key_pair), "tools/call", {"name": GATED_TOOL, "arguments": {}})
    )
    assert called["isError"] is False
    assert backend.paths == ["/accounts"], "the control must actually reach the backend"


async def test_a_raising_consent_check_currently_hides_every_consent_gated_tool(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
) -> None:
    """Question 1: filtered out, or present? Measured: filtered out.

    The customer HAS consent to `accounts` -- seeded here and proven
    sufficient by the control -- so nothing but the unreachable store
    removes the tool. HTTP 200 with a short catalogue, not an error: the
    denial is a filter, and `tools/list` never learns anything went wrong.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    dead = Database(REFUSED_URL)
    try:
        app = _app(dead, database, key_pair, RecordingBackend(), _settings(pg_url))
        response = await _rpc(app, _token(key_pair), "tools/list", {})
        assert response.status_code == 200
        assert _tool_names(response) & GATED_TOOLS == set()
    finally:
        await dead.close()


async def test_a_raising_consent_check_currently_denies_the_call_and_never_runs_the_tool(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
) -> None:
    """Question 2, the one that decides bypass versus disclosure.

    Filtering `tools/list` is not enforcement -- this project measured on
    2026-09-14 that a token filtered out of a tool could still call it by
    name and get `isError: false` -- so the catalogue test above cannot
    answer this. The assertion that matters is the last one: the backend is
    never reached, so no customer data moved. A call that returned data here
    would be an authorization bypass; this one is a refusal.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    dead = Database(REFUSED_URL)
    try:
        backend = RecordingBackend()
        app = _app(dead, database, key_pair, backend, _settings(pg_url))
        response = await _rpc(
            app, _token(key_pair), "tools/call", {"name": GATED_TOOL, "arguments": {}}
        )
        assert response.status_code == 200
        result = _result(response)
        assert result["isError"] is True
        assert result["content"] == [{"type": "text", "text": f"Unknown tool: '{GATED_TOOL}'"}]
        assert backend.paths == [], "the tool body must not run when the consent check raised"
    finally:
        await dead.close()


async def test_a_raising_consent_check_currently_files_no_refusal_reason(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    session: AsyncSession,
) -> None:
    """The cost of failing closed this way: the audit row cannot say why.

    `services/api/consent.py`'s `_refuse` is what puts a reason on the row,
    and it sits on lines 188 and 192 -- both AFTER the `await _domains(...)`
    on line 190 that raised. So a store outage produces exactly the row
    `docs/decisions/0006`-era code produced before `refusal_reason` existed:
    `outcome='raised'`, `detail='NotFoundError'`, reason NULL, which is
    byte-identical to a mistyped tool name. `tests/test_audit_refusal_reason.py`
    exists to keep a real consent denial distinguishable from a typo; this
    records that the outage case is the third thing none of them can tell
    apart. Not a new bug -- a gap in the vocabulary, worth pinning because a
    reviewer reading the table during an outage will see only typos.

    `audit_server` is requested for its clear-`audit_log`-before-and-after
    behaviour (see `tests/conftest.py`), not for the server object: this call
    goes through the ASGI app below.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    dead = Database(REFUSED_URL)
    try:
        app = _app(dead, database, key_pair, RecordingBackend(), _settings(pg_url))
        await _rpc(app, _token(key_pair), "tools/call", {"name": GATED_TOOL, "arguments": {}})
    finally:
        await dead.close()

    rows = await _audit_rows(session)
    assert len(rows) == 1
    assert rows[0].tool_name == GATED_TOOL
    assert rows[0].outcome == "raised"
    assert rows[0].detail == "NotFoundError"
    assert rows[0].refusal_reason is None


async def test_a_blackholed_consent_store_currently_denies_only_after_the_driver_timeout(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    blackhole_port: int,
) -> None:
    """The other failure shape: accepted, then silence. Same verdict, later.

    A refused connection raises in 0.0s. A blackhole raises only when
    something above it gives up, and until `Database` took `connect_args` the
    only thing that did was asyncpg's own `connect(timeout=...)` at its
    60-second default -- measured, and the sole deadline on this path. It is
    now a constructor argument defaulting to 2.0s, lowered to 1s here so CI
    does not spend even that; the assertion that the call took AT LEAST that
    long is what distinguishes a real wait from a fast failure for some other
    reason, which is how the URL-query-string attempt described in the module
    docstring was caught.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    url = f"postgresql+asyncpg://postern:postern@127.0.0.1:{blackhole_port}/postern"
    # Through `Database`'s own constructor, which passes it to asyncpg as
    # `connect_args={"timeout": ...}`. The query-string form still does not
    # work and is still the trap: it hands asyncpg a string it cannot add to
    # a float, in 0.0s.
    hanging = Database(url, connect_timeout_seconds=1.0)
    try:
        backend = RecordingBackend()
        app = _app(hanging, database, key_pair, backend, _settings(pg_url))
        started = time.monotonic()
        response = await _rpc(
            app, _token(key_pair), "tools/call", {"name": GATED_TOOL, "arguments": {}}
        )
        elapsed = time.monotonic() - started
    finally:
        await hanging.close()

    assert elapsed >= 1.0, f"answered in {elapsed:.2f}s -- it cannot have waited on the socket"
    assert response.status_code == 200
    assert _result(response)["isError"] is True
    assert backend.paths == [], "a hung store must not let the tool body run either"

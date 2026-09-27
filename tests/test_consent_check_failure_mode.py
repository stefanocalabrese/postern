"""What a consent check that RAISES does. Characterisation, then a decision.

`services/api/consent.py`'s `check` reaches Postgres through its
`await _domains(db, customer)`. A store outage is not an
exotic condition, and nothing in this repository had ever established what
the check does when that line raises instead of returning a decision:
`dev-docs/decisions/0006-audit-write-failure.md` made that call deliberately for
audit writes and wrote the cost down, but consent never had the equivalent.
These tests pinned the answer measured on 2026-09-17, so it was a fact in
the repository before anyone changed it, and the three whose names still
carry "currently" assert what IS rather than what should be.

ONE OF THEM WAS REWRITTEN ON 26 SEPTEMBER 2026, which is what the file said
would happen when the policy was chosen deliberately. capo ruled that
failing closed is correct and stays, and that denying SILENTLY and
INDISTINGUISHABLY is not: `test_a_raising_consent_check_files_the_store
_unavailable_reason` below asserted a NULL `refusal_reason` under its old
name and now asserts `consent_store_unavailable`. The three tests around it
are untouched, because what they measure -- hidden from the catalogue,
denied on call, backend never reached, in both failure shapes -- is the half
that was ruled correct.

MEASURED ANSWER: it fails CLOSED, on both halves and in both failure shapes.

The mechanism is FastMCP's, not this project's.
`fastmcp/utilities/authorization.py`'s `_evaluate_check` catches
`Exception` around every auth check, logs "Auth check ... raised an
unexpected exception", and returns `False` -- its own docstring: "it is
logged and treated as a denial so a broken check fails closed". Both places
that consult `auth=` go through it (`run_auth_checks`, called from
`fastmcp/server/server.py::list_tools` and from that module's `_get_tool`),
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
from postern_core.auth.revocation import unchecked_revocation
from postern_core.facade.client import BackendClient
from postern_core.store import consents
from postern_core.store.engine import Database
from postern_core.store.models import (
    REFUSAL_CONSENT_STORE_UNAVAILABLE,
    REFUSAL_DOMAIN_NOT_CONSENTED,
    AuditEntry,
    ConsentRecord,
)
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware import Middleware

from services.api import consent
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


class BalanceBackend:
    """Serves one real balance, for the healthy-store test.

    `RecordingBackend` above answers every path with the same three empty
    lists, which `accounts.list` accepts and `accounts.get_balance` cannot:
    the facade reads `account_id`, `amount`, `currency` and `as_of` out of
    the payload, so that handler makes a consented call fail inside the tool
    body. Only the test that has to SUCCEED on the five-evaluation path
    needs this, and only `accounts.get_balance` takes the non-empty
    arguments that make the MCP SDK dispatch its internal `tools/list`.
    """

    def __init__(self) -> None:
        self.paths: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(request.url.path)
        return httpx2.Response(
            200,
            json={
                "account_id": "acc_7f3a",
                "amount": "1200.50",
                "currency": "EUR",
                "as_of": "2026-09-12T10:00:00Z",
            },
        )


class FailingBackend:
    """A backend that answers 500 to everything, so the TOOL BODY raises.

    The third of the three states this file now separates, and the only one
    that is not a refusal: `BackendClient` raises `BackendError` above 400
    and FastMCP wraps it, so the row reads `detail='ToolError'` where both
    refusals read `NotFoundError`.

    It records paths like `RecordingBackend` does, for the one test that
    needs to distinguish "the body ran and the backend refused it" from "the
    body never ran": `detail='ToolError'` proves the first, an empty
    `paths` proves the second, and a test asserting a denial needs both.
    """

    def __init__(self) -> None:
        self.paths: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(request.url.path)
        return httpx2.Response(500, json={"detail": "backend down"})


class _Probes:
    """What one request ASKED of the consent store, counted at two levels.

    The two numbers are the whole subject of the tests below and they are not
    the same number.

    `lookups` counts evaluations that reached `services/api/consent.py`'s
    `_domains`, which is once per `auth=` evaluation for a customer this
    check could name. `attempts` counts the ones that reached Postgres.
    Every gap between them is a request-scoped cache absorbing an
    evaluation, and a gap is the point: one `tools/call` carrying arguments
    is five evaluations (the module docstring of that file measures it), and
    an outage that costs five connection attempts costs five
    `pool_timeout` waits during the event that exhausted the pool.

    Patched at `_domains` rather than at the registered check because the
    check is built inside `build_server` and closed over per domain, while
    these two functions are exactly the two levels being separated. The
    private name is deliberate: no public seam expresses "asked" versus
    "reached the database", and inventing one for a test would put a
    production indirection in the path this test exists to measure.
    """

    def __init__(self) -> None:
        self.lookups: list[str] = []
        self.attempts: list[str] = []


def _count_probes(monkeypatch: pytest.MonkeyPatch, *, fail_first: int = 0) -> _Probes:
    """Count both levels, optionally failing the first `fail_first` attempts.

    `fail_first=0` leaves a healthy store and only counts. A positive value
    raises `ConnectionRefusedError` from the first that many DATABASE
    attempts and serves the rest normally, which is the shape a saturated
    pool has: not down, contended, so whether an individual attempt lands
    depends on whether a slot was free.
    """
    probes = _Probes()
    real_domains = consent._domains
    healthy = consents.granted_domains

    async def counting_domains(db: Database, customer: Any) -> set[str]:
        probes.lookups.append(customer.value)
        return await real_domains(db, customer)

    async def counting_query(db_session: AsyncSession, customer: Any) -> set[str]:
        probes.attempts.append(customer.value)
        if len(probes.attempts) <= fail_first:
            raise ConnectionRefusedError("pool exhausted")
        return await healthy(db_session, customer)

    monkeypatch.setattr(consent, "_domains", counting_domains)
    monkeypatch.setattr(consents, "granted_domains", counting_query)
    return probes


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
            ),
            # Consent, not ZT-7: this server is assembled here rather than by
            # `create_app`, so nothing publishes a revocation decision.
            revocation_decision=unchecked_revocation,
        ),
        transport=httpx2.MockTransport(backend_handler),
        before_backend_request=None,
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


async def test_a_raising_consent_check_files_the_store_unavailable_reason(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    session: AsyncSession,
) -> None:
    """The row now says which of the three refusals happened.

    This test asserted the opposite until 26 September 2026, and its old name
    said so: `_refuse` sat on the two branches AFTER the `await _domains(...)`
    that raised, so a store outage produced `outcome='raised'`,
    `detail='NotFoundError'`, reason NULL, byte-identical to a mistyped tool
    name and to each other. `services/api/consent.py`'s `check` now catches
    what `_domains` raises, files `consent_store_unavailable` and returns
    False, so the denial is unchanged and the row carries the class of it.

    `detail` stays `NotFoundError`, and that is the point of asserting it
    here rather than leaving it out: FastMCP answers no tool for a refusal
    and for an unknown name alike, so the only column that separates the
    three states is this one.

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
    assert rows[0].refusal_reason == REFUSAL_CONSENT_STORE_UNAVAILABLE


async def test_the_three_states_an_operator_must_separate_are_three_different_rows(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    session: AsyncSession,
) -> None:
    """Consent absent, consent check unreachable, tool body raised.

    One test rather than three, because the property is that the rows
    DIFFER, and three tests each asserting one row can all pass while two of
    the rows are identical. Read as a table: `detail` separates the tool body
    from the two refusals, `refusal_reason` separates the two refusals from
    each other, and nothing else on the row does either job.

    The tool body case is driven by a backend that answers 500, which
    `postern_core.facade.client.BackendClient` turns into a `BackendError`
    and FastMCP wraps as `ToolError`.

    Three calls, three rows, measured: `_app` above builds its
    `BackendClient` with `before_backend_request=None`, so this harness
    writes no `outcome='reaching'` row even for the call that does reach the
    backend, and the filter below removes nothing today. It is there so that
    wiring that hook into `_app` later fails this test on the assertion it
    is about rather than on row order. Which calls write an entry row is
    `tests/test_audit_entry_row.py`'s subject, not this file's.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    token = _token(key_pair)

    unreachable = Database(REFUSED_URL)
    try:
        app = _app(unreachable, database, key_pair, RecordingBackend(), _settings(pg_url))
        await _rpc(app, token, "tools/call", {"name": "accounts.list", "arguments": {}})
    finally:
        await unreachable.close()

    consented = _app(database, database, key_pair, RecordingBackend(), _settings(pg_url))
    await _rpc(
        app=consented,
        token=token,
        method="tools/call",
        params={"name": "cards.list", "arguments": {}},
    )

    failing = _app(database, database, key_pair, FailingBackend(), _settings(pg_url))
    await _rpc(
        app=failing,
        token=token,
        method="tools/call",
        params={"name": "accounts.list", "arguments": {}},
    )

    completions = [row for row in await _audit_rows(session) if row.outcome != "reaching"]
    assert [(r.tool_name, r.outcome, r.detail, r.refusal_reason) for r in completions] == [
        ("accounts.list", "raised", "NotFoundError", REFUSAL_CONSENT_STORE_UNAVAILABLE),
        ("cards.list", "raised", "NotFoundError", REFUSAL_DOMAIN_NOT_CONSENTED),
        ("accounts.list", "raised", "ToolError", None),
    ]


async def test_the_caller_still_cannot_tell_an_unreachable_store_from_a_typo(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
) -> None:
    """The half that must NOT change, and the reason the reason went in a
    column instead of the response.

    `tests/test_audit_refusal_reason.py::test_the_caller_still_cannot_tell_a_denial_from_a_typo`
    guards the same property for a consent denial. This one guards it for the
    outage, where the pull in the other direction is real: an agent told
    "the consent store is down" would retry, and a client told it by an
    operator's own server learns that `accounts.list` exists and that this
    customer reached a consent check at all.

    Compared on raw text with the tool names substituted for one
    placeholder, so a differing `Content-Length` fails rather than being
    allowed for: `accounts.lost` is the same 13 characters as
    `accounts.list`.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    dead = Database(REFUSED_URL)
    try:
        app = _app(dead, database, key_pair, RecordingBackend(), _settings(pg_url))
        refused = await _rpc(
            app, _token(key_pair), "tools/call", {"name": "accounts.list", "arguments": {}}
        )
        unknown = await _rpc(
            app, _token(key_pair), "tools/call", {"name": "accounts.lost", "arguments": {}}
        )
    finally:
        await dead.close()

    assert refused.status_code == unknown.status_code == 200
    assert "Unknown tool: 'accounts.list'" in refused.text
    assert refused.text.replace("accounts.list", "X") == unknown.text.replace("accounts.lost", "X")
    assert refused.headers["content-length"] == unknown.headers["content-length"]


async def test_a_recovery_mid_request_no_longer_recovers_the_call(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first probe decides the request. This test IS the cost of that.

    It asserted the opposite until 27 September 2026, under the longer
    name `..._does_not_stamp_the_call_it_allowed`, and what it guarded was a
    withdrawal: the check probed on every evaluation, so a store that raised
    for the first four and answered the fifth ALLOWED the call, and a
    `_clear_refusal` on the allow path had to erase the refusal the earlier
    evaluations had filed under the same tool name.

    The failure is now remembered for the rest of the request, so the fifth
    evaluation never reaches the database and the call is denied. That
    retires the withdrawal -- no evaluation can contradict an earlier one,
    so there is nothing to withdraw -- and it gives up a salvage: this exact
    call used to succeed. It is a deliberate trade and not a regression.
    Nobody chose five attempts; five is what the MCP SDK's internal
    `tools/list` pass costs, the retry it amounts to is unbounded by any
    policy, serial, and spends a `pool_timeout` per attempt during the event
    that exhausted the pool. The client re-issues a dropped call anyway
    (MCP 2026-07-28 has no SSE resumability, and CLAUDE.md's rule is that
    every handler must be safe to re-run), so the retry still exists, one
    layer out, where it holds no connection.

    The backend answers 500 so that the old assertion's shape survives: if
    the call were still allowed, the tool body would run and the row would
    read `detail='ToolError'` with a NULL reason. It reads `NotFoundError`
    with the outage reason instead, and the backend is never touched.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    probes = _count_probes(monkeypatch, fail_first=1)
    backend = FailingBackend()

    app = _app(database, database, key_pair, backend, _settings(pg_url))
    await _rpc(
        app,
        _token(key_pair),
        "tools/call",
        {"name": "accounts.get_balance", "arguments": {"account_ref": "acc_7f3a"}},
    )

    assert len(probes.lookups) == 5, "this is not the five-evaluation path any more"
    assert len(probes.attempts) == 1, "a remembered failure must not be re-probed"
    completions = [row for row in await _audit_rows(session) if row.outcome != "reaching"]
    assert len(completions) == 1
    assert completions[0].tool_name == "accounts.get_balance"
    assert completions[0].detail == "NotFoundError"
    assert completions[0].refusal_reason == REFUSAL_CONSENT_STORE_UNAVAILABLE
    assert backend.paths == [], "a denied call must not reach the backend"


async def test_an_unreachable_store_is_probed_once_per_request_not_once_per_evaluation(
    audit_server: FastMCP,
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Five evaluations, one database attempt, and the row still says why.

    The measurement this change exists for. Before it, every one of the five
    evaluations a `tools/call` with arguments performs opened its own
    session and waited its own `pool_timeout`, so the request that was
    denied because the pool was exhausted held a slot request open five
    times over. The denial is unchanged; the number of times it asks is not.

    THE ROW IS THE OTHER HALF and is why the assertions below are not just
    counts. Caching the failure must not cost the record: the called tool's
    own evaluation is the fifth, it never touches the database now, and it
    still has to file `consent_store_unavailable` against its own name or
    the audit table goes back to being unable to name the outage. One call,
    one completion row, one reason -- the row count does not change, because
    `AuditMiddleware` writes per call and never per evaluation.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    probes = _count_probes(monkeypatch, fail_first=99)

    app = _app(database, database, key_pair, RecordingBackend(), _settings(pg_url))
    response = await _rpc(
        app,
        _token(key_pair),
        "tools/call",
        {"name": "accounts.get_balance", "arguments": {"account_ref": "acc_7f3a"}},
    )

    assert len(probes.lookups) == 5
    assert len(probes.attempts) == 1
    assert _result(response)["isError"] is True
    completions = [row for row in await _audit_rows(session) if row.outcome != "reaching"]
    assert len(completions) == 1
    assert completions[0].refusal_reason == REFUSAL_CONSENT_STORE_UNAVAILABLE


async def test_a_store_that_fails_only_its_first_attempt_still_hides_the_whole_catalogue(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An incoherent catalogue is worse than an empty one, and this is the
    test that says so.

    `tools/list` evaluates one check per gated tool. While the failure was
    re-probed per evaluation, a single contended moment produced a catalogue
    that reflected no authorization state at all: the evaluation that raised
    hid its tool, the next one populated the success cache, and the
    remaining tools were listed. Measured here with consent granted to all
    four domains and exactly one attempt failing -- the old code listed
    three of the four, INCLUDING `accounts.get_balance` while hiding
    `accounts.list`, two tools of the same domain answered two ways in one
    response.

    An agent cannot act sensibly on that, and it is invisible server-side:
    `tools/list` writes no audit row in any state. With the failure
    remembered, the whole gated surface is hidden on one probe, which is a
    state that does correspond to something true -- the operator cannot say
    what this customer consented to. `start_session` stays listed because it
    carries no `auth=` at all, and it is the tool that tells a client to try
    again.
    """
    await _seed(consent_session, CUSTOMER, "accounts", "transactions", "cards")
    probes = _count_probes(monkeypatch, fail_first=1)

    app = _app(database, database, key_pair, RecordingBackend(), _settings(pg_url))
    response = await _rpc(app, _token(key_pair), "tools/list", {})

    listed = _tool_names(response)
    assert listed & GATED_TOOLS == set(), f"partial catalogue: {sorted(listed & GATED_TOOLS)}"
    assert "start_session" in listed
    assert len(probes.lookups) == len(GATED_TOOLS)
    assert len(probes.attempts) == 1


async def test_a_healthy_store_is_still_probed_once_per_request(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The success cache is untouched, asserted rather than assumed.

    Remembering a failure is a second cache beside the domain cache that has
    been there since 2026-09-14, and the constraint on this change was that
    a SUCCESS is not cached one instant longer than it already was. Five
    evaluations, one attempt, the call served: the same numbers the domain
    cache produced before the failure memory existed, which is what makes
    this a test of something unchanged rather than a duplicate of the one
    above.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    probes = _count_probes(monkeypatch)
    backend = BalanceBackend()

    app = _app(database, database, key_pair, backend, _settings(pg_url))
    response = await _rpc(
        app,
        _token(key_pair),
        "tools/call",
        {"name": "accounts.get_balance", "arguments": {"account_ref": "acc_7f3a"}},
    )

    assert _result(response)["isError"] is False
    assert len(probes.lookups) == 5
    assert len(probes.attempts) == 1
    assert backend.paths == ["/accounts/acc_7f3a/balance"]


async def test_a_hung_store_now_costs_one_connect_timeout_per_call_not_five(
    pg_url: str,
    key_pair: RSAKeyPair,
    database: Database,
    consent_session: AsyncSession,
    blackhole_port: int,
) -> None:
    """The latency the counts above buy back, measured on the clock.

    The count tests patch the query out, which is what makes them fast and
    also what stops them saying anything about time. This one waits on a
    real socket: a listener that completes the handshake and never speaks,
    with `Database`'s connect timeout at 1 second, driven by a `tools/call`
    carrying arguments so the full five evaluations run.

    Before the failure was remembered this call took FIVE of those timeouts,
    serially, because each evaluation opened its own session. The bound
    below is 2.5s rather than 1.5s so that a loaded CI machine does not fail
    it on scheduling noise while still being nowhere near the 5 seconds the
    old path spent, and the lower bound is what proves it waited on the
    socket at all rather than failing fast for some other reason -- the trap
    the module docstring above records from the URL-query-string attempt.
    """
    await _seed(consent_session, CUSTOMER, "accounts")
    url = f"postgresql+asyncpg://postern:postern@127.0.0.1:{blackhole_port}/postern"
    hanging = Database(url, connect_timeout_seconds=1.0)
    try:
        backend = RecordingBackend()
        app = _app(hanging, database, key_pair, backend, _settings(pg_url))
        started = time.monotonic()
        response = await _rpc(
            app,
            _token(key_pair),
            "tools/call",
            {"name": "accounts.get_balance", "arguments": {"account_ref": "acc_7f3a"}},
        )
        elapsed = time.monotonic() - started
    finally:
        await hanging.close()

    assert elapsed >= 1.0, f"answered in {elapsed:.2f}s -- it cannot have waited on the socket"
    assert elapsed < 2.5, f"took {elapsed:.2f}s -- that is more than one connect timeout"
    assert _result(response)["isError"] is True
    assert backend.paths == [], "a hung store must not let the tool body run"


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

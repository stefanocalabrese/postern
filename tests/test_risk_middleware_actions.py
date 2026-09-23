"""ZT-5 as it actually executes: `RiskMiddleware` on a real server.

WHAT THIS FILE USED TO BE. Until 2026-09-22 it was 348 lines that never
imported `RiskMiddleware` at all. Every test named for the block asserted
on an exception it raised itself::

    with pytest.raises(RiskActionError):
        raise RiskActionError(high_signals)

which passes whatever the middleware does, and the middleware was catching
that exact exception two lines below where it raised it and logging it as
"risk evaluation failed; continuing". Fifteen green tests, one inert
control. Everything here drives the real middleware instead, and the
assertion that decides each blocking test is a COUNT OF BACKEND TOUCHES,
not a status code: a refusal and a call that returned nothing are both HTTP
200, and `RecordingBackend` below is what separates them, the same way
`tests/test_consent_check_failure_mode.py` separates them for consent.

WHY SO MANY OF THESE RUN OVER REAL HTTP. The identity a risk context is
keyed on comes from the access token, and `get_access_token()` returns None
under the in-process ``Client(transport=server)`` transport, which accepts no
auth argument. A test of "two clients get two contexts" would pass vacuously
there. The in-process transport also carries no HTTP request at all, so
`_client_ip` has nothing to read and the IP tests would measure nothing.

`pg_url` is a dependency of every end-to-end test here and not an incidental
one: `AuditMiddleware` writes a completion row for every call and fails the
call closed if it cannot, so without a reachable store every assertion below
would pass for the wrong reason.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.domain.verification import VerificationTier
from postern_core.identity import CustomerRef
from postern_core.risk.context import RiskContext
from postern_core.risk.session import (
    InMemorySessionStore,
    SessionKey,
    SessionStoreBase,
    SessionStoreUnavailable,
)
from postern_core.risk.types import RiskActionError
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ConsentRecord
from sqlalchemy import delete, select

from services.api.main import create_app
from services.api.middleware.risk import NO_CLIENT, RiskMiddleware
from services.api.settings import Settings
from tests.fixtures import backend_responses as fx

CUSTOMER = CustomerRef(value="cust_7f3a")
OTHER_CUSTOMER = CustomerRef(value="cust_9b21")
#: Used by the one test here that seeds a consent row, and by nothing else in
#: this repository, so that row cannot change what another file measures.
TWO_CLIENT_CUSTOMER = CustomerRef(value="cust_riskb")
ISSUER = "https://issuer.test"
AUDIENCE = "postern"

#: The envelope MCP 2026-07-28 requires on every request. Sending it is also
#: what makes a `tools/call` with arguments trigger the MCP SDK's own internal
#: `tools/list` pass, which is the path a production client takes.
_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}

#: `RiskConfig.max_records_per_session`. Seeded rather than reached: driving
#: 500 records' worth of real calls would measure the fixtures.
RECORD_BUDGET = 500

#: `accounts.list` returns this many rows from `fx.ACCOUNTS`, so it is what
#: one call costs a budget.
ROWS_PER_CALL = 2


class RecordingBackend:
    """Did the tool's BODY run? The decisive signal in this file.

    Every read tool's work is a backend request, so a backend that records
    the paths it was asked for answers what the status code cannot: if this
    stays empty, no customer data was reached.
    """

    def __init__(self) -> None:
        self.paths: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(request.url.path)
        return httpx2.Response(200, json=fx.ACCOUNTS)


class UnreachableStore(SessionStoreBase):
    """A store that cannot answer, which is not the same as having no answer."""

    def __init__(self) -> None:
        self.loads = 0

    async def load(self, key: SessionKey) -> RiskContext | None:
        self.loads += 1
        raise SessionStoreUnavailable("simulated outage")

    async def save(self, key: SessionKey, ctx: RiskContext) -> None:
        raise SessionStoreUnavailable("simulated outage")

    async def remove(self, key: SessionKey) -> None:
        raise SessionStoreUnavailable("simulated outage")


@pytest.fixture(scope="session")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def _settings(pg_url: str, **overrides: Any) -> Settings:
    return Settings(backend_base_url="https://backend.test", database_url=pg_url, **overrides)


def _app(
    settings: Settings,
    backend: Callable[[httpx2.Request], httpx2.Response],
    *,
    resolver: Callable[[], CustomerRef] | None = None,
    from_token: bool = False,
    auth_override: JWTVerifier | None = None,
) -> Any:
    """`create_app`, with a fixed customer unless `from_token` is set.

    `from_token=True` leaves `resolver` unset so `create_app` installs
    `services/api/server.py`'s `token_customer_resolver`, which is what
    production runs and the only way the customer on the wire and the
    customer a budget is charged to are the same value.
    """
    return create_app(
        settings,
        resolver=None if from_token else (resolver or (lambda: CUSTOMER)),
        transport=httpx2.MockTransport(backend),
        auth_override=auth_override,
    )


def _store(app: Any) -> InMemorySessionStore:
    store = app.state.postern_session_store
    assert isinstance(store, InMemorySessionStore)
    return store


def _risk_middleware(app: Any) -> RiskMiddleware:
    installed = [m for m in app.state.postern_server.middleware if isinstance(m, RiskMiddleware)]
    assert len(installed) == 1, installed
    return installed[0]


def _key(customer: CustomerRef = CUSTOMER, client_id: str = NO_CLIENT) -> SessionKey:
    return SessionKey(customer_ref=customer.value, client_id=client_id)


@asynccontextmanager
async def _serving(
    app: Any, *, peer: tuple[str, int] = ("127.0.0.1", 123)
) -> AsyncIterator[httpx2.AsyncClient]:
    """One app, one lifespan, many calls.

    The lifespan is entered ONCE around the whole block rather than per call:
    `create_app` closes the backend client on lifespan exit, so a second call
    against a re-entered lifespan fails inside the tool with "client has been
    closed" -- an `isError` result that would satisfy a careless assertion
    about a refusal.
    """
    transport = httpx2.ASGITransport(app=app, client=peer)
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=transport, base_url="http://t") as client:
            yield client


async def _call(
    client: httpx2.AsyncClient,
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    token: str | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    request_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
        "MCP-Protocol-Version": "2026-07-28",
    }
    if token is not None:
        request_headers["Authorization"] = f"Bearer {token}"
    if headers:
        request_headers.update(headers)
    response = await client.post(
        "/mcp",
        headers=request_headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}, "_meta": _META},
        },
    )
    payload: dict[str, Any] = json.loads(response.text)
    return payload


def _refused(payload: dict[str, Any]) -> None:
    """The envelope a refusal arrives in, measured rather than assumed.

    An exception out of `on_call_tool` escapes the whole tool dispatch and
    FastMCP reports it as a top-level JSON-RPC `error`, not as
    `result.isError` -- `tests/test_asgi_app.py` pins that same envelope for
    the audit middleware's completion write.

    WHAT THE CALLER IS NOT TOLD: the message on the wire is `-32603 Internal
    server error`, scrubbed by FastMCP's dispatcher, so the signal codes
    reach the operator's log and `audit_log.risk_signals` but not the client.
    That is measured here, not endorsed -- `_blocked_on` below is how these
    tests read the cause, and a test that asserted the codes on the wire
    would be asserting something this envelope has never carried.
    """
    assert "error" in payload, payload
    assert "result" not in payload, payload


def _blocked_on(caplog: pytest.LogCaptureFixture) -> set[str]:
    """The signal codes the middleware logged its refusal on."""
    return {
        code
        for record in caplog.records
        if record.name == "services.api.middleware.risk" and "refused" in record.getMessage()
        for code in record.getMessage().replace(",", " ").split()
        if code.isupper() and "_" in code
    }


def _succeeded(payload: dict[str, Any]) -> dict[str, Any]:
    assert "error" not in payload, payload
    result: dict[str, Any] = payload["result"]
    assert result["isError"] is False, result
    return result


# ---------------------------------------------------------------------------
# D1 — a HIGH signal refuses the call, instead of being caught and logged.
# ---------------------------------------------------------------------------


async def test_an_exhausted_record_budget_refuses_the_call_and_the_backend_is_never_reached(
    pg_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The one that matters: refused BEFORE the operator's backend is touched.

    Counting `backend.paths` rather than reading the status is the whole
    point -- both answers are HTTP 200. Evaluating only after `call_next`, as
    this middleware did until 2026-09-22, cannot produce this result even
    with the block working: the data has already been read by the time the
    budget is consulted.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)
    ctx = await _store(app).context_for(_key())
    ctx.record_records(RECORD_BUDGET)

    with caplog.at_level(logging.WARNING, logger="services.api.middleware.risk"):
        async with _serving(app) as client:
            payload = await _call(client, "accounts.list")

    _refused(payload)
    assert backend.paths == []
    assert "RECORD_BUDGET_EXHAUSTED" in _blocked_on(caplog)


async def test_a_budget_exhausted_by_the_call_itself_still_refuses_the_caller(
    pg_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The post-call raise has to ESCAPE, which is defect D1 exactly.

    Seeded one call short of the budget, so admission passes, the tool runs,
    and the evaluation after it crosses the limit. The old code raised
    `RiskActionError` inside a `try` whose `except Exception` sat two lines
    below, logged it as "risk evaluation failed; continuing", and returned
    the data. The backend IS reached here -- that is honest, the request was
    admitted -- and what the fix guarantees is that the result is withheld
    and the next call is refused before any request at all.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)
    ctx = await _store(app).context_for(_key())
    ctx.record_records(RECORD_BUDGET - ROWS_PER_CALL + 1)

    with caplog.at_level(logging.WARNING, logger="services.api.middleware.risk"):
        async with _serving(app) as client:
            first = await _call(client, "accounts.list")
            second = await _call(client, "accounts.list")

    _refused(first)
    assert backend.paths == ["/accounts"], "the admitted call reached the backend exactly once"
    _refused(second)
    assert backend.paths == ["/accounts"], "the second call was refused before any request"
    assert "RECORD_BUDGET_EXHAUSTED" in _blocked_on(caplog)
    refusals = [
        record
        for record in caplog.records
        if record.name == "services.api.middleware.risk" and "refused" in record.getMessage()
    ]
    assert [" after the call" in r.getMessage() for r in refusals] == [True, False], (
        "the first refusal comes after the call that spent the budget, the second before it"
    )


async def test_a_medium_signal_escalates_the_tier_and_the_call_still_runs(pg_url: str) -> None:
    """MEDIUM escalates, it does not block: the other half of the action model."""
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)
    ctx = await _store(app).context_for(_key())
    ctx.record_records(400)  # 80% of the default budget
    assert ctx.verification_tier is VerificationTier.SESSION_ONLY

    async with _serving(app) as client:
        payload = await _call(client, "accounts.list")

    _succeeded(payload)
    assert backend.paths == ["/accounts"]
    # Read back from the store rather than off the object held above: the
    # escalation has to be what the NEXT call will load, not a field this
    # test happens to have a reference to.
    after = await _store(app).load(_key())
    assert after is not None
    assert after.verification_tier is VerificationTier.APP_APPROVAL


async def test_one_call_escalates_the_tier_by_at_most_one_level(pg_url: str) -> None:
    """The admission pass must not escalate a second time for one call.

    Both passes see the same standing MEDIUM condition; only the accounting
    pass acts on it.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)
    ctx = await _store(app).context_for(_key())
    ctx.record_records(400)

    async with _serving(app) as client:
        _succeeded(await _call(client, "accounts.list"))

    assert ctx.verification_tier is VerificationTier.APP_APPROVAL


async def test_a_refused_call_writes_its_signals_to_the_audit_row(
    pg_url: str, database: Database
) -> None:
    """The refusal is recorded, which is what the middleware ORDER buys.

    `RiskMiddleware` is installed inside `AuditMiddleware`, so the contextvar
    is still set when the audit middleware reads `get_current_session()` on
    its exception path. Installed the other way round, or with the contextvar
    reset on the way out, every refusal would land in `audit_log` with
    `risk_signals` NULL -- a blocked call that the table cannot explain.
    """
    async with database.sessionmaker() as session:
        await session.execute(delete(AuditEntry))
        await session.commit()

    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)
    ctx = await _store(app).context_for(_key())
    ctx.record_records(RECORD_BUDGET)

    async with _serving(app) as client:
        _refused(await _call(client, "accounts.list"))

    async with database.sessionmaker() as session:
        rows = list((await session.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars())
        assert [row.outcome for row in rows] == ["raised"], (
            "no entry row: the backend was never reached"
        )
        signals = rows[0].risk_signals
        assert signals is not None
        assert "RECORD_BUDGET_EXHAUSTED" in {s["code"] for s in signals}
        await session.execute(delete(AuditEntry))
        await session.commit()


# ---------------------------------------------------------------------------
# D2 — the context is keyed on identity, so a session cannot be forged or reset.
# ---------------------------------------------------------------------------


async def test_a_second_call_is_charged_to_the_same_context_as_the_first(pg_url: str) -> None:
    """No handle is passed and the budget still accumulates.

    This is the defect in one assertion: no registered tool declared a
    ``session_handle`` parameter and FastMCP emits
    ``"additionalProperties": false``, so nothing could supply one and every
    handler's `get_current_session()` returned None.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)

    async with _serving(app) as client:
        _succeeded(await _call(client, "accounts.list"))
        _succeeded(await _call(client, "accounts.list"))

    store = _store(app)
    ctx = await store.load(_key())
    assert ctx is not None
    assert ctx.record_count.total == 2 * ROWS_PER_CALL
    assert ctx.distinct_accounts == 2


async def test_calling_start_session_again_does_not_reset_the_budget_or_the_tier(
    pg_url: str,
) -> None:
    """The audited reset path, closed by construction.

    `start_session` used to mint a fresh context at tier ``SESSION_ONLY``
    with a zero budget, so an agent that had spent its budget could simply
    ask for another one. It now creates nothing: the middleware runs for it
    exactly as for any other tool, and the handle it returns is the same
    context's id both times.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)

    async with _serving(app) as client:
        first = _succeeded(await _call(client, "start_session"))
        _succeeded(await _call(client, "accounts.list"))
        ctx = await _store(app).load(_key())
        assert ctx is not None
        ctx.record_records(400)  # push the same context to the MEDIUM threshold
        _succeeded(await _call(client, "accounts.list"))
        escalated = ctx.verification_tier
        assert escalated >= VerificationTier.APP_APPROVAL
        second = _succeeded(await _call(client, "start_session"))

    handles = {
        first["structuredContent"]["session_handle"],
        second["structuredContent"]["session_handle"],
    }
    assert len(handles) == 1, "a second start_session minted a new session"
    after = await _store(app).load(_key())
    assert after is ctx
    assert after.record_count.total >= 400 + 2 * ROWS_PER_CALL
    assert after.verification_tier >= escalated, "a second start_session lowered the tier"


async def test_no_registered_tool_accepts_a_session_handle_argument(pg_url: str) -> None:
    """The handle is not an input, and nothing may quietly make it one again.

    A session identifier the model can set is the direct object reference
    CLAUDE.md forbids for `user_id`, for the same reason: an agent under
    adversarial influence can be talked into changing it.
    """
    app = _app(_settings(pg_url), RecordingBackend())
    tools = await app.state.postern_server.list_tools()
    assert {tool.name for tool in tools} >= {"start_session", "accounts.list"}
    for tool in tools:
        properties = (tool.parameters or {}).get("properties", {})
        assert "session_handle" not in properties, tool.name


async def test_two_customers_get_two_contexts(pg_url: str) -> None:
    """One process, two callers, two budgets."""
    backend = RecordingBackend()
    current = [CUSTOMER]
    app = _app(_settings(pg_url), backend, resolver=lambda: current[0])

    async with _serving(app) as client:
        _succeeded(await _call(client, "accounts.list"))
        current[0] = OTHER_CUSTOMER
        _succeeded(await _call(client, "accounts.list"))

    store = _store(app)
    mine = await store.load(_key())
    theirs = await store.load(_key(OTHER_CUSTOMER))
    assert mine is not None and theirs is not None
    assert mine is not theirs
    assert mine.record_count.total == ROWS_PER_CALL
    assert theirs.record_count.total == ROWS_PER_CALL


async def test_one_customer_through_two_clients_gets_two_contexts(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> None:
    """Budgets are per customer AND per OAuth client.

    Real tokens, because `client_id` is only readable from a validated one:
    fastmcp fills `AccessToken.client_id` from the `client_id` or `azp` claim,
    and `get_access_token()` is None under the in-process transport. The pair
    matches the scope ZT-7 revokes on, so "this customer through this vendor"
    means the same thing in the revocation list and here.

    A real token also means real consent enforcement -- `create_app` gates
    that on there being a validated subject to check -- hence the seeded row,
    for a customer reference used by no other test in this repository so that
    the row cannot change what another file measures.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, from_token=True, auth_override=verifier)

    def token(client_id: str) -> str:
        return key_pair.create_token(
            subject=TWO_CLIENT_CUSTOMER.value,
            issuer=ISSUER,
            audience=AUDIENCE,
            additional_claims={"client_id": client_id},
        )

    async with database.sessionmaker() as session:
        session.add(
            ConsentRecord(
                customer_ref=TWO_CLIENT_CUSTOMER.value,
                domain="accounts",
                granted=True,
                granted_at=datetime.now(UTC),
                expires_at=None,
            )
        )
        await session.commit()
    try:
        async with _serving(app) as client:
            _succeeded(await _call(client, "accounts.list", token=token("vendor-a")))
            _succeeded(await _call(client, "accounts.list", token=token("vendor-b")))
            _succeeded(await _call(client, "accounts.list", token=token("vendor-b")))
    finally:
        async with database.sessionmaker() as session:
            await session.execute(
                delete(ConsentRecord).where(ConsentRecord.customer_ref == TWO_CLIENT_CUSTOMER.value)
            )
            await session.commit()

    store = _store(app)
    first = await store.load(_key(TWO_CLIENT_CUSTOMER, "vendor-a"))
    second = await store.load(_key(TWO_CLIENT_CUSTOMER, "vendor-b"))
    assert first is not None and second is not None
    assert first is not second
    assert first.record_count.total == ROWS_PER_CALL
    assert second.record_count.total == 2 * ROWS_PER_CALL


# ---------------------------------------------------------------------------
# D3 — a store that cannot answer refuses; one with nothing stored does not.
# ---------------------------------------------------------------------------


async def test_a_store_that_cannot_answer_refuses_the_call(pg_url: str) -> None:
    """Fail closed, like consent and audit already do.

    The old code logged "session not found ... running without risk tracking"
    and ran the tool. Under MCP 2026-07-28 any request can land on any
    instance, so behind a load balancer with an in-memory store that was not
    an edge case: it was every call after the first.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)
    store = UnreachableStore()
    _risk_middleware(app).store = store

    async with _serving(app) as client:
        payload = await _call(client, "accounts.list")

    assert "error" in payload, payload
    assert backend.paths == []
    assert store.loads == 1


async def test_a_call_whose_identity_cannot_be_derived_is_refused(pg_url: str) -> None:
    """No token, no identity, no context, no call.

    The production resolver raises `PermissionError` when there is nothing to
    resolve, and that now ends the call in the middleware rather than inside
    the tool. The backend counter is what makes this a refusal rather than a
    differently-shaped error: nothing was read for a caller nobody could name.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend, from_token=True)

    async with _serving(app) as client:
        payload = await _call(client, "accounts.list")

    assert "error" in payload, payload
    assert backend.paths == []


async def test_an_identity_with_no_context_yet_gets_one_rather_than_a_refusal(
    pg_url: str,
) -> None:
    """The other half of D3: a miss is not an outage.

    Every session's first call takes this path, so collapsing the two would
    either deny everything or forgive everything.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)
    assert await _store(app).load(_key()) is None

    async with _serving(app) as client:
        _succeeded(await _call(client, "accounts.list"))

    assert backend.paths == ["/accounts"]
    assert await _store(app).load(_key()) is not None


async def test_a_stored_context_that_will_not_deserialise_refuses_the_call() -> None:
    """A corrupt value must not read as "no budget spent yet".

    Whoever can write one key would otherwise have a way to clear the budget
    that key holds.
    """
    import fakeredis.aioredis
    from postern_core.risk.session import RedisSessionStore

    store = RedisSessionStore.__new__(RedisSessionStore)
    store._redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    store._prefix = "test:"
    store._ttl = 300

    key = _key()
    await store._redis.set(store._key(key), "{not json at all")
    with pytest.raises(SessionStoreUnavailable):
        await store.load(key)


# ---------------------------------------------------------------------------
# D5 — the client address is real, and is the one infrastructure wrote.
# ---------------------------------------------------------------------------


async def test_the_socket_peer_is_recorded_when_no_proxy_is_trusted(pg_url: str) -> None:
    """Defect D5's first half: no IP was ever recorded at all.

    `context.fastmcp_context.request` does not exist on fastmcp 4.0.3's
    `Context`, so the old extractor returned None unconditionally and
    `IpAnomalyDetector` always evaluated an empty tracker.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url), backend)

    async with _serving(app, peer=("203.0.113.7", 44321)) as client:
        _succeeded(await _call(client, "accounts.list"))

    ctx = await _store(app).load(_key())
    assert ctx is not None
    assert ctx.ip_tracker.last_ip == "203.0.113.7"


async def test_a_spoofed_x_forwarded_for_cannot_set_the_recorded_ip(pg_url: str) -> None:
    """Defect D5's second half: the LEFTMOST entry is the caller's to write.

    One trusted hop, so the address recorded is the last entry -- the one the
    proxy appended, which is the peer it actually saw. The caller's own
    `9.9.9.9` is ignored. Reading the leftmost entry, as the old code did,
    let an attacker pin their apparent address to defeat the
    impossible-travel and diversity checks, or rotate it to spend another
    caller's budget.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url, trusted_proxy_hops=1), backend)

    async with _serving(app, peer=("10.0.0.1", 5000)) as client:
        _succeeded(
            await _call(
                client,
                "accounts.list",
                headers={"X-Forwarded-For": "9.9.9.9, 203.0.113.7"},
            )
        )

    ctx = await _store(app).load(_key())
    assert ctx is not None
    assert ctx.ip_tracker.last_ip == "203.0.113.7"
    assert "9.9.9.9" not in {entry.ip_address for entry in ctx.ip_tracker.entries}


async def test_a_forwarded_header_shorter_than_the_trusted_hops_records_nothing(
    pg_url: str,
) -> None:
    """Two trusted hops, one entry: not the shape this deployment expects.

    Reading it at whatever offset it happens to have is how a caller who
    strips the header gets to choose which entry is believed.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url, trusted_proxy_hops=2), backend)

    async with _serving(app) as client:
        _succeeded(await _call(client, "accounts.list", headers={"X-Forwarded-For": "9.9.9.9"}))

    ctx = await _store(app).load(_key())
    assert ctx is not None
    assert ctx.ip_tracker.entries == []


async def test_an_unparseable_forwarded_address_is_dropped_not_recorded(pg_url: str) -> None:
    """Garbage in the header must not become an entry in the tracker.

    A recorded non-address would count towards the diversity budget and make
    every later comparison lie.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url, trusted_proxy_hops=1), backend)

    async with _serving(app) as client:
        _succeeded(
            await _call(client, "accounts.list", headers={"X-Forwarded-For": "not-an-address"})
        )

    ctx = await _store(app).load(_key())
    assert ctx is not None
    assert ctx.ip_tracker.entries == []


async def test_two_spellings_of_one_address_count_as_one(pg_url: str) -> None:
    """`ipaddress.ip_address` canonicalises, so a rotation of spellings is not
    a rotation of addresses: three renderings of the same IPv6 address must
    not exhaust a three-address budget."""
    backend = RecordingBackend()
    app = _app(_settings(pg_url, trusted_proxy_hops=1), backend)
    spellings = ["2001:db8::1", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::1"]

    async with _serving(app) as client:
        for spelling in spellings:
            _succeeded(await _call(client, "accounts.list", headers={"X-Forwarded-For": spelling}))

    ctx = await _store(app).load(_key())
    assert ctx is not None
    assert ctx.ip_tracker.distinct_ips == 1


async def test_a_third_distinct_address_refuses_the_call_before_the_backend(
    pg_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    """The A4 control, end to end.

    `IpAnomalyConfig.max_distinct_ips_per_session` is 3, and the third
    address is recorded at admission, so the call that introduces it is
    refused before any request. Decision record 0010 makes this the primary
    compensating control for a stolen token replayed from other
    infrastructure, DPoP being absent from the MCP spec.
    """
    backend = RecordingBackend()
    app = _app(_settings(pg_url, trusted_proxy_hops=1), backend)

    with caplog.at_level(logging.WARNING, logger="services.api.middleware.risk"):
        async with _serving(app) as client:
            _succeeded(
                await _call(client, "accounts.list", headers={"X-Forwarded-For": "198.51.100.1"})
            )
            _succeeded(
                await _call(client, "accounts.list", headers={"X-Forwarded-For": "198.51.100.2"})
            )
            third = await _call(
                client, "accounts.list", headers={"X-Forwarded-For": "198.51.100.3"}
            )

    _refused(third)
    assert backend.paths == ["/accounts", "/accounts"]
    assert "IP_DIVERSITY_EXHAUSTED" in _blocked_on(caplog)


def test_a_negative_trusted_hop_count_is_refused_at_construction() -> None:
    """A misconfiguration that would index the header from the wrong end
    fails when the app is assembled, not silently at the first request."""
    with pytest.raises(ValueError, match="trusted_proxy_hops"):
        RiskMiddleware(InMemorySessionStore(), lambda: CUSTOMER, trusted_proxy_hops=-1)


# ---------------------------------------------------------------------------
# The error the caller sees.
# ---------------------------------------------------------------------------


def test_the_block_names_its_signals_and_carries_no_customer_data() -> None:
    """What reaches the model when a call is refused.

    `RiskActionError` carries the signals so a client can say why, and the
    message is codes and counts: nothing in it is derived from a balance, an
    account reference or a card.
    """
    ctx = RiskContext(session_id="test")
    ctx.record_records(RECORD_BUDGET)
    from postern_core.risk.engine import RiskEngine

    signals = [s for s in RiskEngine().evaluate(ctx) if s.severity.name == "HIGH"]
    error = RiskActionError(signals)
    assert [s.code for s in error.signals] == ["RECORD_BUDGET_EXHAUSTED"]
    assert "RECORD_BUDGET_EXHAUSTED" in str(error)

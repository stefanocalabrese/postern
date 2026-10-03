"""ZT-7 as it actually executes: a revocation an operator can write, that a
call actually obeys, on every replica, after a restart.

WHAT THIS FILE EXISTS FOR. `tests/test_zt7_revocation.py` drives
`RevocationList` directly and passes whatever the rest of the system does --
which until 2026-09-23 was nothing at all, because nothing populated that
list, nothing persisted it, and the one consumer asked it about the backend
audience instead of the OAuth client. Those 24 tests were green the entire
time the control was unreachable. Everything here goes through the assembled
app, and the assertion that decides each blocking test is A COUNT OF BACKEND
TOUCHES, not a status code: a refusal and a call that returned nothing are
both HTTP 200, and `RecordingBackend` is what separates them -- the same
technique `tests/test_risk_middleware_actions.py` uses for ZT-5 and
`tests/test_consent_check_failure_mode.py` uses for consent.

WHY SO MUCH OF THIS RUNS OVER REAL HTTP WITH REAL TOKENS. The scope that was
broken is per-customer plus per-client, and ``client_id`` is readable only
from a validated access token: `get_access_token()` returns None under the
in-process ``Client(transport=server)`` transport, which accepts no auth
argument. A test of "this vendor is cut and that one is not" would pass
vacuously there.

`pg_url` is a dependency of every end-to-end test here and not an incidental
one: `AuditMiddleware` writes a completion row for every call and fails the
call closed if it cannot, so without a reachable store every assertion below
would pass for the wrong reason.
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import time
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from functools import partial
from typing import Any
from uuid import uuid4

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.revocation import (
    InMemoryRevocationStore,
    RedisRevocationStore,
    RevocationStoreBase,
    RevocationStoreUnavailable,
    current_decision,
)
from postern_core.auth.revoke_cli import main as revoke_main
from postern_core.identity import CustomerRef
from postern_core.store.engine import Database
from postern_core.store.models import ConsentRecord
from sqlalchemy import delete

from services.api.main import create_app
from services.api.settings import Settings
from tests.fixtures import backend_responses as fx

ISSUER = "https://issuer.test"
AUDIENCE = "postern"

#: Customer references used only in this file, so a consent row seeded here
#: cannot change what another test file measures.
CUSTOMER = CustomerRef(value="cust_zt7a")
OTHER_CUSTOMER = CustomerRef(value="cust_zt7b")

CLIENT = "vendor-claude"
OTHER_CLIENT = "vendor-perplexity"

#: The envelope MCP 2026-07-28 requires on every request.
_META = {
    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
    "io.modelcontextprotocol/clientCapabilities": {},
}


class RecordingBackend:
    """Did the tool's BODY run? The decisive signal in this file.

    Every read tool's work is a backend request, so a backend that records the
    paths it was asked for answers what the status code cannot: if this stays
    empty, no customer data was reached.
    """

    def __init__(self) -> None:
        self.paths: list[str] = []

    def __call__(self, request: httpx2.Request) -> httpx2.Response:
        self.paths.append(request.url.path)
        return httpx2.Response(200, json=fx.ACCOUNTS)


class UnreachableRevocationStore(RevocationStoreBase):
    """A store that cannot answer, which is not the same as having no entries."""

    def __init__(self) -> None:
        self.checks = 0

    async def is_revoked(self, claims: Any) -> bool:
        self.checks += 1
        raise RevocationStoreUnavailable("simulated outage")

    async def revoke_session(self, *, jti: str) -> None:
        raise RevocationStoreUnavailable("simulated outage")

    async def restore_session(self, *, jti: str) -> None:
        raise RevocationStoreUnavailable("simulated outage")

    async def revoke_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        raise RevocationStoreUnavailable("simulated outage")

    async def restore_customer_client(self, *, customer_ref: str, client_id: str) -> None:
        raise RevocationStoreUnavailable("simulated outage")

    async def kill_switch(self, *, client_id: str) -> None:
        raise RevocationStoreUnavailable("simulated outage")

    async def restore_client(self, *, client_id: str) -> None:
        raise RevocationStoreUnavailable("simulated outage")

    async def entries(self) -> Any:
        raise RevocationStoreUnavailable("simulated outage")


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
    auth_override: JWTVerifier | None = None,
) -> Any:
    """`create_app`, i.e. the composition root, never a hand-assembled server.

    Leaving `resolver` unset is what installs `services/api/server.py`'s
    `token_customer_resolver`, which is what production runs and the only way
    the customer on the wire and the customer a revocation is matched against
    are the same value.
    """
    return create_app(
        settings,
        resolver=resolver,
        transport=httpx2.MockTransport(backend),
        auth_override=auth_override,
    )


def _revocation_store(app: Any) -> RevocationStoreBase:
    store = app.state.postern_revocation_store
    assert isinstance(store, RevocationStoreBase)
    return store


@asynccontextmanager
async def _serving(app: Any) -> AsyncIterator[httpx2.AsyncClient]:
    """One app, one lifespan, many calls.

    The lifespan is entered ONCE around the whole block rather than per call:
    `create_app` closes the backend client on lifespan exit, so a second call
    against a re-entered lifespan fails inside the tool with "client has been
    closed" -- an `isError` result that would satisfy a careless assertion
    about a refusal.
    """
    transport = httpx2.ASGITransport(app=app, client=("127.0.0.1", 5555))
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(transport=transport, base_url="http://t") as client:
            yield client


async def _call(
    client: httpx2.AsyncClient,
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    token: str | None = None,
) -> dict[str, Any]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Method": "tools/call",
        "Mcp-Name": name,
        "MCP-Protocol-Version": "2026-07-28",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    response = await client.post(
        "/mcp",
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}, "_meta": _META},
        },
    )
    payload: dict[str, Any] = json.loads(response.text)
    return payload


async def _list_tools(client: httpx2.AsyncClient, *, token: str | None = None) -> dict[str, Any]:
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Method": "tools/list",
        "Mcp-Name": "",
        "MCP-Protocol-Version": "2026-07-28",
    }
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    response = await client.post(
        "/mcp",
        headers=headers,
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": _META}},
    )
    payload: dict[str, Any] = json.loads(response.text)
    return payload


def _refused(payload: dict[str, Any]) -> None:
    """The envelope a refusal arrives in, measured rather than assumed.

    An exception out of a middleware hook escapes the whole dispatch and
    FastMCP reports it as a top-level JSON-RPC `error`, not as
    `result.isError`. The message on the wire is scrubbed to `-32603 Internal
    server error`, so the reason reaches the operator's log and not the
    client; that is measured here, not endorsed.
    """
    assert "error" in payload, payload
    assert "result" not in payload, payload


def _succeeded(payload: dict[str, Any]) -> dict[str, Any]:
    assert "error" not in payload, payload
    result: dict[str, Any] = payload["result"]
    assert result["isError"] is False, result
    return result


def _token(key_pair: RSAKeyPair, customer: CustomerRef, client_id: str, **claims: Any) -> str:
    return key_pair.create_token(
        subject=customer.value,
        issuer=ISSUER,
        audience=AUDIENCE,
        additional_claims={"client_id": client_id, **claims},
    )


@asynccontextmanager
async def _consent(database: Database, customer: CustomerRef) -> AsyncIterator[None]:
    """A granted `accounts` consent row for the duration of the block.

    A real token means real consent enforcement -- `create_app` gates that on
    there being a validated subject to check -- so a test that wants a call to
    SUCCEED has to seed one, or it would measure consent rather than
    revocation.
    """
    async with database.sessionmaker() as session:
        session.add(
            ConsentRecord(
                customer_ref=customer.value,
                domain="accounts",
                granted=True,
                granted_at=datetime.now(UTC),
                expires_at=None,
            )
        )
        await session.commit()
    try:
        yield
    finally:
        async with database.sessionmaker() as session:
            await session.execute(
                delete(ConsentRecord).where(ConsentRecord.customer_ref == customer.value)
            )
            await session.commit()


# ---------------------------------------------------------------------------
# V1 — a revocation stops a real call, and the backend is never touched.
# ---------------------------------------------------------------------------


async def test_a_revoked_customer_client_is_refused_and_the_backend_is_never_reached(
    pg_url: str, database: Database, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    """The one that matters: refused BEFORE the operator's backend is touched.

    Counting `backend.paths` rather than reading the status is the point --
    both answers are HTTP 200. The same call succeeds before the revocation
    and fails after it, against one running app, with nothing else changed.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)
    token = _token(key_pair, CUSTOMER, CLIENT)

    async with _consent(database, CUSTOMER):
        with caplog.at_level(logging.WARNING, logger="services.api.middleware.revocation"):
            async with _serving(app) as client:
                _succeeded(await _call(client, "accounts.list", token=token))
                assert backend.paths == ["/accounts"], "the pre-revocation call is real"

                await _revocation_store(app).revoke_customer_client(
                    customer_ref=CUSTOMER.value, client_id=CLIENT
                )

                payload = await _call(client, "accounts.list", token=token)

    _refused(payload)
    assert backend.paths == ["/accounts"], "the revoked call reached no backend at all"
    assert any(
        "refused" in record.getMessage() and CLIENT in record.getMessage()
        for record in caplog.records
        if record.name == "services.api.middleware.revocation"
    ), caplog.records


async def test_a_kill_switch_refuses_every_customer_of_that_client(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> None:
    """The "disable one AI vendor" switch, across customers, in one command."""
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)

    async with _consent(database, CUSTOMER), _consent(database, OTHER_CUSTOMER):
        async with _serving(app) as client:
            await _revocation_store(app).kill_switch(client_id=CLIENT)

            first = await _call(client, "accounts.list", token=_token(key_pair, CUSTOMER, CLIENT))
            second = await _call(
                client, "accounts.list", token=_token(key_pair, OTHER_CUSTOMER, CLIENT)
            )
            # A different vendor, same two customers, is untouched.
            survivor = await _call(
                client, "accounts.list", token=_token(key_pair, CUSTOMER, OTHER_CLIENT)
            )

    _refused(first)
    _refused(second)
    _succeeded(survivor)
    assert backend.paths == ["/accounts"], "only the surviving client reached the backend"


async def test_a_revoked_session_jti_is_refused_without_touching_other_sessions(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> None:
    """Per-session scope, keyed on the CUSTOMER token's jti.

    Not the internal token's: `InternalTokenMinter` generates a fresh jti per
    mint, so revoking one of those would name a token already spent.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)
    phone = _token(key_pair, CUSTOMER, CLIENT, jti="sess-phone")
    laptop = _token(key_pair, CUSTOMER, CLIENT, jti="sess-laptop")

    async with _consent(database, CUSTOMER):
        async with _serving(app) as client:
            await _revocation_store(app).revoke_session(jti="sess-phone")
            revoked = await _call(client, "accounts.list", token=phone)
            other = await _call(client, "accounts.list", token=laptop)

    _refused(revoked)
    _succeeded(other)
    assert backend.paths == ["/accounts"], "only the customer's other session was served"


# ---------------------------------------------------------------------------
# V3 — the `client_id=audience` defect, stated as the test that catches it.
# ---------------------------------------------------------------------------


async def test_a_customer_client_revocation_matches_the_real_client_and_only_that_client(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> None:
    """Cutting one vendor must not cut the customer's other vendors.

    Before the fix, `ReadTokenMinter` asked the revocation list about the
    backend audience (``accounts.svc``), so no operator-written entry could
    match at all, and had one somehow matched it would have been keyed on
    something both vendors share. This asserts both halves: the named client
    is refused, and the other client for the SAME customer still gets served.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)

    async with _consent(database, CUSTOMER):
        async with _serving(app) as client:
            await _revocation_store(app).revoke_customer_client(
                customer_ref=CUSTOMER.value, client_id=CLIENT
            )
            cut = await _call(client, "accounts.list", token=_token(key_pair, CUSTOMER, CLIENT))
            kept = await _call(
                client, "accounts.list", token=_token(key_pair, CUSTOMER, OTHER_CLIENT)
            )

    _refused(cut)
    _succeeded(kept)
    assert backend.paths == ["/accounts"], "exactly one of the two clients reached the backend"


async def test_the_audience_is_not_what_a_revocation_is_keyed_on(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> None:
    """The defect itself, asserted directly.

    ``accounts.svc`` is a backend audience, not a caller. An entry written
    against it must match nothing, because that is what the old code was
    silently consulting on every mint.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)

    async with _consent(database, CUSTOMER):
        async with _serving(app) as client:
            await _revocation_store(app).revoke_customer_client(
                customer_ref=CUSTOMER.value, client_id="accounts.svc"
            )
            await _revocation_store(app).kill_switch(client_id="accounts.svc")
            payload = await _call(client, "accounts.list", token=_token(key_pair, CUSTOMER, CLIENT))

    _succeeded(payload)
    assert backend.paths == ["/accounts"]


# ---------------------------------------------------------------------------
# The inbound boundary: `tools/list` mints nothing, so mint-time is not enough.
# ---------------------------------------------------------------------------


async def test_a_revoked_caller_cannot_list_tools(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> None:
    """Listing mints no token, so a mint-time-only check would leave it open.

    The catalog varies with consent state -- which is why `CLAUDE.md` requires
    ``cacheScope: "private"`` -- so which tools a caller is offered discloses
    which domains a customer has connected.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)
    token = _token(key_pair, CUSTOMER, CLIENT)

    async with _consent(database, CUSTOMER):
        async with _serving(app) as client:
            before = await _list_tools(client, token=token)
            await _revocation_store(app).kill_switch(client_id=CLIENT)
            after = await _list_tools(client, token=token)

    assert "error" not in before, before
    assert before["result"]["tools"], "the catalog was non-empty before the kill switch"
    _refused(after)
    assert backend.paths == []


# ---------------------------------------------------------------------------
# V2 — persistence and replica reach, driven through the operator's own CLI.
# ---------------------------------------------------------------------------


@pytest.fixture
def shared_redis(monkeypatch: pytest.MonkeyPatch, redis_url: str) -> Iterator[Any]:
    """The suite's Redis standing in for the deployment's, in a prefix of its own.

    Every `RedisRevocationStore` built while this is active -- by either app
    instance, and by the CLI running in its own thread and its own event loop
    -- reads ``POSTERN_REDIS_URL`` and ``POSTERN_REDIS_KEY_PREFIX`` and lands
    on this one key space. That is what makes the two instances below
    genuinely two replicas of one deployment rather than two objects in one
    process sharing a reference: neither holds the other's store, and the only
    thing between them is the key space.

    A `fakeredis` server until the layer-1 session token: a customer-client
    revocation is now one Lua script (``EVAL``), and fakeredis 2.38.0 without
    ``lupa`` answers "unknown command 'eval'".
    """
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"zt7r{uuid4().hex[:12]}:")
    yield redis_url


async def _run_cli(*argv: str) -> tuple[int, str]:
    """The CLI entry point, on its own thread and its own event loop.

    A thread rather than a direct call because `postern_core.auth.revoke_cli`'s
    `main` owns its event loop through `asyncio.run`, exactly as it does when
    an operator runs ``uv run python tools/revoke.py`` -- and calling
    `asyncio.run` from inside the loop this test is already running on raises.
    The thread is the closest in-test analogue of the separate process an
    operator actually runs, and it means argument parsing, store construction
    from ``POSTERN_REDIS_URL``, the write, and the close are all the real
    path.
    """
    buffer = io.StringIO()
    code = await asyncio.to_thread(partial(revoke_main, list(argv), out=buffer))
    return code, buffer.getvalue()


async def test_a_revocation_written_by_the_cli_reaches_a_second_replica(
    pg_url: str, database: Database, key_pair: RSAKeyPair, shared_redis: Any
) -> None:
    """V2: persistence and replica reach, end to end, through the CLI.

    Two independently assembled apps, each with its own `create_app`, its own
    backend client and its own revocation store object, sharing only Redis.
    The operator runs the command once, against neither of them, and the
    replica that was already serving refuses the next call.

    This is also the restart proof. `create_app` is what runs at process
    start, so an app assembled AFTER the revocation was written is a restarted
    replica by construction: instance B is built here before the write and
    instance C after it, and both refuse.
    """
    backend_a = RecordingBackend()
    backend_b = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app_a = _app(_settings(pg_url), backend_a, auth_override=verifier)
    app_b = _app(_settings(pg_url), backend_b, auth_override=verifier)
    assert isinstance(_revocation_store(app_a), RedisRevocationStore)
    assert _revocation_store(app_a) is not _revocation_store(app_b)

    token = _token(key_pair, CUSTOMER, CLIENT)

    async with _consent(database, CUSTOMER):
        async with _serving(app_a) as client_a, _serving(app_b) as client_b:
            _succeeded(await _call(client_a, "accounts.list", token=token))
            _succeeded(await _call(client_b, "accounts.list", token=token))

            code, output = await _run_cli("kill-switch", CLIENT)
            assert code == 0, output
            assert CLIENT in output

            refused_a = await _call(client_a, "accounts.list", token=token)
            refused_b = await _call(client_b, "accounts.list", token=token)

        # A replica that starts AFTER the write: the restart case.
        backend_c = RecordingBackend()
        app_c = _app(_settings(pg_url), backend_c, auth_override=verifier)
        async with _serving(app_c) as client_c:
            refused_c = await _call(client_c, "accounts.list", token=token)

    _refused(refused_a)
    _refused(refused_b)
    _refused(refused_c)
    assert backend_a.paths == ["/accounts"], "instance A served once, before the CLI ran"
    assert backend_b.paths == ["/accounts"], "instance B served once, before the CLI ran"
    assert backend_c.paths == [], "the replica that started after the write never served at all"


async def test_the_cli_restores_a_revocation_and_the_replicas_serve_again(
    pg_url: str, database: Database, key_pair: RSAKeyPair, shared_redis: Any
) -> None:
    """Every scope has an explicit undo, because none of them has a TTL.

    An undo lets the identity back in for tokens minted after the revocation;
    it does not revive a token minted before it. That held for the
    customer-client scope since 2 October 2026 and for the kill switch since
    3 October 2026, when this test gained its kill-switch half.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)
    now = int(time.time())
    token = _token(key_pair, CUSTOMER, CLIENT, iat=now - 60, exp=now + 540)

    async with _consent(database, CUSTOMER), _consent(database, OTHER_CUSTOMER):
        async with _serving(app) as client:
            assert (await _run_cli("customer-client", CUSTOMER.value, CLIENT))[0] == 0
            refused = await _call(client, "accounts.list", token=token)

            assert (await _run_cli("restore-customer-client", CUSTOMER.value, CLIENT))[0] == 0
            # The token minted before the revocation stays refused after the
            # restore (M2); the replicas serve again a token minted after it.
            # `iat` is explicit and past the 2 s tolerance, so the test never
            # sleeps and never races the stamp.
            still_refused = await _call(client, "accounts.list", token=token)
            stamp_ms = await _revocation_store(app).customer_revoked_at(CUSTOMER.value)
            assert stamp_ms is not None
            issued = stamp_ms // 1000 + 10
            after = _token(key_pair, CUSTOMER, CLIENT, iat=issued, exp=issued + 600)
            served = await _call(client, "accounts.list", token=after)

            # The kill switch through the CLI (3 October 2026): its restore no
            # longer revives a token minted before the kill either. Another
            # customer of the same client, so no pair stamp is in play.
            pre_kill = _token(key_pair, OTHER_CUSTOMER, CLIENT, iat=now - 60, exp=now + 540)
            served_pre_kill = await _call(client, "accounts.list", token=pre_kill)
            assert (await _run_cli("kill-switch", CLIENT))[0] == 0
            killed = await _call(client, "accounts.list", token=pre_kill)
            assert (await _run_cli("restore-kill-switch", CLIENT))[0] == 0
            not_revived = await _call(client, "accounts.list", token=pre_kill)
            client_ms = await _revocation_store(app).client_revoked_at(CLIENT)
            assert client_ms is not None
            later = client_ms // 1000 + 10
            newest = _token(key_pair, CUSTOMER, CLIENT, iat=later, exp=later + 600)
            served_again = await _call(client, "accounts.list", token=newest)

    _refused(refused)
    _refused(still_refused)
    _succeeded(served)
    _succeeded(served_pre_kill)
    _refused(killed)
    _refused(not_revived)
    _succeeded(served_again)
    assert backend.paths == ["/accounts"] * 3


@pytest.fixture(params=["memory", "redis"])
def restore_backend(request: pytest.FixtureRequest) -> str:
    """The revocation backend a restore test runs against.

    ``redis`` pulls in `shared_redis`, which sets ``POSTERN_REDIS_URL`` so that
    `create_app` builds a `RedisRevocationStore`; ``memory`` leaves it unset.
    """
    if request.param == "redis":
        request.getfixturevalue("shared_redis")
    return str(request.param)


async def test_a_restore_does_not_revive_an_access_token_issued_before_the_revocation(
    pg_url: str, database: Database, key_pair: RSAKeyPair, restore_backend: str
) -> None:
    """M2: the api half of "a restore must not revive pre-revocation grants".

    The refresh path already refused a family older than the revocation. The
    api asked only whether the pair was ON the list, so for up to 600 s after
    `restore_customer_client` the token minted BEFORE the revocation was served
    again. Deterministic, no sleeps: the old token's ``iat`` is set a minute in
    the past, so it predates the stamp by far more than the 2 s tolerance, and
    the fresh one is set 10 s past the stamp read back from the store.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)
    store = _revocation_store(app)
    assert isinstance(store, RedisRevocationStore) == (restore_backend == "redis")

    now = int(time.time())
    old = _token(key_pair, CUSTOMER, CLIENT, iat=now - 60, exp=now + 540)

    async with _consent(database, CUSTOMER):
        async with _serving(app) as client:
            _succeeded(await _call(client, "accounts.list", token=old))
            assert backend.paths == ["/accounts"], "the pre-revocation call is real"

            await store.revoke_customer_client(customer_ref=CUSTOMER.value, client_id=CLIENT)
            _refused(await _call(client, "accounts.list", token=old))

            await store.restore_customer_client(customer_ref=CUSTOMER.value, client_id=CLIENT)
            revived = await _call(client, "accounts.list", token=old)

            stamp_ms = await store.customer_revoked_at(CUSTOMER.value)
            assert stamp_ms is not None
            issued = stamp_ms // 1000 + 10
            fresh = _token(key_pair, CUSTOMER, CLIENT, iat=issued, exp=issued + 600)
            served = await _call(client, "accounts.list", token=fresh)

    _refused(revived)
    _succeeded(served)
    assert backend.paths == ["/accounts", "/accounts"], (
        "the old token reached no backend after the restore; the fresh one did"
    )


async def test_a_restored_kill_switch_does_not_revive_an_access_token_issued_before_it(
    pg_url: str, database: Database, key_pair: RSAKeyPair, restore_backend: str
) -> None:
    """The client-wide twin of the M2 test above, through the assembled app.

    A kill switch exists to stop every token the client holds. Restoring it
    lets the client back in, for tokens minted after the stamp; a token minted
    before it stays refused for the rest of its life. Another client's token
    of the same age is untouched. No sleeps: ``iat`` is explicit.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)
    store = _revocation_store(app)
    assert isinstance(store, RedisRevocationStore) == (restore_backend == "redis")

    now = int(time.time())
    old = _token(key_pair, CUSTOMER, CLIENT, iat=now - 60, exp=now + 540)
    old_other_customer = _token(key_pair, OTHER_CUSTOMER, CLIENT, iat=now - 60, exp=now + 540)
    old_other_client = _token(key_pair, CUSTOMER, OTHER_CLIENT, iat=now - 60, exp=now + 540)

    async with _consent(database, CUSTOMER), _consent(database, OTHER_CUSTOMER):
        async with _serving(app) as client:
            _succeeded(await _call(client, "accounts.list", token=old))

            await store.kill_switch(client_id=CLIENT)
            _refused(await _call(client, "accounts.list", token=old))

            await store.restore_client(client_id=CLIENT)
            revived = await _call(client, "accounts.list", token=old)
            revived_other_customer = await _call(client, "accounts.list", token=old_other_customer)
            untouched = await _call(client, "accounts.list", token=old_other_client)

            stamp_ms = await store.client_revoked_at(CLIENT)
            assert stamp_ms is not None
            issued = stamp_ms // 1000 + 10
            fresh = _token(key_pair, CUSTOMER, CLIENT, iat=issued, exp=issued + 600)
            served = await _call(client, "accounts.list", token=fresh)

    _refused(revived)
    _refused(revived_other_customer)
    _succeeded(untouched)
    _succeeded(served)
    assert backend.paths == ["/accounts"] * 3, (
        "before the kill, the other client, and the post-stamp token; nothing older"
    )


async def test_the_cli_lists_every_scope_it_wrote(shared_redis: Any) -> None:
    """``list`` is how an operator confirms what they did, and to whom."""
    assert (await _run_cli("session", "sess-phone"))[0] == 0
    assert (await _run_cli("customer-client", CUSTOMER.value, CLIENT))[0] == 0
    assert (await _run_cli("kill-switch", OTHER_CLIENT))[0] == 0

    code, output = await _run_cli("list")
    assert code == 0
    assert "session\tsess-phone" in output
    assert f"customer-client\t{CUSTOMER.value}\t{CLIENT}" in output
    assert f"kill-switch\t{OTHER_CLIENT}" in output
    assert "3 entries" in output


async def test_the_cli_fails_when_no_shared_store_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Writing into memory this process is about to discard is a failure.

    Reporting success would be the worst outcome available: an operator acting
    on a compromise would believe a kill switch was live when nothing outside
    the command's own heap had ever seen it.
    """
    monkeypatch.delenv("POSTERN_REDIS_URL", raising=False)
    errors = io.StringIO()
    code = await asyncio.to_thread(
        partial(revoke_main, ["kill-switch", CLIENT], out=io.StringIO(), err=errors)
    )
    assert code == 1
    assert "POSTERN_REDIS_URL is not set" in errors.getvalue()


# ---------------------------------------------------------------------------
# Fail-closed, and the decision seam the minter reads.
# ---------------------------------------------------------------------------


async def test_a_revocation_store_that_cannot_answer_refuses_the_call(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> None:
    """Fail closed, like consent, audit and the risk session store already do.

    An outage reported as "not revoked" would un-revoke every entry the store
    holds, at exactly the moment an operator most believes they have acted.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)
    store = UnreachableRevocationStore()

    async with _consent(database, CUSTOMER):
        async with _serving(app) as client:
            _revocation_middleware(app).store = store
            payload = await _call(client, "accounts.list", token=_token(key_pair, CUSTOMER, CLIENT))

    _refused(payload)
    assert backend.paths == []
    assert store.checks == 1


def _revocation_middleware(app: Any) -> Any:
    from services.api.middleware.revocation import RevocationMiddleware

    installed = [
        m for m in app.state.postern_server.middleware if isinstance(m, RevocationMiddleware)
    ]
    assert len(installed) == 1, installed
    return installed[0]


async def test_create_app_installs_the_revocation_middleware_and_exposes_the_store(
    pg_url: str,
) -> None:
    """The wiring defect, pinned.

    Before this commit `create_app` built a `RevocationList`, kept it in a
    local, and exposed no handle: no route, no CLI, no `app.state` entry, and
    therefore no way for anything at all to write to it.
    """
    app = _app(_settings(pg_url), RecordingBackend())
    assert isinstance(_revocation_store(app), InMemoryRevocationStore)
    assert _revocation_middleware(app) is not None


async def test_the_decision_does_not_outlive_the_call_that_published_it(
    pg_url: str, database: Database, key_pair: RSAKeyPair
) -> None:
    """The ContextVar is reset on the way out, and that is load bearing.

    `RiskMiddleware` deliberately leaves its contextvar set so `AuditMiddleware`
    can read it afterwards. This one must not: a "not revoked" left standing
    would be inherited by any task spawned from that context, and would then
    be the answer the minter reads on a call whose middleware never ran --
    exactly the permissive fallback `require_revocation_decision` refuses.
    """
    backend = RecordingBackend()
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = _app(_settings(pg_url), backend, auth_override=verifier)

    async with _consent(database, CUSTOMER):
        async with _serving(app) as client:
            token = _token(key_pair, CUSTOMER, CLIENT)
            _succeeded(await _call(client, "accounts.list", token=token))

    assert current_decision() is None

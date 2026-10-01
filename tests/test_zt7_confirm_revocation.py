"""ZT-7 on the WRITE path: revoking a customer stops the money, on every replica.

WHAT THIS FILE EXISTS FOR. ``tests/test_zt7_revocation_reachable.py`` proved
the control reachable on ``services/api``. It proved nothing here, and said so:
until this commit ``grep -rc revocation services/confirm/*.py`` returned zero
on every file, so an operator who revoked a compromised session stopped every
read and stopped no payment. A challenge already created could still be
approved, a write JWT was still minted, and the backend write endpoint was
still reached.

THE DECIDING ASSERTION IS A COUNT OF BACKEND WRITE CALLS, never a status code.
A refusal and a backend that answered are different HTTP responses here (403
against 200), which makes a status assertion look sufficient -- it is not. The
thing that matters is whether the operator's payments service was touched, and
only ``Backend.calls`` answers that. The same technique
``tests/test_write_audit.py`` uses for the audit entry row and
``tests/test_zt7_revocation_reachable.py`` uses for the read path.

EVERY BLOCKING TEST RUNS BOTH WAYS. A test that only shows the refused case
cannot tell "the control works" from "nothing ever reaches the backend in this
fixture". So each one is paired with the identical flow that is NOT revoked,
in the same test where practical, and the pair is what is asserted.

WHAT IS PINNED HERE THAT IS A LIMITATION RATHER THAN A FEATURE.
``test_a_revoked_session_jti_does_not_stop_an_approval`` and
``test_a_kill_switch_does_not_stop_an_approval`` assert that two of the three
revocation scopes do NOT reach this service. They are not aspirational tests
written backwards: the write path carries neither the AI client's ``jti`` nor
its ``client_id`` (``services/confirm/revocation.py`` holds the argument), so
those scopes cannot match, and an operator reading ``revoke_cli``'s docstring
is told so. Pinning it is what stops the gap from being closed by accident and
believed to have been closed on purpose -- or from widening silently.
"""

from __future__ import annotations

import asyncio
import io
from collections.abc import AsyncGenerator, Generator, Iterator
from datetime import UTC, datetime, timedelta
from functools import partial
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.revocation import (
    InMemoryRevocationStore,
    RedisRevocationStore,
    RevocationSnapshot,
    RevocationStoreBase,
    RevocationStoreUnavailable,
)
from postern_core.auth.revoke_cli import main as revoke_main
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, AuditEntry, ChallengeRecord
from sqlalchemy import delete, select
from starlette.applications import Starlette

from services.confirm.audit import DETAIL_REVOKED, UNRESOLVED_TOOL_NAME
from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import scan_in_store, session_claims
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.fixtures.device_keys import approval_body, device_key, enrolled_store

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"

#: Customer references used only in this file, so nothing seeded here changes
#: what another module measures.
OWNER = "cust_zt7w1"
OTHER = "cust_zt7w2"

CLIENT = "vendor-claude"
OTHER_CLIENT = "vendor-perplexity"

TOOL = "payments.create_payment"

#: Every challenge this module inserts carries it, so teardown can delete by
#: prefix without touching another module's rows.
PREFIX = "chal_zt7w_"

#: One enrolled phone, shared by both customers in this file. Nothing here is
#: about the signature check -- every approval below either passes it or is
#: refused by ZT-7 before it runs -- so the key exists only so that an
#: approval which SHOULD succeed still can. ``approve`` signs the stored row
#: with it automatically; see its docstring.
DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("zt7w-phone")


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture()
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so it gets the safe defaults.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )


@pytest.fixture(scope="session")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def build_app(settings: ConfirmSettings, key_pair: RSAKeyPair) -> Starlette:
    """``create_confirm_app``, i.e. the composition root, never a hand-assembled app.

    The revocation store therefore comes from ``create_revocation_store()``
    inside the factory, reading ``POSTERN_REDIS_URL`` exactly as a running
    replica does. A test that constructed the store itself and injected it
    would pass with the wiring deleted.
    """
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=enrolled_store(OWNER, DEVICE_PUBLIC, **{OTHER: (DEVICE_PUBLIC,)}),
    )


@pytest.fixture()
def app(settings: ConfirmSettings, key_pair: RSAKeyPair) -> Starlette:
    return build_app(settings, key_pair)


def store_of(app: Starlette) -> RevocationStoreBase:
    store: RevocationStoreBase = app.state.postern_revocation_store
    return store


@pytest.fixture()
async def clean(database: Database) -> AsyncGenerator[Database, None]:
    """Remove this module's rows either side of every test.

    Both ends, and by this module's own customer references rather than by
    truncating the tables: ``database`` is session scoped and shared with
    every other module, so a blanket wipe here would delete rows another test
    is mid-way through asserting on.
    """
    await _wipe(database)
    yield database
    await _wipe(database)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(
            s, AuditEntry.customer_ref.in_((OWNER, OTHER))
        )
        await s.execute(
            delete(ChallengeRecord).where(ChallengeRecord.customer_ref.in_((OWNER, OTHER)))
        )
        await s.commit()


class Backend:
    """A stand-in backend write endpoint that COUNTS its calls.

    The count is the whole point of this file: a revocation that returned 403
    while still reaching the operator's payments service would satisfy every
    status assertion here and close nothing.
    """

    def __init__(self) -> None:
        self.calls: list[httpx2.Request] = []

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.calls.append(request)
        return httpx2.Response(201, json={"ok": True})


@pytest.fixture()
def backend() -> Generator[Backend]:
    """Route every ``BackendWriteClient`` through a counting mock transport.

    Patches ``__init__`` rather than passing a transport, because
    ``services/confirm/callback.py`` constructs the client itself -- the same
    pattern ``tests/test_write_audit.py`` uses, and ``**kwargs`` passthrough
    keeps the real ``before_backend_request`` hook wired.
    """
    b = Backend()
    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        kwargs.pop("transport", None)
        original(self, *args, transport=httpx2.MockTransport(b.handle), **kwargs)

    with patch.object(BackendWriteClient, "__init__", patched):
        yield b


class UnreachableStore(RevocationStoreBase):
    """A store that cannot answer, which is not the same as holding no entries."""

    def __init__(self) -> None:
        self.checks = 0

    async def is_revoked(self, claims: Any) -> bool:
        raise RevocationStoreUnavailable("simulated outage")

    async def is_customer_revoked(self, customer_ref: str) -> bool:
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

    async def entries(self) -> RevocationSnapshot:
        raise RevocationStoreUnavailable("simulated outage")


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def bearer(key_pair: RSAKeyPair, subject: str, **claims: Any) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject,
        issuer=ISSUER,
        audience=AUDIENCE,
        additional_claims=claims or None,
        expires_in_seconds=60,
    )
    return {"Authorization": f"Bearer {token}"}


async def approve(
    app: Starlette,
    challenge_id: str,
    headers: dict[str, str],
    *,
    as_a_server_would: bool = False,
) -> httpx2.Response:
    """POST one approval over ASGI.

    ``as_a_server_would`` mirrors ``tests/test_write_audit.py``'s flag: with
    ``raise_app_exceptions=False`` the transport does what uvicorn does and
    turns an unhandled exception into a real 500, so a fail-closed assertion
    reads "the caller was told no" rather than "something blew up in the test".

    THE BODY IS SIGNED FOR REAL, by reading the stored row through the app's
    OWN database and signing it with this module's enrolled key. Every call
    site is unchanged by that: a test asserting 403 gets a valid signature
    that ZT-7 refuses before it is looked at, which is the stronger statement
    of the two -- the revocation check stops an approval that would otherwise
    have been accepted in full. Where no row exists (the ``nosuchid`` probes),
    the body carries a placeholder, because there is nothing to sign and the
    404 does not depend on it.
    """
    body = await _approval_body(app, challenge_id)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=not as_a_server_would),
        base_url="http://t",
    ) as c:
        return await c.post(
            f"/challenges/{challenge_id}/approve",
            json=body,
            headers=headers,
        )


async def _approval_body(app: Starlette, challenge_id: str) -> dict[str, Any]:
    """A signed approval body, or a placeholder when the challenge is absent."""
    database: Database = app.state.postern_database
    async with database.sessionmaker() as session:
        exists = await session.execute(
            select(ChallengeRecord.id).where(ChallengeRecord.challenge_id == challenge_id)
        )
        if exists.scalar_one_or_none() is None:
            return {"signature": "no-such-challenge-to-sign"}
    return await approval_body(database, challenge_id, DEVICE_PRIVATE)


async def post_form(app: Starlette, path: str, data: dict[str, str]) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        return await c.post(path, data=data)


async def post_json(
    app: Starlette, path: str, body: dict[str, Any], headers: dict[str, str]
) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        return await c.post(path, json=body, headers=headers)


async def seed(db: Database, challenge_id: str, *, customer_ref: str = OWNER) -> None:
    """Insert one pending, unexpired challenge, committed so the app's pool sees it."""
    async with db.sessionmaker() as s:
        now = datetime.now(UTC)
        s.add(
            ChallengeRecord(
                challenge_id=challenge_id,
                customer_ref=customer_ref,
                tool_name=TOOL,
                payload={"amount": "EUR 340.00", "payee": "Acme Ltd"},
                tier=1,
                status="pending",
                created_at=now,
                expires_at=now + timedelta(seconds=180),
            )
        )
        await s.commit()


async def status_of(db: Database, challenge_id: str) -> str:
    async with db.sessionmaker() as s:
        result = await s.execute(
            select(ChallengeRecord.status).where(ChallengeRecord.challenge_id == challenge_id)
        )
        return str(result.scalar_one())


async def audit_rows(db: Database, customer_ref: str = OWNER) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(
            select(AuditEntry)
            .where(AuditEntry.customer_ref == customer_ref)
            .order_by(AuditEntry.id)
        )
        return list(result.scalars().all())


@pytest.fixture
def shared_redis(monkeypatch: pytest.MonkeyPatch, redis_url: str) -> Iterator[Any]:
    """The suite's Redis standing in for the deployment's, in a prefix of its own.

    Every store built while this is active -- by either confirm app, and by
    the CLI on its own thread and its own event loop -- reads
    ``POSTERN_REDIS_URL`` and ``POSTERN_REDIS_KEY_PREFIX`` and lands on this
    one key space. That is what makes the two apps below genuinely two replicas
    of one deployment rather than two objects sharing a reference. Copied
    deliberately from ``tests/test_zt7_revocation_reachable.py`` rather than
    promoted to ``conftest.py``: that file's fixture is the read path's and the
    two must be free to diverge.

    A ``fakeredis`` server until the layer-1 session token: a customer-client
    revocation is now one Lua script (``EVAL``), and fakeredis 2.38.0 without
    ``lupa`` answers "unknown command 'eval'".
    """
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"zt7c{uuid4().hex[:12]}:")
    yield redis_url


async def run_cli(*argv: str) -> tuple[int, str]:
    """The operator's own entry point, on its own thread and its own event loop.

    A thread because ``postern_core.auth.revoke_cli``'s ``main`` owns its loop
    through ``asyncio.run``, exactly as it does when an operator runs
    ``uv run python tools/revoke.py`` -- and calling that from inside the
    running loop raises. So argument parsing, store construction from
    ``POSTERN_REDIS_URL``, the write and the close are all the real path.
    """
    buffer = io.StringIO()
    code = await asyncio.to_thread(partial(revoke_main, list(argv), out=buffer))
    return code, buffer.getvalue()


# ---------------------------------------------------------------------------
# V1 — the money stops, and the same flow without the revocation does not.
# ---------------------------------------------------------------------------


async def test_a_revoked_customer_cannot_approve_and_the_backend_is_never_reached(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 1. Both directions, one test, one app, one backend.

    The first approval is real: it reaches the operator's payments service and
    the challenge ends ``executed``. The operator then revokes the customer.
    The second approval, on a second challenge identical in every other way,
    reaches nothing. ``backend.calls`` stays at one across both -- which is the
    assertion, because the status codes alone would also be satisfied by a
    fixture in which no approval ever reached a backend.
    """
    await seed(clean, f"{PREFIX}alive")
    await seed(clean, f"{PREFIX}cut")

    served = await approve(app, f"{PREFIX}alive", bearer(key_pair, OWNER))
    assert served.status_code == 200, served.text
    assert len(backend.calls) == 1, "the pre-revocation approval really moved money"
    assert await status_of(clean, f"{PREFIX}alive") == "executed"

    await store_of(app).revoke_customer_client(customer_ref=OWNER, client_id=CLIENT)

    refused = await approve(app, f"{PREFIX}cut", bearer(key_pair, OWNER))

    assert refused.status_code == 403, refused.text
    assert refused.json()["error"] == "access_revoked"
    assert len(backend.calls) == 1, "the revoked approval reached no backend at all"


async def test_revoking_one_customer_does_not_stop_another(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The wildcard is over CLIENTS, never over customers.

    Without this, a check that refused unconditionally would pass every other
    test in this file.
    """
    await seed(clean, f"{PREFIX}other", customer_ref=OTHER)
    await store_of(app).revoke_customer_client(customer_ref=OWNER, client_id=CLIENT)

    served = await approve(app, f"{PREFIX}other", bearer(key_pair, OTHER))

    assert served.status_code == 200, served.text
    assert len(backend.calls) == 1


async def test_cutting_one_client_cuts_the_customers_approvals_through_every_client(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The accepted over-breadth, asserted rather than left as prose.

    ``challenges`` records no client id, so this service cannot tell which
    vendor proposed a challenge. An operator who cuts a customer from ONE
    client therefore stops that customer's approvals through all of them. It
    errs toward refusing money movement for a customer just declared
    compromised, and ``restore-customer-client`` undoes it -- which the second
    half of this test shows.
    """
    await seed(clean, f"{PREFIX}wide")
    await store_of(app).revoke_customer_client(customer_ref=OWNER, client_id=OTHER_CLIENT)

    refused = await approve(app, f"{PREFIX}wide", bearer(key_pair, OWNER))
    assert refused.status_code == 403, refused.text
    assert backend.calls == []

    await store_of(app).restore_customer_client(customer_ref=OWNER, client_id=OTHER_CLIENT)

    served = await approve(app, f"{PREFIX}wide", bearer(key_pair, OWNER))
    assert served.status_code == 200, served.text
    assert len(backend.calls) == 1, "the restore let the same challenge through"


# ---------------------------------------------------------------------------
# The two scopes that deliberately do NOT reach this service.
# ---------------------------------------------------------------------------


async def test_a_revoked_session_jti_does_not_stop_an_approval(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """A LIMITATION, pinned so it cannot change unnoticed in either direction.

    ``revoke session <jti>`` names the AI client's access token. The approval
    request carries a banking-app assertion from a different issuer, which has
    no such value, and ``challenges`` does not record one. So the scope cannot
    match here, ``revoke_cli``'s docstring says so to the operator's face, and
    this asserts the behaviour matches the documentation.
    """
    await seed(clean, f"{PREFIX}jti")
    await store_of(app).revoke_session(jti="sess-phone")

    served = await approve(app, f"{PREFIX}jti", bearer(key_pair, OWNER, jti="sess-phone"))

    assert served.status_code == 200, served.text
    assert len(backend.calls) == 1


async def test_a_kill_switch_does_not_stop_an_approval(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The other pinned limitation.

    A kill switch names a client. Honouring one here would mean refusing EVERY
    customer's approvals rather than that client's, since no challenge records
    which vendor proposed it. Refusing to guess is the decision; this is its
    test.
    """
    await seed(clean, f"{PREFIX}kill")
    await store_of(app).kill_switch(client_id=CLIENT)

    served = await approve(app, f"{PREFIX}kill", bearer(key_pair, OWNER, client_id=CLIENT))

    assert served.status_code == 200, served.text
    assert len(backend.calls) == 1


# ---------------------------------------------------------------------------
# V3 — the challenge is not burned, and the refusal is recorded.
# ---------------------------------------------------------------------------


async def test_a_refused_approval_leaves_the_challenge_pending(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 3. The check precedes the conditional ``UPDATE``.

    A revoked caller must not be able to push a challenge into a terminal
    state. Were the check placed after the claim, the refusal would still
    answer 403 and still reach no backend -- and would have left the row
    ``approved`` with nothing behind it, stranding a payment that can now
    never execute. The row's status is the only thing that separates those two
    implementations, so it is what this asserts.
    """
    await seed(clean, f"{PREFIX}intact")
    await store_of(app).revoke_customer_client(customer_ref=OWNER, client_id=CLIENT)

    refused = await approve(app, f"{PREFIX}intact", bearer(key_pair, OWNER))

    assert refused.status_code == 403, refused.text
    assert await status_of(clean, f"{PREFIX}intact") == "pending"
    assert backend.calls == []


async def test_a_revoked_stranger_cannot_burn_someone_elses_challenge(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The check runs before the challenge is read, so it is not an oracle.

    A revoked caller aiming at a challenge that is not theirs gets the same
    403 as one aiming at their own, and the same 403 they would get for an id
    that does not exist -- because none of those is looked up. The target row
    is untouched.
    """
    await seed(clean, f"{PREFIX}victim", customer_ref=OTHER)
    await store_of(app).revoke_customer_client(customer_ref=OWNER, client_id=CLIENT)

    at_someone_elses = await approve(app, f"{PREFIX}victim", bearer(key_pair, OWNER))
    at_nothing = await approve(app, f"{PREFIX}nosuchid", bearer(key_pair, OWNER))

    assert at_someone_elses.status_code == 403
    assert at_nothing.status_code == 403
    assert at_someone_elses.json() == at_nothing.json(), "no existence oracle in the refusal"
    assert await status_of(clean, f"{PREFIX}victim") == "pending"
    assert backend.calls == []


async def test_a_revoked_approval_writes_exactly_one_audit_row(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The refusal is the event an operator wants recorded, and it is.

    ONE row, not two: no entry row, because the backend was never about to be
    touched -- which is ``services/confirm/audit.py``'s stated rule. The row
    names no tool, because the challenge was deliberately not read, and
    ``detail`` carries the literal an operator queries on. This service has no
    client id to put in a log line, so this row is the durable record.
    """
    await seed(clean, f"{PREFIX}audited")
    await store_of(app).revoke_customer_client(customer_ref=OWNER, client_id=CLIENT)

    refused = await approve(app, f"{PREFIX}audited", bearer(key_pair, OWNER))
    assert refused.status_code == 403

    rows = await audit_rows(clean)
    assert len(rows) == 1, [(r.outcome, r.detail) for r in rows]
    row = rows[0]
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_REVOKED
    assert row.tool_name == UNRESOLVED_TOOL_NAME
    assert row.reaching_at is None, "nothing was reached, so no touch instant exists"
    assert row.arguments["challenge_id"] == f"{PREFIX}audited"


# ---------------------------------------------------------------------------
# V2 — persistence and replica reach, driven through the operator's own CLI.
# ---------------------------------------------------------------------------


async def test_a_revocation_written_by_the_cli_reaches_a_second_confirm_replica(
    settings: ConfirmSettings,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    shared_redis: Any,
) -> None:
    """Verification step 2, through ``revoke_cli.main`` rather than the store.

    Two independently assembled confirm apps, each with its own
    ``create_confirm_app``, its own database and its own revocation store
    object, sharing only Redis. The operator runs one command against neither
    of them, and both refuse the next approval. A third app built AFTER the
    write is the restart case, since ``create_confirm_app`` is what runs at
    process start.
    """
    app_a = build_app(settings, key_pair)
    app_b = build_app(settings, key_pair)
    assert isinstance(store_of(app_a), RedisRevocationStore)
    assert store_of(app_a) is not store_of(app_b), "two stores, not one shared object"

    await seed(clean, f"{PREFIX}rep_a")
    await seed(clean, f"{PREFIX}rep_b")
    await seed(clean, f"{PREFIX}rep_c")

    assert (await approve(app_a, f"{PREFIX}rep_a", bearer(key_pair, OWNER))).status_code == 200
    assert len(backend.calls) == 1, "replica A served before the CLI ran"

    code, output = await run_cli("customer-client", OWNER, CLIENT)
    assert code == 0, output
    assert OWNER in output

    refused_b = await approve(app_b, f"{PREFIX}rep_b", bearer(key_pair, OWNER))

    app_c = build_app(settings, key_pair)
    refused_c = await approve(app_c, f"{PREFIX}rep_c", bearer(key_pair, OWNER))

    assert refused_b.status_code == 403, refused_b.text
    assert refused_c.status_code == 403, refused_c.text
    assert len(backend.calls) == 1, "neither replica reached the backend after the CLI ran"
    assert await status_of(clean, f"{PREFIX}rep_b") == "pending"
    assert await status_of(clean, f"{PREFIX}rep_c") == "pending"


async def test_the_cli_restores_and_the_confirm_replica_approves_again(
    settings: ConfirmSettings,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    shared_redis: Any,
) -> None:
    """No scope has a TTL, so every one of them needs an explicit undo that works."""
    app = build_app(settings, key_pair)
    await seed(clean, f"{PREFIX}undo")

    assert (await run_cli("customer-client", OWNER, CLIENT))[0] == 0
    refused = await approve(app, f"{PREFIX}undo", bearer(key_pair, OWNER))

    assert (await run_cli("restore-customer-client", OWNER, CLIENT))[0] == 0
    served = await approve(app, f"{PREFIX}undo", bearer(key_pair, OWNER))

    assert refused.status_code == 403, refused.text
    assert served.status_code == 200, served.text
    assert len(backend.calls) == 1


# ---------------------------------------------------------------------------
# V4 — the device grant: the mint is refused, not only the use.
# ---------------------------------------------------------------------------


async def paired(app: Starlette, key_pair: RSAKeyPair, customer: str) -> str:
    """Drive a real device pairing to the point where ``/token`` used to mint.

    Every step but the scan is the production path: the browser opens the
    grant, the banking app approves it with a verified assertion, and the
    customer lands on the device code from that assertion's ``sub`` and from
    nowhere else. The scan is claimed through the store, which is where
    ``POST /scan`` would have claimed it, so this file's audit counts stay
    about revocation. Returns the ``device_code`` the browser would poll with.
    """
    opened = await post_form(app, "/device_authorization", {"client_id": CLIENT})
    assert opened.status_code == 200, opened.text
    device_code = opened.json()["device_code"]
    user_code = opened.json()["user_code"]
    await scan_in_store(app, user_code, customer)

    approved = await post_json(
        app,
        "/approve",
        {"user_code": user_code},
        bearer(key_pair, customer),
    )
    assert approved.status_code == 200, approved.text
    return str(device_code)


async def test_a_revoked_customers_device_code_exchange_mints_nothing(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    """Verification step 4, first half: ``/token`` refuses a revoked customer.

    ZT-7's bar is that a revoked identity stops OBTAINING access. Both
    directions in one test: before the revocation a code is issued a
    session, after it another is answered ``access_denied`` and issued
    nothing.

    TWO CODES, because a successful exchange spends the code
    (`dev-docs/decisions/0012-device-code-single-use.md`). Both codes are
    paired BEFORE the revocation because they have to be: ``POST /approve``
    refuses a revoked customer too, one step earlier, which is what
    ``test_a_revoked_customer_cannot_approve_a_device_pairing_at_all`` below
    asserts.
    """
    served_code = await paired(app, key_pair, OWNER)
    held_back = await paired(app, key_pair, OWNER)

    served = await post_form(
        app, "/token", {"grant_type": "device_code", "device_code": served_code}
    )
    assert session_claims(served, app)["sub"] == OWNER

    await store_of(app).revoke_customer_client(customer_ref=OWNER, client_id=CLIENT)

    refused = await post_form(
        app, "/token", {"grant_type": "device_code", "device_code": held_back}
    )

    assert refused.status_code == 400, refused.text
    assert refused.json()["error"] == "access_denied", (
        "a redeemable code for a revoked customer must be refused by ZT-7, not by anything else"
    )
    assert "access_token" not in refused.json()


async def test_the_token_refusal_is_indistinguishable_from_the_customer_declining(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    """What the browser sees, and what it does not learn.

    ``access_denied`` is RFC 8628 §3.5's code for an authorization that was
    refused, already documented on this endpoint as "user explicitly denied on
    mobile app". So the polling browser -- which holds no credential of its own
    and is not the party that was revoked -- cannot separate "the customer
    declined on their phone" from "the customer's access is revoked". The body
    carries no customer reference, no scope and no mention of revocation.
    """
    device_code = await paired(app, key_pair, OWNER)
    await store_of(app).revoke_customer_client(customer_ref=OWNER, client_id=CLIENT)

    refused = await post_form(
        app, "/token", {"grant_type": "device_code", "device_code": device_code}
    )
    body = refused.json()

    assert body["error"] == "access_denied"
    assert OWNER not in refused.text
    assert "revok" not in refused.text.lower()


async def test_a_revoked_customer_cannot_approve_a_device_pairing_at_all(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    """Verification step 4, second half: refused one step earlier than ``/token``.

    Refusing at ``POST /approve`` means ``customer_ref`` is never written onto
    the device code, so the pairing leaves no half-authorized state for the
    later mint to read back. The browser that keeps polling therefore sees
    ``authorization_pending`` -- the pairing simply never completes -- rather
    than a code that reads as approved and then refuses.
    """
    opened = await post_form(app, "/device_authorization", {"client_id": CLIENT})
    device_code = opened.json()["device_code"]
    user_code = opened.json()["user_code"]

    await store_of(app).revoke_customer_client(customer_ref=OWNER, client_id=CLIENT)

    refused = await post_json(
        app,
        "/approve",
        {"user_code": user_code},
        bearer(key_pair, OWNER),
    )
    assert refused.status_code == 403, refused.text
    assert refused.json()["error"] == "access_revoked"

    still_waiting = await post_form(
        app, "/token", {"grant_type": "device_code", "device_code": device_code}
    )
    assert still_waiting.status_code == 400
    assert still_waiting.json()["error"] == "authorization_pending"


# ---------------------------------------------------------------------------
# Fail closed: a store that cannot answer refuses, in each path's own shape.
# ---------------------------------------------------------------------------


async def test_an_unreachable_store_fails_the_approval_and_leaves_it_pending(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """An outage reported as "not revoked" would un-revoke everything at once.

    The challenge is untouched because the check precedes the claim, and the
    audit row records the exception TYPE, which is this service's established
    convention for a genuine failure as opposed to a named refusal.
    """
    await seed(clean, f"{PREFIX}outage")
    store = UnreachableStore()
    app.state.postern_revocation_store = store

    response = await approve(
        app, f"{PREFIX}outage", bearer(key_pair, OWNER), as_a_server_would=True
    )

    assert response.status_code == 500, response.text
    assert store.checks == 1
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}outage") == "pending"
    rows = await audit_rows(clean)
    assert len(rows) == 1
    assert rows[0].detail == "RevocationStoreUnavailable"


async def test_an_unreachable_store_makes_the_token_endpoint_retryable_not_denied(
    app: Starlette, key_pair: RSAKeyPair
) -> None:
    """503 rather than ``access_denied``, and nothing minted either way.

    ``access_denied`` is terminal, so answering an outage with it would end
    every pairing in flight across the deployment -- an availability failure
    dressed as a security decision. The browser is not the party that was
    revoked; the right signal for it is one it can retry.
    """
    device_code = await paired(app, key_pair, OWNER)
    app.state.postern_revocation_store = UnreachableStore()

    response = await post_form(
        app, "/token", {"grant_type": "device_code", "device_code": device_code}
    )

    assert response.status_code == 503, response.text
    assert response.json()["error"] == "temporarily_unavailable"
    assert "access_token" not in response.json()
    # The outage's own 503, with the poll interval as its Retry-After so a
    # client honouring it is never answered slow_down.
    assert response.json()["error_description"] == (
        "authorization state cannot be checked; retry shortly"
    )
    assert response.headers["retry-after"] == str(app.state.settings.device_poll_interval_seconds)


# ---------------------------------------------------------------------------
# The store method itself: both backends, one matrix.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend_name", ["memory", "redis"])
async def test_is_customer_revoked_agrees_across_both_backends(
    backend_name: str, shared_redis: Any
) -> None:
    """The base's default over ``entries`` and Redis's ``SMEMBERS`` override
    must answer identically, or a deployment's behaviour would depend on
    whether ``POSTERN_REDIS_URL`` happened to be set.

    The matrix is the whole contract: a pair naming the customer matches
    whatever the client, a pair naming another customer does not, a session
    revocation does not (it names no customer), and a kill switch does not (it
    names no customer either).
    """
    store: RevocationStoreBase = (
        InMemoryRevocationStore() if backend_name == "memory" else RedisRevocationStore()
    )
    try:
        assert await store.is_customer_revoked(OWNER) is False

        await store.revoke_session(jti="sess-phone")
        await store.kill_switch(client_id=CLIENT)
        assert await store.is_customer_revoked(OWNER) is False, "neither scope names a customer"

        await store.revoke_customer_client(customer_ref=OTHER, client_id=CLIENT)
        assert await store.is_customer_revoked(OWNER) is False, "another customer's pair"

        await store.revoke_customer_client(customer_ref=OWNER, client_id=OTHER_CLIENT)
        assert await store.is_customer_revoked(OWNER) is True, "any client matches"

        await store.restore_customer_client(customer_ref=OWNER, client_id=OTHER_CLIENT)
        assert await store.is_customer_revoked(OWNER) is False
    finally:
        await store.close()


async def test_the_default_implementation_fails_closed_when_entries_cannot_answer() -> None:
    """The reason the method is concrete rather than abstract.

    A backend that cannot enumerate raises out of ``entries``, and the base's
    default propagates it untouched -- so a store with no override of its own
    refuses rather than answering "not revoked". That is what lets
    ``UnreachableStore``-shaped stubs stay honest without implementing
    anything.
    """

    class EnumerationOnly(UnreachableStore):
        async def is_customer_revoked(self, customer_ref: str) -> bool:
            return await RevocationStoreBase.is_customer_revoked(self, customer_ref)

    with pytest.raises(RevocationStoreUnavailable):
        await EnumerationOnly().is_customer_revoked(OWNER)


async def test_an_approval_with_no_revocation_store_wired_fails_closed(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """A route table that forgets the wiring must refuse, not proceed unchecked.

    ``services/confirm/revocation.py`` writes no absent-store branch on
    purpose: Starlette's ``State`` raises ``AttributeError`` for a name nothing
    set, and the handler's own ``except Exception`` turns that into an audit
    row and a 500. This asserts the consequence rather than the mechanism --
    nothing reaches the backend and the challenge is untouched -- because the
    failure mode being guarded against is a future assembly that quietly
    skips the check.
    """
    await seed(clean, f"{PREFIX}unwired")
    del app.state.postern_revocation_store

    response = await approve(
        app, f"{PREFIX}unwired", bearer(key_pair, OWNER), as_a_server_would=True
    )

    assert response.status_code == 500, response.text
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}unwired") == "pending"
    assert (await audit_rows(clean))[0].detail == "AttributeError"


async def test_create_confirm_app_wires_a_revocation_store(app: Starlette) -> None:
    """The wiring defect, pinned: before this commit there was no store to find."""
    assert isinstance(store_of(app), RevocationStoreBase)
    assert isinstance(store_of(app), InMemoryRevocationStore), "no POSTERN_REDIS_URL in this test"

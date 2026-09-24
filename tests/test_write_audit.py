"""The write path's audit trail, against a real Postgres.

``services/confirm`` wrote no ``audit_log`` rows at all until 2026-09-23. This
module pins what it writes now, and every test here drives the assembled app
over ASGI and reads the rows back out of the database rather than inspecting a
mock, because the properties being asserted (a row is DURABLE before the
backend is reached; a row SURVIVES a crash; a CHECK constraint rejects a
malformed row) are properties of Postgres and not of Python.

The four that matter most, in the order they are hardest to get right:

1. ``test_a_crash_between_the_two_rows_leaves_the_entry_row`` -- the whole
   reason the two-row shape exists. Simulated with a ``BaseException``, which
   ``except Exception`` cannot catch, so the completion write genuinely never
   runs. No timing, no cancellation scope, no flakiness.
2. ``test_a_failed_entry_write_stops_the_backend_write`` -- counts BACKEND
   CALLS, not status codes. A fail-closed audit that still let the money move
   would pass a status-code assertion and fail the only thing it exists for.
3. ``test_an_audit_failure_after_a_successful_backend_write_fails_the_request``
   -- the case somebody will eventually call a bug and "fix". It is not a bug;
   see the module docstring of ``services/confirm/callback.py``.
4. ``test_a_cross_customer_approval_records_the_caller_and_the_target`` -- the
   response is byte-identical to "no such challenge" on purpose, so the audit
   row is the ONLY place the two are distinguishable.
"""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncGenerator, Callable, Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.store import audit as audit_store
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from postern_core.store.models import (
    ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
    OUTCOME_RAISED,
    OUTCOME_REACHING,
    OUTCOME_RETURNED,
    AuditEntry,
    ChallengeRecord,
)
from sqlalchemy import delete, select
from starlette.applications import Starlette

from services.confirm import audit as confirm_audit
from services.confirm.audit import (
    DETAIL_ALREADY_TERMINAL,
    DETAIL_CHALLENGE_NOT_FOUND,
    DETAIL_CHALLENGE_NOT_OWNED,
    DETAIL_EXPIRED,
    DETAIL_MISSING_SIGNATURE,
    UNRESOLVED_TOOL_NAME,
)
from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.device_keys import approval_body, device_key, enrolled_store

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
OWNER = "cust_7f3a"
STRANGER = "cust_9e21"
TOOL = "payments.create_payment"

#: The owner's one enrolled phone. STRANGER enrols nothing, deliberately: the
#: cross-customer tests below must be refused by the OWNERSHIP check, which
#: runs first, and giving them an enrolled key would leave it ambiguous which
#: of the two refusals produced the 404.
DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("write-audit-phone")


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_url() -> Generator[str]:
    """Module-scoped Postgres, mirroring ``tests/test_approval_integration.py``.

    Restores ``POSTERN_DATABASE_URL`` on the way out: leaving it pointed at a
    container about to be torn down would poison every ``from_env()`` call in
    whatever module runs next.
    """
    import docker
    from testcontainers.community.postgres import PostgresContainer

    try:
        docker.from_env().ping()
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping write-audit tests: {exc}")

    previous = os.environ.get("POSTERN_DATABASE_URL")
    with PostgresContainer("postgres:17-alpine", driver="asyncpg") as pg:
        url = pg.get_connection_url()
        os.environ["POSTERN_DATABASE_URL"] = url
        from alembic import command
        from alembic.config import Config

        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        try:
            yield url
        finally:
            if previous is None:
                os.environ.pop("POSTERN_DATABASE_URL", None)
            else:
                os.environ["POSTERN_DATABASE_URL"] = previous


@pytest.fixture()
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(backend_base_url="https://backend.test", database_url=pg_url)


@pytest.fixture()
def db(settings: ConfirmSettings) -> Database:
    return Database(settings.database_url)


@pytest.fixture()
async def clean(db: Database) -> AsyncGenerator[Database, None]:
    """Empty ``audit_log`` and ``challenges`` either side of every test.

    Both ends, for the reason ``tests/conftest.py``'s ``audit_server`` gives:
    the app under test commits through its own pool, so nothing a test fixture
    rolls back can undo those rows, and without the post-test clear the LAST
    test in this module leaves its rows for whatever reads ``audit_log`` next.
    """
    await _wipe(db)
    yield db
    await _wipe(db)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await s.execute(delete(AuditEntry))
        await s.execute(delete(ChallengeRecord))
        await s.commit()


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
def app(settings: ConfirmSettings, key_pair: RSAKeyPair) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=enrolled_store(OWNER, DEVICE_PUBLIC),
    )


class Backend:
    """A stand-in backend that COUNTS its calls.

    The count is the point. A fail-closed audit that failed the response but
    still reached the backend would satisfy every status-code assertion in
    this file and break the one guarantee the entry row exists to provide, so
    the tests that matter assert on ``len(backend.calls)`` and treat the
    status code as secondary.
    """

    def __init__(self) -> None:
        self.calls: list[httpx2.Request] = []
        self.responder: Callable[[httpx2.Request], httpx2.Response] = lambda _: httpx2.Response(
            201, json={"ok": True}
        )

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.calls.append(request)
        return self.responder(request)


@pytest.fixture()
def backend() -> Generator[Backend]:
    """Route every ``BackendWriteClient`` through a counting mock transport.

    Patches ``__init__`` rather than the transport argument because
    ``services/confirm/callback.py`` constructs the client itself and passes
    no transport; the same pattern ``tests/test_approval_integration.py``
    uses. ``**kwargs`` passthrough carries the real
    ``before_backend_request=`` hook the handler supplies, which is what makes
    these tests exercise the wiring rather than a stub of it.
    """
    b = Backend()
    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        kwargs.pop("transport", None)
        original(self, *args, transport=httpx2.MockTransport(b.handle), **kwargs)

    with patch.object(BackendWriteClient, "__init__", patched):
        yield b


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def bearer(key_pair: RSAKeyPair, subject: str, **claims: Any) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject,
        issuer=ISSUER,
        audience=AUDIENCE,
        additional_claims=claims or None,
    )
    return {"Authorization": f"Bearer {token}"}


async def post(
    app: Starlette,
    challenge_id: str,
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    as_a_server_would: bool = False,
) -> httpx2.Response:
    """POST an approval over ASGI.

    ``as_a_server_would`` sets ``raise_app_exceptions=False``, which is what
    makes the fail-closed tests below meaningful. Starlette's
    ``ServerErrorMiddleware`` re-raises an unhandled exception so the ASGI
    SERVER can log it and answer; under the default transport that exception
    surfaces in the test instead, which would let a fail-closed assertion read
    as "something blew up" rather than "the caller was told no". With the flag
    off, the transport does what uvicorn does -- a real ``500 Internal Server
    Error`` -- so the test asserts the status the client actually receives in
    production. Verified against this transport directly, not assumed.
    """
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=not as_a_server_would),
        base_url="http://t",
    ) as c:
        return await c.post(f"/challenges/{challenge_id}/approve", json=body, headers=headers)


async def signed(app: Starlette, challenge_id: str, **extra: Any) -> dict[str, Any]:
    """An approval body carrying a real signature over the STORED row.

    Reads the row through the app's own database and signs it with
    ``DEVICE_PRIVATE``, which is what the customer's phone would present. Used
    by every test below whose request is meant to get past the signature check
    -- including the 409 and 410 cases, because that check runs before the
    conditional ``UPDATE`` that refuses them, so an unsigned approval would
    never reach either refusal.

    The tests that are refused EARLIER (no such challenge, not yours, no
    signature at all) keep their placeholder bodies: a signature is not what
    stops them, and giving them a valid one would hide which check did.
    """
    database: Database = app.state.postern_database
    return await approval_body(database, challenge_id, DEVICE_PRIVATE, **extra)


async def seed(
    db: Database,
    challenge_id: str,
    *,
    customer_ref: str = OWNER,
    tool_name: str = TOOL,
    status: str = "pending",
    expired: bool = False,
) -> None:
    """Insert one challenge, committed so the app's own pool can see it."""
    async with db.sessionmaker() as s:
        now = datetime.now(UTC)
        s.add(
            ChallengeRecord(
                challenge_id=challenge_id,
                customer_ref=customer_ref,
                tool_name=tool_name,
                payload={"amount": "EUR 340.00", "payee": "Acme Ltd"},
                tier=1,
                status=status,
                created_at=now,
                expires_at=now - timedelta(seconds=1) if expired else now + timedelta(seconds=180),
            )
        )
        await s.commit()


async def rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(select(AuditEntry).order_by(AuditEntry.id))
        return list(result.scalars().all())


async def dump(db: Database, title: str) -> None:
    """Print the table the way an investigator would read it."""
    entries = await rows(db)
    print(f"\n=== {title} ===")
    print(
        f"{'id':>4}  {'call_id':36}  {'at':32}  {'reaching_at':32}  "
        f"{'outcome':9}  {'tool_name':24}  {'customer_ref':12}  detail"
    )
    for e in entries:
        print(
            f"{e.id:>4}  {e.call_id or '-':36}  {e.at.isoformat():32}  "
            f"{(e.reaching_at.isoformat() if e.reaching_at else '-'):32}  "
            f"{e.outcome:9}  {e.tool_name:24}  {(e.customer_ref or 'NULL'):12}  {e.detail or '-'}"
        )


# ---------------------------------------------------------------------------
# 1. The pair.
# ---------------------------------------------------------------------------


async def test_a_successful_approval_writes_a_correlated_pair(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 1: the two rows, and every relationship between them."""
    await seed(clean, "chal_pair_001")

    resp = await post(
        app, "chal_pair_001", await signed(app, "chal_pair_001"), bearer(key_pair, OWNER)
    )
    assert resp.status_code == 200, resp.text

    await dump(clean, "step 1: successful approval")
    entry, completion = await rows(clean)

    # One call, one correlation key.
    assert entry.call_id is not None
    assert entry.call_id == completion.call_id

    # `reaching_at` is on EXACTLY the reaching row. The database enforces half
    # of this through `ck_audit_log_reaching_at_matches_outcome`; stating it
    # here is what stops someone loosening that constraint later without a
    # test going red.
    assert entry.outcome == OUTCOME_REACHING
    assert completion.outcome == OUTCOME_RETURNED
    assert entry.reaching_at is not None
    assert completion.reaching_at is None

    # The entry row was committed FIRST. `id` is a sequence, so its ordering
    # is the commit ordering, and the entry row is durable before the backend
    # request the completion row describes the result of.
    assert entry.id < completion.id

    # `at` is the request's arrival and is shared, which is what shows at a
    # glance that the two rows are one request. `reaching_at` is the touch and
    # is strictly later, or equal on a clock too coarse to separate them.
    assert entry.at == completion.at
    assert entry.reaching_at >= entry.at

    # Duration belongs to the completion row alone: the backend write had not
    # finished when the entry row was written, so no duration existed.
    assert entry.duration_ms is None
    assert completion.duration_ms is not None and completion.duration_ms >= 0

    # Both rows name the same customer and the same operation.
    assert entry.customer_ref == completion.customer_ref == OWNER
    assert entry.customer_ref_absence_reason is None
    assert entry.tool_name == completion.tool_name == TOOL

    # And the backend really was reached, once.
    assert len(backend.calls) == 1
    assert backend.calls[0].headers["Idempotency-Key"] == "chal_pair_001"


async def test_the_arguments_column_points_at_the_challenge_without_copying_it(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The join key is recorded; the payload is not.

    ``audit_log`` answers "was a payment approved and did it execute";
    ``challenges`` answers "for how much, to whom". This pins that split, so a
    later change that starts copying the amount in has to argue with a test.
    """
    await seed(clean, "chal_args_001")
    await post(
        app,
        "chal_args_001",
        await signed(
            app, "chal_args_001", confirming_device="pixel-9", verification_result="match_ok"
        ),
        bearer(key_pair, OWNER),
    )

    entry, completion = await rows(clean)
    for row in (entry, completion):
        assert row.arguments == {
            "route": confirm_audit.APPROVE_ROUTE,
            "challenge_id": "chal_args_001",
            "signature_present": True,
            "confirming_device": "pixel-9",
            "verification_result": "match_ok",
        }
        # Nothing from `challenges.payload`.
        assert "amount" not in row.arguments
        assert "payee" not in row.arguments
        assert "Acme Ltd" not in json.dumps(row.arguments)
        # And never the signature itself.
        assert "sig_x" not in json.dumps(row.arguments)


async def test_a_caller_supplied_pan_is_masked_before_it_reaches_the_table(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """`confirming_device` is caller input and lands in a long-lived table.

    The NUL variant is the one that matters: a NUL planted inside the digits
    splits the run so `\\d{12,}` no longer matches it, and any implementation
    that strips the NUL AFTER redacting reassembles the full PAN in the value
    it stores. `scrub_text` strips first.
    """
    await seed(clean, "chal_pan_001")
    await post(
        app,
        "chal_pan_001",
        await signed(
            app,
            "chal_pan_001",
            confirming_device="dev 4111111111114417",
            verification_result="4111\x00111111114417",
        ),
        bearer(key_pair, OWNER),
    )

    for row in await rows(clean):
        blob = json.dumps(row.arguments)
        assert "4111111111114417" not in blob
        assert "4417" in blob  # masked, not deleted
        assert "\x00" not in blob


# ---------------------------------------------------------------------------
# 2. Fail closed, counted in backend calls.
# ---------------------------------------------------------------------------


async def test_a_failed_entry_write_stops_the_backend_write(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 2, and the property the whole design rests on.

    Asserts on the BACKEND CALL COUNT, not the status code. An implementation
    that returned 500 and still moved the money would pass a status assertion
    and fail this one.
    """
    await seed(clean, "chal_closed_001")

    real_append = audit_store.append

    async def only_the_entry_row_fails(session: Any, **kw: Any) -> None:
        if kw["outcome"] == OUTCOME_REACHING:
            raise RuntimeError("audit store unavailable")
        await real_append(session, **kw)

    with patch.object(audit_store, "append", only_the_entry_row_fails):
        resp = await post(
            app,
            "chal_closed_001",
            await signed(app, "chal_closed_001"),
            bearer(key_pair, OWNER),
            as_a_server_would=True,
        )

    assert len(backend.calls) == 0, "the backend was reached despite a failed entry write"
    assert resp.status_code == 500

    await dump(clean, "step 2: entry write fails")
    # The failure is itself recorded: the completion write succeeded, so the
    # table says this request raised, and names what it raised.
    (completion,) = await rows(clean)
    assert completion.outcome == OUTCOME_RAISED
    assert completion.reaching_at is None
    assert completion.detail == "RuntimeError"

    # The challenge was claimed before the backend was attempted, so it is
    # left in `approved` with no execution behind it -- which is exactly what
    # the row above is for.
    async with clean.sessionmaker() as s:
        row = await store.get_challenge(s, "chal_closed_001")
        assert row is not None and row.status == "approved"


async def test_a_total_audit_outage_stops_the_backend_write_and_leaves_no_rows(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Both writes fail: the request still fails and the backend is still untouched.

    This is the bounded, loud outage
    ``dev-docs/decisions/0006-audit-write-failure.md`` chose over a silent gap.
    """
    await seed(clean, "chal_closed_002")

    async def every_write_fails(session: Any, **kw: Any) -> None:
        raise RuntimeError("audit store unavailable")

    with patch.object(audit_store, "append", every_write_fails):
        resp = await post(
            app,
            "chal_closed_002",
            await signed(app, "chal_closed_002"),
            bearer(key_pair, OWNER),
            as_a_server_would=True,
        )

    assert len(backend.calls) == 0
    assert resp.status_code == 500
    assert await rows(clean) == []


async def test_an_audit_failure_after_a_successful_backend_write_fails_the_request(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The money moved and the request still returns 500. This is not a bug.

    Fail-closed does not get an exception for the path where failing is most
    expensive; that is the path where a missing audit row costs the most.
    ``Idempotency-Key`` is what makes the caller's retry safe, and the entry
    row below is what tells an investigator the backend was reached.

    Pinned explicitly because it is the case somebody will later read as a
    defect and "fix" into a logged warning.
    """
    await seed(clean, "chal_closed_003")

    real_append = audit_store.append

    async def only_the_completion_row_fails(session: Any, **kw: Any) -> None:
        if kw["outcome"] == OUTCOME_REACHING:
            await real_append(session, **kw)
            return
        raise RuntimeError("audit store unavailable")

    with patch.object(audit_store, "append", only_the_completion_row_fails):
        resp = await post(
            app,
            "chal_closed_003",
            await signed(app, "chal_closed_003"),
            bearer(key_pair, OWNER),
            as_a_server_would=True,
        )

    assert resp.status_code == 500
    assert len(backend.calls) == 1, "the backend write should have succeeded"

    await dump(clean, "step 5: audit fails after the money moved")
    (entry,) = await rows(clean)
    assert entry.outcome == OUTCOME_REACHING
    assert entry.reaching_at is not None


# ---------------------------------------------------------------------------
# 3. The crash the two-row design exists for.
# ---------------------------------------------------------------------------


async def test_a_crash_between_the_two_rows_leaves_the_entry_row(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 3.

    ``asyncio.CancelledError`` is a ``BaseException`` in 3.12, so the
    handler's ``except Exception`` cannot catch it and the completion write
    genuinely never runs -- a faithful process-death simulation with no
    timing dependency and no cancellation scope to reason about.

    Raised from the transport, which runs AFTER the hook has committed the
    entry row, so the window being tested is exactly the one between the two
    writes.
    """
    await seed(clean, "chal_crash_001")

    def die(request: httpx2.Request) -> httpx2.Response:
        raise asyncio.CancelledError("simulated process death after the entry row")

    backend.responder = die
    body = await signed(app, "chal_crash_001")

    with pytest.raises(asyncio.CancelledError):
        await post(app, "chal_crash_001", body, bearer(key_pair, OWNER))

    await dump(clean, "step 3: crash between the rows")
    surviving = await rows(clean)
    assert len(surviving) == 1, "the entry row did not survive, or a completion row was written"
    (entry,) = surviving
    assert entry.outcome == OUTCOME_REACHING
    assert entry.reaching_at is not None
    assert entry.duration_ms is None
    assert entry.tool_name == TOOL
    # An unpaired `reaching` row is the true statement: "we touched this, no
    # outcome was recorded". That is the shape the two-row design buys.
    assert entry.call_id is not None


# ---------------------------------------------------------------------------
# 4. Refused transitions.
# ---------------------------------------------------------------------------


async def test_a_lost_race_records_one_row_and_no_touch(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """409: already terminal. One row, no entry row, the backend untouched."""
    await seed(clean, "chal_409_001", status="approved")

    resp = await post(
        app, "chal_409_001", await signed(app, "chal_409_001"), bearer(key_pair, OWNER)
    )
    assert resp.status_code == 409

    await dump(clean, "step 4: 409 already terminal")
    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_ALREADY_TERMINAL
    assert row.reaching_at is None
    assert row.tool_name == TOOL
    assert row.customer_ref == OWNER
    assert len(backend.calls) == 0


async def test_an_expired_challenge_records_one_row_and_no_touch(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """410: expired. The one refusal that also WRITES, retiring the challenge."""
    await seed(clean, "chal_410_001", expired=True)

    resp = await post(
        app, "chal_410_001", await signed(app, "chal_410_001"), bearer(key_pair, OWNER)
    )
    assert resp.status_code == 410

    await dump(clean, "step 4: 410 expired")
    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_EXPIRED
    assert row.reaching_at is None
    assert len(backend.calls) == 0

    async with clean.sessionmaker() as s:
        challenge = await store.get_challenge(s, "chal_410_001")
        assert challenge is not None and challenge.status == "expired"


async def test_an_unknown_challenge_records_the_unresolved_tool_name(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """404: no such challenge. The id-enumeration signal.

    ``tool_name`` stays the unresolved literal, which is what makes
    ``WHERE tool_name = 'challenges.approve'`` a query for exactly this.
    """
    resp = await post(app, "chal_404_missing", {"signature": "sig_x"}, bearer(key_pair, OWNER))
    assert resp.status_code == 404

    await dump(clean, "step 4: 404 not found")
    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_CHALLENGE_NOT_FOUND
    assert row.tool_name == UNRESOLVED_TOOL_NAME
    assert row.customer_ref == OWNER
    assert row.reaching_at is None
    assert len(backend.calls) == 0


async def test_a_cross_customer_approval_records_the_caller_and_the_target(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """404: not yours. The highest-value row this service writes.

    The RESPONSE is byte-identical to "no such challenge" -- deliberately, so
    an attacker learns nothing about which ids exist. The AUDIT ROW is
    therefore the only place the two are distinguishable, which is the whole
    argument for recording refusals at all.
    """
    await seed(clean, "chal_404_owned", customer_ref=OWNER)

    resp = await post(app, "chal_404_owned", {"signature": "sig_x"}, bearer(key_pair, STRANGER))
    assert resp.status_code == 404

    await dump(clean, "step 4: 404 cross-customer")
    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RAISED
    # Told apart from "no such challenge" HERE and nowhere else.
    assert row.detail == DETAIL_CHALLENGE_NOT_OWNED
    # The caller, not the victim.
    assert row.customer_ref == STRANGER
    # What they tried to approve.
    assert row.tool_name == TOOL
    assert row.reaching_at is None
    assert len(backend.calls) == 0

    # And the challenge was not touched.
    async with clean.sessionmaker() as s:
        challenge = await store.get_challenge(s, "chal_404_owned")
        assert challenge is not None and challenge.status == "pending"


async def test_the_two_404s_are_indistinguishable_in_the_response_and_not_in_the_table(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The pair of properties stated together, because each is worthless alone."""
    await seed(clean, "chal_404_pair", customer_ref=OWNER)

    not_yours = await post(app, "chal_404_pair", {"signature": "s"}, bearer(key_pair, STRANGER))
    no_such = await post(app, "chal_404_gone", {"signature": "s"}, bearer(key_pair, STRANGER))

    assert not_yours.status_code == no_such.status_code == 404
    # Not byte-identical, because each body echoes the id the caller supplied.
    # The property that matters is that the body is a pure function of THAT
    # id and discloses nothing else: swap the ids and the bodies match exactly,
    # so neither answers "does this challenge exist".
    assert not_yours.content.replace(b"chal_404_pair", b"ID") == no_such.content.replace(
        b"chal_404_gone", b"ID"
    )

    details = [row.detail for row in await rows(clean)]
    assert details == [DETAIL_CHALLENGE_NOT_OWNED, DETAIL_CHALLENGE_NOT_FOUND]


async def test_a_missing_signature_records_one_row(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """400: a malformed approval attempt against a money endpoint, by an
    authenticated caller. Worth counting."""
    await seed(clean, "chal_400_001")

    resp = await post(app, "chal_400_001", {}, bearer(key_pair, OWNER))
    assert resp.status_code == 400

    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_MISSING_SIGNATURE
    assert row.arguments["signature_present"] is False
    # No challenge was read, so the operation is unnamed.
    assert row.tool_name == UNRESOLVED_TOOL_NAME
    assert len(backend.calls) == 0


async def test_a_backend_error_records_a_pair_whose_completion_raised(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """207: claimed, reached, refused by the backend.

    A PAIR, because the backend WAS reached -- which is the fact an
    investigator needs when a challenge sits in ``approved``: the other side
    may have partially processed it. ``raised`` rather than ``returned``
    because the vocabulary describes what the work did, not what HTTP said.
    """
    await seed(clean, "chal_207_001")
    backend.responder = lambda _: httpx2.Response(503, json={"detail": "backend down"})

    resp = await post(
        app, "chal_207_001", await signed(app, "chal_207_001"), bearer(key_pair, OWNER)
    )
    assert resp.status_code == 207

    await dump(clean, "step 4: 207 backend refused")
    entry, completion = await rows(clean)
    assert entry.outcome == OUTCOME_REACHING
    assert completion.outcome == OUTCOME_RAISED
    assert completion.detail == "BackendWriteError"
    assert entry.call_id == completion.call_id
    assert len(backend.calls) == 1


# ---------------------------------------------------------------------------
# 5. Subject and client columns.
# ---------------------------------------------------------------------------


async def test_a_non_conforming_subject_is_recorded_as_an_absence_and_never_stored(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The compromised-issuer signal, and the one absence reachable here.

    A PAN-shaped ``sub`` in a verified assertion means the operator's app
    backend minted it, which is the case
    ``ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF`` exists for. The value must be
    recorded as a CLASS of absence and never as itself.
    """
    pan_subject = "4111111111114417"
    resp = await post(app, "chal_sub_001", {"signature": "s"}, bearer(key_pair, pan_subject))
    assert resp.status_code == 404  # such a subject can never own a challenge

    (row,) = await rows(clean)
    assert row.customer_ref is None
    assert row.customer_ref_absence_reason == ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF
    # The offending value appears nowhere on the row.
    assert pan_subject not in json.dumps(row.arguments)
    assert pan_subject != row.customer_ref
    assert pan_subject not in (row.client_id or "")


async def test_the_client_id_comes_from_the_assertion_claims(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """``client_id``, then ``azp``, and NULL when the assertion names neither.

    NULL beside a non-NULL ``customer_ref`` is impossible on a read-path row
    and normal here: there is no OAuth client on this path. See
    ``services/confirm/audit.py::_client_id``.
    """
    await seed(clean, "chal_cid_001")
    await post(
        app,
        "chal_cid_001",
        await signed(app, "chal_cid_001"),
        bearer(key_pair, OWNER, client_id="bank-app-ios"),
    )
    entry, completion = await rows(clean)
    assert entry.client_id == completion.client_id == "bank-app-ios"

    await _wipe(clean)
    await seed(clean, "chal_cid_002")
    await post(
        app,
        "chal_cid_002",
        await signed(app, "chal_cid_002"),
        bearer(key_pair, OWNER, azp="bank-app-and"),
    )
    assert (await rows(clean))[0].client_id == "bank-app-and"

    await _wipe(clean)
    await seed(clean, "chal_cid_003")
    await post(app, "chal_cid_003", await signed(app, "chal_cid_003"), bearer(key_pair, OWNER))
    row = (await rows(clean))[0]
    assert row.client_id is None
    assert row.customer_ref == OWNER  # the combination the read path never produces


# ---------------------------------------------------------------------------
# 6. Wiring.
# ---------------------------------------------------------------------------


async def test_the_callback_passes_a_real_entry_hook_to_the_write_client(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Fails if ``callback.py`` ever stops passing ``before_backend_request``.

    ``BackendWriteClient`` takes it as a required keyword with no default, so
    dropping it is a TypeError rather than a silent unaudited write -- but
    passing ``None`` would type-check and compile, and this is what catches
    that.
    """
    await seed(clean, "chal_wire_001")
    body = await signed(app, "chal_wire_001")
    seen: list[Any] = []
    original = BackendWriteClient.__init__

    def capture(self: Any, *args: Any, **kwargs: Any) -> None:
        seen.append(kwargs.get("before_backend_request"))
        kwargs.pop("transport", None)
        original(
            self,
            *args,
            transport=httpx2.MockTransport(lambda _: httpx2.Response(201, json={})),
            **kwargs,
        )

    with patch.object(BackendWriteClient, "__init__", capture):
        await post(app, "chal_wire_001", body, bearer(key_pair, OWNER))

    assert len(seen) == 1
    assert seen[0] is not None, "callback.py built a write client with no audit hook"


async def test_an_unauthenticated_request_writes_nothing(
    app: Starlette, clean: Database, backend: Backend
) -> None:
    """No assertion, no row.

    ``AppAssertionMiddleware`` refuses before routing, so nothing opens a
    database session -- and there is no verified subject a row could name.
    """
    await seed(clean, "chal_401_001")

    resp = await post(app, "chal_401_001", {"signature": "s"}, {})
    assert resp.status_code == 401
    assert await rows(clean) == []
    assert len(backend.calls) == 0

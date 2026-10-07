"""Recording ``approved -> executed`` after the backend accepted the write.

THE FAILURE THIS FILE PINS. The claim commits ``pending -> approved``, the
backend accepts the write (money may have moved), and THEN the
``approved -> executed`` UPDATE or its commit raises. Before this change that
reached the outer ``except Exception`` of ``approve_challenge``: a bare 500, a
row left in ``approved`` that looked exactly like a 207 backend refusal, and
nobody told the money moved. Re-calling the backend is not an option (no
documented dedupe behind the ``Idempotency-Key``), so the fix retries the LOCAL
record only, on a fresh session per attempt, and answers 202
``accepted_unrecorded`` when it cannot.

Every test counts BACKEND CALLS, not only status codes: a "fix" that retried
the whole approval would pass the status assertions and double-pay.

Real confirm app and real Postgres, helpers copied from
``tests/test_write_audit.py``.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncGenerator, Callable, Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.store import audit as audit_store
from postern_core.store import challenges as challenge_store
from postern_core.store.engine import Database
from postern_core.store.models import (
    OUTCOME_RAISED,
    OUTCOME_REACHING,
    OUTCOME_RETURNED,
    AuditEntry,
    ChallengeRecord,
)
from sqlalchemy import delete, select
from starlette.applications import Starlette

from services.confirm import callback
from services.confirm.audit import DETAIL_EXECUTED_UNRECORDED
from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.fixtures.device_keys import approval_body, device_key, enrolled_store

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
OWNER = "cust_7f3a"
TOOL = "standing_orders.cancel"
SENTINEL = "SENTINEL-sql-text-do-not-leak-4f9c"

DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("executed-recording-phone")

EXPECTED_202 = {
    "status": "approved",
    "execution": "accepted_unrecorded",
    "message": (
        "the backend accepted the operation but recording it failed; "
        "do not retry, it will be reconciled"
    ),
}


# ---------------------------------------------------------------------------
# Fixtures and helpers.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_url() -> Generator[str]:
    import docker
    from testcontainers.community.postgres import PostgresContainer

    try:
        docker.from_env().ping()
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping executed-recording tests: {exc}")

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
    return ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )


@pytest.fixture()
def db(settings: ConfirmSettings) -> Database:
    return Database(settings.database_url)


@pytest.fixture()
async def clean(db: Database) -> AsyncGenerator[Database, None]:
    await _wipe(db)
    yield db
    await _wipe(db)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
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
    """A stand-in backend that counts its calls."""

    def __init__(self) -> None:
        self.calls: list[httpx2.Request] = []

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.calls.append(request)
        return httpx2.Response(200, json={"ok": True})


@pytest.fixture()
def backend() -> Generator[Backend]:
    b = Backend()
    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        kwargs.pop("transport", None)
        original(self, *args, transport=httpx2.MockTransport(b.handle), **kwargs)

    with patch.object(BackendWriteClient, "__init__", patched):
        yield b


class Sleeps:
    """Records the delays asked of ``asyncio.sleep`` inside the callback module."""

    def __init__(self) -> None:
        self.delays: list[float] = []


@pytest.fixture()
def sleeps(monkeypatch: pytest.MonkeyPatch) -> Sleeps:
    """Replace the callback module's sleep with a recorder that yields once.

    ``asyncio`` is the global ``asyncio`` module, so this patches
    every user of ``asyncio.sleep`` for the test's duration; the stand-in
    delegates to a zero-length real sleep so nothing else notices.
    """
    record = Sleeps()
    real_sleep = asyncio.sleep

    async def fake(delay: float, *a: Any, **kw: Any) -> None:
        record.delays.append(delay)
        await real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake)
    return record


def bearer(key_pair: RSAKeyPair, subject: str) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    return {"Authorization": f"Bearer {token}"}


async def post(app: Starlette, challenge_id: str, key_pair: RSAKeyPair) -> httpx2.Response:
    """Sign over the stored row and POST the approval, the way uvicorn would answer."""
    body = await approval_body(app.state.postern_database, challenge_id, DEVICE_PRIVATE)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://t",
    ) as c:
        return await c.post(
            f"/challenges/{challenge_id}/approve", json=body, headers=bearer(key_pair, OWNER)
        )


async def seed(db: Database, challenge_id: str) -> None:
    async with db.sessionmaker() as s:
        now = datetime.now(UTC)
        s.add(
            ChallengeRecord(
                challenge_id=challenge_id,
                customer_ref=OWNER,
                tool_name=TOOL,
                payload={"order_id": "so_340", "amount": "EUR 340.00", "payee": "Acme Ltd"},
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


async def audit_rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(select(AuditEntry).order_by(AuditEntry.id))
        return list(result.scalars().all())


def row_text(entry: AuditEntry) -> str:
    return repr({c.name: getattr(entry, c.name) for c in AuditEntry.__table__.columns})


class Updates:
    """Wraps ``update_challenge_status`` as the callback module sees it.

    ``on_executed(n, real, args, kwargs)`` runs for the n-th (1-based)
    ``status="executed"`` call and defaults to delegating. The claim call
    (``status="approved"``) always passes straight through.
    """

    def __init__(self) -> None:
        self.executed_calls = 0
        self.sessions: list[Any] = []
        self.on_executed: Callable[..., Any] | None = None


@pytest.fixture()
def updates(monkeypatch: pytest.MonkeyPatch) -> Updates:
    u = Updates()
    real = challenge_store.update_challenge_status

    async def wrapper(session: Any, challenge_id: str, **kw: Any) -> Any:
        if kw.get("status") != "executed":
            return await real(session, challenge_id, **kw)
        u.executed_calls += 1
        u.sessions.append(session)
        if u.on_executed is None:
            return await real(session, challenge_id, **kw)
        return await u.on_executed(u.executed_calls, real, session, challenge_id, kw)

    monkeypatch.setattr("services.confirm.callback.update_challenge_status", wrapper)
    return u


def callback_records(caplog: pytest.LogCaptureFixture, level: int) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == "services.confirm.callback" and r.levelno == level and "executed" in r.message
    ]


def poison(session: Any) -> None:
    """Make a session genuinely unusable, as one after a failed flush would be."""

    async def dead(*a: Any, **kw: Any) -> Any:
        raise RuntimeError(SENTINEL)

    session.execute = dead
    session.commit = dead


# ---------------------------------------------------------------------------
# A transient failure is absorbed; the backend is called once.
# ---------------------------------------------------------------------------


async def test_a_failed_executed_update_is_retried_and_the_approval_succeeds(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await seed(clean, "chal_rec_001")
    caplog.set_level(logging.DEBUG)

    async def first_raises(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        if n == 1:
            raise RuntimeError(SENTINEL)
        return await real(session, cid, **kw)

    updates.on_executed = first_raises
    resp = await post(app, "chal_rec_001", key_pair)

    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "executed"
    assert await status_of(clean, "chal_rec_001") == "executed"
    assert len(backend.calls) == 1, "the backend must never be called again"
    assert updates.executed_calls == 2
    assert sleeps.delays == [0.1]

    warnings = callback_records(caplog, logging.WARNING)
    assert len(warnings) == 1
    assert "RuntimeError" in warnings[0].getMessage()
    assert "'chal_rec_001'" in warnings[0].getMessage()
    assert SENTINEL not in caplog.text
    assert SENTINEL not in resp.text
    assert not callback_records(caplog, logging.ERROR)


async def test_a_commit_that_raises_once_is_retried_and_the_approval_succeeds(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
) -> None:
    await seed(clean, "chal_rec_002")

    async def first_commit_raises(
        n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]
    ) -> Any:
        result = await real(session, cid, **kw)
        if n == 1:

            async def commit_fails() -> None:
                raise RuntimeError(SENTINEL)

            session.commit = commit_fails
        return result

    updates.on_executed = first_commit_raises
    resp = await post(app, "chal_rec_002", key_pair)

    assert resp.status_code == 200, resp.text
    assert await status_of(clean, "chal_rec_002") == "executed"
    assert len(backend.calls) == 1
    assert updates.executed_calls == 2


async def test_each_attempt_uses_a_fresh_session_and_a_poisoned_one_is_never_reused(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
) -> None:
    await seed(clean, "chal_rec_003")

    async def first_poisons(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        if n == 1:
            poison(session)
            raise RuntimeError(SENTINEL)
        return await real(session, cid, **kw)

    updates.on_executed = first_poisons
    resp = await post(app, "chal_rec_003", key_pair)

    assert resp.status_code == 200, resp.text
    assert await status_of(clean, "chal_rec_003") == "executed"
    assert len(backend.calls) == 1
    assert len({id(s) for s in updates.sessions}) == len(updates.sessions) == 2


async def test_an_attempt_that_committed_but_raised_on_the_way_back_counts_as_success(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
) -> None:
    await seed(clean, "chal_rec_004")

    async def lands_then_raises(
        n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]
    ) -> Any:
        result = await real(session, cid, **kw)
        if n == 1:
            await session.commit()
            raise RuntimeError(SENTINEL)
        return result

    updates.on_executed = lands_then_raises
    resp = await post(app, "chal_rec_004", key_pair)

    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "executed"
    assert await status_of(clean, "chal_rec_004") == "executed"
    assert len(backend.calls) == 1
    # The second attempt matched no row (already executed) and was believed.
    assert updates.executed_calls == 2


# ---------------------------------------------------------------------------
# Exhaustion: 202, row stays approved, one ERROR line, one raised row.
# ---------------------------------------------------------------------------


async def test_three_failed_attempts_answer_202_and_leave_one_raised_row(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await seed(clean, "chal_rec_005")
    caplog.set_level(logging.DEBUG)

    async def always_raises(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        raise RuntimeError(SENTINEL)

    updates.on_executed = always_raises
    resp = await post(app, "chal_rec_005", key_pair)

    assert resp.status_code == 202, resp.text
    assert resp.json() == {"challenge_id": "chal_rec_005", **EXPECTED_202}
    assert await status_of(clean, "chal_rec_005") == "approved"
    assert len(backend.calls) == 1, "the backend must never be called again"
    assert updates.executed_calls == 3
    assert sleeps.delays == [0.1, 0.3]

    entry, completion = await audit_rows(clean)
    assert entry.outcome == OUTCOME_REACHING
    assert completion.outcome == OUTCOME_RAISED
    assert completion.detail == DETAIL_EXECUTED_UNRECORDED
    assert completion.call_id == entry.call_id

    errors = callback_records(caplog, logging.ERROR)
    assert len(errors) == 1
    message = errors[0].getMessage()
    assert "'chal_rec_005'" in message and TOOL in message
    assert len(callback_records(caplog, logging.WARNING)) == 3

    # Nothing the driver might say reaches the response, the logs or the table.
    assert SENTINEL not in resp.text
    assert SENTINEL not in caplog.text
    assert all(SENTINEL not in row_text(e) for e in (entry, completion))


async def test_a_row_no_longer_approved_on_the_first_attempt_is_not_retried_and_answers_202(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await seed(clean, "chal_rec_006")
    caplog.set_level(logging.DEBUG)

    async def matches_nothing(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        return None

    updates.on_executed = matches_nothing
    resp = await post(app, "chal_rec_006", key_pair)

    assert resp.status_code == 202, resp.text
    assert resp.json() == {"challenge_id": "chal_rec_006", **EXPECTED_202}
    assert len(backend.calls) == 1
    assert updates.executed_calls == 1
    assert sleeps.delays == []
    assert len(callback_records(caplog, logging.ERROR)) == 1
    _, completion = await audit_rows(clean)
    assert completion.outcome == OUTCOME_RAISED
    assert completion.detail == DETAIL_EXECUTED_UNRECORDED


async def test_a_value_error_while_recording_is_not_reported_as_could_not_be_set_up(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
) -> None:
    await seed(clean, "chal_rec_007")

    async def always_value_error(
        n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]
    ) -> Any:
        raise ValueError(SENTINEL)

    updates.on_executed = always_value_error
    resp = await post(app, "chal_rec_007", key_pair)

    assert resp.status_code == 202, resp.text
    assert resp.json() == {"challenge_id": "chal_rec_007", **EXPECTED_202}
    assert "set up" not in resp.text
    assert updates.executed_calls == 3
    assert len(backend.calls) == 1
    _, completion = await audit_rows(clean)
    assert completion.detail == DETAIL_EXECUTED_UNRECORDED


# ---------------------------------------------------------------------------
# Cancellation is never swallowed.
# ---------------------------------------------------------------------------


async def test_cancellation_during_the_retry_sleep_propagates(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await seed(clean, "chal_rec_008")
    in_sleep = asyncio.Event()
    real_sleep = asyncio.sleep

    async def parked_sleep(delay: float, *a: Any, **kw: Any) -> None:
        if delay in callback.EXECUTED_RECORD_BACKOFF_SECONDS:
            in_sleep.set()
            await asyncio.Event().wait()
        await real_sleep(delay)

    monkeypatch.setattr(asyncio, "sleep", parked_sleep)

    async def first_raises(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        raise RuntimeError(SENTINEL)

    updates.on_executed = first_raises
    task = asyncio.create_task(post(app, "chal_rec_008", key_pair))
    await asyncio.wait_for(in_sleep.wait(), timeout=30)
    task.cancel()
    # Bounded, so an implementation that swallows the cancellation and goes
    # on to sleep again fails here instead of hanging the suite.
    done, _ = await asyncio.wait({task}, timeout=30)
    assert done, "the cancellation was swallowed: the request went on"
    assert task.cancelled()

    assert updates.executed_calls == 1
    assert len(backend.calls) == 1
    assert await status_of(clean, "chal_rec_008") == "approved"


async def test_cancellation_inside_an_attempt_propagates(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
) -> None:
    await seed(clean, "chal_rec_009")

    async def cancelled(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        raise asyncio.CancelledError

    updates.on_executed = cancelled
    with pytest.raises(asyncio.CancelledError):
        await post(app, "chal_rec_009", key_pair)

    assert updates.executed_calls == 1, "a cancelled attempt must not be retried"
    assert len(backend.calls) == 1
    assert sleeps.delays == []


# ---------------------------------------------------------------------------
# Paths that must not change.
# ---------------------------------------------------------------------------


async def test_no_sleep_is_taken_when_the_first_attempt_succeeds(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
) -> None:
    await seed(clean, "chal_rec_010")
    resp = await post(app, "chal_rec_010", key_pair)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "challenge_id": "chal_rec_010",
        "status": "executed",
        "message": f"{TOOL} executed successfully",
    }
    assert updates.executed_calls == 1
    assert sleeps.delays == []
    assert [e.outcome for e in await audit_rows(clean)] == [OUTCOME_REACHING, OUTCOME_RETURNED]


async def test_an_audit_failure_after_the_unrecorded_202_still_fails_the_request(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
) -> None:
    """Decision 0006 is not softened by the new response: no completion row, no 202."""
    await seed(clean, "chal_rec_011")
    real_append = audit_store.append

    async def only_the_completion_row_fails(session: Any, **kw: Any) -> None:
        if kw["outcome"] == OUTCOME_REACHING:
            await real_append(session, **kw)
            return
        raise RuntimeError("audit store unavailable")

    async def always_raises(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        raise RuntimeError(SENTINEL)

    updates.on_executed = always_raises
    with patch.object(audit_store, "append", only_the_completion_row_fails):
        resp = await post(app, "chal_rec_011", key_pair)

    assert resp.status_code == 500
    assert len(backend.calls) == 1

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
import dataclasses
import logging
import os
import threading
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
from sqlalchemy import delete, select, update
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
        "the backend accepted the operation but recording it as executed failed or "
        "could not be confirmed; do not retry, it will be reconciled"
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
    # The line claims only what is known: "stays approved" was false when an
    # attempt committed and both re-reads failed (the row is `executed`).
    assert "could not be confirmed as executed; check the row" in message
    assert "stays" not in message
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
# Cancellation is never swallowed, and the recording outlives the request.
# ---------------------------------------------------------------------------


async def drain_background_records() -> None:
    """Wait, bounded, for every detached recording task to finish."""
    pending = callback.pending_recordings()
    if pending:
        done, still = await asyncio.wait(pending, timeout=30)
        assert not still, "a recording task did not finish"


def cancellation_lines(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The REQUEST-side line: the request was cancelled, a task is still recording."""
    return [
        r
        for r in caplog.records
        if r.name == "services.confirm.callback"
        and r.levelno == logging.ERROR
        and "was cancelled while recording it" in r.getMessage()
    ]


def lost_lines(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    """The TASK-side line: the recording itself was cancelled before it finished."""
    return [
        r
        for r in caplog.records
        if r.name == "services.confirm.callback"
        and r.levelno == logging.ERROR
        and "was cancelled before it finished" in r.getMessage()
    ]


def assert_request_line_claims_only_what_is_true(line: logging.LogRecord) -> None:
    text = line.getMessage()
    assert "a background task is still recording it" in text
    assert "a further ERROR line follows if that task fails or is cancelled" in text
    # The old wording promised an outcome nothing guarantees.
    assert "continues" not in text and "may need reconciliation" not in text


async def test_cancellation_during_the_retry_sleep_propagates_and_the_record_completes(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await seed(clean, "chal_rec_008")
    caplog.set_level(logging.DEBUG)
    in_sleep = asyncio.Event()
    release = asyncio.Event()
    real_sleep = asyncio.sleep

    async def parked_sleep(delay: float, *a: Any, **kw: Any) -> None:
        if delay in callback.EXECUTED_RECORD_BACKOFF_SECONDS:
            in_sleep.set()
            await release.wait()
            return
        await real_sleep(delay)

    monkeypatch.setattr(asyncio, "sleep", parked_sleep)

    async def first_raises(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        if n == 1:
            raise RuntimeError(SENTINEL)
        return await real(session, cid, **kw)

    updates.on_executed = first_raises
    task = asyncio.create_task(post(app, "chal_rec_008", key_pair))
    await asyncio.wait_for(in_sleep.wait(), timeout=30)
    task.cancel()
    # Bounded, so an implementation that swallows the cancellation and goes
    # on to sleep again fails here instead of hanging the suite.
    done, _ = await asyncio.wait({task}, timeout=30)
    assert done, "the cancellation was swallowed: the request went on"
    assert task.cancelled()

    (line,) = cancellation_lines(caplog)
    assert "'chal_rec_008'" in line.getMessage() and TOOL in line.getMessage()
    assert_request_line_claims_only_what_is_true(line)
    assert lost_lines(caplog) == [], "the record was not lost; it finishes below"

    # The recording is still alive after the request is gone, and finishes.
    assert callback._BACKGROUND_RECORDS
    release.set()
    await drain_background_records()
    assert await status_of(clean, "chal_rec_008") == "executed"
    assert len(backend.calls) == 1
    assert app.state.postern_database.engine.pool.checkedout() == 0
    assert callback._BACKGROUND_RECORDS == set()


async def test_cancellation_during_an_attempt_propagates_and_the_record_completes(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await seed(clean, "chal_rec_012")
    caplog.set_level(logging.DEBUG)
    in_attempt = asyncio.Event()
    release = asyncio.Event()

    async def slow_first(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        if n == 1:
            in_attempt.set()
            await release.wait()
            raise RuntimeError(SENTINEL)
        return await real(session, cid, **kw)

    updates.on_executed = slow_first
    task = asyncio.create_task(post(app, "chal_rec_012", key_pair))
    await asyncio.wait_for(in_attempt.wait(), timeout=30)
    task.cancel()
    done, _ = await asyncio.wait({task}, timeout=30)
    assert done and task.cancelled()
    (line,) = cancellation_lines(caplog)
    assert_request_line_claims_only_what_is_true(line)

    release.set()
    await drain_background_records()
    assert await status_of(clean, "chal_rec_012") == "executed"
    assert len(backend.calls) == 1
    assert app.state.postern_database.engine.pool.checkedout() == 0
    assert SENTINEL not in caplog.text


async def test_a_detached_recording_that_exhausts_logs_the_unrecorded_line_once(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
    caplog: pytest.LogCaptureFixture,
) -> None:
    await seed(clean, "chal_rec_013")
    caplog.set_level(logging.DEBUG)
    in_attempt = asyncio.Event()
    release = asyncio.Event()

    async def always_fails(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        if n == 1:
            in_attempt.set()
            await release.wait()
        raise RuntimeError(SENTINEL)

    updates.on_executed = always_fails
    task = asyncio.create_task(post(app, "chal_rec_013", key_pair))
    await asyncio.wait_for(in_attempt.wait(), timeout=30)
    task.cancel()
    await asyncio.wait({task}, timeout=30)
    release.set()
    await drain_background_records()

    assert await status_of(clean, "chal_rec_013") == "approved"
    assert len(backend.calls) == 1
    assert len(cancellation_lines(caplog)) == 1
    assert len(callback_records(caplog, logging.ERROR)) == 1
    assert SENTINEL not in caplog.text


async def test_cancellation_inside_the_recording_task_itself_propagates(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The task being cancelled (a closing loop) is not retried or swallowed.

    It used to log "the record continues in the background" here, which was
    false: the task is the thing that was cancelled. It now logs ONE line, from
    the task, saying the record was lost, and no request-side line (the task
    is already done when the request notices, so nothing is "still recording").
    """
    await seed(clean, "chal_rec_009")
    caplog.set_level(logging.DEBUG)

    async def cancelled(n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]) -> Any:
        raise asyncio.CancelledError

    updates.on_executed = cancelled
    with pytest.raises(asyncio.CancelledError):
        await post(app, "chal_rec_009", key_pair)

    assert updates.executed_calls == 1, "a cancelled attempt must not be retried"
    assert len(backend.calls) == 1
    assert sleeps.delays == []
    (line,) = lost_lines(caplog)
    text = line.getMessage()
    assert "'chal_rec_009'" in text and TOOL in text
    assert "the backend accepted the operation" in text
    assert "do not retry" in text and "reconcile by hand" in text
    assert cancellation_lines(caplog) == [], "nothing is still recording: no request-side line"
    assert "continues" not in caplog.text
    assert await status_of(clean, "chal_rec_009") == "approved"


async def test_an_exception_escaping_the_recording_task_answers_202_not_500(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Whatever escapes `_record_executed`, the backend has accepted: say so.

    Nothing logged an escaping exception and a live request got a bare 500 for
    a payment that went through, which is the one answer that invites a retry.
    """
    await seed(clean, "chal_rec_014")
    caplog.set_level(logging.DEBUG)

    async def escapes(db: Database, challenge_id: str) -> bool:
        raise RuntimeError(SENTINEL)

    monkeypatch.setattr(callback, "_record_executed", escapes)
    resp = await post(app, "chal_rec_014", key_pair)

    assert resp.status_code == 202, resp.text
    assert resp.json() == {"challenge_id": "chal_rec_014", **EXPECTED_202}
    assert len(backend.calls) == 1
    (line,) = callback_records(caplog, logging.ERROR)
    assert "'chal_rec_014'" in line.getMessage() and TOOL in line.getMessage()
    assert "RuntimeError" in line.getMessage(), "the type is logged, as everywhere else"
    assert SENTINEL not in caplog.text and SENTINEL not in resp.text
    _, completion = await audit_rows(clean)
    assert completion.detail == DETAIL_EXECUTED_UNRECORDED


async def test_an_exception_raised_after_the_request_was_cancelled_is_never_reported_unretrieved(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The reviewer's probe: the task fails AFTER nobody is awaiting it.

    asyncio would otherwise log "Task exception was never retrieved" with the
    exception's text when the task is collected, and a driver error's text is
    SQL and bound parameters.
    """
    import gc

    await seed(clean, "chal_rec_015")
    caplog.set_level(logging.DEBUG)
    in_task = asyncio.Event()
    release = asyncio.Event()

    async def fails_late(db: Database, challenge_id: str, tool_name: str) -> bool:
        in_task.set()
        await release.wait()
        raise RuntimeError(SENTINEL)

    monkeypatch.setattr(callback, "_record_and_report", fails_late)
    task = asyncio.create_task(post(app, "chal_rec_015", key_pair))
    await asyncio.wait_for(in_task.wait(), timeout=30)
    task.cancel()
    done, _ = await asyncio.wait({task}, timeout=30)
    assert done and task.cancelled()
    # The cancelled request's CancelledError carries a traceback through frames
    # that hold the recording task; dropping the request task is what lets the
    # recording task be collected at all, and collection is when asyncio reports
    # an exception nobody retrieved.
    del task, done

    release.set()
    await drain_background_records()
    gc.collect()
    await asyncio.sleep(0)
    gc.collect()

    assert not [r for r in caplog.records if r.name == "asyncio"], [
        r.getMessage() for r in caplog.records if r.name == "asyncio"
    ]
    assert SENTINEL not in caplog.text


async def test_a_row_that_left_approved_for_something_else_is_not_reported_executed(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    updates: Updates,
    sleeps: Sleeps,
) -> None:
    """None after a failed attempt is a success only if the row now says executed."""
    await seed(clean, "chal_rec_014")

    async def declined_between_attempts(
        n: int, real: Any, session: Any, cid: str, kw: dict[str, Any]
    ) -> Any:
        if n == 1:
            async with clean.sessionmaker() as other:
                await other.execute(
                    update(ChallengeRecord)
                    .where(ChallengeRecord.challenge_id == cid)
                    .values(status="declined")
                )
                await other.commit()
            raise RuntimeError(SENTINEL)
        return await real(session, cid, **kw)

    updates.on_executed = declined_between_attempts
    resp = await post(app, "chal_rec_014", key_pair)

    assert resp.status_code == 202, resp.text
    assert resp.json() == {"challenge_id": "chal_rec_014", **EXPECTED_202}
    assert await status_of(clean, "chal_rec_014") == "declined"
    assert len(backend.calls) == 1


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
    await asyncio.sleep(0)
    assert callback._BACKGROUND_RECORDS == set(), "the happy path left a task behind"
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


# ---------------------------------------------------------------------------
# A real uvicorn server, stopped for real.
# ---------------------------------------------------------------------------
#
# Everything above drives the app through an in-process ASGI transport, where
# nothing ever stops the process. These tests run `uvicorn.Server.run()` in a
# thread (its own `asyncio.run`, so a recording left over when the server
# returns is cancelled exactly as it is in production) and stop it the ways an
# operator does. What they measured against uvicorn 0.52.4:
#
# - the shipped command has no `--timeout-graceful-shutdown`, and then
#   uvicorn WAITS for the in-flight request, so the recording lands and the
#   shield is never used;
# - with `timeout_graceful_shutdown=N` uvicorn cancels the request after N
#   seconds and THEN runs the lifespan shutdown, which is where this service
#   waits for a recording that outlived its request;
# - a forced exit (`force_exit`) skips the lifespan shutdown altogether.
# A client disconnect never cancels a non-streaming handler under uvicorn, so
# shutdown is the only way a request is cancelled there.


class RealServer:
    """``uvicorn.Server.run()`` in a thread, on a free loopback port."""

    def __init__(self, app: Starlette, *, graceful: int | None) -> None:
        import socket

        import uvicorn

        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self.server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=self.port,
                log_config=None,
                timeout_graceful_shutdown=graceful,
            )
        )
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    async def start(self) -> None:
        self.thread.start()
        for _ in range(300):
            if self.server.started:
                return
            await asyncio.sleep(0.05)
        raise AssertionError("uvicorn did not start")

    def stop(self, *, force: bool = False) -> None:
        self.server.should_exit = True
        if force:
            self.server.force_exit = True

    async def joined(self, seconds: float) -> bool:
        await asyncio.to_thread(self.thread.join, seconds)
        return not self.thread.is_alive()


async def _until(event: threading.Event, seconds: float = 30) -> None:
    assert await asyncio.to_thread(event.wait, seconds), "the recording never started"


def _slow_record(monkeypatch: pytest.MonkeyPatch, seconds: float) -> threading.Event:
    """Make the recording take ``seconds``, cancellably, then do the real thing."""
    started = threading.Event()
    real = callback._record_executed

    async def slow(db: Database, challenge_id: str) -> bool:
        started.set()
        await asyncio.sleep(seconds)
        return await real(db, challenge_id)

    monkeypatch.setattr(callback, "_record_executed", slow)
    return started


async def _real_post(
    server: RealServer, db: Database, challenge_id: str, key_pair: RSAKeyPair
) -> httpx2.Response | str:
    """The status or the failure the client saw, over a real socket."""
    body = await approval_body(db, challenge_id, DEVICE_PRIVATE)
    try:
        async with httpx2.AsyncClient(timeout=30) as c:
            return await c.post(
                f"http://127.0.0.1:{server.port}/challenges/{challenge_id}/approve",
                json=body,
                headers=bearer(key_pair, OWNER),
            )
    except Exception as exc:  # noqa: BLE001
        return type(exc).__name__


async def test_real_uvicorn_default_shutdown_waits_for_the_request_and_the_record_lands(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The shipped command: no graceful-shutdown timeout, so the request finishes."""
    await seed(clean, "chal_rec_020")
    caplog.set_level(logging.INFO)
    started = _slow_record(monkeypatch, 2)
    server = RealServer(app, graceful=None)
    await server.start()
    client = asyncio.create_task(_real_post(server, clean, "chal_rec_020", key_pair))
    await _until(started)
    server.stop()

    assert await server.joined(30), "uvicorn did not exit"
    resp = await asyncio.wait_for(client, 30)
    assert not isinstance(resp, str), resp
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "executed"
    assert await status_of(clean, "chal_rec_020") == "executed"
    assert len(backend.calls) == 1
    assert cancellation_lines(caplog) == [] and lost_lines(caplog) == []


async def test_real_uvicorn_graceful_timeout_cancels_the_request_and_the_lifespan_waits(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The request is cancelled at 1 s; the 3 s record is waited for at shutdown.

    The REAL wait constant is used on purpose: with the wait patched in, a wait of
    zero survives every test that depends on it.
    """
    await seed(clean, "chal_rec_021")
    caplog.set_level(logging.INFO)
    started = _slow_record(monkeypatch, 3)
    server = RealServer(app, graceful=1)
    await server.start()
    client = asyncio.create_task(_real_post(server, clean, "chal_rec_021", key_pair))
    await _until(started)
    server.stop()

    assert await server.joined(30), "uvicorn did not exit"
    await asyncio.wait_for(client, 30)
    assert await status_of(clean, "chal_rec_021") == "executed"
    assert len(backend.calls) == 1
    (line,) = cancellation_lines(caplog)
    assert_request_line_claims_only_what_is_true(line)
    assert lost_lines(caplog) == [], "the record finished, so nothing was lost"
    assert callback.pending_recordings() == set()


async def test_real_uvicorn_a_record_longer_than_the_shutdown_wait_is_lost_and_says_so(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The wait is bounded: the process still exits, and the lost record is named."""
    await seed(clean, "chal_rec_022")
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(callback, "SHUTDOWN_RECORD_WAIT_SECONDS", 1.0)
    started = _slow_record(monkeypatch, 60)
    server = RealServer(app, graceful=1)
    await server.start()
    client = asyncio.create_task(_real_post(server, clean, "chal_rec_022", key_pair))
    await _until(started)
    server.stop()

    assert await server.joined(30), "uvicorn hung on a recording it could not wait for"
    await asyncio.wait_for(client, 30)
    assert await status_of(clean, "chal_rec_022") == "approved"
    assert len(backend.calls) == 1
    assert len(cancellation_lines(caplog)) == 1
    (line,) = lost_lines(caplog)
    assert "'chal_rec_022'" in line.getMessage() and TOOL in line.getMessage()
    assert callback.pending_recordings() == set()


async def test_real_uvicorn_a_forced_exit_skips_the_lifespan_and_the_lost_record_is_named(
    app: Starlette,
    clean: Database,
    backend: Backend,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A second SIGINT: uvicorn never runs the lifespan shutdown, so nothing waits."""
    await seed(clean, "chal_rec_023")
    caplog.set_level(logging.INFO)
    monkeypatch.setattr(callback, "SHUTDOWN_RECORD_WAIT_SECONDS", 15.0)
    started = _slow_record(monkeypatch, 60)
    server = RealServer(app, graceful=None)
    await server.start()
    client = asyncio.create_task(_real_post(server, clean, "chal_rec_023", key_pair))
    await _until(started)
    server.stop(force=True)

    assert await server.joined(30), "uvicorn did not exit on a forced exit"
    await asyncio.wait_for(client, 30)
    assert await status_of(clean, "chal_rec_023") == "approved"
    assert len(backend.calls) == 1
    (line,) = lost_lines(caplog)
    assert "'chal_rec_023'" in line.getMessage() and TOOL in line.getMessage()


# ---------------------------------------------------------------------------
# The shutdown wait: its size, its cancellation, and the logging helper.
# ---------------------------------------------------------------------------


def test_the_shutdown_wait_is_derived_from_the_real_engine_timeouts_and_under_30s() -> None:
    """Pins the derivation, so a wait of zero (or any hand-typed number) is caught."""
    defaults: dict[str, Any] = {f.name: f.default for f in dataclasses.fields(ConfirmSettings)}
    one_attempt = (
        defaults["database_pool_timeout_seconds"]
        + defaults["database_connect_timeout_seconds"]
        + 2 * defaults["database_command_timeout_seconds"]
    )
    assert one_attempt == 9.0
    derived = min(
        25.0,
        callback.EXECUTED_RECORD_ATTEMPTS * one_attempt
        + sum(callback.EXECUTED_RECORD_BACKOFF_SECONDS),
    )
    assert derived == pytest.approx(25.0)
    assert callback.SHUTDOWN_RECORD_WAIT_SECONDS == derived
    assert callback.SHUTDOWN_RECORD_WAIT_SECONDS < 30.0, "ECS stopTimeout default"


async def test_a_cancelled_lifespan_shutdown_propagates_and_cancels_the_leftover_recordings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wait never swallows a cancellation, and leaves no recording task running behind it."""
    from services.confirm import main as confirm_main

    async def no_clock_check(db: object) -> None:
        return None

    monkeypatch.setattr(confirm_main, "run_database_clock_check", no_clock_check)
    monkeypatch.setattr(callback, "SHUTDOWN_RECORD_WAIT_SECONDS", 30.0)
    leftover = asyncio.ensure_future(asyncio.sleep(60))
    callback._BACKGROUND_RECORDS.add(leftover)  # type: ignore[arg-type]
    app = Starlette()
    app.state.postern_database = None
    ctx = confirm_main._lifespan(app)
    await ctx.__aenter__()
    shutdown = asyncio.ensure_future(ctx.__aexit__(None, None, None))
    try:
        await asyncio.sleep(0.1)
        assert not shutdown.done(), "the lifespan did not wait"
        shutdown.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(shutdown, 5)
        await asyncio.sleep(0)
        assert leftover.cancelled()
    finally:
        callback._BACKGROUND_RECORDS.discard(leftover)
        leftover.cancel()


class _RaisingLogger:
    """A logger whose ``error`` raises for any call with more than ``allow_args`` arguments."""

    def __init__(self, allow_args: int | None) -> None:
        self.allow_args = allow_args
        self.written: list[tuple[Any, ...]] = []

    def error(self, msg: str, *args: Any) -> None:
        if self.allow_args is None or len(args) > self.allow_args:
            raise OSError("log sink is gone")
        self.written.append((msg, *args))


def test_the_unrecorded_log_helper_falls_back_to_the_id_alone_when_the_full_line_cannot_be_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _RaisingLogger(allow_args=1)
    monkeypatch.setattr(callback, "logger", fake)
    callback._log_accepted_unrecorded("chal_x", TOOL, "OSError")
    assert fake.written == [(fake.written[0][0], "chal_x")]
    assert TOOL not in str(fake.written)


def test_the_unrecorded_log_helper_never_raises_even_when_every_write_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(callback, "logger", _RaisingLogger(allow_args=None))
    callback._log_accepted_unrecorded("chal_x", TOOL)


async def test_a_logger_that_raises_does_not_turn_the_exhaustion_into_an_escaping_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """False stays False: the caller must still answer the 202, never a 500."""

    async def exhausted(db: Database, challenge_id: str) -> bool:
        return False

    async def blew_up(db: Database, challenge_id: str) -> bool:
        raise RuntimeError(SENTINEL)

    monkeypatch.setattr(callback, "logger", _RaisingLogger(allow_args=None))
    for rec in (exhausted, blew_up):
        monkeypatch.setattr(callback, "_record_executed", rec)
        assert await callback._record_and_report(None, "chal_x", TOOL) is False  # type: ignore[arg-type]

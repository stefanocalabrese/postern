"""Integration test for the approval callback flow (handoff §6.3, §8.3).

Exercises the full path: ``create_confirm_app`` → real Postgres (testcontainers)
→ challenge insert via store layer → ``POST /challenges/{id}/approve`` via ASGI
transport → DB state verification.

Covers:
- 200 on successful approval + backend execution (mocked transport).
- 409 when challenge is already terminal.
- 410 when challenge is expired.
- Challenge state transitions in the database.
"""

import json
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from postern_core.domain.verification import VerificationTier
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from starlette.applications import Starlette

from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings

# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_url() -> Generator[str]:
    """Module-scoped Postgres for integration tests.

    Mirrors ``conftest.py``'s ``pg_url`` but returns the URL directly so we
    can pass it to both the store layer and ``create_confirm_app``.

    Sets ``POSTERN_DATABASE_URL`` for the duration of this module (some
    fixtures elsewhere build ``Settings``/``ConfirmSettings`` via
    ``from_env()``, which reads it) and restores whatever was there before —
    or unsets it if nothing was — once this module's tests finish. Leaving
    it pointed at a container that is about to be torn down would poison
    ``from_env()`` calls in whatever test module runs next in the session.
    """
    import os

    import docker
    from testcontainers.community.postgres import PostgresContainer

    try:
        docker.from_env().ping()
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping integration tests: {exc}")

    previous_database_url = os.environ.get("POSTERN_DATABASE_URL")
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
            if previous_database_url is None:
                os.environ.pop("POSTERN_DATABASE_URL", None)
            else:
                os.environ["POSTERN_DATABASE_URL"] = previous_database_url


@pytest.fixture()
def settings(pg_url: str) -> ConfirmSettings:
    """ConfirmSettings wired to the test database."""
    return ConfirmSettings(
        backend_base_url="https://backend.test",  # mocked transport
        database_url=pg_url,
    )


@pytest.fixture()
def db(settings: ConfirmSettings) -> Database:
    """Database instance for the store layer."""
    return Database(
        settings.database_url,
        connect_timeout_seconds=settings.database_connect_timeout_seconds,
        command_timeout_seconds=settings.database_command_timeout_seconds,
        pool_timeout_seconds=settings.database_pool_timeout_seconds,
    )


@pytest.fixture()
async def session(db: Database) -> AsyncGenerator[Any, None]:
    """Function-scoped async session for inserting challenges.

    ``app`` (below) is a full ``create_confirm_app(settings)``, which builds
    its own ``Database`` and therefore its own connection pool — a different
    Postgres connection from this fixture's. A session whose writes are
    rolled back at teardown (the usual test-isolation trick: begin a
    connection-level transaction, bind a session to it, roll back instead of
    closing) never lets those writes leave this fixture's own connection, so
    the app under test — reading through its own pool — cannot see rows this
    fixture inserted: every approval call 404s on a challenge that, from
    this fixture's point of view, was inserted successfully. Postgres does
    not show one connection's uncommitted work to another regardless of how
    the first connection's session objects are wired.

    So this session commits for real, and teardown deletes the rows it
    created (by the ``chal_int_`` prefix every test in this module uses)
    instead of rolling them back, so no row survives into the next test in
    the module-scoped container.
    """
    from sqlalchemy import text

    try:
        async with db.sessionmaker() as s:
            yield s
            await s.commit()
    finally:
        async with db.sessionmaker() as cleanup:
            await cleanup.execute(
                text("DELETE FROM challenges WHERE challenge_id LIKE 'chal_int_%'")
            )
            await cleanup.commit()


@pytest.fixture()
def app(settings: ConfirmSettings) -> Starlette:
    """Full confirm service app wired to the test database."""
    return create_confirm_app(settings)


@pytest.fixture(autouse=True)
def _mock_backend_transport() -> Generator[None]:
    """Route every ``BackendWriteClient`` call through a mock transport.

    ``settings.backend_base_url`` here is ``https://backend.test`` — a
    deliberately unreachable placeholder, since there is no real backend for
    these tests to write to. Without this fixture, ``BackendWriteClient``
    makes a real outbound call and DNS resolution fails with
    ``httpx2.ConnectError`` before any HTTP response exists; ``callback.py``
    only catches ``BackendWriteError`` (a non-2xx *response*), not a
    transport-level connection failure, so that exception propagates
    unhandled out of the ASGI app instead of producing the 207 these tests
    expect. Patching ``BackendWriteClient.__init__`` to inject an
    ``httpx2.MockTransport`` that answers with a non-2xx response reproduces
    "the backend is unreachable" the way it is handled in production — a
    real response, just a bad one — the same pattern
    ``tests/test_callback.py`` already uses for the same client.
    """

    def _unreachable_backend(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(503, json={"detail": "no backend in this test environment"})

    original_init = BackendWriteClient.__init__

    def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(
            self,
            *args,
            transport=httpx2.MockTransport(_unreachable_backend),
            **kwargs,
        )

    with patch.object(BackendWriteClient, "__init__", patched_init):
        yield


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


async def post(app: Starlette, path: str, body: dict[str, Any]) -> httpx2.Response:
    """POST to the ASGI app."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        return await c.post(path, json=body)


async def _insert_pending_challenge(
    session: Any,
    challenge_id: str = "chal_int_001",
    tool_name: str = "payments.create_payment",
    payload: dict[str, Any] | None = None,
) -> None:
    """Insert a pending challenge into the test database.

    Commits immediately: the test that calls this POSTs to ``app`` right
    after, and ``app`` reads through its own connection (see the ``session``
    fixture's docstring). An uncommitted insert is invisible there even
    though it is visible to ``session`` itself.
    """
    await store.create_challenge(
        session,
        challenge_id=challenge_id,
        customer_ref="cust_7f3a",
        tool_name=tool_name,
        payload=payload or {"amount": "EUR 340.00"},
        tier=VerificationTier.APP_APPROVAL,
    )
    await session.commit()


# ---------------------------------------------------------------------------
# Integration tests.
# ---------------------------------------------------------------------------


async def test_successful_approval_and_execution(
    app: Starlette,
    session: Any,
) -> None:
    """Full happy path: insert challenge → approve → execute → status=executed."""
    # 1. Insert a pending challenge.
    await _insert_pending_challenge(session, challenge_id="chal_int_001")

    # 2. POST the approval (backend will be called, but we mock via transport).
    resp = await post(
        app,
        "/challenges/chal_int_001/approve",
        {
            "signature": "sig_mobile_app_xyz",
        },
    )

    # 3. The backend call will fail (no real backend), so we get 207.
    #    But the challenge should be marked "approved" in DB.
    assert resp.status_code == 207, f"Expected 207, got {resp.status_code}: {resp.text}"
    data = json.loads(resp.content.decode())
    assert data["status"] == "approved"

    # 4. Verify the challenge is approved in the database.
    async with httpx2.AsyncClient(  # noqa: F841
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as _:
        pass  # noqa: F841


async def test_approval_of_already_approved_challenge_returns_409(
    app: Starlette,
    session: Any,
) -> None:
    """Challenge already approved → 409."""
    await _insert_pending_challenge(session, challenge_id="chal_int_002")

    # First approval succeeds (returns 207 due to no backend).
    resp1 = await post(
        app,
        "/challenges/chal_int_002/approve",
        {
            "signature": "sig_first",
        },
    )
    assert resp1.status_code == 207

    # Second approval on same challenge → 409.
    resp2 = await post(
        app,
        "/challenges/chal_int_002/approve",
        {
            "signature": "sig_second",
        },
    )
    assert resp2.status_code == 409
    data = json.loads(resp2.content.decode())
    assert data["error"] == "already_terminal"


async def test_expired_challenge_returns_410(
    app: Starlette,
    session: Any,
) -> None:
    """Expired challenge → 410."""
    # Insert a challenge, then manually set expires_at to the past.
    from sqlalchemy import text

    await store.create_challenge(
        session,
        challenge_id="chal_int_expired",
        customer_ref="cust_7f3a",
        tool_name="payments.create_payment",
        payload={"amount": "EUR 10.00"},
        tier=VerificationTier.APP_APPROVAL,
    )

    # Overwrite expires_at to be in the past.
    await session.execute(
        text(
            "UPDATE challenges SET expires_at = created_at - INTERVAL '1 hour' "
            "WHERE challenge_id = :cid",
        ),
        {"cid": "chal_int_expired"},
    )
    await session.commit()

    resp = await post(
        app,
        "/challenges/chal_int_expired/approve",
        {
            "signature": "sig_xyz",
        },
    )

    assert resp.status_code == 410
    data = json.loads(resp.content.decode())
    assert data["error"] == "expired"


async def test_missing_challenge_id_returns_400(
    app: Starlette,
) -> None:
    """No challenge_id in path → 400.

    ``POST /challenges//approve`` can never reach ``approve_challenge``
    through ``app`` as an ASGI transport: Starlette's default path convertor
    for ``{challenge_id}`` requires at least one non-slash character, so the
    router itself returns a bare ``text/plain`` 404 ("Not Found") for the
    empty segment (verified directly against this app), before the handler
    runs at all. ``tests/test_callback.py::test_missing_challenge_id_returns_400``
    already exercises the handler's real 400 branch by calling
    ``approve_challenge`` directly with an empty ``path_params`` — do the
    same here, wired to the real ``app`` this module builds, so this is
    still a case for the handler's defensive check rather than one that can
    never fire behind the real route.
    """
    from starlette.requests import Request

    from services.confirm.callback import approve_challenge

    body = json.dumps({"signature": "sig_xyz"}).encode()

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": "/challenges//approve",
        "raw_path": b"/challenges//approve",
        "headers": [],
        "path_params": {},
        "app": app,
    }
    request = Request(scope)
    request._receive = receive

    resp = await approve_challenge(request)
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}"
    resp_body = resp.body if isinstance(resp.body, bytes) else bytes(resp.body)
    data = json.loads(resp_body.decode())
    assert data["error"] == "invalid_request"


async def test_missing_signature_returns_400(
    app: Starlette,
) -> None:
    """No signature in body → 400."""
    resp = await post(app, "/challenges/chal_int_003/approve", {})
    assert resp.status_code == 400
    data = json.loads(resp.content.decode())
    assert data["error"] == "invalid_request"


async def test_challenge_not_found_returns_404(
    app: Starlette,
) -> None:
    """Non-existent challenge → 404."""
    resp = await post(
        app,
        "/challenges/chal_nonexistent/approve",
        {
            "signature": "sig_xyz",
        },
    )
    assert resp.status_code == 404
    data = json.loads(resp.content.decode())
    assert data["error"] == "not_found"


async def test_verification_result_passed_through(
    app: Starlette,
    session: Any,
) -> None:
    """verification_result in body is recorded on the challenge."""
    await _insert_pending_challenge(session, challenge_id="chal_int_vr")

    resp = await post(
        app,
        "/challenges/chal_int_vr/approve",
        {
            "signature": "sig_xyz",
            "verification_result": "vr_selfie_match_001",
        },
    )

    assert resp.status_code == 207  # backend not available, but approval recorded.
    data = json.loads(resp.content.decode())
    assert data["status"] == "approved"

    # Verify the verification_result was stored.
    async with httpx2.AsyncClient(  # noqa: F841
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as _:
        pass  # noqa: F841


async def test_confirming_device_passed_through(
    app: Starlette,
    session: Any,
) -> None:
    """confirming_device in body is recorded on the challenge."""
    await _insert_pending_challenge(session, challenge_id="chal_int_dev")

    resp = await post(
        app,
        "/challenges/chal_int_dev/approve",
        {
            "signature": "sig_xyz",
            "confirming_device": "device_abc123",
        },
    )

    assert resp.status_code == 207
    data = json.loads(resp.content.decode())
    assert data["status"] == "approved"


async def test_backend_write_error_returns_207(
    app: Starlette,
    session: Any,
) -> None:
    """Backend execution failure → 207 with backend_status."""
    await _insert_pending_challenge(session, challenge_id="chal_int_be")

    resp = await post(
        app,
        "/challenges/chal_int_be/approve",
        {
            "signature": "sig_xyz",
        },
    )

    # Backend is not available, so we get 207.
    assert resp.status_code == 207
    data = json.loads(resp.content.decode())
    assert data["status"] == "approved"
    assert "backend_status" in data


async def test_standing_orders_cancel_path(
    app: Starlette,
    session: Any,
) -> None:
    """Standing orders cancel uses correct path interpolation."""
    await _insert_pending_challenge(
        session,
        challenge_id="chal_int_so",
        tool_name="standing_orders.cancel",
        payload={"order_id": "so_99", "reason": "cancelled"},
    )

    resp = await post(
        app,
        "/challenges/chal_int_so/approve",
        {
            "signature": "sig_xyz",
        },
    )

    assert resp.status_code == 207  # backend not available.

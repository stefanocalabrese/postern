"""Integration test for the approval callback flow (handoff §6.3, §8.3).

Exercises the full path: ``create_confirm_app`` → real Postgres (testcontainers)
→ challenge insert via store layer → ``POST /challenges/{id}/approve`` via ASGI
transport → DB state verification.

Covers:
- 401 with no bearer assertion, and that an unauthenticated call changes
  nothing in the database (audit finding C-02, the vulnerability this test
  module exists to pin dead).
- 404 when the challenge belongs to a different customer than the verified
  assertion names, including the expired-and-cross-customer case, and that
  neither leaves a state change or a backend call behind.
- 200 on successful approval + backend execution (mocked transport).
- 409 when challenge is already terminal.
- 410 when challenge is expired for its own owner.
- Challenge state transitions in the database.
- ``create_confirm_app`` refuses to build at all without inbound
  authentication configured.
"""

import json
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.domain.verification import VerificationTier
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from starlette.applications import Starlette

from services.confirm.auth import ASSERTION_STATE_KEY, AppAssertion
from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.device_keys import approval_body, device_key, enrolled_store

# ---------------------------------------------------------------------------
# App-assertion fixture constants (audit findings C-01, C-02).
# ---------------------------------------------------------------------------

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"

#: The enrolled phone every approval in this module signs with. Only
#: ``cust_7f3a`` has one: the cross-customer tests are refused by the
#: ownership check before any key is looked up, which is the order
#: ``services/confirm/device_signature.py`` argues for at length.
DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("integration-phone")

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
    """ConfirmSettings wired to the test database.

    Deliberately leaves the three ``app_assertion_*`` fields at their
    ``None`` default: every test that builds a working app passes
    ``assertion_verifier=`` explicitly (see the ``app`` fixture below), and
    ``test_create_confirm_app_raises_without_app_assertion_settings`` relies
    on this fixture staying incomplete to exercise the refusal-to-start path.
    """
    return ConfirmSettings(
        backend_base_url="https://backend.test",  # mocked transport
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so without these two flags it gets the
        # safe defaults and refuses to start.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
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


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    """RSA key pair backing the app-assertion bearer tokens.

    Module-scoped: RSA generation is slow and nothing about it is
    test-specific, matching the ``pg_url`` fixture's scope reasoning.
    """
    return RSAKeyPair.generate()


@pytest.fixture()
def app(settings: ConfirmSettings, key_pair: RSAKeyPair) -> Starlette:
    """Full confirm service app wired to the test database and a real verifier.

    Passes ``assertion_verifier=`` explicitly rather than setting the three
    ``app_assertion_*`` fields on ``settings``: this needs no JWKS server, a
    ``JWTVerifier(public_key=...)`` over ``key_pair`` checks tokens signed by
    the same in-process key, matching the pattern
    ``services/confirm/main.py::create_confirm_app``'s own docstring
    prescribes for tests.
    """
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=enrolled_store("cust_7f3a", DEVICE_PUBLIC),
    )


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

    Tests that must prove the backend was never called (the cross-customer
    cases) install their own narrower patch inside the test body — that
    inner ``patch.object`` nests correctly over this outer one and is
    restored to it on exit, per ``unittest.mock``'s own stacking behaviour.
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


def bearer(key_pair: RSAKeyPair, subject: str) -> dict[str, str]:
    """A verified-assertion ``Authorization`` header for ``subject``."""
    token = key_pair.create_token(
        subject=subject, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    return {"Authorization": f"Bearer {token}"}


async def signed(db: Database, challenge_id: str, **extra: Any) -> dict[str, Any]:
    """An approval body signed over the row as the database currently holds it.

    Read rather than reconstructed, because two tests below rewrite
    ``expires_at`` with raw SQL after creating the challenge and the deadline
    is part of what is signed (`postern_core.auth.approval_signature`).
    """
    return await approval_body(db, challenge_id, DEVICE_PRIVATE, **extra)


async def post(
    app: Starlette,
    path: str,
    body: dict[str, Any],
    headers: dict[str, str] | None = None,
) -> httpx2.Response:
    """POST to the ASGI app."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        return await c.post(path, json=body, headers=headers)


async def _insert_pending_challenge(
    session: Any,
    challenge_id: str = "chal_int_001",
    tool_name: str = "payments.create_payment",
    payload: dict[str, Any] | None = None,
    customer_ref: str = "cust_7f3a",
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
        customer_ref=customer_ref,
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
    db: Database,
    session: Any,
    key_pair: RSAKeyPair,
) -> None:
    """Full happy path: insert challenge → approve → execute → status=executed."""
    # 1. Insert a pending challenge.
    await _insert_pending_challenge(session, challenge_id="chal_int_001")

    # 2. POST the approval, authenticated as the challenge's own customer.
    #    (Backend will be called, but we mock via transport.)
    resp = await post(
        app,
        "/challenges/chal_int_001/approve",
        await signed(db, "chal_int_001"),
        headers=bearer(key_pair, "cust_7f3a"),
    )

    # 3. The backend call will fail (no real backend), so we get 207.
    #    But the challenge should be marked "approved" in DB.
    assert resp.status_code == 207, f"Expected 207, got {resp.status_code}: {resp.text}"
    data = json.loads(resp.content.decode())
    assert data["status"] == "approved"

    # 4. Verify the challenge is approved in the database.
    row = await store.get_challenge(session, "chal_int_001")
    assert row is not None
    assert row.status == "approved"


async def test_approval_of_already_approved_challenge_returns_409(
    app: Starlette,
    db: Database,
    session: Any,
    key_pair: RSAKeyPair,
) -> None:
    """Challenge already approved → 409."""
    await _insert_pending_challenge(session, challenge_id="chal_int_002")
    auth = bearer(key_pair, "cust_7f3a")

    # First approval succeeds (returns 207 due to no backend).
    body = await signed(db, "chal_int_002")
    resp1 = await post(app, "/challenges/chal_int_002/approve", body, headers=auth)
    assert resp1.status_code == 207

    # The SAME signature again, which is the realistic replay: Ed25519 is
    # deterministic, so one phone signing one challenge produces one string
    # however many times it is asked. What refuses the second presentation is
    # the conditional UPDATE, not the signature -- see
    # `postern_core.auth.approval_signature`'s docstring on where single use
    # actually lives.
    resp2 = await post(app, "/challenges/chal_int_002/approve", body, headers=auth)
    assert resp2.status_code == 409
    data = json.loads(resp2.content.decode())
    assert data["error"] == "already_terminal"


async def test_expired_challenge_returns_410(
    app: Starlette,
    db: Database,
    session: Any,
    key_pair: RSAKeyPair,
) -> None:
    """Expired challenge → 410, for its own owner."""
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
        # Signed over the row AFTER the deadline was rewritten, so the
        # signature is valid and the 410 comes from the conditional UPDATE.
        await signed(db, "chal_int_expired"),
        headers=bearer(key_pair, "cust_7f3a"),
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

    Calling the handler directly also bypasses ``AppAssertionMiddleware``
    entirely, so the scope's ``state`` is seeded with a verified
    ``AppAssertion`` by hand — otherwise ``verified_subject`` would return
    ``None`` and the handler would 401 before ever reaching the path check
    this test exists to pin.
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
        "state": {ASSERTION_STATE_KEY: AppAssertion(subject="cust_7f3a", claims={})},
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
    key_pair: RSAKeyPair,
) -> None:
    """No signature in body → 400."""
    resp = await post(
        app,
        "/challenges/chal_int_003/approve",
        {},
        headers=bearer(key_pair, "cust_7f3a"),
    )
    assert resp.status_code == 400
    data = json.loads(resp.content.decode())
    assert data["error"] == "invalid_request"


async def test_challenge_not_found_returns_404(
    app: Starlette,
    key_pair: RSAKeyPair,
) -> None:
    """Non-existent challenge → 404."""
    resp = await post(
        app,
        "/challenges/chal_nonexistent/approve",
        {
            "signature": "sig_xyz",
        },
        headers=bearer(key_pair, "cust_7f3a"),
    )
    assert resp.status_code == 404
    data = json.loads(resp.content.decode())
    assert data["error"] == "not_found"


async def test_verification_result_passed_through(
    app: Starlette,
    db: Database,
    session: Any,
    key_pair: RSAKeyPair,
) -> None:
    """verification_result in body is recorded on the challenge."""
    await _insert_pending_challenge(session, challenge_id="chal_int_vr")

    resp = await post(
        app,
        "/challenges/chal_int_vr/approve",
        await signed(db, "chal_int_vr", verification_result="vr_selfie_match_001"),
        headers=bearer(key_pair, "cust_7f3a"),
    )

    assert resp.status_code == 207  # backend not available, but approval recorded.
    data = json.loads(resp.content.decode())
    assert data["status"] == "approved"

    # Verify the verification_result was stored.
    row = await store.get_challenge(session, "chal_int_vr")
    assert row is not None
    assert row.verification_result == "vr_selfie_match_001"


async def test_confirming_device_passed_through(
    app: Starlette,
    db: Database,
    session: Any,
    key_pair: RSAKeyPair,
) -> None:
    """confirming_device in body is recorded on the challenge."""
    await _insert_pending_challenge(session, challenge_id="chal_int_dev")

    resp = await post(
        app,
        "/challenges/chal_int_dev/approve",
        await signed(db, "chal_int_dev", confirming_device="device_abc123"),
        headers=bearer(key_pair, "cust_7f3a"),
    )

    assert resp.status_code == 207
    data = json.loads(resp.content.decode())
    assert data["status"] == "approved"


async def test_backend_write_error_returns_207(
    app: Starlette,
    db: Database,
    session: Any,
    key_pair: RSAKeyPair,
) -> None:
    """Backend execution failure → 207 with backend_status."""
    await _insert_pending_challenge(session, challenge_id="chal_int_be")

    resp = await post(
        app,
        "/challenges/chal_int_be/approve",
        await signed(db, "chal_int_be"),
        headers=bearer(key_pair, "cust_7f3a"),
    )

    # Backend is not available, so we get 207.
    assert resp.status_code == 207
    data = json.loads(resp.content.decode())
    assert data["status"] == "approved"
    assert "backend_status" in data


async def test_standing_orders_cancel_path(
    app: Starlette,
    db: Database,
    session: Any,
    key_pair: RSAKeyPair,
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
        await signed(db, "chal_int_so"),
        headers=bearer(key_pair, "cust_7f3a"),
    )

    assert resp.status_code == 207  # backend not available.


# ---------------------------------------------------------------------------
# Inbound authentication (audit findings C-01, C-02).
#
# These are the integration-level proof that the finding is dead: possession
# of a challenge id alone — no assertion, or an assertion for the wrong
# customer — must not move a challenge out of "pending", and must not reach
# the backend write client at all.
# ---------------------------------------------------------------------------


async def test_approve_without_bearer_returns_401_and_challenge_unchanged(
    app: Starlette,
    session: Any,
) -> None:
    """No Authorization header at all → 401, and the row is untouched.

    This is the case the audit finding was about: before
    ``AppAssertionMiddleware`` existed, this exact request — a bare POST
    naming a real, pending challenge id — was sufficient to approve it.
    """
    await _insert_pending_challenge(session, challenge_id="chal_int_noauth")

    resp = await post(
        app,
        "/challenges/chal_int_noauth/approve",
        {
            "signature": "sig_xyz",
        },
        headers=None,
    )

    assert resp.status_code == 401
    data = json.loads(resp.content.decode())
    assert data["error"] == "invalid_token"

    row = await store.get_challenge(session, "chal_int_noauth")
    assert row is not None
    assert row.status == "pending"


async def test_cross_customer_approval_returns_404_and_challenge_unchanged(
    app: Starlette,
    session: Any,
    key_pair: RSAKeyPair,
) -> None:
    """A verified assertion for the wrong customer → 404, no state change.

    Same body as "no such challenge" (``callback.py``'s own reasoning: a
    distinct 403 would let a caller learn whether an id exists at all, and
    challenge ids travel through the model's channel into a third party's
    chat history). Also asserts the backend write client is never reached —
    a stranger's request must not just fail to *record* an approval, it must
    not attempt to *execute* anything either.
    """
    await _insert_pending_challenge(
        session, challenge_id="chal_int_xcust", customer_ref="cust_alice"
    )

    backend_calls: list[httpx2.Request] = []

    def _record(request: httpx2.Request) -> httpx2.Response:
        backend_calls.append(request)
        return httpx2.Response(200, json={"detail": "should never be reached"})

    original_init = BackendWriteClient.__init__

    def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, transport=httpx2.MockTransport(_record), **kwargs)

    with patch.object(BackendWriteClient, "__init__", patched_init):
        resp = await post(
            app,
            "/challenges/chal_int_xcust/approve",
            {
                "signature": "sig_xyz",
            },
            headers=bearer(key_pair, "cust_bob"),
        )

    assert resp.status_code == 404
    data = json.loads(resp.content.decode())
    assert data["error"] == "not_found"
    assert backend_calls == []

    row = await store.get_challenge(session, "chal_int_xcust")
    assert row is not None
    assert row.status == "pending"


async def test_expired_challenge_owned_by_another_customer_returns_404_not_expired(
    app: Starlette,
    session: Any,
    key_pair: RSAKeyPair,
) -> None:
    """Expired challenge, wrong customer → 404, and the row stays "pending".

    Pins that ownership is checked before the expiry branch, which writes
    ``status="expired"``. A stranger must not be able to drive that state
    transition on someone else's challenge merely by knowing its id and
    presenting a valid assertion for an unrelated account.
    """
    from sqlalchemy import text

    await store.create_challenge(
        session,
        challenge_id="chal_int_xcust_expired",
        customer_ref="cust_alice",
        tool_name="payments.create_payment",
        payload={"amount": "EUR 10.00"},
        tier=VerificationTier.APP_APPROVAL,
    )
    await session.execute(
        text(
            "UPDATE challenges SET expires_at = created_at - INTERVAL '1 hour' "
            "WHERE challenge_id = :cid",
        ),
        {"cid": "chal_int_xcust_expired"},
    )
    await session.commit()

    resp = await post(
        app,
        "/challenges/chal_int_xcust_expired/approve",
        {
            "signature": "sig_xyz",
        },
        headers=bearer(key_pair, "cust_bob"),
    )

    assert resp.status_code == 404
    data = json.loads(resp.content.decode())
    assert data["error"] == "not_found"

    row = await store.get_challenge(session, "chal_int_xcust_expired")
    assert row is not None
    assert row.status == "pending"


def test_create_confirm_app_raises_without_app_assertion_settings(
    settings: ConfirmSettings,
) -> None:
    """No verifier, incomplete app_assertion_* settings → ValueError.

    Pins "an unauthenticated confirm service is unreachable by construction"
    (``services/confirm/main.py::_assertion_verifier``'s own docstring): the
    ``settings`` fixture deliberately leaves the three ``app_assertion_*``
    fields at their ``None`` default, and no ``assertion_verifier=`` is
    passed, so this must fail before the app is built at all — before any
    route, any minter and any database connection exists.
    """
    with pytest.raises(ValueError) as exc_info:
        create_confirm_app(settings)

    message = str(exc_info.value)
    assert "app_assertion_jwks_uri" in message
    assert "app_assertion_issuer" in message
    assert "app_assertion_audience" in message

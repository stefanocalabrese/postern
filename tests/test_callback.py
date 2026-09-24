"""Approval callback handler tests (handoff §6.3, §8.3).

Tests ``services.confirm.callback.approve_challenge`` by calling it directly
with a mock ``starlette.requests.Request``, avoiding ASGI transport and real
DB connections.

Covers:
- 401 when no verified app assertion is in scope (audit finding C-02): the
  handler's own fail-closed backstop for the case where a caller reaches it
  without ``AppAssertionMiddleware`` having run first — which is exactly how
  this file invokes the handler.
- 404 when a challenge belongs to a different customer than the verified
  assertion, byte-identical to the "no such challenge" body (no ownership
  oracle for ids that leak into the model's channel), including the ordering
  guarantee that ownership is checked before the expiry branch that writes.
- 400 when challenge_id is missing from path / signature from body, and 403
  when a signature is present and does not verify against an enrolled device
  key — with no state transition attempted, so a caller who cannot sign
  cannot burn somebody's challenge.
- 404 when challenge not found in DB.
- 409 when challenge is already terminal (approved/executed/declined/expired).
- 410 when challenge is expired (marks it as expired in DB via update_challenge_status).
- 200 on successful approval + backend execution.
- 207 on successful approval + backend execution failure (BackendWriteError).
- The ``signature`` field is verified against an enrolled Ed25519 device key
  over the STORED row, and the value that reaches ``update_challenge_status``
  is the one that verified.
- Verification result and confirming device passthrough.
- JWT injection, PAN scrubbing, standing-orders path interpolation.
- BackendWriteClient always closed (success and error paths).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from unittest.mock import AsyncMock, MagicMock, patch

import httpx2
import pytest
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.revocation import InMemoryRevocationStore
from postern_core.domain.verification import VerificationTier
from postern_core.store.models import ChallengeRecord
from starlette.requests import Request

from services.confirm.auth import ASSERTION_STATE_KEY, AppAssertion
from services.confirm.callback import approve_challenge
from services.confirm.execute import BackendWriteClient
from services.confirm.settings import ConfirmSettings
from tests.fixtures.device_keys import device_key, enrolled_store, sign_row

#: The one enrolled phone this module signs with. `_make_state` enrols its
#: public half for whichever customer the challenge record names, so a test
#: that hands in a record gets a store that can verify an approval for it, and
#: `_make_request(record=...)` produces the signature that phone would send.
DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("callback-phone")


class _Patcher(Protocol):
    """Minimal patch protocol — unittest.mock._patch satisfies this."""

    def start(self) -> Any: ...
    def stop(self) -> None: ...


def _resp_body(resp: Any) -> bytes:
    """Safely extract body as bytes from a response object."""
    body = resp.body
    if isinstance(body, memoryview):
        return bytes(body)
    assert isinstance(body, bytes)
    return body


@contextmanager
def _applied(patches: list[_Patcher]) -> Iterator[None]:
    """Start every patch, guaranteeing ``stop()`` even when the body raises.

    The previous shape in this file started every patch, ran the test body,
    then stopped every patch, with none of it inside a ``try``/``finally``.
    A single failing assertion mid-body skipped every ``stop()`` call and
    left that patch active for the rest of the pytest session, corrupting
    whichever test ran next. This wraps the same start-in-order,
    stop-in-reverse-order shape in a ``finally`` so a raised assertion or
    exception still unwinds every patch before propagating.
    """
    started: list[_Patcher] = []
    try:
        for p in patches:
            p.start()
            started.append(p)
        yield
    finally:
        for p in reversed(started):
            p.stop()


# ---------------------------------------------------------------------------
# Helpers — build a mock Request for approve_challenge.
# ---------------------------------------------------------------------------


def _make_request(
    challenge_id: str = "chal_abc123",
    body: dict[str, Any] | None = None,
    subject: str | None = "cust_7f3a",
    record: ChallengeRecord | None = None,
) -> Request:
    """Build a Starlette ``Request`` with mock scope and receive.

    ``subject`` seeds ``scope["state"][ASSERTION_STATE_KEY]`` with a verified
    ``AppAssertion``, which is what ``AppAssertionMiddleware`` would already
    have done before the handler ran in the assembled app. Pass ``subject=None``
    to build a request as if no middleware ever verified anything, which is
    what every call site in this file did before the write-path
    authentication fix (audit finding C-02) — the handler's own 401 backstop
    is what must fire then.

    Defaults to ``"cust_7f3a"``, the default ``customer_ref`` in
    ``_pending_record``, so call sites that are not testing identity keep
    exercising a caller who owns the challenge, same as before this
    parameter existed.
    """
    if body is None:
        # `record` is the stored row this approval is for. Given one, the
        # default body carries the signature the enrolled phone would produce
        # over it -- which is what every test that means to get PAST the
        # signature check needs. Without one the placeholder stays, and those
        # are exactly the tests refused before the check runs (no assertion,
        # not the owner, no such challenge, no signature at all).
        body = {"signature": sign_row(DEVICE_PRIVATE, record)} if record else {"signature": "sig"}
    raw_body = json.dumps(body).encode()

    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": f"/challenges/{challenge_id}/approve",
        "raw_path": f"/challenges/{challenge_id}/approve".encode(),
        "headers": [],
    }

    if subject is not None:
        scope["state"] = {ASSERTION_STATE_KEY: AppAssertion(subject=subject, claims={})}

    # path_params comes from the routing layer.
    if challenge_id:
        scope["path_params"] = {"challenge_id": challenge_id}

    async def receive() -> dict[str, Any]:
        return {
            "type": "http.request",
            "body": raw_body,
            "more_body": False,
        }

    req = Request(scope)
    req._receive = receive
    return req


# ---------------------------------------------------------------------------
# Mock app.state factory.
# ---------------------------------------------------------------------------


def _make_state(
    challenge_record: ChallengeRecord | None = None,
    update_status_calls: list[dict[str, Any]] | None = None,
    backend_response: httpx2.Response | None = None,
) -> tuple[MagicMock, list[_Patcher]]:
    """Build a mock ``app.state`` and return (state, patches).

    Patches are applied at the module where ``approve_challenge`` imports
    from: ``services.confirm.callback``.
    """

    if update_status_calls is None:
        update_status_calls = []

    # --- get_challenge ---
    async def mock_get_challenge(*args: Any, **kwargs: Any) -> ChallengeRecord | None:
        return challenge_record

    # --- update_challenge_status ---
    #
    # Models the real conditional transition (audit finding C-03), not a
    # rubber stamp: it honours `expected_status` and `expiry` against the
    # record, returns None when either refuses, and mutates the record when
    # both hold. A mock that returned the record unconditionally would let
    # `approve_challenge` pass this file's 409 and 410 cases while failing
    # them against Postgres, which is the whole thing those cases exist to
    # catch.
    async def mock_update_status(
        *args: Any,
        status: str = "",
        expected_status: str = "",
        expiry: str = "ignore",
        confirming_device: str | None = None,
        verification_result: str | None = None,
        signature: str = "",
    ) -> ChallengeRecord | None:
        update_status_calls.append(
            {
                "status": status,
                "expected_status": expected_status,
                "expiry": expiry,
                "confirming_device": confirming_device,
                "verification_result": verification_result,
                "signature": signature,
            }
        )
        if challenge_record is None or challenge_record.status != expected_status:
            return None
        past_deadline = datetime.now(UTC) >= challenge_record.expires_at
        if expiry == "unexpired" and past_deadline:
            return None
        if expiry == "expired" and not past_deadline:
            return None

        challenge_record.status = status
        if confirming_device is not None:
            challenge_record.confirming_device = confirming_device
        if verification_result is not None:
            challenge_record.verification_result = verification_result
        if signature:
            challenge_record.signature = signature
        return challenge_record

    # --- Stub minter ---
    class _StubMinter:
        def mint(
            self, *, subject_value: str, audience: str, scope: str, challenge_id: str = ""
        ) -> str:
            return f"stub.write.{subject_value}.{audience}"

    # --- BackendWriteClient transport patch (optional) ---
    patches: list[_Patcher] = []

    if backend_response is not None:

        def _backend_transport(req: httpx2.Request) -> httpx2.Response:
            return backend_response

        original_init = BackendWriteClient.__init__

        def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
            original_init(
                self,
                *args,
                transport=httpx2.MockTransport(_backend_transport),
                **kwargs,
            )

        patches.append(patch.object(BackendWriteClient, "__init__", patched_init))

    # --- DB sessionmaker (handler reads app.state.postern_database.sessionmaker) ---
    # The handler does: async with db.sessionmaker() as session:
    # So sessionmaker must be a callable that returns an async context manager.

    _session_mock = MagicMock()
    # session.commit() is awaited by the handler.
    _session_mock.commit = AsyncMock()

    class _SessionMaker:
        async def __aenter__(self) -> MagicMock:
            return _session_mock

        async def __aexit__(self, *args: Any) -> None:
            pass

    db_mock = MagicMock()
    db_mock.sessionmaker = _SessionMaker

    state = MagicMock()
    state.postern_database = db_mock
    state.write_minter = _StubMinter()
    state.settings = ConfirmSettings.for_testing()
    # ZT-7. An EMPTY store, not a mock: `_approve`'s first statement asks it
    # whether this customer is revoked, and the bare `MagicMock` attribute
    # this line replaces returned a `MagicMock` from `is_customer_revoked`,
    # which is not awaitable. Every test below therefore exercises the real
    # check answering "not revoked" rather than skipping it.
    #
    # NOT a permissive stub either. Leaving the attribute off entirely also
    # fails closed -- Starlette's `State` raises `AttributeError` for a name
    # nothing set, and the handler turns that into a 500 with an audit row --
    # which is why `services/confirm/revocation.py` needs no absent-store
    # branch of its own. `tests/test_zt7_confirm_revocation.py` is where the
    # refusing side of this check is measured.
    state.postern_revocation_store = InMemoryRevocationStore()
    # The device signature check (2026-09-24), wired the same way and for the
    # same reason: a bare `MagicMock` attribute returns a `MagicMock` from
    # `keys_for`, which is not awaitable, so every test below exercises the
    # real check rather than skipping it. The record's own customer is what is
    # enrolled -- a cross-customer test therefore reaches a store that holds a
    # key for the OWNER and never for the caller, which is the shape
    # production has.
    state.postern_device_key_store = (
        enrolled_store(challenge_record.customer_ref, DEVICE_PUBLIC)
        if challenge_record is not None
        else no_enrolled_devices()
    )

    import services.confirm.callback as cb

    patches.append(patch.object(cb, "get_challenge", mock_get_challenge))
    patches.append(patch.object(cb, "update_challenge_status", mock_update_status))

    return state, patches


# ---------------------------------------------------------------------------
# Record helpers.
# ---------------------------------------------------------------------------


def _pending_record(
    challenge_id: str = "chal_abc123",
    customer_ref: str = "cust_7f3a",
    tool_name: str = "payments.create_payment",
    payload: dict[str, Any] | None = None,
) -> ChallengeRecord:
    return ChallengeRecord(
        challenge_id=challenge_id,
        customer_ref=customer_ref,
        tool_name=tool_name,
        payload=payload or {},
        tier=VerificationTier.APP_APPROVAL.value,
        status="pending",
        created_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(seconds=180),
    )


# ---------------------------------------------------------------------------
# 401 — no verified app assertion (audit finding C-02).
# ---------------------------------------------------------------------------


async def test_no_app_assertion_returns_401() -> None:
    """No verified app assertion in scope → the handler's own fail-closed
    backstop fires: 401, the uniform body shared with ``AppAssertionMiddleware``.

    In the assembled app, ``AppAssertionMiddleware`` would already have
    refused the request before routing. This file calls the handler
    directly, which is exactly the invocation shape that bypasses the
    middleware — precisely why this branch exists and must be covered.
    """
    req = _make_request(subject=None)
    resp = await approve_challenge(req)

    assert resp.status_code == 401
    data = json.loads(_resp_body(resp).decode())
    assert data == {
        "error": "invalid_token",
        "error_description": "a verified app assertion is required",
    }


# ---------------------------------------------------------------------------
# 404 — cross-customer challenge access (no ownership oracle).
# ---------------------------------------------------------------------------


async def test_cross_customer_approval_returns_404_matching_not_found_body() -> None:
    """cust_bob approving cust_alice's challenge gets the byte-identical 404
    body as a nonexistent challenge id.

    A distinct 403 would be an existence oracle: challenge ids travel back
    through the model's channel into a third-party vendor's chat history, so
    anyone who got hold of one could otherwise learn whether it is real.
    """
    challenge_id = "chal_owned_by_alice"
    owned_rec = _pending_record(challenge_id=challenge_id, customer_ref="cust_alice")

    state_owned, patches_owned = _make_state(challenge_record=owned_rec)
    with _applied(patches_owned):
        req = _make_request(challenge_id=challenge_id, subject="cust_bob")
        req.scope["app"] = type("FakeApp", (), {"state": state_owned})()
        cross_customer_resp = await approve_challenge(req)

    state_missing, patches_missing = _make_state(challenge_record=None)
    with _applied(patches_missing):
        req2 = _make_request(challenge_id=challenge_id, subject="cust_bob")
        req2.scope["app"] = type("FakeApp", (), {"state": state_missing})()
        not_found_resp = await approve_challenge(req2)

    assert cross_customer_resp.status_code == 404
    assert not_found_resp.status_code == 404
    assert _resp_body(cross_customer_resp) == _resp_body(not_found_resp)
    data = json.loads(_resp_body(cross_customer_resp).decode())
    assert data == {
        "error": "not_found",
        "error_description": f"challenge {challenge_id} not found",
    }


async def test_cross_customer_approval_does_not_mutate_challenge_state() -> None:
    """A stranger's approval attempt must not drive any state transition."""
    rec = _pending_record(customer_ref="cust_alice")
    update_status_calls: list[dict[str, Any]] = []

    state, patches = _make_state(challenge_record=rec, update_status_calls=update_status_calls)
    with _applied(patches):
        req = _make_request(subject="cust_bob")
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 404
    assert update_status_calls == []


async def test_cross_customer_approval_on_expired_challenge_returns_404_not_mutating() -> None:
    """Ownership is checked before expiry: a stranger gets 404, not the 410
    that would write an "expired" status transition on someone else's
    challenge.
    """
    rec = _pending_record(customer_ref="cust_alice")
    rec.expires_at = datetime.now(UTC) - timedelta(minutes=5)
    update_status_calls: list[dict[str, Any]] = []

    state, patches = _make_state(challenge_record=rec, update_status_calls=update_status_calls)
    with _applied(patches):
        req = _make_request(subject="cust_bob")
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 404
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "not_found"
    assert update_status_calls == []


# ---------------------------------------------------------------------------
# 400 — invalid_request.
# ---------------------------------------------------------------------------


async def test_missing_challenge_id_returns_400() -> None:
    """No challenge_id in path → 400."""
    state, patches = _make_state()

    req = _make_request(challenge_id="")  # empty → no path_params in scope
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 400
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "invalid_request"


async def test_missing_signature_returns_400() -> None:
    """No signature in body → 400."""
    rec = _pending_record()
    state, patches = _make_state(challenge_record=rec)

    req = _make_request(challenge_id="chal_abc", body={})
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 400
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# 404 — not_found.
# ---------------------------------------------------------------------------


async def test_challenge_not_found_returns_404() -> None:
    """get_challenge returns None → 404."""
    state, patches = _make_state(challenge_record=None)

    req = _make_request()
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 404
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "not_found"


# ---------------------------------------------------------------------------
# 409 — already_terminal.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "status",
    ["approved", "executed", "declined", "expired"],
)
async def test_terminal_challenge_returns_409(status: str) -> None:
    """Challenge already in a terminal state → 409."""
    rec = _pending_record()
    rec.status = status

    state, patches = _make_state(challenge_record=rec)

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 409
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "already_terminal"


# ---------------------------------------------------------------------------
# 410 — expired.
# ---------------------------------------------------------------------------


async def test_expired_challenge_returns_410_and_marks_expired() -> None:
    """Challenge is pending but past expiry → 410, marks expired in DB."""
    rec = _pending_record()
    rec.status = "pending"
    rec.created_at = datetime.now(UTC) - timedelta(hours=1)
    rec.expires_at = datetime.now(UTC) - timedelta(minutes=5)

    state, patches = _make_state(challenge_record=rec)

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 410
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "expired"


# ---------------------------------------------------------------------------
# 200 — successful approval + backend execution.
# ---------------------------------------------------------------------------


async def test_successful_approval_and_execution() -> None:
    """Pending challenge → approved, backend returns 201 → executed."""
    rec = _pending_record()
    update_status_calls: list[dict[str, Any]] = []

    state, patches = _make_state(
        challenge_record=rec,
        update_status_calls=update_status_calls,
        backend_response=httpx2.Response(201, json={"id": "pay_99"}),
    )

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 200
    data = json.loads(_resp_body(resp).decode())
    assert data["status"] == "executed"
    # First call: approve, second call: execute.
    assert update_status_calls[0]["status"] == "approved"


# ---------------------------------------------------------------------------
# 207 — approved but backend execution failed.
# ---------------------------------------------------------------------------


async def test_approval_recorded_but_backend_execution_fails() -> None:
    """Pending challenge → approved, backend returns 500 → 207."""
    rec = _pending_record()
    update_status_calls: list[dict[str, Any]] = []

    state, patches = _make_state(
        challenge_record=rec,
        update_status_calls=update_status_calls,
        backend_response=httpx2.Response(500, json={"detail": "internal server error"}),
    )

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 207
    data = json.loads(_resp_body(resp).decode())
    assert data["status"] == "approved"  # approved but not executed.
    assert data["backend_status"] == 500


# ---------------------------------------------------------------------------
# 500 — internal error during approval update.
# ---------------------------------------------------------------------------


async def test_approval_update_failure_returns_500() -> None:
    """If update_challenge_status raises, return 500."""
    rec = _pending_record()

    async def mock_update_raises(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("db lock timeout")

    state, patches = _make_state(challenge_record=rec)
    import services.confirm.callback as cb

    patches.append(patch.object(cb, "update_challenge_status", mock_update_raises))

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 500
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "internal_error"


# ---------------------------------------------------------------------------
# 500 — update returns None (no row updated).
# ---------------------------------------------------------------------------


async def test_update_returns_none_returns_500() -> None:
    """A conditional transition that matches nothing on a live row → 500.

    What this pins changed with audit finding C-03. ``None`` from
    ``update_challenge_status`` no longer means "the row vanished"; it is the
    ordinary answer for losing the race or arriving after the deadline, and
    ``approve_challenge`` classifies it by reading the row once more. 500 is
    what is left when that read says the row is still ``pending`` and still
    inside its deadline — a statement whose only remaining predicate was the
    primary key matched nothing, which no state of the table produces. The
    patch below forces exactly that by refusing every transition, including
    the ``pending`` → ``expired`` one the 410 branch attempts.
    """
    rec = _pending_record()

    async def mock_update_none(*args: Any, **kwargs: Any) -> None:
        return None

    state, patches = _make_state(challenge_record=rec)
    import services.confirm.callback as cb

    patches.append(patch.object(cb, "update_challenge_status", mock_update_none))

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 500
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "internal_error"


# ---------------------------------------------------------------------------
# 500 — unknown tool in challenge.
# ---------------------------------------------------------------------------


async def test_unknown_tool_returns_500() -> None:
    """Challenge references an unknown tool → 500."""
    rec = _pending_record(tool_name="nonexistent.tool")

    state, patches = _make_state(challenge_record=rec)

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 500
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "internal_error"


# ---------------------------------------------------------------------------
# Verification result passthrough.
# ---------------------------------------------------------------------------


async def test_verification_result_passed_to_update() -> None:
    """verification_result in the request body is forwarded to update."""
    rec = _pending_record()
    update_status_calls: list[dict[str, Any]] = []

    state, patches = _make_state(
        challenge_record=rec,
        update_status_calls=update_status_calls,
        backend_response=httpx2.Response(200, json={}),
    )

    req = _make_request(
        body={"signature": sign_row(DEVICE_PRIVATE, rec), "verification_result": "vr_match_001"}
    )
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 200
    # The update call should include the verification_result.
    assert any(c.get("verification_result") == "vr_match_001" for c in update_status_calls)


# ---------------------------------------------------------------------------
# Confirming device passthrough.
# ---------------------------------------------------------------------------


async def test_confirming_device_passed_to_update() -> None:
    """confirming_device in the request body is forwarded to update."""
    rec = _pending_record()
    update_status_calls: list[dict[str, Any]] = []

    state, patches = _make_state(
        challenge_record=rec,
        update_status_calls=update_status_calls,
        backend_response=httpx2.Response(200, json={}),
    )

    req = _make_request(
        body={"signature": sign_row(DEVICE_PRIVATE, rec), "confirming_device": "dev_ios_abc"}
    )
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 200
    assert any(c.get("confirming_device") == "dev_ios_abc" for c in update_status_calls)


# ---------------------------------------------------------------------------
# JWT injection — verify the minter is called with correct parameters.
# ---------------------------------------------------------------------------


async def test_backend_write_receives_correct_jwt_claims() -> None:
    """The JWT carries the customer_ref as subject and correct audience."""
    rec = _pending_record(
        challenge_id="chal_abc123",
        customer_ref="cust_special",
        tool_name="cards.freeze_card",
        payload={"card_id": "card_xyz"},
    )

    seen_auth: list[str] = []

    def backend_handler(request: httpx2.Request) -> httpx2.Response:
        seen_auth.append(request.headers["authorization"])
        return httpx2.Response(200, json={"frozen": True})

    state, patches = _make_state(
        challenge_record=rec,
        backend_response=httpx2.Response(200, json={"frozen": True}),
    )

    # Override the transport to capture auth header.
    from services.confirm.execute import BackendWriteClient

    original_init = BackendWriteClient.__init__

    def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(
            self,
            *args,
            transport=httpx2.MockTransport(backend_handler),
            **kwargs,
        )

    patches.append(patch.object(BackendWriteClient, "__init__", patched_init))

    req = _make_request(subject="cust_special", record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 200
    # The stub minter produces "stub.write.{subject}.{audience}".
    assert seen_auth == ["Bearer stub.write.cust_special.cards.svc"]


# ---------------------------------------------------------------------------
# Challenge ID in execution message.
# ---------------------------------------------------------------------------


async def test_response_includes_challenge_id() -> None:
    """The 200 response includes the challenge_id."""
    rec = _pending_record(challenge_id="chal_unique_99")

    state, patches = _make_state(
        challenge_record=rec, backend_response=httpx2.Response(200, json={})
    )

    req = _make_request(challenge_id="chal_unique_99", record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 200
    data = json.loads(_resp_body(resp).decode())
    assert data["challenge_id"] == "chal_unique_99"


# ---------------------------------------------------------------------------
# 207 response includes backend_status.
# ---------------------------------------------------------------------------


async def test_207_response_includes_backend_status() -> None:
    """The 207 response includes the backend HTTP status code."""
    rec = _pending_record()

    state, patches = _make_state(
        challenge_record=rec,
        backend_response=httpx2.Response(502, json={"detail": "bad gateway"}),
    )

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 207
    data = json.loads(_resp_body(resp).decode())
    assert data["backend_status"] == 502


# ---------------------------------------------------------------------------
# PAN/IBAN scrubbing on backend error detail.
# ---------------------------------------------------------------------------


async def test_backend_error_detail_scrubs_pan() -> None:
    """PAN in backend error detail is scrubbed before reaching response."""
    rec = _pending_record()
    TEST_PAN = "4111111111111111"

    state, patches = _make_state(
        challenge_record=rec,
        backend_response=httpx2.Response(400, json={"detail": f"card {TEST_PAN} declined"}),
    )

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 207
    data = json.loads(_resp_body(resp).decode())
    assert TEST_PAN not in data["message"]


# ---------------------------------------------------------------------------
# Standing orders tool — path interpolation with order_id.
# ---------------------------------------------------------------------------


async def test_standing_orders_cancel_execution() -> None:
    """standing_orders.cancel resolves with order_id in path."""
    rec = _pending_record(
        tool_name="standing_orders.cancel",
        payload={"order_id": "so_99"},
    )

    seen_path: list[str] = []

    def backend_handler(request: httpx2.Request) -> httpx2.Response:
        seen_path.append(str(request.url.path))
        return httpx2.Response(200, json={"cancelled": True})

    state, patches = _make_state(
        challenge_record=rec,
        backend_response=httpx2.Response(200, json={"cancelled": True}),
    )

    from services.confirm.execute import BackendWriteClient

    original_init = BackendWriteClient.__init__

    def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(
            self,
            *args,
            transport=httpx2.MockTransport(backend_handler),
            **kwargs,
        )

    patches.append(patch.object(BackendWriteClient, "__init__", patched_init))

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 200
    assert seen_path == ["/standing-orders/so_99/cancel"]


# ---------------------------------------------------------------------------
# Missing path param in payload — ValueError from resolve_endpoint.
# ---------------------------------------------------------------------------


async def test_missing_path_param_returns_500() -> None:
    """Challenge payload missing card_id for cards.freeze_card → 500."""
    rec = _pending_record(
        tool_name="cards.freeze_card",
        payload={"reason": "lost"},  # missing card_id.
    )

    state, patches = _make_state(challenge_record=rec)

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 500
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "internal_error"


# ---------------------------------------------------------------------------
# BackendWriteClient always closed.
# ---------------------------------------------------------------------------


async def test_backend_write_client_closed_on_success() -> None:
    """BackendWriteClient.aclose is called on success."""
    rec = _pending_record()
    closed: list[bool] = []

    state, patches = _make_state(
        challenge_record=rec,
        backend_response=httpx2.Response(200, json={}),
    )

    from services.confirm.execute import BackendWriteClient

    original_aclose = BackendWriteClient.aclose

    async def patched_aclose(self: Any) -> None:
        closed.append(True)
        await original_aclose(self)

    patches.append(patch.object(BackendWriteClient, "aclose", patched_aclose))

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 200
    assert closed


async def test_backend_write_client_closed_on_error() -> None:
    """BackendWriteClient.aclose is called on BackendWriteError."""
    rec = _pending_record()
    closed: list[bool] = []

    state, patches = _make_state(
        challenge_record=rec,
        backend_response=httpx2.Response(503, json={"detail": "service unavailable"}),
    )

    from services.confirm.execute import BackendWriteClient

    original_aclose = BackendWriteClient.aclose

    async def patched_aclose(self: Any) -> None:
        closed.append(True)
        await original_aclose(self)

    patches.append(patch.object(BackendWriteClient, "aclose", patched_aclose))

    req = _make_request(record=rec)
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 207
    assert closed


# ---------------------------------------------------------------------------
# Signature passthrough to update.
# ---------------------------------------------------------------------------


async def test_the_verified_signature_is_what_reaches_the_row() -> None:
    """The signature forwarded to ``update_challenge_status`` is the one that
    verified, so the value on the row is evidence rather than an echo."""
    rec = _pending_record()
    update_status_calls: list[dict[str, Any]] = []

    state, patches = _make_state(
        challenge_record=rec,
        update_status_calls=update_status_calls,
        backend_response=httpx2.Response(200, json={}),
    )

    signature = sign_row(DEVICE_PRIVATE, rec)
    req = _make_request(body={"signature": signature})
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 200
    assert update_status_calls[0]["signature"] == signature


async def test_a_junk_signature_is_refused_and_nothing_is_written() -> None:
    """What this file used to pin, inverted.

    Until 2026-09-24 the test here was
    ``test_unverified_signature_junk_value_is_accepted_and_stored``: a string
    with no relationship to any device key was accepted, stored verbatim, and
    a payment was executed behind it. Its own docstring said "when a real
    per-device signature check lands, this test must fail and force an update
    here, not silently keep passing". It landed, and this is that update.

    The three assertions are the whole of the control at this level: the
    caller is refused, NO transition is attempted -- so the challenge is not
    burned and the customer's real phone can still approve it -- and the
    refusal is a 403 naming the signature rather than the 404 that would tell
    a stranger whether the id exists.
    """
    rec = _pending_record()
    update_status_calls: list[dict[str, Any]] = []

    state, patches = _make_state(
        challenge_record=rec,
        update_status_calls=update_status_calls,
        backend_response=httpx2.Response(200, json={}),
    )

    req = _make_request(body={"signature": "not-a-real-signature"})
    with _applied(patches):
        req.scope["app"] = type("FakeApp", (), {"state": state})()
        resp = await approve_challenge(req)

    assert resp.status_code == 403
    assert update_status_calls == []
    assert json.loads(_resp_body(resp).decode())["error"] == "invalid_signature"

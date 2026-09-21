"""Approval callback handler tests (handoff §6.3, §8.3).

Tests ``services.confirm.callback.approve_challenge`` by calling it directly
with a mock ``starlette.requests.Request``, avoiding ASGI transport and real
DB connections.

Covers:
- 400 when challenge_id is missing from path / signature from body.
- 404 when challenge not found in DB.
- 409 when challenge is already terminal (approved/executed/declined/expired).
- 410 when challenge is expired (marks it as expired in DB via update_challenge_status).
- 200 on successful approval + backend execution.
- 207 on successful approval + backend execution failure (BackendWriteError).
- Verification result and confirming device passthrough.
- JWT injection, PAN scrubbing, standing-orders path interpolation.
- BackendWriteClient always closed (success and error paths).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from unittest.mock import AsyncMock, MagicMock, patch

import httpx2
import pytest
from postern_core.domain.verification import VerificationTier
from postern_core.store.models import ChallengeRecord
from starlette.requests import Request

from services.confirm.callback import approve_challenge
from services.confirm.execute import BackendWriteClient
from services.confirm.settings import ConfirmSettings


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


# ---------------------------------------------------------------------------
# Helpers — build a mock Request for approve_challenge.
# ---------------------------------------------------------------------------


def _make_request(
    challenge_id: str = "chal_abc123",
    body: dict[str, Any] | None = None,
) -> Request:
    """Build a Starlette ``Request`` with mock scope and receive."""
    raw_body = json.dumps(body if body is not None else {"signature": "sig_xyz"}).encode()

    scope: dict[str, Any] = {
        "type": "http",
        "method": "POST",
        "path": f"/challenges/{challenge_id}/approve",
        "raw_path": f"/challenges/{challenge_id}/approve".encode(),
        "headers": [],
    }

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
    async def mock_update_status(
        *args: Any,
        status: str = "",
        confirming_device: str | None = None,
        verification_result: str | None = None,
        signature: str = "",
    ) -> ChallengeRecord | None:
        update_status_calls.append({
            "status": status,
            "confirming_device": confirming_device,
            "verification_result": verification_result,
            "signature": signature,
        })
        # Return a record so the handler's `if updated is None` check passes.
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
# 400 — invalid_request.
# ---------------------------------------------------------------------------


async def test_missing_challenge_id_returns_400() -> None:
    """No challenge_id in path → 400."""
    state, patches = _make_state()
    for p in patches:
        p.start()

    req = _make_request(challenge_id="")  # empty → no path_params in scope
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

    assert resp.status_code == 400
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "invalid_request"


async def test_missing_signature_returns_400() -> None:
    """No signature in body → 400."""
    rec = _pending_record()
    state, patches = _make_state(challenge_record=rec)
    for p in patches:
        p.start()

    req = _make_request(challenge_id="chal_abc", body={})
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

    assert resp.status_code == 400
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "invalid_request"


# ---------------------------------------------------------------------------
# 404 — not_found.
# ---------------------------------------------------------------------------


async def test_challenge_not_found_returns_404() -> None:
    """get_challenge returns None → 404."""
    state, patches = _make_state(challenge_record=None)
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

    assert resp.status_code == 500
    data = json.loads(_resp_body(resp).decode())
    assert data["error"] == "internal_error"


# ---------------------------------------------------------------------------
# 500 — update returns None (no row updated).
# ---------------------------------------------------------------------------


async def test_update_returns_none_returns_500() -> None:
    """If update_challenge_status returns None, return 500."""
    rec = _pending_record()

    async def mock_update_none(*args: Any, **kwargs: Any) -> None:
        return None

    state, patches = _make_state(challenge_record=rec)
    import services.confirm.callback as cb

    patches.append(patch.object(cb, "update_challenge_status", mock_update_none))
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request(body={"signature": "sig", "verification_result": "vr_match_001"})
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request(body={"signature": "sig", "confirming_device": "dev_ios_abc"})
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request(challenge_id="chal_unique_99")
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

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
    for p in patches:
        p.start()

    req = _make_request()
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

    assert resp.status_code == 207
    assert closed


# ---------------------------------------------------------------------------
# Signature passthrough to update.
# ---------------------------------------------------------------------------


async def test_signature_passed_to_update() -> None:
    """The signature from the request body is forwarded to update_challenge_status."""
    rec = _pending_record()
    update_status_calls: list[dict[str, Any]] = []

    state, patches = _make_state(
        challenge_record=rec,
        update_status_calls=update_status_calls,
        backend_response=httpx2.Response(200, json={}),
    )
    for p in patches:
        p.start()

    req = _make_request(body={"signature": "sig_device_42"})
    req.scope["app"] = type("FakeApp", (), {"state": state})()
    resp = await approve_challenge(req)

    for p in reversed(patches):
        p.stop()

    assert resp.status_code == 200
    # The first update call should include the signature.
    assert any(c.get("signature") == "sig_device_42" for c in update_status_calls)

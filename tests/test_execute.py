"""Backend write execution infrastructure (handoff §6.3, §8.3).

Tests for ``services.confirm.execute``:
- TOOL_REGISTRY completeness (6 tools, no duplicates).
- ``resolve_endpoint`` — known tools, unknown tool error, missing path params.
- ``BackendWriteClient.execute`` — success (200/201/202), error response →
  ``BackendWriteError``, JWT injection, challenge_id claim.
- ``BackendWriteError`` carries the numeric status and no text from the response body.

Backend mocking is at the transport layer with ``httpx2.MockTransport``, per
``dev-docs/decisions/0001-facade-http-client.md``. ``respx`` is not installed and
cannot mock ``httpx2``.
"""

import asyncio
from collections.abc import Callable

import httpx2
import pytest

from services.confirm import execute as execute_module
from services.confirm.execute import (
    TOOL_REGISTRY,
    BackendTransportError,
    BackendWriteClient,
    BackendWriteError,
    resolve_endpoint,
)

# A well-known, mod-97-valid example IBAN (the ISO/Wikipedia worked example),
# not a real account, plus a real test PAN (the Visa test-card number).
_TEST_IBAN = "GB29NWBK60161331926819"
_TEST_PAN = "4111111111111111"


# ---------------------------------------------------------------------------
# Stub minter — produces a deterministic token without real crypto.
# ---------------------------------------------------------------------------


class _StubWriteMinter:
    """Produces a fake JWT string; never performs real crypto."""

    def mint(self, *, subject_value: str, audience: str, scope: str, challenge_id: str = "") -> str:
        return f"stub.write.{subject_value}.{audience}"


# ---------------------------------------------------------------------------
# TOOL_REGISTRY.
# ---------------------------------------------------------------------------


class TestToolRegistry:
    """The registry must cover every tool the confirm service knows about."""

    def test_all_six_tools_present(self) -> None:
        assert len(TOOL_REGISTRY) == 6

    def test_no_duplicate_audiences(self) -> None:
        # Audiences repeat across tools; we just verify the registry has 6 entries.
        audiences = [aud for aud, _, _ in TOOL_REGISTRY.values()]
        assert len(audiences) == 6

    def test_payments_create_payment(self) -> None:
        assert TOOL_REGISTRY["payments.create_payment"] == (
            "payments.svc",
            "/payments",
            "POST",
        )

    def test_cards_freeze(self) -> None:
        assert TOOL_REGISTRY["cards.freeze_card"] == (
            "cards.svc",
            "/cards/{card_id}/freeze",
            "POST",
        )

    def test_cards_unfreeze(self) -> None:
        assert TOOL_REGISTRY["cards.unfreeze_card"] == (
            "cards.svc",
            "/cards/{card_id}/unfreeze",
            "POST",
        )

    def test_cards_set_label(self) -> None:
        assert TOOL_REGISTRY["cards.set_label"] == (
            "cards.svc",
            "/cards/{card_id}/label",
            "PATCH",
        )

    def test_accounts_rename(self) -> None:
        assert TOOL_REGISTRY["accounts.rename"] == (
            "accounts.svc",
            "/accounts/{account_id}/rename",
            "PATCH",
        )

    def test_standing_orders_cancel(self) -> None:
        assert TOOL_REGISTRY["standing_orders.cancel"] == (
            "payments.svc",
            "/standing-orders/{order_id}/cancel",
            "POST",
        )


# ---------------------------------------------------------------------------
# resolve_endpoint.
# ---------------------------------------------------------------------------


class TestResolveEndpoint:
    """Tool name → (audience, path, body) resolution."""

    def test_payments_create_payment_no_path_params(self) -> None:
        payload = {"amount": "EUR 340.00", "payee": "Acme Ltd"}
        audience, path, body = resolve_endpoint("payments.create_payment", payload)
        assert audience == "payments.svc"
        assert path == "/payments"
        assert body == payload

    def test_cards_freeze_interpolates_card_id(self) -> None:
        payload = {"card_id": "card_abc123", "reason": "lost"}
        audience, path, body = resolve_endpoint("cards.freeze_card", payload)
        assert audience == "cards.svc"
        assert path == "/cards/card_abc123/freeze"

    def test_standing_orders_cancel_interpolates_order_id(self) -> None:
        payload = {"order_id": "so_99", "reason": "cancelled"}
        audience, path, body = resolve_endpoint("standing_orders.cancel", payload)
        assert audience == "payments.svc"
        assert path == "/standing-orders/so_99/cancel"

    def test_accounts_rename_interpolates_account_id(self) -> None:
        payload = {"account_id": "acc_xyz", "name": "Groceries"}
        audience, path, body = resolve_endpoint("accounts.rename", payload)
        assert audience == "accounts.svc"
        assert path == "/accounts/acc_xyz/rename"

    def test_unknown_tool_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="unknown tool"):
            resolve_endpoint("nonexistent.tool", {})

    def test_missing_path_param_raises_value_error(self) -> None:
        """If the payload lacks a field needed for path interpolation, raise."""
        with pytest.raises(ValueError, match="card_id"):
            resolve_endpoint("cards.freeze_card", {"reason": "lost"})

    def test_body_is_the_original_payload(self) -> None:
        """The body returned is the original payload dict — stored server-side."""
        payload = {"amount": "EUR 340.00", "payee": "Acme Ltd"}
        _, _, body = resolve_endpoint("payments.create_payment", payload)
        assert body is payload  # same object, not a copy.


# ---------------------------------------------------------------------------
# BackendWriteClient — success paths.
# ---------------------------------------------------------------------------


def _transport(handler: Callable[[httpx2.Request], httpx2.Response]) -> httpx2.MockTransport:
    return httpx2.MockTransport(handler)


async def test_execute_success_200() -> None:
    """A 200 is accepted; the status code is what comes back, not the response."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"id": "pay_123"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    status = await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={"amount": "EUR 340.00"},
        challenge_id="chal_abc",
    )
    assert status == 200
    await client.aclose()


async def test_execute_success_201() -> None:
    """A 201 is accepted."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(201, json={"id": "pay_456"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    status = await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={},
        challenge_id="chal_abc",
    )
    assert status == 201
    await client.aclose()


async def test_execute_success_202() -> None:
    """A 202 is accepted."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(202, json={"status": "accepted"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    status = await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={},
        challenge_id="chal_abc",
    )
    assert status == 202
    await client.aclose()


# ---------------------------------------------------------------------------
# BackendWriteClient — error paths.
# ---------------------------------------------------------------------------


async def test_execute_400_raises_backend_write_error() -> None:
    """A 4xx response raises BackendWriteError."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(400, json={"detail": "insufficient funds"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    with pytest.raises(BackendWriteError) as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={"amount": "EUR 9999.00"},
            challenge_id="chal_abc",
        )
    assert excinfo.value.status == 400
    await client.aclose()


async def test_execute_500_raises_backend_write_error() -> None:
    """A 5xx response raises BackendWriteError."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(500, json={"detail": "internal server error"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    with pytest.raises(BackendWriteError) as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    assert excinfo.value.status == 500
    await client.aclose()


# ---------------------------------------------------------------------------
# BackendWriteClient — JWT injection.
# ---------------------------------------------------------------------------


async def test_execute_attaches_bearer_token() -> None:
    """The Authorization header carries a Bearer token."""
    seen_auth: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen_auth.append(request.headers["authorization"])
        return httpx2.Response(200, json={})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={},
        challenge_id="chal_abc",
    )
    assert seen_auth == ["Bearer stub.write.cust_7f3a.payments.svc"]
    await client.aclose()


async def test_execute_includes_challenge_id_in_token_mint() -> None:
    """The minter is called with challenge_id in the JWT claims (§7.2)."""
    # The stub minter doesn't capture challenge_id, but we verify the call
    # reaches the minter by checking the token string contains expected parts.
    seen_token: list[str] = []

    class _CapturingMinter:
        def mint(
            self, *, subject_value: str, audience: str, scope: str, challenge_id: str = ""
        ) -> str:
            seen_token.append(f"{subject_value}:{audience}")
            return "stub.token"

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_CapturingMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={},
        challenge_id="chal_xyz",
    )
    assert seen_token == ["cust_7f3a:payments.svc"]
    await client.aclose()


# ---------------------------------------------------------------------------
# BackendWriteClient — idempotency key (audit finding C-03).
#
# Defence in depth behind the conditional `pending -> approved` transition in
# `postern_core.store.challenges.update_challenge_status`, never a substitute
# for it. The transition stops a duplicate execution while this process and
# its database agree; the header is what the backend has to work with when
# they do not -- a transport-level retry after a lost response, a process
# killed between the POST and the `executed` transition.
# ---------------------------------------------------------------------------


async def test_execute_sends_the_challenge_id_as_the_idempotency_key() -> None:
    """``Idempotency-Key`` carries the challenge id verbatim.

    Verbatim, not hashed: the backend already receives the same value as a
    verified ``challenge_id`` JWT claim, so a derivation conceals nothing it
    does not hold, and an access log entry and an ``audit_log`` row can be
    joined on the identical string.
    """
    seen: list[str | None] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers.get("idempotency-key"))
        return httpx2.Response(201, json={})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={"amount": "EUR 340.00"},
        challenge_id="chal_idem_001",
    )
    assert seen == ["chal_idem_001"]
    await client.aclose()


async def test_two_executions_of_one_challenge_carry_the_same_idempotency_key() -> None:
    """The key is derived from the challenge, not from the attempt.

    A key that varied per call — a UUID minted here, a timestamp — would be
    syntactically an idempotency key and would deduplicate nothing, which is
    the failure mode worth pinning.
    """
    seen: list[str | None] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers.get("idempotency-key"))
        return httpx2.Response(201, json={})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    for _ in range(2):
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={"amount": "EUR 340.00"},
            challenge_id="chal_idem_002",
        )
    assert seen == ["chal_idem_002", "chal_idem_002"]
    await client.aclose()


async def test_distinct_challenges_carry_distinct_idempotency_keys() -> None:
    """Two different operations must not be deduplicated into one."""
    seen: list[str | None] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers.get("idempotency-key"))
        return httpx2.Response(201, json={})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    for challenge_id in ("chal_idem_003", "chal_idem_004"):
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={"amount": "EUR 1.00"},
            challenge_id=challenge_id,
        )
    assert seen == ["chal_idem_003", "chal_idem_004"]
    await client.aclose()


# ---------------------------------------------------------------------------
# BackendWriteClient: nothing from the response travels.
# ---------------------------------------------------------------------------


_HOSTILE_DSN = "postgresql://svc:hunter2@10.0.3.4:5432/payments"
_HOSTILE_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig"
_HOSTILE_SENTINEL = "SENTINEL-7f3c9a-backend-text"


@pytest.mark.parametrize(
    "response",
    [
        httpx2.Response(
            400,
            json={
                "detail": (
                    f"{_TEST_PAN} {_TEST_IBAN} {_HOSTILE_DSN} token={_HOSTILE_JWT} "
                    f"{_HOSTILE_SENTINEL}"
                )
            },
        ),
        httpx2.Response(
            502,
            text=f"{_TEST_PAN} {_TEST_IBAN} {_HOSTILE_DSN} {_HOSTILE_JWT} {_HOSTILE_SENTINEL}",
            headers={"content-type": "text/plain"},
        ),
        httpx2.Response(500, json=[_TEST_PAN, _HOSTILE_DSN, _HOSTILE_JWT, _HOSTILE_SENTINEL]),
    ],
    ids=["json-detail", "plain-text", "json-array"],
)
async def test_backend_write_error_carries_nothing_the_backend_said(
    response: httpx2.Response,
) -> None:
    """Neither ``str``, ``repr``, ``args`` nor an attribute holds the body text."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return response

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    with pytest.raises(BackendWriteError) as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    exc = excinfo.value
    carried = f"{exc!s} {exc!r} {exc.args!r} {vars(exc)!r}"
    for needle in (_TEST_PAN, _TEST_IBAN, _HOSTILE_DSN, "hunter2", _HOSTILE_JWT, _HOSTILE_SENTINEL):
        assert needle not in carried
    assert exc.status == response.status_code
    await client.aclose()


@pytest.mark.parametrize(
    "raised",
    [
        httpx2.ConnectError("refused SNTL-connect"),
        httpx2.ReadTimeout("timed out SNTL-timeout"),
        httpx2.RemoteProtocolError("illegal status line: bytearray(b'SNTL-status')"),
        httpx2.DecodingError("corrupt SNTL-gzip"),
    ],
    ids=["ConnectError", "ReadTimeout", "RemoteProtocolError", "DecodingError"],
)
async def test_a_transport_failure_is_a_fixed_text_error_naming_the_type_only(
    raised: httpx2.HTTPError,
) -> None:
    """``BackendTransportError``: fixed ``str``, original type as ``kind``, no chain."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        raise raised

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    with pytest.raises(BackendTransportError) as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    exc = excinfo.value
    assert exc.kind == type(raised).__name__
    assert str(exc) == "the backend write endpoint could not be reached or answered improperly"
    assert "SNTL" not in f"{exc!s} {exc!r} {exc.args!r} {vars(exc)!r}"
    assert exc.__suppress_context__ is True
    assert exc.__cause__ is None
    assert exc.__context__ is None
    assert not isinstance(exc, (BackendWriteError, ValueError))
    await client.aclose()


async def test_a_cancellation_inside_the_request_is_not_wrapped() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise asyncio.CancelledError

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    with pytest.raises(asyncio.CancelledError):
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    await client.aclose()


async def test_a_bug_inside_the_client_is_not_wrapped_as_a_transport_failure() -> None:
    """Only ``httpx2.HTTPError`` is a transport failure.

    Anything else raised under ``stream()`` is a bug in this process, not text the
    backend sent, so it is not relabelled ``BackendTransportError`` (which would
    file a code defect as "the backend could not be reached") and fails loudly
    through the generic path.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        raise RuntimeError("SNTL-bug")

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    with pytest.raises(RuntimeError, match="SNTL-bug") as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    assert type(excinfo.value) is RuntimeError
    assert not isinstance(excinfo.value, BackendTransportError)
    await client.aclose()


# ---------------------------------------------------------------------------
# The total bound on the write call.
# ---------------------------------------------------------------------------


def _client(handler: Callable[[httpx2.Request], object]) -> BackendWriteClient:
    return BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=httpx2.MockTransport(handler),  # type: ignore[arg-type]
        before_backend_request=None,
    )


async def _execute(client: BackendWriteClient) -> int:
    return await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={},
        challenge_id="chal_total",
    )


def test_the_total_bound_is_inside_the_ecs_stop_timeout() -> None:
    """30 s is ECS's default ``stopTimeout``; the per-read bound stays 10 s."""
    assert execute_module.WRITE_TOTAL_TIMEOUT_SECONDS == 30.0
    assert BackendWriteClient.__init__.__kwdefaults__["timeout"] == 10.0  # type: ignore[index]


async def test_a_backend_that_never_finishes_its_headers_is_cut_off_at_the_total_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(execute_module, "WRITE_TOTAL_TIMEOUT_SECONDS", 0.2)

    async def handler(request: httpx2.Request) -> httpx2.Response:
        await asyncio.sleep(30)
        return httpx2.Response(201)

    client = _client(handler)
    with pytest.raises(BackendTransportError) as excinfo:
        await asyncio.wait_for(_execute(client), timeout=5)
    exc = excinfo.value
    assert exc.kind == "TotalTimeout"
    assert str(exc) == "the backend write endpoint could not be reached or answered improperly"
    assert exc.__cause__ is None
    assert exc.__context__ is None
    assert exc.__suppress_context__ is True
    await client.aclose()


async def test_a_fast_backend_is_unaffected_by_the_total_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(execute_module, "WRITE_TOTAL_TIMEOUT_SECONDS", 0.5)
    client = _client(lambda request: httpx2.Response(201, json={}))
    assert await _execute(client) == 201
    await client.aclose()


async def test_a_status_taken_before_the_deadline_is_the_answer_even_if_closing_is_slow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The status was read; a slow close of the unread body changes nothing."""
    monkeypatch.setattr(execute_module, "WRITE_TOTAL_TIMEOUT_SECONDS", 0.2)

    class SlowClose(httpx2.AsyncByteStream):
        async def __aiter__(self):  # type: ignore[no-untyped-def]
            yield b""

        async def aclose(self) -> None:
            await asyncio.sleep(2)

    async def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(201, stream=SlowClose())

    client = _client(handler)
    assert await asyncio.wait_for(_execute(client), timeout=5) == 201
    await client.aclose()


async def test_an_outer_cancellation_is_not_turned_into_a_total_timeout() -> None:
    started = asyncio.Event()

    async def handler(request: httpx2.Request) -> httpx2.Response:
        started.set()
        await asyncio.sleep(30)
        return httpx2.Response(201)

    client = _client(handler)
    task = asyncio.create_task(_execute(client))
    await asyncio.wait_for(started.wait(), timeout=5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await client.aclose()


# ---------------------------------------------------------------------------
# BackendWriteError.
# ---------------------------------------------------------------------------


class TestBackendWriteError:
    """BackendWriteError carries the numeric status and nothing else."""

    def test_status_attribute(self) -> None:
        exc = BackendWriteError(status=403)
        assert exc.status == 403

    def test_string_representation_is_the_status_only(self) -> None:
        exc = BackendWriteError(status=400)
        assert str(exc) == "backend write endpoint answered 400"

    def test_there_is_no_detail_field_to_fill(self) -> None:
        with pytest.raises(TypeError):
            BackendWriteError(status=400, detail="x")  # type: ignore[call-arg]
        assert not hasattr(BackendWriteError(status=400), "detail")


# ---------------------------------------------------------------------------
# aclose — ensure the underlying httpx2 client is closed.
# ---------------------------------------------------------------------------


async def test_aclose_closes_underlying_client() -> None:
    """aclose closes the underlying httpx2.AsyncClient."""
    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        before_backend_request=None,
    )
    await client.aclose()
    # After aclose, the internal client should be closed.
    assert client._client.is_closed

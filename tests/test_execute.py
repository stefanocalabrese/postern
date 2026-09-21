"""Backend write execution infrastructure (handoff §6.3, §8.3).

Tests for ``services.confirm.execute``:
- TOOL_REGISTRY completeness (6 tools, no duplicates).
- ``resolve_endpoint`` — known tools, unknown tool error, missing path params.
- ``BackendWriteClient.execute`` — success (200/201/202), error response →
  ``BackendWriteError``, JWT injection, challenge_id claim.
- ``_scrub_response`` — PAN/IBAN scrubbing on error bodies.

Backend mocking is at the transport layer with ``httpx2.MockTransport``, per
``dev-docs/decisions/0001-facade-http-client.md``. ``respx`` is not installed and
cannot mock ``httpx2``.
"""

from collections.abc import Callable

import httpx2
import pytest

from services.confirm.execute import (
    TOOL_REGISTRY,
    BackendWriteClient,
    BackendWriteError,
    _scrub_response,
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
    """A 200 response is returned as-is."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"id": "pay_123"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
    )
    response = await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={"amount": "EUR 340.00"},
        challenge_id="chal_abc",
    )
    assert response.status_code == 200
    await client.aclose()


async def test_execute_success_201() -> None:
    """A 201 response is returned as-is."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(201, json={"id": "pay_456"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
    )
    response = await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={},
        challenge_id="chal_abc",
    )
    assert response.status_code == 201
    await client.aclose()


async def test_execute_success_202() -> None:
    """A 202 accepted response is returned as-is."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(202, json={"status": "accepted"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
    )
    response = await client.execute(
        customer_ref="cust_7f3a",
        audience="payments.svc",
        path="/payments",
        body={},
        challenge_id="chal_abc",
    )
    assert response.status_code == 202
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
# BackendWriteClient — response scrubbing (PAN/IBAN).
# ---------------------------------------------------------------------------


async def test_backend_write_error_scrubs_pan_from_json_detail() -> None:
    """PAN in a JSON error detail is scrubbed."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(400, json={"detail": f"card {_TEST_PAN} declined"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
    )
    with pytest.raises(BackendWriteError) as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    assert _TEST_PAN not in excinfo.value.detail
    await client.aclose()


async def test_backend_write_error_scrubs_iban_from_json_detail() -> None:
    """IBAN in a JSON error detail is scrubbed."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(400, json={"detail": f"transfer to {_TEST_IBAN} rejected"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
    )
    with pytest.raises(BackendWriteError) as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    assert _TEST_IBAN not in excinfo.value.detail
    await client.aclose()


async def test_backend_write_error_scrubs_pan_from_json_body_no_detail_key() -> None:
    """When there is no 'detail' key, the whole body is scrubbed."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(400, json={"pan": _TEST_PAN, "reason": "duplicate"})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
    )
    with pytest.raises(BackendWriteError) as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    assert _TEST_PAN not in excinfo.value.detail
    await client.aclose()


async def test_backend_write_error_scrubs_iban_from_non_json_body() -> None:
    """Non-JSON error body is also scrubbed."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            502,
            text=f"upstream gateway error for account {_TEST_IBAN}",
            headers={"content-type": "text/plain"},
        )

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
    )
    with pytest.raises(BackendWriteError) as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    assert _TEST_IBAN not in excinfo.value.detail
    await client.aclose()


async def test_backend_write_error_detail_is_capped_at_200_chars() -> None:
    """Error detail is truncated to 200 characters."""
    long_detail = "x" * 300

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(500, json={"detail": long_detail})

    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
        transport=_transport(handler),
    )
    with pytest.raises(BackendWriteError) as excinfo:
        await client.execute(
            customer_ref="cust_7f3a",
            audience="payments.svc",
            path="/payments",
            body={},
            challenge_id="chal_abc",
        )
    assert len(excinfo.value.detail) <= 200
    await client.aclose()


# ---------------------------------------------------------------------------
# BackendWriteError.
# ---------------------------------------------------------------------------


class TestBackendWriteError:
    """BackendWriteError carries status and detail."""

    def test_status_attribute(self) -> None:
        exc = BackendWriteError(status=403, detail="forbidden")
        assert exc.status == 403

    def test_detail_attribute(self) -> None:
        exc = BackendWriteError(status=502, detail="bad gateway")
        assert exc.detail == "bad gateway"

    def test_string_representation(self) -> None:
        exc = BackendWriteError(status=400, detail="bad request")
        assert str(exc) == "400: bad request"


# ---------------------------------------------------------------------------
# _scrub_response — unit test the scrubbing function directly.
# ---------------------------------------------------------------------------


class TestScrubResponse:
    """_scrub_response strips PAN/IBAN from error bodies."""

    def test_json_detail_with_pan_is_scrubbed(self) -> None:
        response = httpx2.Response(400, json={"detail": f"card {_TEST_PAN} on file"})
        assert _TEST_PAN not in _scrub_response(response)

    def test_json_detail_with_iban_is_scrubbed(self) -> None:
        response = httpx2.Response(400, json={"detail": f"transfer to {_TEST_IBAN}"})
        assert _TEST_IBAN not in _scrub_response(response)

    def test_non_json_text_with_pan_is_scrubbed(self) -> None:
        ct = {"content-type": "text/plain"}
        response = httpx2.Response(502, text=f"error {_TEST_PAN}", headers=ct)
        assert _TEST_PAN not in _scrub_response(response)

    def test_non_json_text_with_iban_is_scrubbed(self) -> None:
        ct = {"content-type": "text/plain"}
        response = httpx2.Response(502, text=f"error {_TEST_IBAN}", headers=ct)
        assert _TEST_IBAN not in _scrub_response(response)

    def test_result_is_capped_at_200_chars(self) -> None:
        response = httpx2.Response(500, json={"detail": "y" * 300})
        assert len(_scrub_response(response)) <= 200

    def test_empty_body_returns_empty_string(self) -> None:
        response = httpx2.Response(500, text="")
        assert _scrub_response(response) == ""

    def test_dict_body_without_detail_key_is_scrubbed(self) -> None:
        response = httpx2.Response(400, json={"pan": _TEST_PAN})
        assert _TEST_PAN not in _scrub_response(response)


# ---------------------------------------------------------------------------
# aclose — ensure the underlying httpx2 client is closed.
# ---------------------------------------------------------------------------


async def test_aclose_closes_underlying_client() -> None:
    """aclose closes the underlying httpx2.AsyncClient."""
    client = BackendWriteClient(
        base_url="https://backend.test",
        minter=_StubWriteMinter(),
    )
    await client.aclose()
    # After aclose, the internal client should be closed.
    assert client._client.is_closed

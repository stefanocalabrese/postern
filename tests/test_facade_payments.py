"""`get_payee` against `stub/backend.py` over ASGI (decision 0022)."""

import httpx2
import pytest
from postern_core.facade import payments
from postern_core.facade.client import BackendClient, BackendError, StubTokenMinter
from postern_core.identity import CustomerRef

from stub import backend as stub
from tests.fixtures import backend_responses as fx

OWNER = CustomerRef(value="cust_7f3a")


def stub_backend(transport: httpx2.AsyncBaseTransport | None = None) -> BackendClient:
    return BackendClient(
        "http://backend-stub",
        StubTokenMinter(),
        transport=transport or httpx2.ASGITransport(app=stub.app),
        before_backend_request=None,
    )


async def test_a_payee_is_a_ref_and_a_masked_name() -> None:
    payee = await payments.get_payee(stub_backend(), OWNER, "pay_nw01")
    assert payee.model_dump() == {
        "payee_ref": "pay_nw01",
        "display_name": "Northwind Energy DE•• •••• 3000",
    }
    assert fx.COUNTERPARTY_IBAN not in payee.model_dump_json()


async def test_a_field_the_projection_does_not_name_is_dropped() -> None:
    """Handoff §6.5 omits counterparty account numbers entirely: a backend
    that sends one beside the name has it dropped here."""

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={**fx.PAYEE, "iban": fx.COUNTERPARTY_IBAN})

    payee = await payments.get_payee(stub_backend(httpx2.MockTransport(handler)), OWNER, "pay_nw01")
    assert set(payee.model_dump()) == {"payee_ref", "display_name"}


async def test_a_backend_answering_a_different_payee_is_a_502() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"payee_ref": "pay_ll02", "name": "Landlord"})

    with pytest.raises(BackendError) as failed:
        await payments.get_payee(stub_backend(httpx2.MockTransport(handler)), OWNER, "pay_nw01")
    assert failed.value.status == 502
    assert "pay_nw01" not in str(failed.value)
    assert "pay_ll02" not in str(failed.value)
    assert "Landlord" not in str(failed.value)


@pytest.mark.parametrize(
    "payee_ref",
    ["pay_x?all=1", "pay_a/b", "../accounts", "pay_ x", "pay_x\n", "pay_x#f", ""],
)
async def test_a_malformed_ref_is_refused_before_any_request(payee_ref: str) -> None:
    calls: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json=fx.PAYEE)

    with pytest.raises(ValueError, match="payee_ref is not a valid ref") as failed:
        await payments.get_payee(stub_backend(httpx2.MockTransport(handler)), OWNER, payee_ref)
    assert calls == []
    assert payee_ref not in str(failed.value) or payee_ref == ""


@pytest.mark.parametrize("payee_ref", ["pay_ll02", "pay_none"], ids=["foreign", "invented"])
async def test_a_foreign_or_invented_payee_is_the_same_404(payee_ref: str) -> None:
    with pytest.raises(BackendError) as failed:
        await payments.get_payee(stub_backend(), OWNER, payee_ref)
    assert failed.value.status == 404

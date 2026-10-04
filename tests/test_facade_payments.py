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


@pytest.mark.parametrize("payee_ref", ["pay_ll02", "pay_none"], ids=["foreign", "invented"])
async def test_a_foreign_or_invented_payee_is_the_same_404(payee_ref: str) -> None:
    with pytest.raises(BackendError) as failed:
        await payments.get_payee(stub_backend(), OWNER, payee_ref)
    assert (failed.value.status, failed.value.detail) == (404, "no such payee")

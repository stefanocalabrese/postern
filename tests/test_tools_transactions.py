"""`transactions.list` (Task 9): bounded time window, bounded row count,
free text redacted through `Transaction.description`'s `FreeText` type.

Two independent bounds meet in this tool, per handoff §6.5 ("Bound result
sets hard") and the Task 9 handoff gap this task closes: `days` bounds the
*time window* (schema-enforced, 1..365, default 30) and `MAX_ROWS` bounds the
*row count* returned in one call (enforced in
`postern_core.facade.transactions.list_transactions`, independent of
whatever the backend sends). A wide time window on an active account can
still be thousands of rows; only the row bound stops that reaching a vendor
chat history in one call. See `packages/postern-core/src/postern_core/facade/
transactions.py`'s module docstring for the full design note.
"""

import json
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from postern_core.facade import transactions as facade
from postern_core.facade.client import BackendClient, StubTokenMinter

from services.api.server import build_server
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER
from tests.fixtures import backend_responses as fx

SEEN: list[httpx2.Request] = []


def _handler(request: httpx2.Request) -> httpx2.Response:
    SEEN.append(request)
    return httpx2.Response(200, json=fx.TRANSACTIONS)


@pytest.fixture
def server() -> FastMCP:
    SEEN.clear()
    backend = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(_handler),
        before_backend_request=None,
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


def _server_with_rows(rows: list[dict[str, Any]]) -> FastMCP:
    """A server whose backend answers `/transactions` with exactly `rows`,
    ignoring `days`/any row-limiting parameter -- the adversarial-pass proof
    that this repo's own row cap, not the backend's cooperation, is what
    bounds the result.
    """

    def handler(request: httpx2.Request) -> httpx2.Response:
        SEEN.append(request)
        return httpx2.Response(200, json={"transactions": rows})

    backend = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(handler),
        before_backend_request=None,
    )
    return build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=backend)


def _row(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "txn_1",
        "account_id": "acc_7f3a",
        "booked_at": "2026-09-11T08:30:00Z",
        "amount": "-34.20",
        "currency": "EUR",
        "counterparty_name": "Acme Ltd",
        "counterparty_iban": fx.COUNTERPARTY_IBAN,
        "description": "groceries",
    }
    base.update(overrides)
    return base


# --- Base behaviour (adapted from the plan: TransactionPage wraps items, not a bare list) ---


async def test_default_window_is_thirty_days(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert SEEN[0].url.params["days"] == "30"


async def test_window_can_be_widened_explicitly(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        await client.call_tool("transactions.list", {"account_ref": "acc_7f3a", "days": 90})
    assert SEEN[0].url.params["days"] == "90"


async def test_window_is_capped(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool(
            "transactions.list", {"account_ref": "acc_7f3a", "days": 4000}, raise_on_error=False
        )
    assert result.is_error
    assert SEEN == [], "an out-of-range days must be rejected before any backend call"


async def test_days_below_the_minimum_is_also_rejected_before_any_call(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool(
            "transactions.list", {"account_ref": "acc_7f3a", "days": 0}, raise_on_error=False
        )
    assert result.is_error
    assert SEEN == []


async def test_days_out_of_range_error_names_the_valid_bounds(server: FastMCP) -> None:
    """The adversarial-pass question: is the rejection message useful enough
    for a model to self-correct, or just "invalid"? Captured real message
    below the assertions.
    """
    async with Client(transport=server) as client:
        result = await client.call_tool(
            "transactions.list", {"account_ref": "acc_7f3a", "days": 4000}, raise_on_error=False
        )
    rendered = json.dumps([block.model_dump(mode="json") for block in result.content])
    assert "365" in rendered, f"error message does not name the upper bound: {rendered}"


async def test_counterparty_account_is_absent_from_the_result(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    row = result.structured_content["items"][0]
    assert row["counterparty_name"] == "Acme Ltd"
    assert "counterparty_iban" not in row


async def test_free_text_description_is_scrubbed(server: FastMCP) -> None:
    """`Transaction.description` is `FreeText` (Task 3, second security-review
    round): the redaction happens on model validation inside `Transaction(...)`,
    not because this façade remembers to call a scrub function.
    """
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    description = result.structured_content["items"][0]["description"]
    assert fx.FULL_PAN not in description
    assert fx.COUNTERPARTY_IBAN not in description
    assert "•••• " in description


async def test_direction_is_derived_from_the_sign(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    assert result.structured_content["items"][0]["direction"] == "debit"


async def test_amount_is_returned_as_its_absolute_value(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    assert result.structured_content["items"][0]["amount"]["amount"] == "34.20"


# --- The row bound this task adds on top of the plan (handoff §6.5 gap) ---


async def test_result_is_not_truncated_within_the_cap(server: FastMCP) -> None:
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    assert result.structured_content["truncated"] is False


async def test_row_count_is_capped_when_the_backend_sends_more_than_the_cap() -> None:
    """Proves the cap is enforced in this process, not merely requested of
    the backend: the stub below ignores `days` entirely and always returns
    `MAX_ROWS + 50` rows. If the tool trusted the backend to honor a `limit`
    it never even sends, this would return all of them, unbounded, straight
    into the model's context.
    """
    rows = [_row(id=f"txn_{i}") for i in range(facade.MAX_ROWS + 50)]
    server = _server_with_rows(rows)
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    assert len(result.structured_content["items"]) == facade.MAX_ROWS
    assert result.structured_content["truncated"] is True


async def test_row_count_exactly_at_the_cap_is_not_flagged_truncated() -> None:
    rows = [_row(id=f"txn_{i}") for i in range(facade.MAX_ROWS)]
    server = _server_with_rows(rows)
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    assert len(result.structured_content["items"]) == facade.MAX_ROWS
    assert result.structured_content["truncated"] is False


# --- Adversarial pass: redaction through every client-visible channel ---


async def test_full_pan_and_iban_are_absent_from_content_and_structured_content(
    server: FastMCP,
) -> None:
    """The fixture's `description` embeds a full PAN and the counterparty's
    full IBAN (`tests/fixtures/backend_responses.py`). Scans `content`
    (what an error path or a hand-built result would carry) as well as
    `structured_content`, matching `tests/test_masking_golden.py`'s
    `_render_result` scan scope: a leak through `content` alone would be
    invisible to a check that only inspects `structured_content`.
    """
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    rendered = json.dumps(
        {
            "content": [block.model_dump(mode="json") for block in result.content],
            "structured_content": result.structured_content,
            "data": result.data,
        },
        default=str,
    )
    assert fx.FULL_PAN not in rendered, f"PAN leaked: {rendered[:400]}"
    assert fx.COUNTERPARTY_IBAN not in rendered, f"IBAN leaked: {rendered[:400]}"
    assert "counterparty_iban" not in rendered


# --- Adversarial pass: amount/direction edge cases ---


async def test_zero_amount_direction_defaults_to_credit() -> None:
    server = _server_with_rows([_row(amount="0.00")])
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    row = result.structured_content["items"][0]
    assert row["direction"] == "credit"
    assert row["amount"]["amount"] == "0.00"


async def test_explicit_negative_zero_amount_behaves_like_zero() -> None:
    """`Decimal("-0.00") < 0` is `False` in Python: a backend sending an
    explicit negative zero is indistinguishable from a plain zero through
    this façade's sign check, and both land on the same (arbitrary but
    deterministic) `"credit"` side. Documented, not a defect: there is no
    "correct" direction for an amount of zero.
    """
    server = _server_with_rows([_row(amount="-0.00")])
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    row = result.structured_content["items"][0]
    assert row["direction"] == "credit"
    assert row["amount"]["amount"] == "0.00"


async def test_missing_amount_field_fails_without_leaking_a_value() -> None:
    rows = [_row()]
    del rows[0]["amount"]
    server = _server_with_rows(rows)
    async with Client(transport=server) as client:
        result = await client.call_tool(
            "transactions.list", {"account_ref": "acc_7f3a"}, raise_on_error=False
        )
    assert result.is_error
    rendered = json.dumps([block.model_dump(mode="json") for block in result.content])
    assert fx.COUNTERPARTY_IBAN not in rendered
    assert "groceries" not in rendered


async def test_null_amount_fails_without_leaking_a_value() -> None:
    server = _server_with_rows([_row(amount=None)])
    async with Client(transport=server) as client:
        result = await client.call_tool(
            "transactions.list", {"account_ref": "acc_7f3a"}, raise_on_error=False
        )
    assert result.is_error
    rendered = json.dumps([block.model_dump(mode="json") for block in result.content])
    assert fx.COUNTERPARTY_IBAN not in rendered
    assert "groceries" not in rendered


def test_decimal_error_messages_never_embed_the_offending_value() -> None:
    """Documents why `test_null_amount_...`/`test_missing_amount_...` above
    don't need a `caplog` leak assertion the way Task 8's
    `test_accounts_list_validation_error_does_not_leak_the_raw_iban` does:
    unlike a masking `ValidationError`, `decimal.InvalidOperation` and the
    `TypeError` from `Decimal(None)` never carry the input in their message
    in the first place, confirmed here directly against the stdlib.
    """
    with pytest.raises(TypeError, match="NoneType") as exc_info:
        Decimal(None)  # type: ignore[arg-type]
    assert "None" not in str(exc_info.value).split("NoneType")[0]

    with pytest.raises(InvalidOperation) as exc_info2:
        Decimal("not-a-number")
    assert "not-a-number" not in str(exc_info2.value)


async def test_direction_from_sign_is_wrong_if_the_backend_signals_direction_separately() -> None:
    """Recorded adversarial finding, not fixable from this façade alone: this
    tool derives `direction` from the *sign* of `row["amount"]`, per the plan.
    A backend contract that instead sends an always-positive `amount` and
    signals direction through a separate field (e.g. `"type": "debit"`) is
    indistinguishable, from this row alone, from an all-credits account: the
    façade has no second field to fall back on, and `_row()`'s default fixture
    already has no such field. This test pins the current (plan-specified)
    behaviour -- an unsigned positive amount is always reported "credit" --
    so a real backend integration test against the actual contract is what
    must confirm the sign convention holds, not this repo alone.
    """
    # positive amount, no separate direction field: an actual debit per the fixture's memo
    server = _server_with_rows([_row(amount="34.20")])
    async with Client(transport=server) as client:
        result = await client.call_tool("transactions.list", {"account_ref": "acc_7f3a"})
    assert result.structured_content is not None
    assert result.structured_content["items"][0]["direction"] == "credit"

"""The create tool: amount, reference, idempotency and refusals, at handler level."""

import asyncio
import logging
from decimal import Decimal

import httpx2
import pytest
from fastmcp.exceptions import ToolError
from postern_core.facade.client import BackendError
from postern_core.identity import CustomerRef, TokenClaims
from postern_core.payments import (
    CREATE_PAYMENT_TOOL,
    PAYMENT_TIER,
    request_fingerprint,
)
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from sqlalchemy import text

from services.api.tools.payments import (
    ACCOUNT_NOT_FOUND,
    AMOUNT_INVALID,
    NOT_RECORDED,
    PAYEE_NOT_FOUND,
    REFERENCE_NOT_PRINTABLE,
    REFERENCE_TOO_LONG,
    build_create_payment,
    canonical_amount,
)
from stub import backend as stub
from tests.fixtures.payments_http import (
    ARGS,
    OWNER,
    SUMMARY,
    create_payment,
    offline_runtime,
    rows,
    stub_backend,
)

# `payments_key_pair` and `payments_produced` live in the shared module; loading it as a plugin
# registers them without importing the names into every signature's scope.
pytest_plugins = ["tests.fixtures.payments_http"]


# -- The amount --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("340.5", "340.50"),
        ("340.50", "340.50"),
        ("340.5000", "340.50"),
        ("100", "100.00"),
        ("007", "7.00"),
        ("0.0001", "0.0001"),
        ("1.2340", "1.234"),
    ],
)
def test_canonical_amount(raw: str, expected: str) -> None:
    assert canonical_amount(Decimal(raw)) == expected


# -- create_payment, handler level -----------------------------------------------


async def test_a_proposal_returns_a_pending_challenge_and_its_summary(
    payments_produced: Database,
) -> None:
    result = await create_payment(payments_produced)(**ARGS)
    assert set(result) == {"challenge_id", "status", "expires_at", "human_summary"}
    assert result["status"] == "pending"
    assert len(result["challenge_id"]) == 32
    assert result["human_summary"] == SUMMARY


async def test_the_stored_row_is_built_from_server_resolved_data_only(
    payments_produced: Database,
) -> None:
    result = await create_payment(payments_produced)(**ARGS, reference="Rent October")
    (row,) = await rows(payments_produced)
    assert row.challenge_id == result["challenge_id"]
    assert row.payload == {
        "from_account_ref": "acc_7f3a",
        "payee_ref": "pay_nw01",
        "payee_name": "Northwind Energy DE•• •••• 3000",
        "amount": "340.50",
        "currency": "EUR",
        "reference": "Rent October",
    }
    assert all(isinstance(value, str) for value in row.payload.values())
    assert (row.tool_name, row.tier, row.status) == (
        CREATE_PAYMENT_TOOL,
        int(PAYMENT_TIER),
        "pending",
    )
    assert (row.client_id, row.session_jti) == ("claude-code", "jti-handler-1")
    assert row.request_fingerprint == request_fingerprint(
        customer_ref=OWNER, tool_name=CREATE_PAYMENT_TOOL, payload=row.payload
    )
    assert row.expires_at.isoformat() == result["expires_at"]


async def test_a_repeat_inside_the_window_returns_the_same_challenge(
    payments_produced: Database,
) -> None:
    handler = create_payment(payments_produced)
    first = await handler(**ARGS)
    second = await handler(**ARGS)
    assert (second["challenge_id"], second["expires_at"]) == (
        first["challenge_id"],
        first["expires_at"],
    )
    assert len(await rows(payments_produced)) == 1


async def test_two_spellings_of_one_amount_are_one_challenge(payments_produced: Database) -> None:
    handler = create_payment(payments_produced)
    first = await handler(**{**ARGS, "amount": "340.5"})
    second = await handler(**{**ARGS, "amount": "340.50"})
    assert first["challenge_id"] == second["challenge_id"]


async def test_a_different_amount_or_reference_is_a_new_challenge(
    payments_produced: Database,
) -> None:
    handler = create_payment(payments_produced)
    base = await handler(**ARGS)
    other_amount = await handler(**{**ARGS, "amount": "340.51"})
    with_reference = await handler(**ARGS, reference="Rent October")
    ids = {base["challenge_id"], other_amount["challenge_id"], with_reference["challenge_id"]}
    assert len(ids) == 3


async def test_two_concurrent_calls_make_one_row(payments_produced: Database) -> None:
    first, second = await asyncio.gather(
        create_payment(payments_produced)(**ARGS), create_payment(payments_produced)(**ARGS)
    )
    assert first["challenge_id"] == second["challenge_id"]
    assert len(await rows(payments_produced)) == 1


async def test_a_stale_pending_row_is_expired_and_a_new_challenge_created(
    payments_produced: Database,
) -> None:
    handler = create_payment(payments_produced)
    first = await handler(**ARGS)
    async with payments_produced.sessionmaker() as s:
        await s.execute(
            text(
                "UPDATE challenges SET expires_at = now() - interval '1 second' "
                "WHERE challenge_id = :c"
            ),
            {"c": first["challenge_id"]},
        )
        await s.commit()
    second = await handler(**ARGS)
    assert second["challenge_id"] != first["challenge_id"]
    statuses = {row.challenge_id: row.status for row in await rows(payments_produced)}
    assert statuses == {first["challenge_id"]: "expired", second["challenge_id"]: "pending"}


@pytest.mark.parametrize("account", ["acc_9b21", "acc_nope"], ids=["foreign", "invented"])
async def test_a_foreign_or_invented_account_is_one_refusal(
    payments_produced: Database, account: str
) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(payments_produced)(**{**ARGS, "from_account_ref": account})
    assert str(refused.value) == ACCOUNT_NOT_FOUND
    assert await rows(payments_produced) == []


@pytest.mark.parametrize("payee", ["pay_ll02", "pay_none"], ids=["foreign", "invented"])
async def test_a_foreign_or_invented_payee_is_one_refusal(
    payments_produced: Database, payee: str
) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(payments_produced)(**{**ARGS, "payee_ref": payee})
    assert str(refused.value) == PAYEE_NOT_FOUND
    assert await rows(payments_produced) == []


@pytest.mark.parametrize(
    "amount",
    [
        "0",
        "0.00",
        "-1",
        "+1",
        "1e3",
        "1.23456",
        "abc",
        "",
        "1,000.00",
        " 1",
        "1 ",
        "12345678901234567",
        "١٢٣",
    ],
)
async def test_an_amount_that_is_not_a_positive_short_decimal_is_refused(
    payments_produced: Database, amount: str
) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(payments_produced)(**{**ARGS, "amount": amount})
    assert str(refused.value) == AMOUNT_INVALID
    assert await rows(payments_produced) == []


async def test_a_reference_over_140_characters_is_refused_before_scrubbing(
    payments_produced: Database,
) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(payments_produced)(**ARGS, reference="a" * 141)
    assert str(refused.value) == REFERENCE_TOO_LONG
    assert await rows(payments_produced) == []


async def test_a_reference_of_140_characters_is_accepted(payments_produced: Database) -> None:
    reference = "Rent " * 28
    assert len(reference) == 140
    await create_payment(payments_produced)(**ARGS, reference=reference)
    (row,) = await rows(payments_produced)
    assert row.payload["reference"] == reference


@pytest.mark.parametrize(
    "reference",
    [
        "line1\nTo: Mallory\nAmount: 1.00",
        "a\rb",
        "a\tb",
        "a\x00b",
        "a\x1bb",
        "a\u0085b",
        "a\u2028b",
        "a\u2029b",
        "a\u202eb",
        "a\u200bb",
        "family \U0001f468\u200d\U0001f469",
        "a\ue000b",
        "a\u0378b",
        "a\ud800b",
    ],
    ids=[
        "newline",
        "cr",
        "tab",
        "nul",
        "escape",
        "nel",
        "line-separator",
        "paragraph-separator",
        "bidi-override",
        "zero-width-space",
        "zwj-sequence",
        "private-use",
        "unassigned",
        "surrogate",
    ],
)
async def test_a_reference_with_a_non_printable_character_is_refused(
    payments_produced: Database, reference: str
) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(payments_produced)(**ARGS, reference=reference)
    assert str(refused.value) == REFERENCE_NOT_PRINTABLE
    assert await rows(payments_produced) == []


async def test_a_reference_with_accents_and_plain_emoji_is_accepted_unchanged(
    payments_produced: Database,
) -> None:
    reference = "Café été \u2615 \U0001f389 Müller"
    await create_payment(payments_produced)(**ARGS, reference=reference)
    (row,) = await rows(payments_produced)
    assert row.payload["reference"] == reference


async def test_a_malformed_amount_or_long_reference_makes_no_backend_request(
    payments_produced: Database,
) -> None:
    requests: list[str] = []

    def counting(request: httpx2.Request) -> httpx2.Response:
        requests.append(request.url.path)
        return httpx2.Response(500)

    backend = stub_backend(httpx2.MockTransport(counting))
    handler = create_payment(payments_produced, backend=backend)
    with pytest.raises(ToolError) as bad_amount:
        await handler(**{**ARGS, "amount": "abc"})
    with pytest.raises(ToolError) as long_reference:
        await handler(**ARGS, reference="a" * 141)
    with pytest.raises(ToolError) as unprintable:
        await handler(**ARGS, reference="a\nb")
    assert str(bad_amount.value) == AMOUNT_INVALID
    assert str(long_reference.value) == REFERENCE_TOO_LONG
    assert str(unprintable.value) == REFERENCE_NOT_PRINTABLE
    assert requests == []


async def test_a_reference_is_stored_as_the_customer_will_see_it(
    payments_produced: Database,
) -> None:
    await create_payment(payments_produced)(**ARGS, reference=f"Invoice {stub.FULL_PAN}")
    (row,) = await rows(payments_produced)
    assert row.payload["reference"] == "Invoice •••• 1111"


async def test_absent_or_overlong_claims_are_stored_as_null(payments_produced: Database) -> None:
    def no_claims() -> TokenClaims:
        return TokenClaims(client_id=None, jti=None)

    def long_claims() -> TokenClaims:
        return TokenClaims(client_id="c" * 129, jti="j" * 129)

    await create_payment(payments_produced, claims=no_claims)(**ARGS)
    await create_payment(payments_produced, claims=long_claims)(**{**ARGS, "amount": "1.00"})
    assert [(row.client_id, row.session_jti) for row in await rows(payments_produced)] == [
        (None, None),
        (None, None),
    ]


async def test_an_unreachable_store_is_a_fixed_refusal_and_creates_nothing(
    payments_produced: Database, caplog: pytest.LogCaptureFixture
) -> None:
    runtime = offline_runtime()
    caplog.set_level(logging.DEBUG)
    try:
        handler = build_create_payment(lambda: CustomerRef(value=OWNER), stub_backend(), runtime)
        with pytest.raises(ToolError) as refused:
            await handler(**ARGS, reference="Rent October")
    finally:
        await runtime.db.close()
    assert str(refused.value) == NOT_RECORDED
    assert await rows(payments_produced) == []
    # The log names the exception type and nothing of the payload or customer.
    ours = [r for r in caplog.records if r.name == "services.api.tools.payments"]
    assert len(ours) == 1
    assert (
        ours[0].getMessage().startswith(f"{CREATE_PAYMENT_TOOL} could not record its challenge: ")
    )
    assert ours[0].getMessage().rsplit(": ", 1)[1].isidentifier()
    assert ours[0].exc_info is None
    # Every logger: no customer ref and no payload text. The backend client's
    # own request lines name refs in URLs, which is not this tool's log.
    for forbidden in (OWNER, "cust_", "Northwind", "340.50", "Rent October"):
        assert forbidden not in caplog.text
    for forbidden in ("pay_nw01", "acc_7f3a"):
        assert forbidden not in ours[0].getMessage()


async def test_a_store_that_returns_nothing_is_a_fixed_refusal_and_creates_nothing(
    payments_produced: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def nothing(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(store, "create_pending_challenge_once", nothing)
    with pytest.raises(ToolError) as refused:
        await create_payment(payments_produced)(**ARGS)
    assert str(refused.value) == NOT_RECORDED
    assert await rows(payments_produced) == []


async def test_the_stored_currency_is_the_payer_accounts_not_a_default(
    payments_produced: Database,
) -> None:
    def gbp(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith("/payees/"):
            return httpx2.Response(200, json=stub.PAYEE)
        return httpx2.Response(200, json={**stub.BALANCE, "currency": "GBP"})

    result = await create_payment(
        payments_produced, backend=stub_backend(httpx2.MockTransport(gbp))
    )(**ARGS)
    (row,) = await rows(payments_produced)
    assert row.payload["currency"] == "GBP"
    assert result["human_summary"].startswith("Approve GBP 340.50 to ")


async def test_any_other_backend_failure_keeps_the_facade_text(payments_produced: Database) -> None:
    def payee_down(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith("/payees/"):
            return httpx2.Response(503, json={"detail": "payees unavailable"})
        return httpx2.Response(200, json=stub.BALANCE)

    backend = stub_backend(httpx2.MockTransport(payee_down))
    with pytest.raises(BackendError) as failed:
        await create_payment(payments_produced, backend=backend)(**ARGS)
    assert failed.value.status == 503
    assert await rows(payments_produced) == []

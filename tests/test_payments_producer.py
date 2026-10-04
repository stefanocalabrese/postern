"""The payments producer (spec sections 6 to 9).

Two harnesses, and each tests what the other cannot. The handler tests call
the function the builder returns directly, against the real `stub/backend.py`
over ASGI and the suite's Postgres: fast, and every refusal is a `ToolError`
whose message is asserted exactly. The HTTP tests go through `create_app` with
a real signed token, because both tools are always consent-gated and
`Client(transport=server)` carries no token; they assert what a client
actually receives.
"""

import asyncio
from collections.abc import AsyncIterator
from decimal import Decimal

import httpx2
import pytest
import pytest_asyncio
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.facade.client import BackendClient, BackendError, StubTokenMinter
from postern_core.identity import CustomerRef, TokenClaims, TokenClaimsProvider
from postern_core.modules.read import (
    ModuleSeamViolation,
    ReadContext,
    ReadModule,
    ReadTool,
    ToolHandler,
)
from postern_core.payments import CREATE_PAYMENT_TOOL, PAYMENT_TIER, request_fingerprint
from postern_core.store.engine import Database
from postern_core.store.models import ChallengeRecord
from sqlalchemy import select, text

from services.api.server import build_server
from services.api.settings import Settings
from services.api.tools.payments import (
    ACCOUNT_NOT_FOUND,
    AMOUNT_INVALID,
    NOT_RECORDED,
    PAYEE_NOT_FOUND,
    REFERENCE_TOO_LONG,
    PaymentsRuntime,
    build_create_payment,
    canonical_amount,
)
from stub import backend as stub
from tests.fixtures.payments_http import (
    OWNER,
    call_tool,
    delete_produced_challenges,
    grant,
    list_tool_names,
    offline_runtime,
    result_of,
    revoke_all_consents,
    token_for,
)

ARGS: dict[str, str] = {"from_account_ref": "acc_7f3a", "payee_ref": "pay_nw01", "amount": "340.50"}
SUMMARY = "Approve EUR 340.50 to Northwind Energy DE•• •••• 3000 in your banking app."


def fixed_claims() -> TokenClaims:
    return TokenClaims(client_id="claude-code", jti="jti-handler-1")


def stub_backend(transport: httpx2.AsyncBaseTransport | None = None) -> BackendClient:
    return BackendClient(
        "http://backend-stub",
        StubTokenMinter(),
        transport=transport or httpx2.ASGITransport(app=stub.app),
        before_backend_request=None,
    )


def create_payment(
    database: Database,
    *,
    customer: str = OWNER,
    backend: BackendClient | None = None,
    claims: TokenClaimsProvider = fixed_claims,
) -> ToolHandler:
    runtime = PaymentsRuntime(db=database, claims=claims)
    return build_create_payment(
        lambda: CustomerRef(value=customer), backend or stub_backend(), runtime
    )


async def rows(database: Database) -> list[ChallengeRecord]:
    async with database.sessionmaker() as s:
        result = await s.execute(
            select(ChallengeRecord)
            .where(ChallengeRecord.request_fingerprint.is_not(None))
            .order_by(ChallengeRecord.id)
        )
        return list(result.scalars().all())


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest_asyncio.fixture
async def produced(database: Database) -> AsyncIterator[Database]:
    """No produced challenge and no consent row before or after each test."""
    await delete_produced_challenges(database)
    await revoke_all_consents(database)
    yield database
    await delete_produced_challenges(database)
    await revoke_all_consents(database)


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
    produced: Database,
) -> None:
    result = await create_payment(produced)(**ARGS)
    assert set(result) == {"challenge_id", "status", "expires_at", "human_summary"}
    assert result["status"] == "pending"
    assert len(result["challenge_id"]) == 32
    assert result["human_summary"] == SUMMARY


async def test_the_stored_row_is_built_from_server_resolved_data_only(
    produced: Database,
) -> None:
    result = await create_payment(produced)(**ARGS, reference="Rent October")
    (row,) = await rows(produced)
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
    produced: Database,
) -> None:
    handler = create_payment(produced)
    first = await handler(**ARGS)
    second = await handler(**ARGS)
    assert (second["challenge_id"], second["expires_at"]) == (
        first["challenge_id"],
        first["expires_at"],
    )
    assert len(await rows(produced)) == 1


async def test_two_spellings_of_one_amount_are_one_challenge(produced: Database) -> None:
    handler = create_payment(produced)
    first = await handler(**{**ARGS, "amount": "340.5"})
    second = await handler(**{**ARGS, "amount": "340.50"})
    assert first["challenge_id"] == second["challenge_id"]


async def test_a_different_amount_or_reference_is_a_new_challenge(produced: Database) -> None:
    handler = create_payment(produced)
    base = await handler(**ARGS)
    other_amount = await handler(**{**ARGS, "amount": "340.51"})
    with_reference = await handler(**ARGS, reference="Rent October")
    ids = {base["challenge_id"], other_amount["challenge_id"], with_reference["challenge_id"]}
    assert len(ids) == 3


async def test_two_concurrent_calls_make_one_row(produced: Database) -> None:
    first, second = await asyncio.gather(
        create_payment(produced)(**ARGS), create_payment(produced)(**ARGS)
    )
    assert first["challenge_id"] == second["challenge_id"]
    assert len(await rows(produced)) == 1


async def test_a_stale_pending_row_is_expired_and_a_new_challenge_created(
    produced: Database,
) -> None:
    handler = create_payment(produced)
    first = await handler(**ARGS)
    async with produced.sessionmaker() as s:
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
    statuses = {row.challenge_id: row.status for row in await rows(produced)}
    assert statuses == {first["challenge_id"]: "expired", second["challenge_id"]: "pending"}


@pytest.mark.parametrize("account", ["acc_9b21", "acc_nope"], ids=["foreign", "invented"])
async def test_a_foreign_or_invented_account_is_one_refusal(
    produced: Database, account: str
) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(produced)(**{**ARGS, "from_account_ref": account})
    assert str(refused.value) == ACCOUNT_NOT_FOUND
    assert await rows(produced) == []


@pytest.mark.parametrize("payee", ["pay_ll02", "pay_none"], ids=["foreign", "invented"])
async def test_a_foreign_or_invented_payee_is_one_refusal(produced: Database, payee: str) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(produced)(**{**ARGS, "payee_ref": payee})
    assert str(refused.value) == PAYEE_NOT_FOUND
    assert await rows(produced) == []


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
    produced: Database, amount: str
) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(produced)(**{**ARGS, "amount": amount})
    assert str(refused.value) == AMOUNT_INVALID
    assert await rows(produced) == []


async def test_a_reference_over_140_characters_is_refused_before_scrubbing(
    produced: Database,
) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(produced)(**ARGS, reference="a" * 141)
    assert str(refused.value) == REFERENCE_TOO_LONG
    assert await rows(produced) == []


async def test_a_reference_of_140_characters_is_accepted(produced: Database) -> None:
    reference = "Rent " * 28
    assert len(reference) == 140
    await create_payment(produced)(**ARGS, reference=reference)
    (row,) = await rows(produced)
    assert row.payload["reference"] == reference


async def test_a_reference_is_stored_as_the_customer_will_see_it(produced: Database) -> None:
    await create_payment(produced)(**ARGS, reference=f"Invoice {stub.FULL_PAN}")
    (row,) = await rows(produced)
    assert row.payload["reference"] == "Invoice •••• 1111"


async def test_absent_or_overlong_claims_are_stored_as_null(produced: Database) -> None:
    def no_claims() -> TokenClaims:
        return TokenClaims(client_id=None, jti=None)

    def long_claims() -> TokenClaims:
        return TokenClaims(client_id="c" * 129, jti="j" * 129)

    await create_payment(produced, claims=no_claims)(**ARGS)
    await create_payment(produced, claims=long_claims)(**{**ARGS, "amount": "1.00"})
    assert [(row.client_id, row.session_jti) for row in await rows(produced)] == [
        (None, None),
        (None, None),
    ]


async def test_an_unreachable_store_is_a_fixed_refusal_and_creates_nothing(
    produced: Database,
) -> None:
    runtime = offline_runtime()
    try:
        handler = build_create_payment(lambda: CustomerRef(value=OWNER), stub_backend(), runtime)
        with pytest.raises(ToolError) as refused:
            await handler(**ARGS)
    finally:
        await runtime.db.close()
    assert str(refused.value) == NOT_RECORDED
    assert await rows(produced) == []


async def test_any_other_backend_failure_keeps_the_facade_text(produced: Database) -> None:
    def payee_down(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith("/payees/"):
            return httpx2.Response(503, json={"detail": "payees unavailable"})
        return httpx2.Response(200, json=stub.BALANCE)

    backend = stub_backend(httpx2.MockTransport(payee_down))
    with pytest.raises(BackendError) as failed:
        await create_payment(produced, backend=backend)(**ARGS)
    assert failed.value.status == 503
    assert await rows(produced) == []


def _noop_build(context: ReadContext) -> ToolHandler:
    async def shadow() -> list[str]:
        """A read tool squatting on a producer name."""
        return []

    return shadow


async def test_a_read_module_cannot_shadow_a_producer_tool() -> None:
    shadow = ReadModule(
        name="shadow",
        tools=(ReadTool(name=CREATE_PAYMENT_TOOL, consent_domain="payments", build=_noop_build),),
    )
    runtime = offline_runtime()
    try:
        with pytest.raises(ModuleSeamViolation, match="payments.create_payment"):
            build_server(
                Settings.for_testing(),
                resolver=lambda: CustomerRef(value=OWNER),
                backend=stub_backend(),
                read_modules=[shadow],
                payments=runtime,
            )
    finally:
        await runtime.db.close()


# -- create_payment, over HTTP -----------------------------------------------------


async def test_over_http_a_consented_customer_gets_the_proposal(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    await grant(produced, OWNER, "payments")
    response = await call_tool(
        pg_url, key_pair, token_for(key_pair, OWNER), CREATE_PAYMENT_TOOL, ARGS
    )
    result = result_of(response)
    assert result["isError"] is False, response.text
    assert result["structuredContent"]["status"] == "pending"
    assert result["structuredContent"]["human_summary"] == SUMMARY
    (row,) = await rows(produced)
    assert row.challenge_id == result["structuredContent"]["challenge_id"]
    assert (row.client_id, row.session_jti) == ("claude-code", "jti-test-1")


async def test_over_http_a_refusal_is_its_fixed_message_and_nothing_else(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    await grant(produced, OWNER, "payments")
    response = await call_tool(
        pg_url,
        key_pair,
        token_for(key_pair, OWNER),
        CREATE_PAYMENT_TOOL,
        {**ARGS, "from_account_ref": "acc_9b21"},
    )
    result = result_of(response)
    assert result["isError"] is True
    assert [block["text"] for block in result["content"]] == [ACCOUNT_NOT_FOUND]


async def test_without_payments_consent_the_tool_is_unlisted_and_unknown(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    await grant(produced, OWNER, "accounts")
    token = token_for(key_pair, OWNER)
    assert CREATE_PAYMENT_TOOL not in await list_tool_names(pg_url, key_pair, token)
    response = await call_tool(pg_url, key_pair, token, CREATE_PAYMENT_TOOL, ARGS)
    assert [block["text"] for block in result_of(response)["content"]] == [
        f"Unknown tool: '{CREATE_PAYMENT_TOOL}'"
    ]
    assert await rows(produced) == []


async def test_with_payments_consent_the_tool_is_listed(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    await grant(produced, OWNER, "payments")
    names = await list_tool_names(pg_url, key_pair, token_for(key_pair, OWNER))
    assert CREATE_PAYMENT_TOOL in names


async def test_with_the_flag_off_the_producer_is_not_registered(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    await grant(produced, OWNER, "payments")
    names = await list_tool_names(
        pg_url, key_pair, token_for(key_pair, OWNER), payments_enabled=False
    )
    assert names == {"start_session"}


async def test_a_proposal_completes_through_a_pool_of_one(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    """No reserve, one connection, no overflow: the consent probe, the entry
    audit row, the tool's transaction and the completion row must each take
    the connection and give it back, because any overlap waits out the pool
    timeout and fails the call."""
    await grant(produced, OWNER, "payments")
    response = await call_tool(
        pg_url,
        key_pair,
        token_for(key_pair, OWNER),
        CREATE_PAYMENT_TOOL,
        ARGS,
        database_pool_size=1,
        database_max_overflow=0,
        database_audit_reserve_size=0,
    )
    assert result_of(response)["isError"] is False, response.text

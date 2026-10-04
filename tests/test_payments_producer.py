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
import json
import logging
import uuid
from collections.abc import AsyncIterator
from decimal import Decimal
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.approval_signature import (
    canonical_approval_message,
    decode_signature,
    verify_approval_signature,
)
from postern_core.facade.client import BackendClient, BackendError, StubTokenMinter
from postern_core.identity import CustomerRef, TokenClaims, TokenClaimsProvider
from postern_core.modules.read import (
    ModuleSeamViolation,
    ReadContext,
    ReadModule,
    ReadTool,
    ToolHandler,
)
from postern_core.payments import (
    CREATE_PAYMENT_TOOL,
    PAYMENT_STATUS_TOOL,
    PAYMENT_TIER,
    request_fingerprint,
)
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from postern_core.store.models import REFUSAL_DOMAIN_NOT_CONSENTED, AuditEntry, ChallengeRecord
from sqlalchemy import event, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.applications import Starlette

from services.api.server import build_server
from services.api.settings import Settings
from services.api.tools.payments import (
    ACCOUNT_NOT_FOUND,
    AMOUNT_INVALID,
    CHALLENGE_NOT_FOUND,
    CHALLENGE_UNREADABLE,
    NOT_RECORDED,
    PAYEE_NOT_FOUND,
    REFERENCE_NOT_PRINTABLE,
    REFERENCE_TOO_LONG,
    PaymentsRuntime,
    build_create_payment,
    build_get_payment_status,
    canonical_amount,
)
from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from stub import backend as stub
from tests.fixtures.device_keys import approval_body, device_key, enrolled_store, sign_row
from tests.fixtures.payments_http import (
    OTHER,
    OWNER,
    call_tool,
    delete_produced_challenges,
    grant,
    list_tool_names,
    offline_runtime,
    post_rpc,
    producer_app,
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
    produced: Database, reference: str
) -> None:
    with pytest.raises(ToolError) as refused:
        await create_payment(produced)(**ARGS, reference=reference)
    assert str(refused.value) == REFERENCE_NOT_PRINTABLE
    assert await rows(produced) == []


async def test_a_reference_with_accents_and_plain_emoji_is_accepted_unchanged(
    produced: Database,
) -> None:
    reference = "Café été \u2615 \U0001f389 Müller"
    await create_payment(produced)(**ARGS, reference=reference)
    (row,) = await rows(produced)
    assert row.payload["reference"] == reference


async def test_a_malformed_amount_or_long_reference_makes_no_backend_request(
    produced: Database,
) -> None:
    requests: list[str] = []

    def counting(request: httpx2.Request) -> httpx2.Response:
        requests.append(request.url.path)
        return httpx2.Response(500)

    backend = stub_backend(httpx2.MockTransport(counting))
    handler = create_payment(produced, backend=backend)
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
    produced: Database, caplog: pytest.LogCaptureFixture
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
    assert await rows(produced) == []
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
    produced: Database, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def nothing(*args: object, **kwargs: object) -> None:
        return None

    monkeypatch.setattr(store, "create_pending_challenge_once", nothing)
    with pytest.raises(ToolError) as refused:
        await create_payment(produced)(**ARGS)
    assert str(refused.value) == NOT_RECORDED
    assert await rows(produced) == []


async def test_the_stored_currency_is_the_payer_accounts_not_a_default(
    produced: Database,
) -> None:
    def gbp(request: httpx2.Request) -> httpx2.Response:
        if request.url.path.startswith("/payees/"):
            return httpx2.Response(200, json=stub.PAYEE)
        return httpx2.Response(200, json={**stub.BALANCE, "currency": "GBP"})

    result = await create_payment(produced, backend=stub_backend(httpx2.MockTransport(gbp)))(**ARGS)
    (row,) = await rows(produced)
    assert row.payload["currency"] == "GBP"
    assert result["human_summary"].startswith("Approve GBP 340.50 to ")


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


async def test_payments_without_a_backend_is_refused_at_build_time() -> None:
    runtime = offline_runtime()
    try:
        with pytest.raises(ValueError, match="payments requires a backend"):
            build_server(
                Settings.for_testing(),
                resolver=lambda: CustomerRef(value=OWNER),
                backend=None,
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


async def test_without_payments_consent_the_status_tool_is_unlisted_and_unknown(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    await grant(produced, OWNER, "accounts")
    expired = await insert_row(
        produced, customer_ref=OWNER, tool_name=CREATE_PAYMENT_TOOL, past_deadline=True
    )
    token = token_for(key_pair, OWNER)
    assert PAYMENT_STATUS_TOOL not in await list_tool_names(pg_url, key_pair, token)
    response = await call_tool(
        pg_url, key_pair, token, PAYMENT_STATUS_TOOL, {"challenge_id": expired}
    )
    assert [block["text"] for block in result_of(response)["content"]] == [
        f"Unknown tool: '{PAYMENT_STATUS_TOOL}'"
    ]
    assert await status_of(produced, expired) == "pending"


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


@pytest.mark.parametrize("tool_name", [CREATE_PAYMENT_TOOL, PAYMENT_STATUS_TOOL])
async def test_the_registered_tool_declares_exactly_these_annotations(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP, tool_name: str
) -> None:
    await grant(produced, OWNER, "payments")
    app = producer_app(pg_url, key_pair)
    response = await post_rpc(app, token_for(key_pair, OWNER), "tools/list", {})
    (tool,) = [t for t in json.loads(response.text)["result"]["tools"] if t["name"] == tool_name]
    annotations = tool["annotations"]
    assert (
        annotations["readOnlyHint"],
        annotations["destructiveHint"],
        annotations["idempotentHint"],
        annotations["openWorldHint"],
    ) == (False, False, True, False)


# -- get_payment_status ------------------------------------------------------------

STATUS_FIELDS = {
    "challenge_id",
    "status",
    "expires_at",
    "amount",
    "currency",
    "payee_name",
    "reference",
}


def payment_status(database: Database, *, customer: str = OWNER) -> ToolHandler:
    return build_get_payment_status(
        lambda: CustomerRef(value=customer), PaymentsRuntime(db=database, claims=fixed_claims)
    )


async def insert_row(
    database: Database,
    *,
    customer_ref: str,
    tool_name: str,
    payload: Any = None,
    past_deadline: bool = False,
) -> str:
    """A pending row the producer did not make through its handler: another
    customer's, or another tool's, or one with a payload of any shape.
    Fingerprinted, so the `produced` fixture deletes it. `past_deadline` moves
    `expires_at` into the past, still `pending`."""
    challenge_id = uuid.uuid4().hex
    async with database.sessionmaker() as s:
        await store.create_pending_challenge_once(
            s,
            challenge_id=challenge_id,
            customer_ref=customer_ref,
            tool_name=tool_name,
            payload=(
                {"amount": "1.00", "currency": "EUR", "payee_name": "Payee"}
                if payload is None
                else payload
            ),
            tier=PAYMENT_TIER,
            request_fingerprint=challenge_id * 2,
            client_id=None,
            session_jti=None,
        )
        if past_deadline:
            await s.execute(
                text(
                    "UPDATE challenges SET expires_at = now() - interval '1 second' "
                    "WHERE challenge_id = :c"
                ),
                {"c": challenge_id},
            )
        await s.commit()
    return challenge_id


async def status_of(database: Database, challenge_id: str) -> str:
    async with database.sessionmaker() as s:
        result = await s.execute(
            text("SELECT status FROM challenges WHERE challenge_id = :c"), {"c": challenge_id}
        )
        return str(result.scalar_one())


async def test_status_reports_a_pending_proposal_from_the_stored_row(
    produced: Database,
) -> None:
    created = await create_payment(produced)(**ARGS, reference="Rent October")
    status = await payment_status(produced)(challenge_id=created["challenge_id"])
    assert status == {
        "challenge_id": created["challenge_id"],
        "status": "pending",
        "expires_at": created["expires_at"],
        "amount": "340.50",
        "currency": "EUR",
        "payee_name": "Northwind Energy DE•• •••• 3000",
        "reference": "Rent October",
    }


async def test_status_without_a_reference_reports_none(produced: Database) -> None:
    created = await create_payment(produced)(**ARGS)
    status = await payment_status(produced)(challenge_id=created["challenge_id"])
    assert status["reference"] is None


async def test_status_expires_a_row_past_its_deadline(produced: Database) -> None:
    created = await create_payment(produced)(**ARGS)
    async with produced.sessionmaker() as s:
        await s.execute(
            text(
                "UPDATE challenges SET expires_at = now() - interval '1 second' "
                "WHERE challenge_id = :c"
            ),
            {"c": created["challenge_id"]},
        )
        await s.commit()
    status = await payment_status(produced)(challenge_id=created["challenge_id"])
    assert status["status"] == "expired"
    (row,) = await rows(produced)
    assert row.status == "expired"


async def test_an_approved_row_whose_execution_failed_stays_approved(
    produced: Database,
) -> None:
    """The callback answers 207 and leaves the row `approved` when the backend
    write fails. No status is invented on top of that."""
    created = await create_payment(produced)(**ARGS)
    async with produced.sessionmaker() as s:
        await store.update_challenge_status(
            s,
            created["challenge_id"],
            status="approved",
            expected_status="pending",
            expiry="unexpired",
        )
        await s.commit()
    status = await payment_status(produced)(challenge_id=created["challenge_id"])
    assert status["status"] == "approved"


async def test_status_never_returns_the_approval_or_the_session_record(
    produced: Database,
) -> None:
    created = await create_payment(produced)(**ARGS)
    async with produced.sessionmaker() as s:
        await store.update_challenge_status(
            s,
            created["challenge_id"],
            status="approved",
            expected_status="pending",
            expiry="unexpired",
            confirming_device="dev_secret_1",
            verification_result="vr_secret_1",
            signature="sig_secret_1",
        )
        await s.commit()
    status = await payment_status(produced)(challenge_id=created["challenge_id"])
    assert set(status) == STATUS_FIELDS
    (row,) = await rows(produced)
    rendered = json.dumps(status)
    for withheld in (
        "dev_secret_1",
        "vr_secret_1",
        "sig_secret_1",
        "claude-code",
        "jti-handler-1",
        str(row.request_fingerprint),
        "from_account_ref",
        "acc_7f3a",
    ):
        assert withheld not in rendered, withheld


@pytest.mark.parametrize(
    "case",
    ["unknown", "foreign", "not_a_payment", "malformed", "nul", "traversal", "space"],
)
async def test_unknown_foreign_non_payment_and_malformed_ids_are_one_refusal(
    produced: Database, case: str
) -> None:
    if case == "unknown":
        challenge_id = uuid.uuid4().hex
    elif case == "foreign":
        challenge_id = await insert_row(produced, customer_ref=OTHER, tool_name=CREATE_PAYMENT_TOOL)
    elif case == "not_a_payment":
        challenge_id = await insert_row(produced, customer_ref=OWNER, tool_name="accounts.rename")
    elif case == "nul":
        challenge_id = "a\x00b"
    elif case == "traversal":
        challenge_id = "../x"
    elif case == "space":
        challenge_id = "a b"
    else:
        challenge_id = "x" * 37
    with pytest.raises(ToolError) as refused:
        await payment_status(produced)(challenge_id=challenge_id)
    assert str(refused.value) == CHALLENGE_NOT_FOUND


async def test_a_foreign_expired_row_is_refused_and_left_pending(produced: Database) -> None:
    """The expiry UPDATE must not run for a row the caller does not own: it
    would let one customer change another's row, and its outcome would differ
    from an unknown id's."""
    foreign = await insert_row(
        produced, customer_ref=OTHER, tool_name=CREATE_PAYMENT_TOOL, past_deadline=True
    )
    statements: list[str] = []

    def record(conn: object, cursor: object, statement: str, *rest: object) -> None:
        statements.append(statement.lstrip().split(None, 1)[0].upper())

    sync_engine = produced.engine.sync_engine
    event.listen(sync_engine, "before_cursor_execute", record)
    try:
        with pytest.raises(ToolError) as refused:
            await payment_status(produced)(challenge_id=foreign)
    finally:
        event.remove(sync_engine, "before_cursor_execute", record)
    assert str(refused.value) == CHALLENGE_NOT_FOUND
    assert statements
    assert set(statements) == {"SELECT"}
    assert await status_of(produced, foreign) == "pending"


@pytest.mark.parametrize(
    "payload",
    [
        ["amount", "currency"],
        "EUR 340.00",
        {"amount": "EUR 340.00"},
        {"amount": "340.00", "payee_name": "Payee"},
        {"amount": "340.00", "currency": "EUR"},
        {"amount": "340.00", "currency": "EUR", "payee_name": 7},
        {"amount": 340, "currency": "EUR", "payee_name": "Payee"},
    ],
    ids=[
        "list",
        "string",
        "legacy-amount-only",
        "missing-currency",
        "missing-payee-name",
        "non-str-payee-name",
        "non-str-amount",
    ],
)
async def test_an_unreadable_stored_payload_is_one_fixed_refusal(
    produced: Database, payload: object, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    challenge_id = await insert_row(
        produced, customer_ref=OWNER, tool_name=CREATE_PAYMENT_TOOL, payload=payload
    )
    with pytest.raises(ToolError) as refused:
        await payment_status(produced)(challenge_id=challenge_id)
    assert str(refused.value) == CHALLENGE_UNREADABLE
    ours = [r for r in caplog.records if r.name == "services.api.tools.payments"]
    assert len(ours) == 1
    assert ours[0].levelno == logging.ERROR
    assert ours[0].getMessage() == f"{PAYMENT_STATUS_TOOL} found an unreadable stored payment"


async def test_over_http_an_unreadable_stored_payload_is_the_fixed_text(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    await grant(produced, OWNER, "payments")
    token = token_for(key_pair, OWNER)
    ids = [
        await insert_row(
            produced, customer_ref=OWNER, tool_name=CREATE_PAYMENT_TOOL, payload=payload
        )
        for payload in (["a"], "EUR 1.00", {"amount": "1.00", "payee_name": "P"})
    ]
    ids.append(
        await insert_row(
            produced,
            customer_ref=OWNER,
            tool_name=CREATE_PAYMENT_TOOL,
            payload={"amount": "1.00", "currency": "EUR", "payee_name": 5},
        )
    )
    for challenge_id in ids:
        response = await call_tool(
            pg_url, key_pair, token, PAYMENT_STATUS_TOOL, {"challenge_id": challenge_id}
        )
        result = result_of(response)
        assert result["isError"] is True, response.text
        assert [block["text"] for block in result["content"]] == [CHALLENGE_UNREADABLE]


async def test_status_on_an_unreachable_store_is_a_fixed_refusal(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runtime = offline_runtime()
    caplog.set_level(logging.DEBUG)
    try:
        handler = build_get_payment_status(lambda: CustomerRef(value=OWNER), runtime)
        with pytest.raises(ToolError) as refused:
            await handler(challenge_id=uuid.uuid4().hex)
    finally:
        await runtime.db.close()
    assert str(refused.value) == CHALLENGE_UNREADABLE
    assert str(refused.value) != NOT_RECORDED
    ours = [r for r in caplog.records if r.name == "services.api.tools.payments"]
    assert len(ours) == 1
    assert ours[0].getMessage().startswith(f"{PAYMENT_STATUS_TOOL} could not read its challenge: ")
    assert ours[0].getMessage().rsplit(": ", 1)[1].isidentifier()
    assert ours[0].exc_info is None
    for forbidden in (OWNER, "cust_"):
        assert forbidden not in caplog.text


async def test_over_http_both_tools_are_listed_with_payments_consent(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    await grant(produced, OWNER, "payments")
    names = await list_tool_names(pg_url, key_pair, token_for(key_pair, OWNER))
    assert {CREATE_PAYMENT_TOOL, PAYMENT_STATUS_TOOL} <= names


async def test_over_http_the_ownership_refusals_are_byte_identical(
    pg_url: str, key_pair: RSAKeyPair, produced: Database, audit_server: FastMCP
) -> None:
    """A foreign id, another tool's id and an invented id must answer the same
    bytes: anything else confirms which ids exist to a holder of one valid
    customer token."""
    await grant(produced, OWNER, "payments")
    foreign = await insert_row(produced, customer_ref=OTHER, tool_name=CREATE_PAYMENT_TOOL)
    not_a_payment = await insert_row(produced, customer_ref=OWNER, tool_name="accounts.rename")
    unknown = uuid.uuid4().hex
    token = token_for(key_pair, OWNER)
    responses = [
        await call_tool(pg_url, key_pair, token, PAYMENT_STATUS_TOOL, {"challenge_id": cid})
        for cid in (foreign, not_a_payment, unknown)
    ]
    assert len({response.text for response in responses}) == 1
    assert [block["text"] for block in result_of(responses[0])["content"]] == [CHALLENGE_NOT_FOUND]


# -- Audit (spec section 8) --------------------------------------------------------


async def audit_rows(session: AsyncSession) -> list[AuditEntry]:
    result = await session.execute(select(AuditEntry).order_by(AuditEntry.id))
    return list(result.scalars().all())


async def test_a_proposal_writes_one_reaching_row_and_one_completion_row(
    pg_url: str,
    key_pair: RSAKeyPair,
    produced: Database,
    audit_server: FastMCP,
    session: AsyncSession,
) -> None:
    """Two backend reads, one entry row: `_PendingEntry` writes at most once
    per call. The challenge insert is the tool's own write and not an audit
    row, and the returned challenge id is not recorded (a non-goal)."""
    await grant(produced, OWNER, "payments")
    response = await call_tool(
        pg_url,
        key_pair,
        token_for(key_pair, OWNER),
        CREATE_PAYMENT_TOOL,
        {**ARGS, "reference": "Rent October"},
    )
    result = result_of(response)
    assert result["isError"] is False, response.text
    entries = await audit_rows(session)
    assert [(e.tool_name, e.outcome) for e in entries] == [
        (CREATE_PAYMENT_TOOL, "reaching"),
        (CREATE_PAYMENT_TOOL, "returned"),
    ]
    assert entries[0].call_id == entries[1].call_id
    assert entries[0].arguments == entries[1].arguments
    assert entries[0].arguments["reference"] == "Rent October"
    challenge_id = result["structuredContent"]["challenge_id"]
    assert all(challenge_id not in json.dumps(e.arguments) for e in entries)


async def test_a_call_refused_by_consent_writes_one_row(
    pg_url: str,
    key_pair: RSAKeyPair,
    produced: Database,
    audit_server: FastMCP,
    session: AsyncSession,
) -> None:
    await grant(produced, OWNER, "accounts")
    await call_tool(pg_url, key_pair, token_for(key_pair, OWNER), CREATE_PAYMENT_TOOL, ARGS)
    entries = await audit_rows(session)
    assert [(e.tool_name, e.outcome, e.detail, e.refusal_reason) for e in entries] == [
        (CREATE_PAYMENT_TOOL, "raised", "NotFoundError", REFUSAL_DOMAIN_NOT_CONSENTED)
    ]


# -- The stored row is what a phone signs ------------------------------------------

DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("producer-phone")
CONFIRM_ISSUER = "https://app.test.invalid"
CONFIRM_AUDIENCE = "postern-confirm"


async def test_the_stored_payload_signs_and_verifies_as_an_approval_message(
    produced: Database,
) -> None:
    await create_payment(produced)(**ARGS, reference="Rent October")
    (row,) = await rows(produced)
    assert all(isinstance(value, str) for value in row.payload.values())
    message = canonical_approval_message(
        challenge_id=row.challenge_id,
        customer_ref=row.customer_ref,
        tool_name=row.tool_name,
        payload=row.payload,
        expires_at=row.expires_at,
    )
    signature = decode_signature(sign_row(DEVICE_PRIVATE, row))
    assert signature is not None
    assert (
        verify_approval_signature(keys=(DEVICE_PUBLIC,), message=message, signature=signature)
        == DEVICE_PUBLIC
    )


def confirm_app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    settings = ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
    verifier = JWTVerifier(
        public_key=key_pair.public_key, issuer=CONFIRM_ISSUER, audience=CONFIRM_AUDIENCE
    )
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=enrolled_store(OWNER, DEVICE_PUBLIC),
    )


async def test_a_produced_challenge_is_approved_and_executes_the_stored_payload(
    pg_url: str,
    key_pair: RSAKeyPair,
    produced: Database,
    audit_server: FastMCP,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The whole path this slice opens: proposed through the api, approved
    through the real callback with a device signature over the stored row,
    and executed against a mock backend that receives exactly the stored
    payload. Tier 2 is not enforced at approval yet (spec section 2), which is
    why a signature alone suffices here."""
    await grant(produced, OWNER, "payments")
    created = result_of(
        await call_tool(
            pg_url,
            key_pair,
            token_for(key_pair, OWNER),
            CREATE_PAYMENT_TOOL,
            {**ARGS, "reference": "Rent October"},
        )
    )
    challenge_id = created["structuredContent"]["challenge_id"]
    (row,) = await rows(produced)

    sent: list[httpx2.Request] = []

    def backend(request: httpx2.Request) -> httpx2.Response:
        sent.append(request)
        return httpx2.Response(200, json={"status": "accepted"})

    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, transport=httpx2.MockTransport(backend), **kwargs)

    monkeypatch.setattr(BackendWriteClient, "__init__", patched)

    app = confirm_app(pg_url, key_pair)
    assertion = key_pair.create_token(
        subject=OWNER, issuer=CONFIRM_ISSUER, audience=CONFIRM_AUDIENCE, expires_in_seconds=60
    )
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        response = await client.post(
            f"/challenges/{challenge_id}/approve",
            json=await approval_body(produced, challenge_id, DEVICE_PRIVATE),
            headers={"Authorization": f"Bearer {assertion}"},
        )
    assert response.status_code == 200, response.text
    (request,) = sent
    assert (request.method, request.url.path) == ("POST", "/payments")
    assert json.loads(request.content) == row.payload
    status = await payment_status(produced)(challenge_id=challenge_id)
    assert status["status"] == "executed"

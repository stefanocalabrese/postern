"""The producer over HTTP: consent, the flag, annotations, and what a client receives."""

import json
import uuid

import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.identity import CustomerRef
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
)
from postern_core.store.engine import Database

from services.api.server import build_server
from services.api.settings import Settings
from services.api.tools.payments import (
    ACCOUNT_NOT_FOUND,
    CHALLENGE_NOT_FOUND,
    CHALLENGE_UNREADABLE,
)
from tests.fixtures.payments_http import (
    ARGS,
    OTHER,
    OWNER,
    SUMMARY,
    call_tool,
    grant,
    insert_row,
    list_tool_names,
    offline_runtime,
    post_rpc,
    producer_app,
    result_of,
    rows,
    status_of,
    stub_backend,
    token_for,
)

# `payments_key_pair` and `payments_produced` live in the shared module; loading it as a plugin
# registers them without importing the names into every signature's scope.
pytest_plugins = ["tests.fixtures.payments_http"]


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
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    await grant(payments_produced, OWNER, "payments")
    response = await call_tool(
        pg_url, payments_key_pair, token_for(payments_key_pair, OWNER), CREATE_PAYMENT_TOOL, ARGS
    )
    result = result_of(response)
    assert result["isError"] is False, response.text
    assert result["structuredContent"]["status"] == "pending"
    assert result["structuredContent"]["human_summary"] == SUMMARY
    (row,) = await rows(payments_produced)
    assert row.challenge_id == result["structuredContent"]["challenge_id"]
    assert (row.client_id, row.session_jti) == ("claude-code", "jti-test-1")


async def test_over_http_a_refusal_is_its_fixed_message_and_nothing_else(
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    await grant(payments_produced, OWNER, "payments")
    response = await call_tool(
        pg_url,
        payments_key_pair,
        token_for(payments_key_pair, OWNER),
        CREATE_PAYMENT_TOOL,
        {**ARGS, "from_account_ref": "acc_9b21"},
    )
    result = result_of(response)
    assert result["isError"] is True
    assert [block["text"] for block in result["content"]] == [ACCOUNT_NOT_FOUND]


async def test_without_payments_consent_the_tool_is_unlisted_and_unknown(
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    await grant(payments_produced, OWNER, "accounts")
    token = token_for(payments_key_pair, OWNER)
    assert CREATE_PAYMENT_TOOL not in await list_tool_names(pg_url, payments_key_pair, token)
    response = await call_tool(pg_url, payments_key_pair, token, CREATE_PAYMENT_TOOL, ARGS)
    assert [block["text"] for block in result_of(response)["content"]] == [
        f"Unknown tool: '{CREATE_PAYMENT_TOOL}'"
    ]
    assert await rows(payments_produced) == []


async def test_without_payments_consent_the_status_tool_is_unlisted_and_unknown(
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    await grant(payments_produced, OWNER, "accounts")
    expired = await insert_row(
        payments_produced, customer_ref=OWNER, tool_name=CREATE_PAYMENT_TOOL, past_deadline=True
    )
    token = token_for(payments_key_pair, OWNER)
    assert PAYMENT_STATUS_TOOL not in await list_tool_names(pg_url, payments_key_pair, token)
    response = await call_tool(
        pg_url, payments_key_pair, token, PAYMENT_STATUS_TOOL, {"challenge_id": expired}
    )
    assert [block["text"] for block in result_of(response)["content"]] == [
        f"Unknown tool: '{PAYMENT_STATUS_TOOL}'"
    ]
    assert await status_of(payments_produced, expired) == "pending"


async def test_with_payments_consent_the_tool_is_listed(
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    await grant(payments_produced, OWNER, "payments")
    names = await list_tool_names(pg_url, payments_key_pair, token_for(payments_key_pair, OWNER))
    assert CREATE_PAYMENT_TOOL in names


async def test_with_the_flag_off_the_producer_is_not_registered(
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    await grant(payments_produced, OWNER, "payments")
    names = await list_tool_names(
        pg_url, payments_key_pair, token_for(payments_key_pair, OWNER), payments_enabled=False
    )
    assert names == {"start_session"}


async def test_a_proposal_completes_through_a_pool_of_one(
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    """No reserve, one connection, no overflow: the consent probe, the entry
    audit row, the tool's transaction and the completion row must each take
    the connection and give it back, because any overlap waits out the pool
    timeout and fails the call."""
    await grant(payments_produced, OWNER, "payments")
    response = await call_tool(
        pg_url,
        payments_key_pair,
        token_for(payments_key_pair, OWNER),
        CREATE_PAYMENT_TOOL,
        ARGS,
        database_pool_size=1,
        database_max_overflow=0,
        database_audit_reserve_size=0,
    )
    assert result_of(response)["isError"] is False, response.text


@pytest.mark.parametrize("tool_name", [CREATE_PAYMENT_TOOL, PAYMENT_STATUS_TOOL])
async def test_the_registered_tool_declares_exactly_these_annotations(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    tool_name: str,
) -> None:
    await grant(payments_produced, OWNER, "payments")
    app = producer_app(pg_url, payments_key_pair)
    response = await post_rpc(app, token_for(payments_key_pair, OWNER), "tools/list", {})
    (tool,) = [t for t in json.loads(response.text)["result"]["tools"] if t["name"] == tool_name]
    annotations = tool["annotations"]
    assert (
        annotations["readOnlyHint"],
        annotations["destructiveHint"],
        annotations["idempotentHint"],
        annotations["openWorldHint"],
    ) == (False, False, True, False)


async def test_over_http_an_unreadable_stored_payload_is_the_fixed_text(
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    await grant(payments_produced, OWNER, "payments")
    token = token_for(payments_key_pair, OWNER)
    ids = [
        await insert_row(
            payments_produced, customer_ref=OWNER, tool_name=CREATE_PAYMENT_TOOL, payload=payload
        )
        for payload in (["a"], "EUR 1.00", {"amount": "1.00", "payee_name": "P"})
    ]
    ids.append(
        await insert_row(
            payments_produced,
            customer_ref=OWNER,
            tool_name=CREATE_PAYMENT_TOOL,
            payload={"amount": "1.00", "currency": "EUR", "payee_name": 5},
        )
    )
    for challenge_id in ids:
        response = await call_tool(
            pg_url, payments_key_pair, token, PAYMENT_STATUS_TOOL, {"challenge_id": challenge_id}
        )
        result = result_of(response)
        assert result["isError"] is True, response.text
        assert [block["text"] for block in result["content"]] == [CHALLENGE_UNREADABLE]


async def test_over_http_both_tools_are_listed_with_payments_consent(
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    await grant(payments_produced, OWNER, "payments")
    names = await list_tool_names(pg_url, payments_key_pair, token_for(payments_key_pair, OWNER))
    assert {CREATE_PAYMENT_TOOL, PAYMENT_STATUS_TOOL} <= names


async def test_over_http_the_ownership_refusals_are_byte_identical(
    pg_url: str, payments_key_pair: RSAKeyPair, payments_produced: Database, audit_server: FastMCP
) -> None:
    """A foreign id, another tool's id and an invented id must answer the same
    bytes: anything else confirms which ids exist to a holder of one valid
    customer token."""
    await grant(payments_produced, OWNER, "payments")
    foreign = await insert_row(payments_produced, customer_ref=OTHER, tool_name=CREATE_PAYMENT_TOOL)
    not_a_payment = await insert_row(
        payments_produced, customer_ref=OWNER, tool_name="accounts.rename"
    )
    unknown = uuid.uuid4().hex
    token = token_for(payments_key_pair, OWNER)
    responses = [
        await call_tool(
            pg_url, payments_key_pair, token, PAYMENT_STATUS_TOOL, {"challenge_id": cid}
        )
        for cid in (foreign, not_a_payment, unknown)
    ]
    assert len({response.text for response in responses}) == 1
    assert [block["text"] for block in result_of(responses[0])["content"]] == [CHALLENGE_NOT_FOUND]

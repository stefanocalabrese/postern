"""The status tool, at handler level, plus the one interleaving only HTTP reaches."""

import json
import logging
import uuid
from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.identity import CustomerRef
from postern_core.payments import (
    CREATE_PAYMENT_TOOL,
    PAYMENT_STATUS_TOOL,
)
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession

from services.api.tools.payments import (
    CHALLENGE_NOT_FOUND,
    CHALLENGE_UNREADABLE,
    NOT_RECORDED,
    build_get_payment_status,
)
from tests.fixtures.payments_http import (
    ARGS,
    OTHER,
    OWNER,
    call_tool,
    create_payment,
    grant,
    insert_row,
    offline_runtime,
    payment_status,
    result_of,
    rows,
    status_of,
    token_for,
)

# `payments_key_pair` and `payments_produced` live in the shared module; loading it as a plugin
# registers them without importing the names into every signature's scope.
pytest_plugins = ["tests.fixtures.payments_http"]


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


async def test_status_reports_a_pending_proposal_from_the_stored_row(
    payments_produced: Database,
) -> None:
    created = await create_payment(payments_produced)(**ARGS, reference="Rent October")
    status = await payment_status(payments_produced)(challenge_id=created["challenge_id"])
    assert status == {
        "challenge_id": created["challenge_id"],
        "status": "pending",
        "expires_at": created["expires_at"],
        "amount": "340.50",
        "currency": "EUR",
        "payee_name": "Northwind Energy DE•• •••• 3000",
        "reference": "Rent October",
    }


async def test_status_without_a_reference_reports_none(payments_produced: Database) -> None:
    created = await create_payment(payments_produced)(**ARGS)
    status = await payment_status(payments_produced)(challenge_id=created["challenge_id"])
    assert status["reference"] is None


async def test_status_expires_a_row_past_its_deadline(payments_produced: Database) -> None:
    created = await create_payment(payments_produced)(**ARGS)
    async with payments_produced.sessionmaker() as s:
        await s.execute(
            text(
                "UPDATE challenges SET expires_at = now() - interval '1 second' "
                "WHERE challenge_id = :c"
            ),
            {"c": created["challenge_id"]},
        )
        await s.commit()
    status = await payment_status(payments_produced)(challenge_id=created["challenge_id"])
    assert status["status"] == "expired"
    (row,) = await rows(payments_produced)
    assert row.status == "expired"


async def test_an_approved_row_whose_execution_failed_stays_approved(
    payments_produced: Database,
) -> None:
    """The callback answers 207 and leaves the row `approved` when the backend
    write fails. No status is invented on top of that."""
    created = await create_payment(payments_produced)(**ARGS)
    async with payments_produced.sessionmaker() as s:
        await store.update_challenge_status(
            s,
            created["challenge_id"],
            status="approved",
            expected_status="pending",
            expiry="unexpired",
        )
        await s.commit()
    status = await payment_status(payments_produced)(challenge_id=created["challenge_id"])
    assert status["status"] == "approved"


async def test_status_never_returns_the_approval_or_the_session_record(
    payments_produced: Database,
) -> None:
    created = await create_payment(payments_produced)(**ARGS)
    async with payments_produced.sessionmaker() as s:
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
    status = await payment_status(payments_produced)(challenge_id=created["challenge_id"])
    assert set(status) == STATUS_FIELDS
    (row,) = await rows(payments_produced)
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
    payments_produced: Database, case: str
) -> None:
    if case == "unknown":
        challenge_id = uuid.uuid4().hex
    elif case == "foreign":
        challenge_id = await insert_row(
            payments_produced, customer_ref=OTHER, tool_name=CREATE_PAYMENT_TOOL
        )
    elif case == "not_a_payment":
        challenge_id = await insert_row(
            payments_produced, customer_ref=OWNER, tool_name="accounts.rename"
        )
    elif case == "nul":
        challenge_id = "a\x00b"
    elif case == "traversal":
        challenge_id = "../x"
    elif case == "space":
        challenge_id = "a b"
    else:
        challenge_id = "x" * 37
    with pytest.raises(ToolError) as refused:
        await payment_status(payments_produced)(challenge_id=challenge_id)
    assert str(refused.value) == CHALLENGE_NOT_FOUND


async def test_a_foreign_expired_row_is_refused_and_left_pending(
    payments_produced: Database,
) -> None:
    """The expiry UPDATE must not run for a row the caller does not own: it
    would let one customer change another's row, and its outcome would differ
    from an unknown id's."""
    foreign = await insert_row(
        payments_produced, customer_ref=OTHER, tool_name=CREATE_PAYMENT_TOOL, past_deadline=True
    )
    statements: list[str] = []

    def record(conn: object, cursor: object, statement: str, *rest: object) -> None:
        statements.append(statement.lstrip().split(None, 1)[0].upper())

    sync_engine = payments_produced.engine.sync_engine
    event.listen(sync_engine, "before_cursor_execute", record)
    try:
        with pytest.raises(ToolError) as refused:
            await payment_status(payments_produced)(challenge_id=foreign)
    finally:
        event.remove(sync_engine, "before_cursor_execute", record)
    assert str(refused.value) == CHALLENGE_NOT_FOUND
    assert statements
    assert set(statements) == {"SELECT"}
    assert await status_of(payments_produced, foreign) == "pending"


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
    payments_produced: Database, payload: object, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    challenge_id = await insert_row(
        payments_produced, customer_ref=OWNER, tool_name=CREATE_PAYMENT_TOOL, payload=payload
    )
    with pytest.raises(ToolError) as refused:
        await payment_status(payments_produced)(challenge_id=challenge_id)
    assert str(refused.value) == CHALLENGE_UNREADABLE
    ours = [r for r in caplog.records if r.name == "services.api.tools.payments"]
    assert len(ours) == 1
    assert ours[0].levelno == logging.ERROR
    assert ours[0].getMessage() == f"{PAYMENT_STATUS_TOOL} found an unreadable stored payment"


async def test_over_http_an_approval_that_races_the_expiry_update_is_reported_approved(
    pg_url: str,
    payments_key_pair: RSAKeyPair,
    payments_produced: Database,
    audit_server: FastMCP,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The row is pending and past its deadline when the handler reads it. An
    approval commits between that read and the handler's conditional expiry
    UPDATE, so the UPDATE matches nothing, and the handler's own session still
    holds the `pending` copy it loaded. The answer must be the committed
    `approved`, which only the re-read with `refresh=True` produces.

    The interleaving is forced, not timed: `update_challenge_status` is wrapped
    so that its first call from the status handler commits the approval through
    a separate session before running the real UPDATE."""
    await grant(payments_produced, OWNER, "payments")
    token = token_for(payments_key_pair, OWNER)
    challenge_id = await insert_row(
        payments_produced, customer_ref=OWNER, tool_name=CREATE_PAYMENT_TOOL, past_deadline=True
    )
    real_update = store.update_challenge_status
    raced: list[str] = []

    async def approve_first(session: AsyncSession, cid: str, **kwargs: Any) -> Any:
        if kwargs.get("status") == "expired" and not raced:
            raced.append(cid)
            async with payments_produced.sessionmaker() as other:
                # Plain SQL: the row is past its deadline, which the store's
                # own transition would refuse, and this test needs it committed.
                await other.execute(
                    text(
                        "UPDATE challenges SET status = 'approved' "
                        "WHERE challenge_id = :c AND status = 'pending'"
                    ),
                    {"c": cid},
                )
                await other.commit()
        return await real_update(session, cid, **kwargs)

    monkeypatch.setattr(store, "update_challenge_status", approve_first)
    response = await call_tool(
        pg_url, payments_key_pair, token, PAYMENT_STATUS_TOOL, {"challenge_id": challenge_id}
    )
    assert raced == [challenge_id]
    result = result_of(response)
    assert result.get("isError") is not True, response.text
    assert result["structuredContent"]["status"] == "approved", response.text
    assert await status_of(payments_produced, challenge_id) == "approved"


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

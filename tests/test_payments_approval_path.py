"""The producer's audit rows, the payload a phone signs, and the approval path end to end."""

import json
from typing import Any

import httpx2
import pytest
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from joserfc import jwt
from joserfc.jwk import KeySet
from postern_core.auth.approval_signature import (
    canonical_approval_message,
    decode_signature,
    verify_approval_signature,
)
from postern_core.payments import (
    CREATE_PAYMENT_TOOL,
    PAYMENT_TIER,
)
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from postern_core.store.models import REFUSAL_DOMAIN_NOT_CONSENTED, AuditEntry
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.applications import Starlette

from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from stub import backend as stub
from tests.fixtures.device_keys import (
    approval_body,
    device_key,
    enrolled_store,
    sign_fields,
    sign_row,
)
from tests.fixtures.payments_http import (
    ARGS,
    OWNER,
    call_tool,
    create_payment,
    grant,
    payment_status,
    result_of,
    rows,
    token_for,
)

# `key_pair` and `produced` live in the shared module; loading it as a plugin
# registers them without importing the names into every signature's scope.
pytest_plugins = ["tests.fixtures.payments_http"]


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
    # The reaching row carries the last reading taken before the backend touch,
    # which cannot precede the call's arrival; the completion row carries none.
    assert entries[0].reaching_at is not None
    assert entries[0].reaching_at >= entries[0].at
    assert entries[1].reaching_at is None
    assert {e.customer_ref for e in entries} == {OWNER}
    assert {e.client_id for e in entries} == {"claude-code"}


async def test_a_pan_and_an_iban_in_the_reference_are_not_stored_in_the_audit_arguments(
    pg_url: str,
    key_pair: RSAKeyPair,
    produced: Database,
    audit_server: FastMCP,
    session: AsyncSession,
) -> None:
    await grant(produced, OWNER, "payments")
    response = await call_tool(
        pg_url,
        key_pair,
        token_for(key_pair, OWNER),
        CREATE_PAYMENT_TOOL,
        {**ARGS, "reference": f"Invoice {stub.FULL_PAN} to {stub.GROUPED_IBAN}"},
    )
    assert result_of(response)["isError"] is False, response.text
    entries = await audit_rows(session)
    assert len(entries) == 2
    for entry in entries:
        stored = json.dumps(entry.arguments)
        assert stub.FULL_PAN not in stored
        assert stub.GROUPED_IBAN not in stored
        assert stub.FULL_IBAN not in stored


async def test_a_call_refused_by_consent_writes_one_row(
    pg_url: str,
    key_pair: RSAKeyPair,
    produced: Database,
    audit_server: FastMCP,
    session: AsyncSession,
) -> None:
    await grant(produced, OWNER, "accounts")
    response = await call_tool(
        pg_url, key_pair, token_for(key_pair, OWNER), CREATE_PAYMENT_TOOL, ARGS
    )
    assert [block["text"] for block in result_of(response)["content"]] == [
        "Unknown tool: 'payments.create_payment'"
    ]
    entries = await audit_rows(session)
    assert [(e.tool_name, e.outcome, e.detail, e.refusal_reason) for e in entries] == [
        (CREATE_PAYMENT_TOOL, "raised", "NotFoundError", REFUSAL_DOMAIN_NOT_CONSENTED)
    ]
    assert await rows(produced) == []


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
    assert set(row.payload) == {
        "from_account_ref",
        "payee_ref",
        "payee_name",
        "amount",
        "currency",
        "reference",
    }
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

    # The same signature must stop verifying once the stored payload changes:
    # the message is rebuilt from the re-read row, as the callback does.
    async with produced.sessionmaker() as s:
        await s.execute(
            text(
                "UPDATE challenges SET payload = jsonb_set(payload, '{currency}', '\"GBP\"') "
                "WHERE challenge_id = :c"
            ),
            {"c": row.challenge_id},
        )
        await s.commit()
    (altered,) = await rows(produced)
    assert altered.payload["currency"] == "GBP"
    altered_message = canonical_approval_message(
        challenge_id=altered.challenge_id,
        customer_ref=altered.customer_ref,
        tool_name=altered.tool_name,
        payload=altered.payload,
        expires_at=altered.expires_at,
    )
    assert altered_message != message
    assert (
        verify_approval_signature(
            keys=(DEVICE_PUBLIC,), message=altered_message, signature=signature
        )
        is None
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

    # Confirm does not read the tier yet; this pins the stored value for when
    # enforcement lands.
    assert row.tier == PAYMENT_TIER

    app = confirm_app(pg_url, key_pair)
    assertion = key_pair.create_token(
        subject=OWNER, issuer=CONFIRM_ISSUER, audience=CONFIRM_AUDIENCE, expires_in_seconds=60
    )
    headers = {"Authorization": f"Bearer {assertion}"}
    approve = f"/challenges/{challenge_id}/approve"
    other_private, _ = device_key("other")
    altered_signature = sign_fields(
        DEVICE_PRIVATE,
        challenge_id=row.challenge_id,
        customer_ref=row.customer_ref,
        tool_name=row.tool_name,
        payload={**row.payload, "currency": "GBP"},
        expires_at=row.expires_at,
    )
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        # Refused before the claim: a key that is not enrolled, and an
        # enrolled key signing bytes other than the stored row's.
        for bad in (
            await approval_body(produced, challenge_id, other_private),
            {"signature": altered_signature},
        ):
            refused = await client.post(approve, json=bad, headers=headers)
            assert refused.status_code == 403, refused.text
            assert refused.json()["error"] == "invalid_signature"
            async with produced.sessionmaker() as s:
                still = await store.get_challenge(s, challenge_id)
            assert still is not None
            assert still.status == "pending"
            assert sent == []

        body = await approval_body(produced, challenge_id, DEVICE_PRIVATE)
        response = await client.post(approve, json=body, headers=headers)
        assert response.status_code == 200, response.text
        (request,) = sent
        assert (request.method, request.url.path) == ("POST", "/payments")
        assert json.loads(request.content) == row.payload
        assert request.headers["Idempotency-Key"] == challenge_id

        # The bearer the executor sent, verified against the write key this
        # confirm app publishes.
        jwks = (await client.get("/.well-known/jwks.json")).json()
        bearer = request.headers["Authorization"].removeprefix("Bearer ")
        claims = jwt.decode(bearer, KeySet.import_key_set(jwks), algorithms=["RS256"]).claims
        assert claims["aud"] == "payments.svc"
        assert claims["scope"] == "payments:execute"
        assert claims["sub"] == OWNER
        assert claims["challenge_id"] == challenge_id

        # The same approval again is refused by the row and reaches nothing.
        again = await client.post(approve, json=body, headers=headers)
        assert again.status_code == 409, again.text
        assert again.json()["error"] == "already_terminal"
        assert len(sent) == 1
    status = await payment_status(produced)(challenge_id=challenge_id)
    assert status["status"] == "executed"

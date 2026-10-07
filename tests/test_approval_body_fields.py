"""Body fields of an approval: refused before the claim, and no exception text out.

`confirming_device` (`String(128)`) and `verification_result` (`Text`) went
from the request body to the claiming UPDATE unchecked, so a wrong type, a NUL
or an over-long device made the driver raise and the 500 carried the SQL and
its bound parameters. These tests drive the real confirm app and Postgres.
"""

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx2
import pytest
import pytest_asyncio
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.payments import CREATE_PAYMENT_TOOL
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ChallengeRecord
from sqlalchemy import select, text
from starlette.applications import Starlette

from services.confirm import callback
from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.device_keys import device_key, enrolled_store, sign_row

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
OWNER = "cust_bodyfields"
IDV = "postern-dev-idv"
TIER_1_TOOL = "standing_orders.cancel"
TIER_1_PAYLOAD: dict[str, Any] = {"order_id": "so_bodyfields"}
TIER_2_PAYLOAD: dict[str, Any] = {
    "from_account_ref": "acc_bodyfields",
    "payee_ref": "payee_bodyfields",
    "payee_name": "Northwind Energy",
    "amount": "10.00",
    "currency": "EUR",
    "reference": "Rent October",
}
SENTINEL = "secret_sentinel"
#: What a driver error looks like: the statement and its bound parameters.
DRIVER_MESSAGE = (
    "SELECT secret_sentinel FROM challenges WHERE x = $1 [parameters: (secret_sentinel,)]"
)

DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("bodyfields-phone")


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest_asyncio.fixture
async def db(database: Database) -> AsyncIterator[Database]:
    yield database
    async with database.sessionmaker() as s:
        await s.execute(text("DELETE FROM challenges WHERE challenge_id LIKE 'bf_%'"))
        await s.commit()


@pytest.fixture()
def sent(monkeypatch: pytest.MonkeyPatch) -> list[httpx2.Request]:
    calls: list[httpx2.Request] = []

    def backend(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json={"status": "accepted"})

    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, transport=httpx2.MockTransport(backend), **kwargs)

    monkeypatch.setattr(BackendWriteClient, "__init__", patched)
    return calls


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    settings = ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
        idv_value=IDV,
    )
    return create_confirm_app(
        settings,
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=enrolled_store(OWNER, DEVICE_PUBLIC),
    )


_counter = iter(range(10**9))


def new_challenge_id() -> str:
    """No digit after the prefix: the audit scrub masks some digit runs."""
    n = next(_counter)
    return "bf_" + "".join("abcdefghij"[int(d)] for d in str(n)) + "_xyz"


async def seed(db: Database, *, tier: int) -> ChallengeRecord:
    async with db.sessionmaker() as s:
        record = await store.create_challenge(
            s,
            challenge_id=new_challenge_id(),
            customer_ref=OWNER,
            tool_name=TIER_1_TOOL if tier == 1 else CREATE_PAYMENT_TOOL,
            payload=dict(TIER_1_PAYLOAD if tier == 1 else TIER_2_PAYLOAD),
            tier=tier,
        )
        await s.commit()
    return record


def bearer(key_pair: RSAKeyPair, claims: dict[str, Any] | None = None) -> dict[str, str]:
    token = key_pair.create_token(
        subject=OWNER,
        issuer=ISSUER,
        audience=AUDIENCE,
        expires_in_seconds=60,
        additional_claims=claims or None,
    )
    return {"Authorization": f"Bearer {token}"}


def tier2_claims(record: ChallengeRecord) -> dict[str, Any]:
    return {
        "idv": IDV,
        "challenge_id": record.challenge_id,
        "jti": "jti-bodyfields-0001",
        "auth_time": record.created_at.timestamp(),
    }


async def approve(
    app: Starlette,
    record: ChallengeRecord,
    headers: dict[str, str],
    *,
    as_a_server_would: bool = False,
    **extra: Any,
) -> httpx2.Response:
    body = {"signature": sign_row(DEVICE_PRIVATE, record), **extra}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=not as_a_server_would),
        base_url="http://t",
    ) as client:
        return await client.post(
            f"/challenges/{record.challenge_id}/approve", json=body, headers=headers
        )


async def stored(db: Database, challenge_id: str) -> ChallengeRecord:
    async with db.sessionmaker() as s:
        row = await store.get_challenge(s, challenge_id)
    assert row is not None
    return row


async def audit_rows(db: Database, challenge_id: str) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(select(AuditEntry).order_by(AuditEntry.id))
        entries = list(result.scalars().all())
    return [e for e in entries if e.arguments.get("challenge_id") == challenge_id]


async def assert_refused_field(
    response: httpx2.Response,
    field: str,
    db: Database,
    record: ChallengeRecord,
    sent: list[httpx2.Request],
    value: Any,
) -> None:
    assert response.status_code == 400, response.text
    payload = response.json()
    assert payload["error"] == "invalid_request"
    assert field in payload["error_description"]
    lowered = response.text.lower()
    for leaked in ("select", "insert", "update", "asyncpg", "sqlalchemy", "parameters"):
        assert leaked not in lowered
    if isinstance(value, str) and len(value) > 3:
        assert value not in response.text
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []
    (row,) = await audit_rows(db, record.challenge_id)
    assert (row.outcome, row.detail) == ("raised", "body_field_invalid")


BAD_VERIFICATION_RESULTS: list[Any] = [
    pytest.param(7, id="int"),
    pytest.param(["a"], id="list"),
    pytest.param({"a": "b"}, id="dict"),
    pytest.param(True, id="bool"),
    pytest.param("abc\x00def", id="nul"),
    pytest.param("abc\ndef", id="newline"),
]


@pytest.mark.parametrize("value", BAD_VERIFICATION_RESULTS)
async def test_a_malformed_verification_result_is_refused_before_the_claim(
    value: Any,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    record = await seed(db, tier=1)
    response = await approve(app, record, bearer(key_pair), verification_result=value)
    await assert_refused_field(response, "verification_result", db, record, sent, value)


BAD_DEVICES: list[Any] = [
    pytest.param(7, id="int"),
    pytest.param("d" * 129, id="129-characters"),
    pytest.param("", id="empty"),
    pytest.param("dev\x00ice", id="nul"),
]


@pytest.mark.parametrize("value", BAD_DEVICES)
async def test_a_malformed_confirming_device_is_refused_before_the_claim(
    value: Any,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    record = await seed(db, tier=1)
    response = await approve(app, record, bearer(key_pair), confirming_device=value)
    await assert_refused_field(response, "confirming_device", db, record, sent, value)


async def test_a_confirming_device_of_128_characters_is_accepted(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db, tier=1)
    response = await approve(app, record, bearer(key_pair), confirming_device="d" * 128)
    assert response.status_code == 200, response.text
    row = await stored(db, record.challenge_id)
    assert row.confirming_device == "d" * 128
    assert len(sent) == 1


async def test_valid_values_are_stored_unchanged(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db, tier=1)
    response = await approve(
        app,
        record,
        bearer(key_pair),
        confirming_device="phone-1",
        verification_result="selfie ok: 0.98",
    )
    assert response.status_code == 200, response.text
    row = await stored(db, record.challenge_id)
    assert (row.confirming_device, row.verification_result) == ("phone-1", "selfie ok: 0.98")


@pytest.mark.parametrize("value", [None, "abc\x00def", 7])
async def test_a_tier_2_body_verification_result_is_ignored_and_not_validated(
    value: Any,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    record = await seed(db, tier=2)
    response = await approve(
        app, record, bearer(key_pair, tier2_claims(record)), verification_result=value
    )
    assert response.status_code == 200, response.text
    assert (await stored(db, record.challenge_id)).verification_result == "jti-bodyfields-0001"
    assert len(sent) == 1


async def test_a_database_error_returns_no_exception_text(
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def boom(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError(DRIVER_MESSAGE)

    monkeypatch.setattr(callback, "update_challenge_status", boom)
    record = await seed(db, tier=1)
    response = await approve(app, record, bearer(key_pair), as_a_server_would=True)
    assert response.status_code == 500, response.text
    assert response.json()["error"] == "internal_error"
    assert SENTINEL not in response.text
    assert "SELECT" not in response.text
    assert "parameters" not in response.text
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []
    (row,) = await audit_rows(db, record.challenge_id)
    assert (row.outcome, row.detail) == ("raised", "RuntimeError")
    assert SENTINEL not in json.dumps(row.arguments)


async def test_an_execution_setup_error_returns_no_exception_text(
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The claim has committed by then, so the row is left `approved`."""

    def boom(*args: Any, **kwargs: Any) -> None:
        raise ValueError("SENTINEL_SETUP_TEXT")

    monkeypatch.setattr(callback, "resolve_endpoint", boom)
    record = await seed(db, tier=1)
    response = await approve(app, record, bearer(key_pair))
    assert response.status_code == 500, response.text
    assert response.json() == {
        "error": "internal_error",
        "error_description": "the approved operation could not be set up",
    }
    assert "SENTINEL_SETUP_TEXT" not in response.text
    assert (await stored(db, record.challenge_id)).status == "approved"
    assert sent == []
    (row,) = await audit_rows(db, record.challenge_id)
    assert (row.outcome, row.detail) == ("raised", "ValueError")

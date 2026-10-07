"""Body fields of an approval: refused before the claim, and no exception text out.

`confirming_device` (`String(128)`) and `verification_result` (`Text`) went
from the request body to the claiming UPDATE unchecked, so a wrong type, a NUL
or an over-long device made the driver raise and the 500 carried the SQL and
its bound parameters. These tests drive the real confirm app and Postgres.
"""

import json
import logging
import traceback
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote

import httpx2
import pytest
import pytest_asyncio
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.payments import CREATE_PAYMENT_TOOL
from postern_core.store import audit as audit_store
from postern_core.store import challenges as store
from postern_core.store.audit import bound_arguments
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry, ChallengeRecord
from sqlalchemy import func, select, text
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
OTHER_PRIVATE, _OTHER_PUBLIC = device_key("bodyfields-not-enrolled")


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


async def seed(db: Database, *, tier: int, customer_ref: str = OWNER) -> ChallengeRecord:
    async with db.sessionmaker() as s:
        record = await store.create_challenge(
            s,
            challenge_id=new_challenge_id(),
            customer_ref=customer_ref,
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
    signer: Any = DEVICE_PRIVATE,
    raw_body: bytes | None = None,
    **extra: Any,
) -> httpx2.Response:
    """POST the approval; ``raw_body`` replaces the JSON built from ``extra``."""
    body = {"signature": sign_row(signer, record), **extra}
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=not as_a_server_would),
        base_url="http://t",
    ) as client:
        if raw_body is not None:
            return await client.post(
                f"/challenges/{record.challenge_id}/approve",
                content=raw_body,
                headers={**headers, "Content-Type": "application/json"},
            )
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
    assert response.json() == {
        "error": "internal_error",
        "error_description": "the approval could not be recorded",
    }
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


# -- Non-finite JSON numbers ---------------------------------------------------------
#
# `request.json()` accepts NaN, Infinity and -Infinity, PostgreSQL refuses them
# in JSONB, and the audit write then failed with no row. Refused at parse time
# they are a malformed body, which is decided BEFORE the challenge is looked
# at: a foreign challenge with such a body gets a 400 `malformed_body` row, not
# the 404 a well formed body would get, and the 404's oracle is not touched
# because the body is refused for every caller alike.


def raw_with(record: ChallengeRecord, field: str, constant: str) -> bytes:
    signature = sign_row(DEVICE_PRIVATE, record)
    return ('{"signature": "' + signature + '", "' + field + '": ' + constant + "}").encode()


NON_FINITE = ["NaN", "Infinity", "-Infinity"]
FIELDS = ["confirming_device", "verification_result"]


@pytest.mark.parametrize("target", ["foreign", "tier-1", "tier-2"])
@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("constant", NON_FINITE)
async def test_a_non_finite_number_is_a_malformed_body_with_a_row_and_no_claim(
    constant: str,
    field: str,
    target: str,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    if target == "foreign":
        record = await seed(db, tier=1, customer_ref="cust_someone_else")
        headers = bearer(key_pair)
    elif target == "tier-1":
        record = await seed(db, tier=1)
        headers = bearer(key_pair)
    else:
        record = await seed(db, tier=2)
        headers = bearer(key_pair, tier2_claims(record))
    response = await approve(app, record, headers, raw_body=raw_with(record, field, constant))
    assert response.status_code == 400, response.text
    assert response.json() == {
        "error": "invalid_request",
        "error_description": "body must be a JSON object",
    }
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []
    (row,) = await audit_rows(db, record.challenge_id)
    assert (row.outcome, row.detail) == ("raised", "malformed_body")


async def test_the_audit_arguments_survive_a_non_finite_number_that_got_past_the_parser(
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence in depth: with the parse-time refusal bypassed, the row is still written."""
    record = await seed(db, tier=1)
    signature = sign_row(DEVICE_PRIVATE, record)

    async def parsed(request: Any) -> dict[str, Any]:
        return {"signature": signature, "confirming_device": float("nan")}

    monkeypatch.setattr(callback, "_read_body", parsed)
    response = await approve(app, record, bearer(key_pair))
    assert response.status_code == 400, response.text
    assert (await stored(db, record.challenge_id)).status == "pending"
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "body_field_invalid"
    assert row.arguments["confirming_device"] == "NaN"


@pytest.mark.parametrize("constant", [float("inf"), float("-inf")])
async def test_a_tier_2_approval_is_not_stranded_by_a_non_finite_unvalidated_field(
    constant: float,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tier-2 body `verification_result` is not validated but is audited."""
    record = await seed(db, tier=2)
    signature = sign_row(DEVICE_PRIVATE, record)

    async def parsed(request: Any) -> dict[str, Any]:
        return {"signature": signature, "verification_result": constant}

    monkeypatch.setattr(callback, "_read_body", parsed)
    response = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert response.status_code == 200, response.text
    assert [e.outcome for e in await audit_rows(db, record.challenge_id)] == [
        "reaching",
        "returned",
    ]


def test_bound_arguments_replaces_non_finite_floats_and_leaves_finite_ones() -> None:
    tree = {
        "a": float("nan"),
        "b": [float("inf"), {"c": float("-inf")}],
        "d": 1.5,
        "e": 3,
        "f": True,
    }
    out = bound_arguments(tree)
    assert out == {"a": "NaN", "b": ["Infinity", {"c": "-Infinity"}], "d": 1.5, "e": 3, "f": True}
    json.dumps(out, allow_nan=False)


# -- Audit failures log the type only ------------------------------------------------


def assert_no_sentinel_anywhere(caplog: pytest.LogCaptureFixture) -> None:
    for record in caplog.records:
        rendered = [record.getMessage(), record.exc_text or "", str(record.args)]
        if record.exc_info is not None:
            rendered.append("".join(traceback.format_exception(*record.exc_info)))
        for text_ in rendered:
            assert "secret_sentinel" not in text_


@pytest.mark.parametrize("only_the_completion_row_fails", [False, True])
async def test_an_audit_write_failure_logs_and_raises_the_type_name_only(
    only_the_completion_row_fails: bool,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_append = audit_store.append

    async def failing(session: Any, **kw: Any) -> None:
        if only_the_completion_row_fails and kw["outcome"] == "reaching":
            await real_append(session, **kw)
            return
        raise RuntimeError(DRIVER_MESSAGE)

    monkeypatch.setattr(audit_store, "append", failing)
    record = await seed(db, tier=1)
    with caplog.at_level(logging.WARNING):
        with pytest.raises(RuntimeError) as caught:
            await approve(app, record, bearer(key_pair))
    # What escapes is the original exception (decision 0006 and the class
    # `tests/test_audit_reserve.py` pins), so its own text is in the
    # traceback and is not asserted on here. The audit exception is not
    # chained onto it when the approval itself raised.
    if not only_the_completion_row_fails:
        assert caught.value.__cause__ is None
        assert caught.value.__suppress_context__
        assert "".join(traceback.format_exception(caught.value)).count("secret_sentinel") == 2
    assert any("RuntimeError" in r.getMessage() for r in caplog.records if r.levelno >= 40)
    assert_no_sentinel_anywhere(caplog)


# -- The step-2d warning -------------------------------------------------------------


async def test_the_body_field_warning_names_the_field_and_not_the_value(
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
    caplog: pytest.LogCaptureFixture,
) -> None:
    record = await seed(db, tier=1)
    with caplog.at_level(logging.WARNING, logger="services.confirm.callback"):
        response = await approve(
            app, record, bearer(key_pair), confirming_device="OFFENDING_VALUE\x00"
        )
    assert response.status_code == 400
    messages = [r.getMessage() for r in caplog.records if r.name == "services.confirm.callback"]
    assert any("confirming_device" in m for m in messages)
    assert not any("OFFENDING_VALUE" in m for m in messages)


# -- Where step 2d sits --------------------------------------------------------------


async def test_the_tier_check_answers_before_the_body_check(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db, tier=2)
    response = await approve(app, record, bearer(key_pair), confirming_device="a\x00")
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "verification_required"
    assert (await stored(db, record.challenge_id)).status == "pending"


async def test_the_signature_check_answers_before_the_body_check(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db, tier=1)
    response = await approve(
        app, record, bearer(key_pair), signer=OTHER_PRIVATE, confirming_device="a\x00"
    )
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "invalid_signature"
    assert (await stored(db, record.challenge_id)).status == "pending"


async def test_the_ownership_check_answers_before_the_body_check(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db, tier=1, customer_ref="cust_someone_else")
    response = await approve(app, record, bearer(key_pair), confirming_device="a\x00")
    assert response.status_code == 404, response.text
    assert response.json() == {
        "error": "not_found",
        "error_description": f"challenge {record.challenge_id} not found",
    }
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "challenge_not_owned"


async def test_an_expired_row_with_a_malformed_body_is_a_400_and_stays_pending(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db, tier=1)
    async with db.sessionmaker() as s:
        await s.execute(
            text(
                "UPDATE challenges SET expires_at = now() - interval '1 minute' "
                "WHERE challenge_id = :c"
            ),
            {"c": record.challenge_id},
        )
        await s.commit()
    record = await stored(db, record.challenge_id)
    response = await approve(app, record, bearer(key_pair), confirming_device="a\x00")
    assert response.status_code == 400, response.text
    assert (await stored(db, record.challenge_id)).status == "pending"
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "body_field_invalid"


async def test_an_executed_row_with_a_malformed_body_is_a_400_not_a_409(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db, tier=1)
    async with db.sessionmaker() as s:
        await s.execute(
            text("UPDATE challenges SET status = 'executed' WHERE challenge_id = :c"),
            {"c": record.challenge_id},
        )
        await s.commit()
    record = await stored(db, record.challenge_id)
    response = await approve(app, record, bearer(key_pair), confirming_device="a\x00")
    assert response.status_code == 400, response.text
    assert (await stored(db, record.challenge_id)).status == "executed"


# -- A signature that is not a string ------------------------------------------------


@pytest.mark.parametrize("value", [1, True, ["x"], {"k": "v"}], ids=repr)
async def test_a_signature_of_the_wrong_json_type_is_a_400_missing_signature(
    value: Any,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    """Treated as absent: the closest existing refusal, `missing_signature`."""
    record = await seed(db, tier=1)
    response = await approve(app, record, bearer(key_pair), signature=value)
    assert response.status_code == 400, response.text
    assert response.json()["error"] == "invalid_request"
    assert (await stored(db, record.challenge_id)).status == "pending"
    (row,) = await audit_rows(db, record.challenge_id)
    assert (row.outcome, row.detail) == ("raised", "missing_signature")


# -- A path id that cannot name a challenge ------------------------------------------


async def audit_count(db: Database) -> int:
    async with db.sessionmaker() as s:
        return int((await s.execute(select(func.count()).select_from(AuditEntry))).scalar_one())


@pytest.mark.parametrize(
    "raw_id",
    ["chal\x00x", "chal x", "c" * 37, "chal.x", "chal x"],
    ids=["nul", "space", "37-characters", "dot", "line-separator"],
)
async def test_a_path_id_outside_the_alphabet_is_the_unknown_id_404_with_a_row(
    raw_id: str,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    before = await audit_count(db)
    path_id = raw_id if "%" in raw_id else quote(raw_id, safe="")
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        response = await client.post(
            f"/challenges/{path_id}/approve", json={"signature": "x"}, headers=bearer(key_pair)
        )
    assert response.status_code == 404, response.text
    body = response.json()
    assert body["error"] == "not_found"
    assert body["error_description"].startswith("challenge ")
    assert body["error_description"].endswith(" not found")
    assert await audit_count(db) == before + 1
    async with db.sessionmaker() as s:
        latest = (
            await s.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1))
        ).scalar_one()
    assert latest.detail == "challenge_not_found"


# -- Line and paragraph separators ---------------------------------------------------


@pytest.mark.parametrize("field", FIELDS)
@pytest.mark.parametrize("separator", [" ", " "], ids=["U+2028", "U+2029"])
async def test_a_line_or_paragraph_separator_is_refused(
    separator: str,
    field: str,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    record = await seed(db, tier=1)
    body_field: dict[str, Any] = {field: f"a{separator}b"}
    response = await approve(app, record, bearer(key_pair), **body_field)
    await assert_refused_field(response, field, db, record, sent, None)

"""Tier enforcement at approval, through the real confirm app and Postgres.

Spec docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md,
section 11, and decision record 0023. Every approval here carries a valid
device signature over the stored row unless a test says otherwise, so what is
measured is the tier check that sits between that signature and the claim.
`tests/test_tier_proof.py` holds the same rule as a pure function, with the
bounds tested exactly.
"""

import asyncio
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator, Callable
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
from services.confirm.revocation import REVOKED_ERROR
from services.confirm.settings import ConfirmSettings
from services.confirm.tier_proof import (
    TIER_MISMATCH_DESCRIPTION,
    TIER_UNSUPPORTED_DESCRIPTION,
    VERIFICATION_REQUIRED_DESCRIPTION,
)
from tests.fixtures.device_keys import device_key, enrolled_store, sign_row

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
OWNER = "cust_tier2owner"
OTHER = "cust_tier2other"
IDV = "postern-dev-idv"
TIER_1_TOOL = "standing_orders.cancel"
PAYLOAD: dict[str, Any] = {
    "from_account_ref": "acc_tier2",
    "payee_ref": "payee_tier2",
    "payee_name": "Northwind Energy",
    "amount": "10.00",
    "currency": "EUR",
    "reference": "Rent October",
}
TIER_1_PAYLOAD: dict[str, Any] = {"order_id": "so_tier2"}
#: A string no refusal may echo, in a response, an audit row or a log line.
SENTINEL = "SENTINEL-claim-value"

DEVICE_PRIVATE, DEVICE_PUBLIC = device_key("tier2-phone")
OTHER_PRIVATE, OTHER_PUBLIC = device_key("tier2-other-phone")


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest_asyncio.fixture
async def db(database: Database) -> AsyncIterator[Database]:
    """The session-scoped database, with this module's challenges deleted after."""
    yield database
    async with database.sessionmaker() as s:
        await s.execute(text("DELETE FROM challenges WHERE challenge_id LIKE 't2_%'"))
        await s.commit()


@pytest.fixture()
def sent(monkeypatch: pytest.MonkeyPatch) -> list[httpx2.Request]:
    """Every request the executor sends; the backend accepts each."""
    calls: list[httpx2.Request] = []

    def backend(request: httpx2.Request) -> httpx2.Response:
        calls.append(request)
        return httpx2.Response(200, json={"status": "accepted"})

    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        original(self, *args, transport=httpx2.MockTransport(backend), **kwargs)

    monkeypatch.setattr(BackendWriteClient, "__init__", patched)
    return calls


def build_app(pg_url: str, key_pair: RSAKeyPair, *, idv_value: str | None = IDV) -> Starlette:
    settings = ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
        idv_value=idv_value,
    )
    return create_confirm_app(
        settings,
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=enrolled_store(OWNER, DEVICE_PUBLIC, **{OTHER: (OTHER_PUBLIC,)}),
    )


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    return build_app(pg_url, key_pair)


#: Maps the digits of a uuid4 hex to letters. A hex id carries a twelve-digit
#: run or a letter-letter-digit-digit opener often enough for the audit scrub
#: to mask part of it (the producer plan's masking note), and these tests find
#: their audit rows by the recorded `challenge_id`, so the ids carry no digit
#: after the prefix.
_DIGITS_TO_LETTERS = str.maketrans("0123456789", "ghijklmnop")


def new_challenge_id() -> str:
    return f"t2_{uuid.uuid4().hex.translate(_DIGITS_TO_LETTERS)}"


async def seed(
    db: Database,
    *,
    tier: int = 2,
    tool_name: str = CREATE_PAYMENT_TOOL,
    customer_ref: str = OWNER,
    payload: dict[str, Any] | None = None,
) -> ChallengeRecord:
    """One pending challenge, committed so the app's own pool sees it."""
    async with db.sessionmaker() as s:
        record = await store.create_challenge(
            s,
            challenge_id=new_challenge_id(),
            customer_ref=customer_ref,
            tool_name=tool_name,
            payload=dict(payload if payload is not None else PAYLOAD),
            tier=tier,
        )
        await s.commit()
    return record


def tier2_claims(record: ChallengeRecord, **overrides: Any) -> dict[str, Any]:
    """The four claims, valid for ``record`` unless overridden."""
    claims: dict[str, Any] = {
        "idv": IDV,
        "challenge_id": record.challenge_id,
        "jti": f"jti-{uuid.uuid4().hex}",
        "auth_time": record.created_at.timestamp(),
    }
    claims.update(overrides)
    return claims


def bearer(
    key_pair: RSAKeyPair, claims: dict[str, Any] | None = None, *, subject: str = OWNER
) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject,
        issuer=ISSUER,
        audience=AUDIENCE,
        expires_in_seconds=60,
        additional_claims=claims or None,
    )
    return {"Authorization": f"Bearer {token}"}


async def approve(
    app: Starlette,
    record: ChallengeRecord,
    headers: dict[str, str],
    *,
    signer: Any = DEVICE_PRIVATE,
    as_a_server_would: bool = False,
    **extra: Any,
) -> httpx2.Response:
    """POST the approval; ``as_a_server_would`` answers an unhandled raise with a 500."""
    body = {"signature": sign_row(signer, record), **extra}
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


# -- The happy path ------------------------------------------------------------------


async def test_a_tier_2_approval_with_all_four_claims_executes_and_stores_the_jti(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    claims = tier2_claims(record, jti="jti-happy-path-0001")
    response = await approve(
        app, record, bearer(key_pair, claims), verification_result="body-chosen-string"
    )
    assert response.status_code == 200, response.text
    assert len(sent) == 1
    row = await stored(db, record.challenge_id)
    assert row.status == "executed"
    assert row.verification_result == "jti-happy-path-0001"
    entries = await audit_rows(db, record.challenge_id)
    assert [e.outcome for e in entries] == ["reaching", "returned"]
    assert all(e.arguments["assertion_jti"] == "jti-happy-path-0001" for e in entries)
    # The scrubbed body is still recorded, and is not what the row stores.
    assert all(e.arguments["verification_result"] == "body-chosen-string" for e in entries)


@pytest.mark.parametrize("case", ["jti-128", "auth-time-lower-bound", "auth-time-upper-bound"])
async def test_the_boundary_values_are_accepted(
    case: str, app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """The upper bound is minted against this process's clock just before the
    request, so it sits within the request's own latency of the bound;
    `tests/test_tier_proof.py` tests both bounds exactly."""
    record = await seed(db)
    cases: dict[str, dict[str, Any]] = {
        "jti-128": {"jti": "j" * 128},
        "auth-time-lower-bound": {"auth_time": record.created_at.timestamp() - 30},
        "auth-time-upper-bound": {"auth_time": time.time() + 30},
    }
    claims = tier2_claims(record, **cases[case])
    response = await approve(app, record, bearer(key_pair, claims))
    assert response.status_code == 200, response.text
    assert len(sent) == 1


# -- Each claim refused -------------------------------------------------------------

Claims = Callable[[ChallengeRecord], dict[str, Any]]


def _drop(name: str) -> Claims:
    def build(record: ChallengeRecord) -> dict[str, Any]:
        claims = tier2_claims(record)
        del claims[name]
        return claims

    return build


def _set(**overrides: Any) -> Claims:
    return lambda record: tier2_claims(record, **overrides)


def _set_from(name: str, make: Callable[[ChallengeRecord], Any]) -> Claims:
    """One claim set from the record, for values that depend on it."""
    return lambda record: tier2_claims(record, **{name: make(record)})


REFUSED: list[Any] = [
    pytest.param(_drop("idv"), False, id="idv-missing"),
    pytest.param(_set(idv=1), False, id="idv-not-a-string"),
    pytest.param(_set(idv=SENTINEL), False, id="idv-wrong"),
    pytest.param(_set(idv=IDV.upper()), False, id="idv-other-case"),
    pytest.param(_set(idv=""), False, id="idv-empty"),
    pytest.param(_set(idv=None), False, id="idv-null"),
    pytest.param(_drop("challenge_id"), False, id="challenge-id-missing"),
    pytest.param(_set(challenge_id=7), False, id="challenge-id-number"),
    pytest.param(_set(challenge_id=SENTINEL), False, id="challenge-id-wrong"),
    pytest.param(
        _set_from("challenge_id", lambda r: r.challenge_id[:-1]),
        False,
        id="challenge-id-prefix-of-the-path",
    ),
    pytest.param(
        _set_from("challenge_id", lambda r: r.challenge_id + "0"),
        False,
        id="challenge-id-extends-the-path",
    ),
    pytest.param(
        _set_from("challenge_id", lambda r: r.challenge_id + "\n"),
        False,
        id="challenge-id-trailing-newline",
    ),
    pytest.param(_drop("jti"), False, id="jti-missing"),
    pytest.param(_set(jti=7), False, id="jti-number"),
    pytest.param(_set(jti=""), False, id="jti-empty"),
    pytest.param(_set(jti="j" * 129), False, id="jti-129-characters"),
    pytest.param(_set(jti=f"{SENTINEL}\x00"), False, id="jti-nul"),
    pytest.param(_set(jti=f"{SENTINEL} x"), False, id="jti-space"),
    pytest.param(_drop("auth_time"), True, id="auth-time-missing"),
    pytest.param(_set(auth_time=True), True, id="auth-time-bool"),
    # An IN-RANGE numeric string: a `float(value)` coercion would accept it.
    pytest.param(
        _set_from("auth_time", lambda r: str(r.created_at.timestamp() + 5)),
        True,
        id="auth-time-numeric-string",
    ),
    pytest.param(_set(auth_time=float("nan")), True, id="auth-time-nan"),
    pytest.param(_set(auth_time=float("inf")), True, id="auth-time-inf"),
    pytest.param(
        _set_from("auth_time", lambda r: r.created_at.timestamp() - 31),
        True,
        id="auth-time-31s-before-creation",
    ),
    # An hour ahead and not 31 seconds, so a delayed request cannot flake the
    # case; `tests/test_tier_proof.py` pins the exact bound.
    pytest.param(
        lambda record: tier2_claims(record, auth_time=time.time() + 3600),
        True,
        id="auth-time-an-hour-ahead",
    ),
]


@pytest.mark.parametrize(("build_claims", "jti_recorded"), REFUSED)
async def test_each_failed_claim_is_refused_and_the_row_stays_pending(
    build_claims: Claims,
    jti_recorded: bool,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
    caplog: pytest.LogCaptureFixture,
) -> None:
    record = await seed(db)
    claims = build_claims(record)
    with caplog.at_level(logging.WARNING, logger="services.confirm.tier_proof"):
        response = await approve(app, record, bearer(key_pair, claims))
    assert response.status_code == 403, response.text
    assert response.json() == {
        "error": "verification_required",
        "error_description": VERIFICATION_REQUIRED_DESCRIPTION,
    }
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []
    (row,) = await audit_rows(db, record.challenge_id)
    assert (row.outcome, row.detail) == ("raised", "verification_required")
    assert ("assertion_jti" in row.arguments) is jti_recorded
    # Neither the configured value nor a claim value reaches anything a
    # caller or an operator reads; the log line names a claim, not a value.
    for where in (response.text, json.dumps(row.arguments), caplog.text):
        assert SENTINEL not in where
        assert IDV not in where
    (logged,) = [r for r in caplog.records if r.name == "services.confirm.tier_proof"]
    assert record.challenge_id in logged.getMessage()
    assert "claim does not prove" in logged.getMessage()


async def test_an_assertion_minted_for_one_challenge_does_not_approve_another(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    first = await seed(db)
    second = await seed(db)
    response = await approve(app, second, bearer(key_pair, tier2_claims(first)))
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "verification_required"
    assert (await stored(db, second.challenge_id)).status == "pending"
    assert (await stored(db, first.challenge_id)).status == "pending"
    assert sent == []


# -- The setting ---------------------------------------------------------------------


async def test_unset_refuses_tier_2_and_still_approves_tier_1(
    pg_url: str, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    app = build_app(pg_url, key_pair, idv_value=None)
    tier_2 = await seed(db)
    refused = await approve(app, tier_2, bearer(key_pair, tier2_claims(tier_2)))
    assert refused.status_code == 403, refused.text
    assert refused.json() == {
        "error": "verification_required",
        "error_description": VERIFICATION_REQUIRED_DESCRIPTION,
    }
    (row,) = await audit_rows(db, tier_2.challenge_id)
    assert row.detail == "verification_not_configured"
    assert (await stored(db, tier_2.challenge_id)).status == "pending"

    tier_1 = await seed(db, tier=1, tool_name=TIER_1_TOOL, payload=TIER_1_PAYLOAD)
    approved = await approve(app, tier_1, bearer(key_pair))
    assert approved.status_code == 200, approved.text
    assert len(sent) == 1


# -- Tier 1, tier 0 and the declared tier --------------------------------------------


@pytest.mark.parametrize("with_claims", [False, True], ids=["no-claims", "extra-claims"])
async def test_a_tier_1_row_is_approved_as_before(
    with_claims: bool,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    record = await seed(db, tier=1, tool_name=TIER_1_TOOL, payload=TIER_1_PAYLOAD)
    claims = tier2_claims(record) if with_claims else None
    response = await approve(
        app, record, bearer(key_pair, claims), verification_result="selfie-ref-0001"
    )
    assert response.status_code == 200, response.text
    assert len(sent) == 1
    assert (await stored(db, record.challenge_id)).verification_result == "selfie-ref-0001"
    entries = await audit_rows(db, record.challenge_id)
    assert all("assertion_jti" not in e.arguments for e in entries)


async def test_a_tier_0_row_is_refused_as_unsupported(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """Of an operation confirm does not declare: a tier-0 row of a declared one
    is refused as a mismatch first (`tests/test_tier_proof.py`)."""
    record = await seed(db, tier=0, tool_name="test.unregistered_write")
    response = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert response.status_code == 403, response.text
    assert response.json() == {
        "error": "tier_unsupported",
        "error_description": TIER_UNSUPPORTED_DESCRIPTION,
    }
    assert (await stored(db, record.challenge_id)).status == "pending"
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "tier_unsupported"
    assert sent == []


async def test_a_payment_row_stored_at_tier_1_is_a_mismatch(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """What an api compromise holding `postern_app` could write: a payment the
    customer would approve with a device signature alone."""
    record = await seed(db, tier=1)
    response = await approve(app, record, bearer(key_pair))
    assert response.status_code == 403, response.text
    assert response.json() == {
        "error": "tier_mismatch",
        "error_description": TIER_MISMATCH_DESCRIPTION,
    }
    assert (await stored(db, record.challenge_id)).status == "pending"
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "tier_mismatch"
    assert sent == []


# -- Order: the tier check runs after the signature and the ownership checks ---------


async def test_the_signature_is_checked_before_the_tier(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """A wrong device signature and the claims MISSING: the signature answers."""
    record = await seed(db)
    response = await approve(app, record, bearer(key_pair), signer=OTHER_PRIVATE)
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "invalid_signature"
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []


async def test_ownership_is_checked_before_the_tier(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """Another customer's tier-2 challenge and NO claims: the byte-identical
    404 every unknown id gets, and the table tells the two apart."""
    record = await seed(db, customer_ref=OTHER)
    response = await approve(app, record, bearer(key_pair))
    assert response.status_code == 404, response.text
    assert response.json() == {
        "error": "not_found",
        "error_description": f"challenge {record.challenge_id} not found",
    }
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "challenge_not_owned"
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []


async def test_a_revoked_customer_is_refused_as_revoked_even_with_valid_claims(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    await app.state.postern_revocation_store.revoke_customer_client(
        customer_ref=OWNER, client_id="any-client"
    )
    response = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert response.status_code == 403, response.text
    assert response.json()["error"] == REVOKED_ERROR
    (row,) = await audit_rows(db, record.challenge_id)
    assert row.detail == "revoked"
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []


# -- Retry and concurrency ---------------------------------------------------------


async def test_a_refusal_leaves_the_row_approvable_inside_its_window(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    first = await approve(app, record, bearer(key_pair, _drop("idv")(record)))
    assert first.status_code == 403, first.text
    second = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert second.status_code == 200, second.text
    assert len(sent) == 1


async def test_a_valid_and_an_invalid_approval_race_and_only_the_valid_one_executes(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    valid, invalid = await asyncio.gather(
        approve(app, record, bearer(key_pair, tier2_claims(record))),
        approve(app, record, bearer(key_pair, _drop("jti")(record))),
    )
    assert valid.status_code == 200, valid.text
    assert invalid.status_code == 403, invalid.text
    assert invalid.json()["error"] == "verification_required"
    assert len(sent) == 1
    assert (await stored(db, record.challenge_id)).status == "executed"


async def test_two_valid_approvals_race_to_one_execution_and_each_row_carries_its_own_jti(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    first, second = await asyncio.gather(
        approve(app, record, bearer(key_pair, tier2_claims(record, jti="jti-A"))),
        approve(app, record, bearer(key_pair, tier2_claims(record, jti="jti-B"))),
    )
    assert sorted([first.status_code, second.status_code]) == [200, 409]
    assert len(sent) == 1
    row = await stored(db, record.challenge_id)
    assert row.status == "executed"
    winner = row.verification_result
    assert winner in {"jti-A", "jti-B"}
    loser = ({"jti-A", "jti-B"} - {winner}).pop()
    entries = await audit_rows(db, record.challenge_id)
    by_outcome = {e.outcome: e.arguments["assertion_jti"] for e in entries}
    assert by_outcome["reaching"] == by_outcome["returned"] == winner
    assert by_outcome["raised"] == loser


# -- The jti is recorded as the backend issued it ------------------------------------

#: Three values `scrub_text` rewrites: a PAN, a `uuid4().hex`-shaped id the
#: masker catches (12.9% of hex ids are masked; this one is an md5 digest found
#: by search), and an IBAN. The audit row must carry each as issued, or it
#: cannot be joined to the app backend's issuance log.
SCRUBBABLE_JTIS = [
    pytest.param("4111111111111111", id="pan-shaped"),
    pytest.param("f2aee81c67e9e6a3e0feadc451f05d9f", id="hex-id-the-scrubber-masks"),
    pytest.param("GB82WEST12345698765432", id="iban-shaped"),
]


@pytest.mark.parametrize("jti", SCRUBBABLE_JTIS)
async def test_the_audit_rows_carry_the_jti_unscrubbed_on_success(
    jti: str,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    record = await seed(db)
    response = await approve(app, record, bearer(key_pair, tier2_claims(record, jti=jti)))
    assert response.status_code == 200, response.text
    row = await stored(db, record.challenge_id)
    entries = await audit_rows(db, record.challenge_id)
    assert [e.outcome for e in entries] == ["reaching", "returned"]
    assert row.verification_result == jti
    assert all(e.arguments["assertion_jti"] == jti for e in entries)


@pytest.mark.parametrize("jti", SCRUBBABLE_JTIS)
async def test_the_audit_row_carries_the_jti_unscrubbed_on_a_refusal_after_it_passed(
    jti: str,
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
) -> None:
    record = await seed(db)
    claims = tier2_claims(record, jti=jti, auth_time=time.time() + 3600)
    response = await approve(app, record, bearer(key_pair, claims))
    assert response.status_code == 403, response.text
    (entry,) = await audit_rows(db, record.challenge_id)
    assert entry.detail == "verification_required"
    assert entry.arguments["assertion_jti"] == jti
    row = await stored(db, record.challenge_id)
    assert (row.status, row.verification_result) == ("pending", None)


# -- Expired and terminal rows: the tier check answers first -------------------------


async def expired_row(db: Database) -> ChallengeRecord:
    """A pending tier-2 row whose deadline has passed, as `stored` reads it.

    The device signature covers ``expires_at``, so the caller signs the
    returned row, not the seeded one.
    """
    record = await seed(db)
    async with db.sessionmaker() as s:
        await s.execute(
            text(
                "UPDATE challenges SET expires_at = created_at - INTERVAL '1 hour' "
                "WHERE challenge_id = :c"
            ),
            {"c": record.challenge_id},
        )
        await s.commit()
    return await stored(db, record.challenge_id)


async def test_an_expired_row_with_bad_claims_is_refused_as_verification_and_not_retired(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await expired_row(db)
    response = await approve(app, record, bearer(key_pair, _drop("idv")(record)))
    assert response.status_code == 403, response.text
    assert response.json()["error"] == "verification_required"
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []


async def test_an_expired_row_with_good_claims_is_410_and_retired(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await expired_row(db)
    response = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert response.status_code == 410, response.text
    assert response.json()["error"] == "expired"
    row = await stored(db, record.challenge_id)
    assert (row.status, row.verification_result) == ("expired", None)
    assert sent == []


async def test_an_executed_row_with_bad_claims_is_403_and_with_good_claims_is_409(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    record = await seed(db)
    done = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert done.status_code == 200, done.text
    bad = await approve(app, record, bearer(key_pair, _drop("idv")(record)))
    assert bad.status_code == 403, bad.text
    assert bad.json()["error"] == "verification_required"
    good = await approve(app, record, bearer(key_pair, tier2_claims(record)))
    assert good.status_code == 409, good.text
    assert good.json()["error"] == "already_terminal"
    assert len(sent) == 1
    assert (await stored(db, record.challenge_id)).status == "executed"


# -- auth_time: a bool is not the number 1 --------------------------------------------


async def test_auth_time_one_is_accepted_and_true_is_refused_when_one_is_in_range(
    app: Starlette, db: Database, key_pair: RSAKeyPair, sent: list[httpx2.Request]
) -> None:
    """`True == 1`, so a bool the check let through would pass at the HTTP level
    only if 1 were inside the window: the rows are created at the epoch here."""
    first = await seed(db)
    second = await seed(db)
    async with db.sessionmaker() as s:
        await s.execute(
            text(
                "UPDATE challenges SET created_at = to_timestamp(0) WHERE challenge_id IN (:a, :b)"
            ),
            {"a": first.challenge_id, "b": second.challenge_id},
        )
        await s.commit()
    refused = await stored(db, first.challenge_id)
    accepted = await stored(db, second.challenge_id)
    assert refused.created_at.timestamp() == 0
    bad = await approve(app, refused, bearer(key_pair, tier2_claims(refused, auth_time=True)))
    assert bad.status_code == 403, bad.text
    assert (await stored(db, refused.challenge_id)).status == "pending"
    good = await approve(app, accepted, bearer(key_pair, tier2_claims(accepted, auth_time=1)))
    assert good.status_code == 200, good.text
    assert len(sent) == 1


# -- An exception in the check is not an update failure -------------------------------


async def test_an_exception_in_the_tier_check_is_a_bare_500_and_leaves_the_row_pending(
    app: Starlette,
    db: Database,
    key_pair: RSAKeyPair,
    sent: list[httpx2.Request],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check sits outside the `try` that wraps the claim, whose handler puts
    `str(exc)` in the response: an exception here must not reach the caller as text."""

    def explode(**_: Any) -> Any:
        raise ValueError("SENTINEL")

    monkeypatch.setattr(callback, "check_tier", explode)
    record = await seed(db)
    response = await approve(
        app, record, bearer(key_pair, tier2_claims(record)), as_a_server_would=True
    )
    assert response.status_code == 500, response.text
    assert "SENTINEL" not in response.text
    (entry,) = await audit_rows(db, record.challenge_id)
    assert (entry.outcome, entry.detail) == ("raised", "ValueError")
    assert (await stored(db, record.challenge_id)).status == "pending"
    assert sent == []

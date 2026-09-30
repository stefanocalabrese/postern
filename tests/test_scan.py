"""``POST /scan``: the banking app's half of the QR, over the assembled app.

Every branch of section 5 of ``dev-docs/qr-page-spec.md`` is driven here
through ``create_confirm_app`` and read back out of Postgres, for the reason
``tests/test_pairing_audit.py`` gives: whether a row is written, and what it
carries, is a property of the database and not of a mock.

The rotation token is computed with ``tests/device_grant_helpers.py``'s
``qr_for`` from the stored row's secret, which is what the page would have
drawn; the page itself is ``tests/test_verify_page.py``'s subject.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    DeviceCodeStoreContended,
)
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.revocation import RevocationStoreBase, RevocationStoreUnavailable
from postern_core.store import audit as audit_store
from postern_core.store.engine import Database
from postern_core.store.models import (
    ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
    OUTCOME_RAISED,
    OUTCOME_RETURNED,
    AuditEntry,
)
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_ALREADY_APPROVED,
    DETAIL_INVALID_SUBJECT,
    DETAIL_QR_INVALID,
    DETAIL_QR_STALE,
    DETAIL_REVOKED,
    DETAIL_SCAN_CONFLICT,
    DETAIL_USER_CODE_NOT_FOUND,
    SCAN_ROUTE,
    SCAN_TOOL_NAME,
    device_code_handle,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import DEFAULT_DEVICE_SCOPES, ConfirmSettings
from tests.device_grant_helpers import device_store_of, overwrite_in_memory, qr_for, stored_code
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
ALICE = "cust_a11ce"
BOB = "cust_b0b0"
BROWSER_CLIENT = "claude-desktop-42"


# ---------------------------------------------------------------------------
# Fixtures and helpers.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    """The composition root, pointed at ``tests/conftest.py``'s Postgres."""
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    """Empty ``audit_log`` either side of every test, as the pairing audit tests do."""
    await _wipe(database)
    yield database
    await _wipe(database)


def bearer(key_pair: RSAKeyPair, subject: str) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    return {"Authorization": f"Bearer {token}"}


async def post(
    app: Starlette,
    path: str,
    *,
    json_body: Any = None,
    form: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
    as_a_server_would: bool = False,
) -> httpx2.Response:
    """POST over ASGI. ``as_a_server_would`` turns an unhandled exception
    into the 500 a real client receives, as ``tests/test_pairing_audit.py``'s
    ``approve`` does."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=not as_a_server_would),
        base_url="http://t",
    ) as c:
        if form is not None:
            return await c.post(path, data=form, headers=headers or {})
        return await c.post(path, json=json_body, headers=headers or {})


async def start(app: Starlette) -> DeviceCode:
    """A pairing created the way the browser creates one."""
    resp = await post(app, "/device_authorization", json_body={"client_id": BROWSER_CLIENT})
    assert resp.status_code == 200, resp.text
    return await stored_code(app, resp.json()["user_code"])


async def scan(
    app: Starlette,
    key_pair: RSAKeyPair,
    customer: str,
    code: DeviceCode,
    *,
    qr: str | None = None,
    as_a_server_would: bool = False,
) -> httpx2.Response:
    return await post(
        app,
        "/scan",
        json_body={
            "user_code": code.user_code_display,
            "qr": qr if qr is not None else qr_for(code),
        },
        headers=bearer(key_pair, customer),
        as_a_server_would=as_a_server_would,
    )


async def rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(select(AuditEntry).order_by(AuditEntry.id))
        return list(result.scalars().all())


async def one_row(db: Database) -> AuditEntry:
    entries = await rows(db)
    assert len(entries) == 1, f"expected exactly one audit row, got {len(entries)}"
    return entries[0]


def forged(code: DeviceCode) -> str:
    """A token for the current slot whose MAC is not the pairing's."""
    slot, mac = qr_for(code).split(".")
    return f"{slot}.{('B' if mac[0] == 'A' else 'A') + mac[1:]}"


# ---------------------------------------------------------------------------
# 1. The scan that claims.
# ---------------------------------------------------------------------------


async def test_a_scan_answers_with_the_stored_context_and_records_one_row(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app)

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "client_id": BROWSER_CLIENT,
        "client_id_verified": False,
        "scopes": DEFAULT_DEVICE_SCOPES,
        "expires_at": code.expires_at.isoformat(),
        "user_code": code.user_code_display,
    }
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None
    assert stored.scanned_by == ALICE
    assert stored.scanned_at is not None
    assert stored.approved is False

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RETURNED
    assert row.detail is None
    assert row.tool_name == SCAN_TOOL_NAME
    assert row.customer_ref == ALICE
    assert row.arguments["route"] == SCAN_ROUTE
    assert row.arguments["device_code_handle"] == device_code_handle(code.device_code)
    assert row.arguments["paired_client_id"] == BROWSER_CLIENT


async def test_a_retried_scan_by_the_same_customer_answers_the_same(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """``already_mine``: a dropped response retried inside the token window."""
    code = await start(app)

    first = await scan(app, key_pair, ALICE, code)
    second = await scan(app, key_pair, ALICE, code)

    assert first.status_code == second.status_code == 200
    assert first.json() == second.json()
    assert [r.outcome for r in await rows(clean)] == [OUTCOME_RETURNED, OUTCOME_RETURNED]


# ---------------------------------------------------------------------------
# 2. Refused before the pairing is looked up.
# ---------------------------------------------------------------------------


async def test_a_subject_that_is_not_a_customer_reference_is_403(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app)

    resp = await scan(app, key_pair, "4111111111111111", code)

    assert resp.status_code == 403
    assert resp.json()["error"] == "invalid_subject"
    row = await one_row(clean)
    assert row.detail == DETAIL_INVALID_SUBJECT
    assert row.customer_ref is None
    assert row.customer_ref_absence_reason == ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF


async def test_a_revoked_customer_is_403_and_claims_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    store: RevocationStoreBase = app.state.postern_revocation_store
    await store.revoke_customer_client(customer_ref=ALICE, client_id=BROWSER_CLIENT)
    code = await start(app)

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 403
    assert resp.json()["error"] == "access_revoked"
    row = await one_row(clean)
    assert row.detail == DETAIL_REVOKED
    assert "device_code_handle" not in row.arguments
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ""


async def test_a_revocation_store_that_cannot_answer_is_a_recorded_500(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app)

    class Unavailable:
        async def is_customer_revoked(self, customer_ref: str) -> bool:
            raise RevocationStoreUnavailable("the revocation store is gone")

    app.state.postern_revocation_store = Unavailable()

    resp = await scan(app, key_pair, ALICE, code, as_a_server_would=True)

    assert resp.status_code == 500
    assert (await one_row(clean)).detail == "RevocationStoreUnavailable"


# ---------------------------------------------------------------------------
# 3. The one identical invalid_grant, and the detail that tells them apart.
# ---------------------------------------------------------------------------


async def test_an_unknown_user_code_is_invalid_grant(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    resp = await post(
        app,
        "/scan",
        json_body={"user_code": "ZZZ-ZZZ", "qr": "1.AAAAAAAAAAAAAAAAAAAAAA"},
        headers=bearer(key_pair, ALICE),
    )

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    row = await one_row(clean)
    assert row.detail == DETAIL_USER_CODE_NOT_FOUND
    assert "device_code_handle" not in row.arguments


async def test_an_expired_code_is_invalid_grant(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app)
    overwrite_in_memory(app, replace(code, expires_at=datetime.now(UTC) - timedelta(seconds=1)))

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    assert (await one_row(clean)).detail == DETAIL_USER_CODE_NOT_FOUND


async def test_a_code_this_customer_already_approved_is_invalid_grant(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """``approved_mine``: nothing new to show, so nothing distinct to say."""
    code = await start(app)
    assert (await scan(app, key_pair, ALICE, code)).status_code == 200
    assert await device_store_of(app).approve_scanned(code.device_code, ALICE) is True
    await _wipe(clean)

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    assert (await one_row(clean)).detail == DETAIL_ALREADY_APPROVED


@pytest.mark.parametrize("shape", ["forged mac", "future slot", "malformed"])
async def test_a_token_that_does_not_verify_is_invalid_grant_and_claims_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, shape: str
) -> None:
    code = await start(app)
    token = {
        "forged mac": forged(code),
        # Three, not two: a slot boundary can pass between computing the
        # token and the server checking it, and +3 is still beyond +1 then.
        "future slot": qr_for(code, slot_offset=3),
        "malformed": "not-a-token",
    }[shape]

    resp = await scan(app, key_pair, ALICE, code, qr=token)

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"
    row = await one_row(clean)
    assert row.detail == DETAIL_QR_INVALID
    assert row.arguments["device_code_handle"] == device_code_handle(code.device_code)
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ""


async def test_unknown_expired_approved_and_forged_answer_one_identical_body(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The existence oracle closed: four causes, one body, four details."""
    expired = await start(app)
    overwrite_in_memory(app, replace(expired, expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    approved = await start(app)
    assert (await scan(app, key_pair, ALICE, approved)).status_code == 200
    await device_store_of(app).approve_scanned(approved.device_code, ALICE)
    live = await start(app)
    await _wipe(clean)

    answers = [
        await post(
            app,
            "/scan",
            json_body={"user_code": "ZZZ-ZZZ", "qr": "1.AAAAAAAAAAAAAAAAAAAAAA"},
            headers=bearer(key_pair, ALICE),
        ),
        await scan(app, key_pair, ALICE, expired),
        await scan(app, key_pair, ALICE, approved),
        await scan(app, key_pair, ALICE, live, qr=forged(live)),
    ]

    assert {r.status_code for r in answers} == {400}
    assert all(r.json() == answers[0].json() for r in answers), [r.json() for r in answers]
    assert [r.detail for r in await rows(clean)] == [
        DETAIL_USER_CODE_NOT_FOUND,
        DETAIL_USER_CODE_NOT_FOUND,
        DETAIL_ALREADY_APPROVED,
        DETAIL_QR_INVALID,
    ]


# ---------------------------------------------------------------------------
# 4. The two distinct answers: a stale QR, and a pairing another phone holds.
# ---------------------------------------------------------------------------


async def test_a_genuine_token_past_the_window_is_qr_stale(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The screenshot relay, refused and recorded, with nothing claimed."""
    code = await start(app)

    resp = await scan(app, key_pair, ALICE, code, qr=qr_for(code, slot_offset=-6))

    assert resp.status_code == 400
    assert resp.json()["error"] == "qr_stale"
    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_QR_STALE
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ""


async def test_a_stale_token_from_another_customer_revokes_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The MAC is checked before the claim, so only a scan inside the window
    reaches session-swap detection."""
    code = await start(app)
    assert (await scan(app, key_pair, ALICE, code)).status_code == 200

    resp = await scan(app, key_pair, BOB, code, qr=qr_for(code, slot_offset=-6))

    assert resp.json()["error"] == "qr_stale"
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE
    assert [r.detail for r in await rows(clean)] == [None, DETAIL_QR_STALE]


async def test_session_swap_before_the_exchange_revokes_the_pairing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """B scans A's QR first; A's own scan ends the pairing, and A's AI client
    receives nothing on its next poll rather than B's accounts."""
    code = await start(app)
    assert (await scan(app, key_pair, BOB, code)).status_code == 200

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 400
    assert resp.json()["error"] == "scan_conflict"
    assert await device_store_of(app).get_device_code(code.device_code) is None
    poll = await post(
        app, "/token", form={"grant_type": "device_code", "device_code": code.device_code}
    )
    assert poll.status_code == 400
    assert poll.json()["error"] == "invalid_grant"
    written = await rows(clean)
    assert [(r.customer_ref, r.detail) for r in written] == [
        (BOB, None),
        (ALICE, DETAIL_SCAN_CONFLICT),
    ]


async def test_session_swap_after_the_exchange_is_refused_with_nothing_revoked(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The window this spec does not close: B's token is already out. The
    conflict is refused and recorded; the spent row is left exactly as it was,
    because revoking it would recall nothing.

    SPENT THROUGH THE STORE since 2026-09-30: ``POST /token`` spends nothing
    while issuance is disabled, so the spent state is reached the way an
    earlier build left it, and the way the session-token change will again."""
    code = await start(app)
    assert (await scan(app, key_pair, BOB, code)).status_code == 200
    assert await device_store_of(app).approve_scanned(code.device_code, BOB) is True
    assert await device_store_of(app).consume_device_code(code.device_code) is True
    before = await device_store_of(app).get_device_code(code.device_code)

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 400
    assert resp.json()["error"] == "scan_conflict"
    assert await device_store_of(app).get_device_code(code.device_code) == before
    assert (await rows(clean))[-1].detail == DETAIL_SCAN_CONFLICT


async def test_the_two_distinct_answers_are_distinct_from_invalid_grant(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    stale_code = await start(app)
    stale = await scan(app, key_pair, ALICE, stale_code, qr=qr_for(stale_code, slot_offset=-6))
    swapped = await start(app)
    await scan(app, key_pair, BOB, swapped)
    conflict = await scan(app, key_pair, ALICE, swapped)
    unknown = await post(
        app,
        "/scan",
        json_body={"user_code": "ZZZ-ZZZ", "qr": "1.AAAAAAAAAAAAAAAAAAAAAA"},
        headers=bearer(key_pair, ALICE),
    )

    errors = {stale.json()["error"], conflict.json()["error"], unknown.json()["error"]}
    assert errors == {"qr_stale", "scan_conflict", "invalid_grant"}


# ---------------------------------------------------------------------------
# 5. What writes no row, and what fails closed.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param([1, 2, 3], id="a JSON array"),
        pytest.param({}, id="neither field"),
        pytest.param({"user_code": "ABC-DEF"}, id="no qr"),
        pytest.param({"qr": "1.x"}, id="no user_code"),
        pytest.param({"user_code": 123, "qr": "1.x"}, id="user_code is a number"),
        pytest.param({"user_code": "ABC-DEF", "qr": ["x"]}, id="qr is a list"),
        pytest.param({"user_code": "", "qr": "1.x"}, id="user_code is empty"),
    ],
)
async def test_a_malformed_body_is_invalid_request_with_no_row(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, body: Any
) -> None:
    resp = await post(app, "/scan", json_body=body, headers=bearer(key_pair, ALICE))

    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_request"
    assert await rows(clean) == []


async def test_no_assertion_is_401_with_no_row(app: Starlette, clean: Database) -> None:
    resp = await post(app, "/scan", json_body={"user_code": "ABC-DEF", "qr": "1.x"})

    assert resp.status_code == 401
    assert await rows(clean) == []


async def test_a_claim_that_cannot_be_audited_is_withdrawn(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Asserted on the STORE: a claim nobody recorded would still decide who
    may approve."""
    code = await start(app)

    async def unavailable(session: Any, **kw: Any) -> None:
        raise RuntimeError("audit store unavailable")

    with patch.object(audit_store, "append", unavailable):
        resp = await scan(app, key_pair, ALICE, code, as_a_server_would=True)

    assert resp.status_code == 500
    assert await rows(clean) == []
    assert await device_store_of(app).get_device_code(code.device_code) is None


async def test_a_repeat_scan_that_cannot_be_audited_withdraws_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The first scan's claim was recorded when it was made; a retry that
    fails to write its own row must not undo it."""
    code = await start(app)
    assert (await scan(app, key_pair, ALICE, code)).status_code == 200

    async def unavailable(session: Any, **kw: Any) -> None:
        raise RuntimeError("audit store unavailable")

    with patch.object(audit_store, "append", unavailable):
        resp = await scan(app, key_pair, ALICE, code, as_a_server_would=True)

    assert resp.status_code == 500
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE


async def test_a_claim_whose_reply_is_lost_is_withdrawn_and_recorded_as_the_store_error(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The claim commits and its reply is lost, as a Redis ``EXEC`` can. The
    row records the store's exception as a refusal, so a claim left standing
    behind it would decide who may approve with no row saying it was made."""
    store: DeviceCodeStoreBase = device_store_of(app)
    code = await start(app)
    real_claim = store.claim_scan

    async def claim_then_time_out(device_code: str, customer_ref: str) -> Any:
        await real_claim(device_code, customer_ref)
        raise TimeoutError("reply lost after EXEC")

    monkeypatch.setattr(store, "claim_scan", claim_then_time_out)

    resp = await scan(app, key_pair, ALICE, code, as_a_server_would=True)

    assert resp.status_code == 500
    assert await store.get_device_code(code.device_code) is None
    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == "TimeoutError"


async def test_a_contended_claim_withdraws_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every ``WATCH`` beaten means nothing committed, so the pairing stays
    live and unscanned for the customer to scan again."""
    store: DeviceCodeStoreBase = device_store_of(app)
    code = await start(app)

    async def contended(device_code: str, customer_ref: str) -> Any:
        raise DeviceCodeStoreContended("beaten on every try")

    monkeypatch.setattr(store, "claim_scan", contended)

    resp = await scan(app, key_pair, ALICE, code, as_a_server_would=True)

    assert resp.status_code == 500
    stored = await store.get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ""
    assert (await one_row(clean)).detail == "DeviceCodeStoreContended"


async def test_a_second_scan_of_an_approved_unexchanged_code_revokes_it_before_the_mint(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """B scanned and approved through the real endpoints, and the browser has
    not polled yet. A's scan inside the window ends the pairing, so the next
    poll mints nothing: the case where revocation actually stops a token."""
    code = await start(app)
    assert (await scan(app, key_pair, BOB, code)).status_code == 200
    approved = await post(
        app,
        "/approve",
        json_body={"user_code": code.user_code_display},
        headers=bearer(key_pair, BOB),
    )
    assert approved.status_code == 200, approved.text

    resp = await scan(app, key_pair, ALICE, code)

    assert resp.status_code == 400
    assert resp.json()["error"] == "scan_conflict"
    assert await device_store_of(app).get_device_code(code.device_code) is None
    poll = await post(
        app, "/token", form={"grant_type": "device_code", "device_code": code.device_code}
    )
    assert poll.status_code == 400
    assert poll.json()["error"] == "invalid_grant"
    assert (await rows(clean))[-1].detail == DETAIL_SCAN_CONFLICT


async def test_the_conflict_warning_names_the_handle_and_never_the_codes(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    code = await start(app)
    assert (await scan(app, key_pair, BOB, code)).status_code == 200

    with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
        resp = await scan(app, key_pair, ALICE, code)

    assert resp.json()["error"] == "scan_conflict"
    warnings = [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and "second customer" in r.getMessage()
    ]
    assert len(warnings) == 1, warnings
    assert device_code_handle(code.device_code) in warnings[0]
    assert code.device_code not in warnings[0]
    assert code.user_code not in warnings[0]
    assert code.user_code_display not in warnings[0]


async def test_a_failed_withdrawal_of_an_ambiguous_claim_says_claimed_and_the_store_cause(
    app: Starlette,
    clean: Database,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The double failure on the scan path: the claim commits and its reply is
    lost, then the revocation fails too. The ERROR line says what is left
    behind, a claim and not an approval, and that a store write caused it."""
    store: DeviceCodeStoreBase = device_store_of(app)
    code = await start(app)
    real_claim = store.claim_scan

    async def claim_then_time_out(device_code: str, customer_ref: str) -> Any:
        await real_claim(device_code, customer_ref)
        raise TimeoutError("reply lost after EXEC")

    async def revoke_fails(device_code: str) -> None:
        raise ConnectionError("store gone")

    monkeypatch.setattr(store, "claim_scan", claim_then_time_out)
    monkeypatch.setattr(store, "revoke_device_code", revoke_fails)

    with caplog.at_level(logging.ERROR, logger="services.confirm.device_auth"):
        resp = await scan(app, key_pair, ALICE, code, as_a_server_would=True)

    assert resp.status_code == 500
    assert (await one_row(clean)).detail == "TimeoutError"
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    withdrawal = [m for m in errors if "could not be withdrawn" in m]
    assert len(withdrawal) == 1, errors
    assert "may be claimed" in withdrawal[0]
    assert "approved" not in withdrawal[0]
    assert "store write failed ambiguously" in withdrawal[0]
    assert device_code_handle(code.device_code) in withdrawal[0]

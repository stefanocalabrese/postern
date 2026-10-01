"""Session-swap recall at ``POST /scan`` (spec section 7).

Customer B scans victim A's QR first and approves; A's AI client exchanges
and receives a session for B's accounts; A's scan then arrives and
``claim_scan`` answers ``CONFLICT_EXCHANGED``. The family is revoked, its
access tokens go on the ZT-7 list, and two rows share one ``call_id``: the
recall row naming B, then the scan row naming A. The end-to-end half, A's
client refused at the assembled ``services/api``, is in
``tests/test_session_end_to_end.py``.
"""

from __future__ import annotations

import base64
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any
from uuid import uuid4

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import DeviceCode
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.refresh_sessions import RefreshSessionStoreBase
from postern_core.auth.revocation import RevocationStoreBase
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, OUTCOME_RETURNED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_QR_STALE,
    DETAIL_RECALL_LOCAL_ONLY,
    DETAIL_RECALL_NO_SESSION,
    DETAIL_SCAN_CONFLICT,
    DETAIL_SESSION_REVOKED,
    RECALL_TOOL_NAME,
    SCAN_ROUTE,
    SCAN_TOOL_NAME,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import device_store_of, qr_for, session_claims
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_scan import ALICE, AUDIENCE, BOB, ISSUER, bearer, post, scan, start


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def _build(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    return _build(pg_url, key_pair)


@pytest.fixture()
def shared_app(
    pg_url: str, key_pair: RSAKeyPair, redis_url: str, monkeypatch: pytest.MonkeyPatch
) -> Starlette:
    """Every store on the suite's Redis, as a deployment runs."""
    monkeypatch.setenv("POSTERN_REDIS_URL", redis_url)
    monkeypatch.setenv("POSTERN_REDIS_KEY_PREFIX", f"rc{uuid4().hex[:12]}:")
    return _build(pg_url, key_pair)


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    async with database.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()
    yield database


async def _rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        return list((await s.execute(select(AuditEntry).order_by(AuditEntry.id))).scalars())


async def _swapped(app: Starlette, key_pair: RSAKeyPair) -> tuple[DeviceCode, dict[str, Any]]:
    """B scans and approves A's pairing; A's client exchanges. Returns the
    pairing and the session body A's client holds."""
    code = await start(app)
    assert (await scan(app, key_pair, BOB, code)).status_code == 200
    approved = await post(
        app,
        "/approve",
        json_body={"user_code": code.user_code_display},
        headers=bearer(key_pair, BOB),
    )
    assert approved.status_code == 200, approved.text
    exchanged = await post(
        app, "/token", form={"grant_type": "device_code", "device_code": code.device_code}
    )
    assert session_claims(exchanged, app)["sub"] == BOB
    return code, exchanged.json()


def _jti(body: dict[str, Any]) -> str:
    payload = body["access_token"].split(".")[1]
    return str(json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))["jti"])


def _sid(body: dict[str, Any]) -> str:
    return str(body["refresh_token"].split(".")[1])


async def _refresh(app: Starlette, body: dict[str, Any]) -> Any:
    return await post(
        app, "/token", form={"grant_type": "refresh_token", "refresh_token": body["refresh_token"]}
    )


class TestTheRecall:
    async def test_a_swap_after_the_exchange_recalls_the_session(
        self, shared_app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        app = shared_app
        code, session = await _swapped(app, key_pair)

        response = await scan(app, key_pair, ALICE, code)

        assert response.status_code == 400
        assert response.json()["error"] == "scan_conflict"
        sessions: RefreshSessionStoreBase = app.state.refresh_session_store
        family = await sessions.get(_sid(session))
        assert family is not None and family.revoked_reason == "recall"
        revocations: RevocationStoreBase = app.state.postern_revocation_store
        assert await revocations.is_revoked({"jti": _jti(session)})

        refused = await _refresh(app, session)
        assert refused.json()["error"] == "invalid_grant"

        written = await _rows(clean)
        # B's scan, B's approval, the exchange, then this request's two rows
        # and the refused refresh.
        assert len(written) == 6
        recall, conflict = written[3], written[4]
        assert (recall.tool_name, recall.outcome, recall.detail) == (
            RECALL_TOOL_NAME,
            OUTCOME_RETURNED,
            None,
        )
        assert recall.customer_ref == BOB
        assert recall.arguments["route"] == SCAN_ROUTE
        assert recall.arguments["session_id"] == _sid(session)
        assert (conflict.tool_name, conflict.outcome, conflict.detail) == (
            SCAN_TOOL_NAME,
            OUTCOME_RAISED,
            DETAIL_SCAN_CONFLICT,
        )
        assert conflict.customer_ref == ALICE
        assert recall.call_id == conflict.call_id
        assert written[-1].detail == DETAIL_SESSION_REVOKED
        for secret in (session["access_token"], session["refresh_token"]):
            assert all(secret not in json.dumps(r.arguments) for r in written)

    async def test_under_process_local_stores_the_recall_says_so(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        code, session = await _swapped(app, key_pair)
        assert (await scan(app, key_pair, ALICE, code)).json()["error"] == "scan_conflict"
        recall = next(r for r in await _rows(clean) if r.tool_name == RECALL_TOOL_NAME)
        assert (recall.outcome, recall.detail) == (OUTCOME_RAISED, DETAIL_RECALL_LOCAL_ONLY)
        assert await app.state.postern_revocation_store.is_revoked({"jti": _jti(session)})

    async def test_a_code_spent_with_no_family_records_nothing_to_recall(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        code = await start(app)
        assert (await scan(app, key_pair, BOB, code)).status_code == 200
        assert await device_store_of(app).approve_scanned(code.device_code, BOB)
        assert await device_store_of(app).consume_device_code(code.device_code, session_id="")
        assert (await scan(app, key_pair, ALICE, code)).json()["error"] == "scan_conflict"
        recall = next(r for r in await _rows(clean) if r.tool_name == RECALL_TOOL_NAME)
        assert (recall.outcome, recall.detail) == (OUTCOME_RAISED, DETAIL_RECALL_NO_SESSION)
        assert recall.customer_ref == BOB

    async def test_a_conflict_before_the_exchange_recalls_nothing(
        self, app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        code = await start(app)
        assert (await scan(app, key_pair, BOB, code)).status_code == 200
        assert (await scan(app, key_pair, ALICE, code)).json()["error"] == "scan_conflict"
        assert [r for r in await _rows(clean) if r.tool_name == RECALL_TOOL_NAME] == []


class TestTheRaceWithTheExchange:
    async def test_a_recall_between_the_claim_and_the_signature_lists_the_token_to_be_signed(
        self,
        shared_app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The family and its first ``jti`` exist before the code is spent, so a
        recall that lands after the claim and before the signature already
        names the token about to be signed."""
        app = shared_app
        code = await start(app)
        assert (await scan(app, key_pair, BOB, code)).status_code == 200
        assert (
            await post(
                app,
                "/approve",
                json_body={"user_code": code.user_code_display},
                headers=bearer(key_pair, BOB),
            )
        ).status_code == 200
        store = device_store_of(app)
        real = store.consume_device_code
        conflicts: list[Any] = []

        async def consume_then_recall(device_code: str, *, session_id: str) -> bool:
            won = await real(device_code, session_id=session_id)
            conflicts.append(await scan(app, key_pair, ALICE, code))
            return won

        monkeypatch.setattr(store, "consume_device_code", consume_then_recall)
        exchanged = await post(
            app, "/token", form={"grant_type": "device_code", "device_code": code.device_code}
        )

        session = exchanged.json()
        session_claims(exchanged, app)
        assert conflicts[0].json()["error"] == "scan_conflict"
        assert await app.state.postern_revocation_store.is_revoked({"jti": _jti(session)})


class TestFailure:
    async def test_a_failed_recall_answers_503_retry_after_1_and_writes_both_rows(
        self,
        shared_app: Starlette,
        key_pair: RSAKeyPair,
        clean: Database,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        app = shared_app
        code, session = await _swapped(app, key_pair)
        sessions: RefreshSessionStoreBase = app.state.refresh_session_store
        real = sessions.revoke

        async def down(sid: str, *, reason: str) -> tuple[str, ...] | None:
            raise ConnectionError("redis went away")

        monkeypatch.setattr(sessions, "revoke", down)
        with caplog.at_level(logging.ERROR, logger="services.confirm.device_auth"):
            failed = await scan(app, key_pair, ALICE, code)
        assert failed.status_code == 503
        assert failed.headers["retry-after"] == "1"
        recall, conflict = (await _rows(clean))[-2:]
        assert (recall.tool_name, recall.outcome, recall.detail) == (
            RECALL_TOOL_NAME,
            OUTCOME_RAISED,
            "ConnectionError",
        )
        assert (conflict.tool_name, conflict.detail) == (SCAN_TOOL_NAME, DETAIL_SCAN_CONFLICT)
        assert "may still be live" in caplog.text

        monkeypatch.setattr(sessions, "revoke", real)
        retried = await scan(app, key_pair, ALICE, code)
        assert retried.json()["error"] == "scan_conflict"
        family = await sessions.get(_sid(session))
        assert family is not None and family.revoked_reason == "recall"
        assert await app.state.postern_revocation_store.is_revoked({"jti": _jti(session)})

    async def test_a_retry_after_the_rotation_window_is_stale_and_recalls_nothing(
        self, shared_app: Starlette, key_pair: RSAKeyPair, clean: Database
    ) -> None:
        app = shared_app
        code, session = await _swapped(app, key_pair)
        late = await scan(app, key_pair, ALICE, code, qr=qr_for(code, slot_offset=-6))
        assert late.json()["error"] == "qr_stale"
        family = await app.state.refresh_session_store.get(_sid(session))
        assert family is not None and family.revoked_at is None
        assert (await _rows(clean))[-1].detail == DETAIL_QR_STALE

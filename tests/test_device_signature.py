"""The approval signature as a control, driven end to end against Postgres.

``tests/test_approval_signature.py`` is about bytes. This is about what the
service does with them: every test here POSTs to the assembled app over ASGI,
counts what the operator's backend was asked to do, and reads the challenge row
and the ``audit_log`` rows back out of the database.

WHAT THIS FILE PINS, in the order the refusals happen:

1. A valid signature approves, once, and the backend is reached.
2. A wrong signature refuses, the backend is NEVER reached, and the challenge
   is still ``pending`` -- it must not be burned, or the customer's own phone
   could no longer approve it.
3. A signature over DIFFERENT content refuses. This is the property that makes
   the control worth having: an injected agent proposing a different amount
   cannot borrow a signature made for another one.
4. A signature replayed against a terminal or expired challenge refuses,
   without re-reaching the backend.
5. An unconfigured store refuses to BUILD, so the unverified configuration is
   unreachable rather than merely unlikely.
6. A known customer with no enrolled device refuses, and the audit row tells
   that apart from a store that could not answer.

Until 2026-09-24 the whole of this file was one line in
``services/confirm/callback.py``: ``if not unverified_signature``.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncGenerator, Generator
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import (
    DeviceKeyStoreBase,
    DeviceKeyStoreUnavailable,
    EnrolledDeviceKey,
    InMemoryDeviceKeyStore,
    no_enrolled_devices,
)
from postern_core.store import challenges as store
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, AuditEntry, ChallengeRecord
from sqlalchemy import delete, select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_DEVICE_NOT_ENROLLED,
    DETAIL_SIGNATURE_INVALID,
    DETAIL_SIGNATURE_MALFORMED,
    UNRESOLVED_TOOL_NAME,
)
from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.fixtures.device_keys import device_key, enrolled_store, sign_fields, sign_row

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
OWNER = "cust_sig1"
STRANGER = "cust_sig2"
TOOL = "standing_orders.cancel"
PAYLOAD: dict[str, Any] = {"order_id": "so_340", "amount": "EUR 340.00", "payee": "Acme Ltd"}

#: Every challenge this module inserts carries it, so teardown deletes by
#: prefix without touching another module's rows.
PREFIX = "chal_sig_"

#: The owner's phone, and a second one that is never enrolled anywhere -- the
#: attacker's key, in the tests that need one.
OWNER_PRIVATE, OWNER_PUBLIC = device_key("owner-phone")
ATTACKER_PRIVATE, _ATTACKER_PUBLIC = device_key("attacker-phone")


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture()
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so without these two flags it gets the
        # safe defaults and refuses to start.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def build_app(
    settings: ConfirmSettings,
    key_pair: RSAKeyPair,
    *,
    device_key_store: DeviceKeyStoreBase | None = None,
) -> Starlette:
    """The composition root, never a hand-assembled app.

    The store is the only thing overridden, so what is under test is the
    wiring ``services/confirm/main.py`` actually performs.
    """
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=device_key_store or enrolled_store(OWNER, OWNER_PUBLIC),
    )


@pytest.fixture()
def app(settings: ConfirmSettings, key_pair: RSAKeyPair) -> Starlette:
    return build_app(settings, key_pair)


@pytest.fixture()
async def clean(database: Database) -> AsyncGenerator[Database, None]:
    """Remove this module's rows either side of every test, by its own
    customer references: ``database`` is session scoped and shared."""
    await _wipe(database)
    yield database
    await _wipe(database)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as session:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(
            session, AuditEntry.customer_ref.in_((OWNER, STRANGER))
        )
        await session.execute(
            delete(ChallengeRecord).where(ChallengeRecord.customer_ref.in_((OWNER, STRANGER)))
        )
        await session.commit()


class Backend:
    """A stand-in backend write endpoint that COUNTS its calls.

    The count is what every test here asserts on. A refusal that answered 403
    and still reached the operator's payments service would satisfy a status
    assertion and close nothing.
    """

    def __init__(self) -> None:
        self.calls: list[httpx2.Request] = []

    def handle(self, request: httpx2.Request) -> httpx2.Response:
        self.calls.append(request)
        return httpx2.Response(201, json={"ok": True})


@pytest.fixture()
def backend() -> Generator[Backend]:
    b = Backend()
    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        kwargs.pop("transport", None)
        original(self, *args, transport=httpx2.MockTransport(b.handle), **kwargs)

    with patch.object(BackendWriteClient, "__init__", patched):
        yield b


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def bearer(key_pair: RSAKeyPair, subject: str) -> dict[str, str]:
    token = key_pair.create_token(
        subject=subject, issuer=ISSUER, audience=AUDIENCE, expires_in_seconds=60
    )
    return {"Authorization": f"Bearer {token}"}


async def approve(
    app: Starlette,
    challenge_id: str,
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    as_a_server_would: bool = False,
) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=not as_a_server_would),
        base_url="http://t",
    ) as client:
        return await client.post(f"/challenges/{challenge_id}/approve", json=body, headers=headers)


async def seed(
    db: Database,
    challenge_id: str,
    *,
    customer_ref: str = OWNER,
    tool_name: str = TOOL,
    payload: dict[str, Any] | None = None,
    status: str = "pending",
    expired: bool = False,
) -> ChallengeRecord:
    """Insert one challenge, committed so the app's own pool sees it, and
    return the row as stored -- which is what a signature must cover."""
    now = datetime.now(UTC)
    record = ChallengeRecord(
        challenge_id=challenge_id,
        customer_ref=customer_ref,
        tool_name=tool_name,
        payload=payload if payload is not None else dict(PAYLOAD),
        tier=1,
        status=status,
        created_at=now,
        expires_at=now - timedelta(seconds=1) if expired else now + timedelta(seconds=180),
    )
    async with db.sessionmaker() as session:
        session.add(record)
        await session.commit()
    return record


async def rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as session:
        result = await session.execute(
            select(AuditEntry)
            .where(AuditEntry.customer_ref.in_((OWNER, STRANGER)))
            .order_by(AuditEntry.id)
        )
        return list(result.scalars().all())


async def status_of(db: Database, challenge_id: str) -> str:
    async with db.sessionmaker() as session:
        row = await store.get_challenge(session, challenge_id)
        assert row is not None
        return row.status


async def stored_signature(db: Database, challenge_id: str) -> str | None:
    async with db.sessionmaker() as session:
        row = await store.get_challenge(session, challenge_id)
        assert row is not None
        return row.signature


# ---------------------------------------------------------------------------
# 1. A valid signature approves.
# ---------------------------------------------------------------------------


async def test_a_valid_signature_approves_and_reaches_the_backend(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 1. The backend touch is counted, not inferred."""
    record = await seed(clean, f"{PREFIX}ok")

    response = await approve(
        app,
        f"{PREFIX}ok",
        {"signature": sign_row(OWNER_PRIVATE, record)},
        bearer(key_pair, OWNER),
    )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "executed"
    assert len(backend.calls) == 1
    assert backend.calls[0].headers["Idempotency-Key"] == f"{PREFIX}ok"
    assert await status_of(clean, f"{PREFIX}ok") == "executed"
    # The verified signature is what the row now carries.
    assert await stored_signature(clean, f"{PREFIX}ok") == sign_row(OWNER_PRIVATE, record)


async def test_either_enrolled_phone_can_approve(
    settings: ConfirmSettings, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Decision 5, at the HTTP boundary: the store answers with a SET, so a
    customer with two devices approves from either, and a rotated key works
    the moment the operator publishes it -- with no code change here."""
    second_private, second_public = device_key("owner-tablet")
    app = build_app(
        settings, key_pair, device_key_store=enrolled_store(OWNER, OWNER_PUBLIC, second_public)
    )

    first = await seed(clean, f"{PREFIX}phone")
    second = await seed(clean, f"{PREFIX}tablet")

    from_phone = await approve(
        app,
        f"{PREFIX}phone",
        {"signature": sign_row(OWNER_PRIVATE, first)},
        bearer(key_pair, OWNER),
    )
    from_tablet = await approve(
        app,
        f"{PREFIX}tablet",
        {"signature": sign_row(second_private, second)},
        bearer(key_pair, OWNER),
    )

    assert [from_phone.status_code, from_tablet.status_code] == [200, 200]
    assert len(backend.calls) == 2


async def test_a_de_enrolled_phone_stops_approving(
    settings: ConfirmSettings, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The other half of rotation. The operator removes the lost phone from
    the store; the same signature that worked a moment ago is refused, with
    nothing in this repository changed."""
    lost_private, lost_public = device_key("lost-phone")
    record = await seed(clean, f"{PREFIX}rotated")
    signature = sign_row(lost_private, record)

    while_enrolled = build_app(
        settings, key_pair, device_key_store=enrolled_store(OWNER, OWNER_PUBLIC, lost_public)
    )
    after_removal = build_app(
        settings, key_pair, device_key_store=enrolled_store(OWNER, OWNER_PUBLIC)
    )

    refused = await approve(
        after_removal, f"{PREFIX}rotated", {"signature": signature}, bearer(key_pair, OWNER)
    )
    assert refused.status_code == 403
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}rotated") == "pending"

    accepted = await approve(
        while_enrolled, f"{PREFIX}rotated", {"signature": signature}, bearer(key_pair, OWNER)
    )
    assert accepted.status_code == 200, accepted.text
    assert len(backend.calls) == 1


# ---------------------------------------------------------------------------
# 2. A wrong signature refuses, and burns nothing.
# ---------------------------------------------------------------------------


async def test_a_wrong_signature_refuses_and_the_challenge_stays_pending(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 2, and the placement argument in one assertion.

    The challenge must still be ``pending`` afterwards: if the check ran after
    the conditional ``UPDATE``, a caller who cannot sign could burn every
    challenge a customer holds, and the customer's own phone would then be
    refused with 409 on a payment nobody approved.
    """
    record = await seed(clean, f"{PREFIX}wrong")

    response = await approve(
        app,
        f"{PREFIX}wrong",
        {"signature": sign_row(ATTACKER_PRIVATE, record)},
        bearer(key_pair, OWNER),
    )

    assert response.status_code == 403
    assert response.json()["error"] == "invalid_signature"
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}wrong") == "pending"
    assert await stored_signature(clean, f"{PREFIX}wrong") is None

    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_SIGNATURE_INVALID
    assert row.reaching_at is None
    # The operation is named: an investigator asking what this caller tried to
    # approve gets an answer.
    assert row.tool_name == TOOL


async def test_the_owners_own_phone_can_still_approve_after_a_forgery_attempt(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The consequence of step 2 stated as behaviour rather than as a status
    column: a refused forgery must not be a denial of service on the customer."""
    record = await seed(clean, f"{PREFIX}survives")

    forged = await approve(
        app,
        f"{PREFIX}survives",
        {"signature": sign_row(ATTACKER_PRIVATE, record)},
        bearer(key_pair, OWNER),
    )
    real = await approve(
        app,
        f"{PREFIX}survives",
        {"signature": sign_row(OWNER_PRIVATE, record)},
        bearer(key_pair, OWNER),
    )

    assert forged.status_code == 403
    assert real.status_code == 200, real.text
    assert len(backend.calls) == 1


async def test_a_malformed_signature_is_recorded_as_its_own_class(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """A client that sends the wrong encoding and one that sends a forgery are
    the same refusal to the caller and different rows in the table."""
    await seed(clean, f"{PREFIX}malformed")

    response = await approve(
        app, f"{PREFIX}malformed", {"signature": "not-base64url!"}, bearer(key_pair, OWNER)
    )

    assert response.status_code == 403
    assert response.json()["error"] == "invalid_signature"
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}malformed") == "pending"
    (row,) = await rows(clean)
    assert row.detail == DETAIL_SIGNATURE_MALFORMED


async def test_the_two_signature_refusals_are_one_answer_to_the_caller(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Byte-identical bodies, two details. The caller learns "it did not
    verify" and nothing about which check said so."""
    record = await seed(clean, f"{PREFIX}pairA")
    await seed(clean, f"{PREFIX}pairB")

    forged = await approve(
        app,
        f"{PREFIX}pairA",
        {"signature": sign_row(ATTACKER_PRIVATE, record)},
        bearer(key_pair, OWNER),
    )
    malformed = await approve(
        app, f"{PREFIX}pairB", {"signature": "still-not-base64url"}, bearer(key_pair, OWNER)
    )

    assert forged.status_code == malformed.status_code == 403
    assert forged.content == malformed.content
    assert [row.detail for row in await rows(clean)] == [
        DETAIL_SIGNATURE_INVALID,
        DETAIL_SIGNATURE_MALFORMED,
    ]


# ---------------------------------------------------------------------------
# 3. A signature over different content.
# ---------------------------------------------------------------------------


async def test_a_signature_for_another_challenge_does_not_approve_this_one(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 3, first shape: the customer's OWN phone signed this,
    for a different challenge of their own. It is still refused."""
    theirs = await seed(clean, f"{PREFIX}held")
    target = await seed(clean, f"{PREFIX}target")
    assert theirs.payload == target.payload  # identical in every field but the id

    response = await approve(
        app,
        f"{PREFIX}target",
        {"signature": sign_row(OWNER_PRIVATE, theirs)},
        bearer(key_pair, OWNER),
    )

    assert response.status_code == 403
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}target") == "pending"


async def test_a_signature_over_an_altered_amount_does_not_approve_the_stored_one(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 3, the shape that matters most.

    The stored challenge's payload carries an amount of EUR 340.00. The phone
    signs EUR 3.40 -- the amount an injected agent would rather have shown --
    against the same challenge id, customer, tool and deadline. The message is
    built from the ROW, so what the caller signed is not what the server
    checks, and the approval is refused.
    """
    record = await seed(clean, f"{PREFIX}amount")
    assert record.payload["amount"] == "EUR 340.00"

    over_a_different_amount = sign_fields(
        OWNER_PRIVATE,
        challenge_id=record.challenge_id,
        customer_ref=record.customer_ref,
        tool_name=record.tool_name,
        payload={"amount": "EUR 3.40", "payee": "Acme Ltd"},
        expires_at=record.expires_at,
    )

    response = await approve(
        app, f"{PREFIX}amount", {"signature": over_a_different_amount}, bearer(key_pair, OWNER)
    )

    assert response.status_code == 403
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}amount") == "pending"


async def test_a_signature_over_another_tool_does_not_approve_another_operation(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """A card freeze the customer really did approve must not approve the
    stored challenge, which is for a different operation."""
    record = await seed(clean, f"{PREFIX}tool")

    as_a_card_freeze = sign_fields(
        OWNER_PRIVATE,
        challenge_id=record.challenge_id,
        customer_ref=record.customer_ref,
        tool_name="cards.freeze_card",
        payload=record.payload,
        expires_at=record.expires_at,
    )

    response = await approve(
        app, f"{PREFIX}tool", {"signature": as_a_card_freeze}, bearer(key_pair, OWNER)
    )

    assert response.status_code == 403
    assert backend.calls == []


async def test_the_request_body_cannot_influence_what_is_verified(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The load-bearing property, asserted directly.

    The body carries a full set of fields naming a different payload, matching
    the ones the caller signed. None of them is read: the message comes from
    the stored row, so the extra fields change nothing and the refusal stands.
    """
    record = await seed(clean, f"{PREFIX}body")
    cheaper: dict[str, Any] = {"amount": "EUR 1.00", "payee": "Attacker Ltd"}

    response = await approve(
        app,
        f"{PREFIX}body",
        {
            "signature": sign_fields(
                OWNER_PRIVATE,
                challenge_id=record.challenge_id,
                customer_ref=record.customer_ref,
                tool_name=record.tool_name,
                payload=cheaper,
                expires_at=record.expires_at,
            ),
            # Everything below is an attempt to tell the server what to verify.
            "payload": cheaper,
            "amount": "EUR 1.00",
            "tool_name": "payments.create_payment",
            "expires_at": record.expires_at.isoformat(),
            "customer_ref": OWNER,
        },
        bearer(key_pair, OWNER),
    )

    assert response.status_code == 403
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}body") == "pending"


# ---------------------------------------------------------------------------
# 4. Replay against a challenge that is no longer claimable.
# ---------------------------------------------------------------------------


async def test_a_replayed_signature_on_a_terminal_challenge_refuses(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 4, first half. Ed25519 is deterministic, so the
    replay is the SAME string the first approval carried -- which is the
    realistic case, not a contrived one. The conditional ``UPDATE`` refuses
    it, the backend is not touched again, and the row is untouched."""
    record = await seed(clean, f"{PREFIX}replay")
    signature = sign_row(OWNER_PRIVATE, record)

    first = await approve(app, f"{PREFIX}replay", {"signature": signature}, bearer(key_pair, OWNER))
    second = await approve(
        app, f"{PREFIX}replay", {"signature": signature}, bearer(key_pair, OWNER)
    )

    assert first.status_code == 200, first.text
    assert second.status_code == 409
    assert second.json()["error"] == "already_terminal"
    assert len(backend.calls) == 1, "the replay reached the backend a second time"
    assert await status_of(clean, f"{PREFIX}replay") == "executed"


async def test_a_valid_signature_on_an_expired_challenge_refuses(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 4, second half. The signature verifies -- the deadline
    is part of what was signed and it is the stored one -- and the approval is
    still refused, by the deadline in the ``UPDATE``'s ``WHERE``."""
    record = await seed(clean, f"{PREFIX}expired", expired=True)

    response = await approve(
        app,
        f"{PREFIX}expired",
        {"signature": sign_row(OWNER_PRIVATE, record)},
        bearer(key_pair, OWNER),
    )

    assert response.status_code == 410
    assert response.json()["error"] == "expired"
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}expired") == "expired"


# ---------------------------------------------------------------------------
# 5. The ordering: this check is not an existence oracle.
# ---------------------------------------------------------------------------


async def test_a_stranger_gets_the_ordinary_404_and_never_a_signature_refusal(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Decision 4's first edge. The ownership check runs first, so a caller
    who does not own the challenge gets the same 404 as for an id that names
    nothing -- whatever they present as a signature, and whether or not they
    have a device enrolled at all."""
    record = await seed(clean, f"{PREFIX}owned", customer_ref=OWNER)

    not_yours = await approve(
        app,
        f"{PREFIX}owned",
        {"signature": sign_row(OWNER_PRIVATE, record)},
        bearer(key_pair, STRANGER),
    )
    no_such = await approve(
        app, f"{PREFIX}absent", {"signature": "irrelevant"}, bearer(key_pair, STRANGER)
    )

    assert not_yours.status_code == no_such.status_code == 404
    assert not_yours.content.replace(f"{PREFIX}owned".encode(), b"ID") == no_such.content.replace(
        f"{PREFIX}absent".encode(), b"ID"
    )
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}owned") == "pending"


async def test_no_signature_at_all_is_still_the_400_it_was(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The presence check stays ahead of the row, so an empty field is
    answerable without reading anything and cannot become an oracle either."""
    response = await approve(app, f"{PREFIX}nobody_signed", {}, bearer(key_pair, OWNER))

    assert response.status_code == 400
    assert response.json()["error_description"] == "signature is required"
    (row,) = await rows(clean)
    assert row.tool_name == UNRESOLVED_TOOL_NAME
    assert row.arguments["signature_present"] is False


# ---------------------------------------------------------------------------
# 6. Unconfigured, unenrolled, and unavailable: three different events.
# ---------------------------------------------------------------------------


def test_an_unconfigured_store_refuses_to_build_the_app(
    settings: ConfirmSettings, key_pair: RSAKeyPair
) -> None:
    """Verification step 5, and decision 2.

    No ``device_keys_path``, no ``device_key_store=``: the app does not exist.
    The unverified configuration is therefore unreachable rather than
    unlikely, which is the same shape ``_assertion_verifier`` gives inbound
    authentication one guard earlier.
    """
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)

    with pytest.raises(ValueError) as excinfo:
        create_confirm_app(settings, assertion_verifier=verifier)

    message = str(excinfo.value)
    # Actionable: an operator reading a crash loop needs the variable name and
    # the way out, not the field name.
    assert "POSTERN_DEVICE_KEYS_PATH" in message
    assert "no unverified-signature mode" in message
    assert '{"customers": {}}' in message


def test_the_configured_path_is_what_builds_the_store(
    settings: ConfirmSettings, key_pair: RSAKeyPair, tmp_path: Any
) -> None:
    """The positive of the guard above: a path an operator sets produces a
    working app, and the store it produces is the file's contents."""
    document = tmp_path / "device-keys.json"
    document.write_text(json.dumps({"customers": {}}))
    configured = ConfirmSettings(
        backend_base_url=settings.backend_base_url,
        database_url=settings.database_url,
        device_keys_path=str(document),
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so without these two flags it gets the
        # safe defaults and refuses to start.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)

    with pytest.warns(RuntimeWarning, match="no device is enrolled"):
        app = create_confirm_app(configured, assertion_verifier=verifier)

    assert isinstance(app.state.postern_device_key_store, DeviceKeyStoreBase)


async def test_a_customer_with_no_enrolled_device_is_refused_and_named_as_such(
    settings: ConfirmSettings, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """Verification step 6, and decision 3.

    The store ANSWERS and the answer is "nobody". That is a support event --
    this customer has not enrolled a phone -- and it must be distinguishable
    in the table from the store failing to answer, which the next test covers.
    """
    app = build_app(settings, key_pair, device_key_store=no_enrolled_devices())
    record = await seed(clean, f"{PREFIX}unenrolled")

    response = await approve(
        app,
        f"{PREFIX}unenrolled",
        {"signature": sign_row(OWNER_PRIVATE, record)},
        bearer(key_pair, OWNER),
    )

    assert response.status_code == 403
    assert response.json()["error"] == "device_not_enrolled"
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}unenrolled") == "pending"

    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_DEVICE_NOT_ENROLLED
    assert row.tool_name == TOOL


async def test_a_store_that_cannot_answer_fails_closed_and_is_told_apart(
    settings: ConfirmSettings, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The other half of decision 3, and the reason
    `DeviceKeyStoreUnavailable` exists as a separate exception.

    An enrolment store that is down must not read as every customer having
    un-enrolled at once. It fails the request with a 500, leaves the challenge
    ``pending``, and lands on a row whose ``detail`` is the exception TYPE --
    which is what an operator filters on to tell an outage from a support
    queue.
    """

    class UnreachableStore(DeviceKeyStoreBase):
        async def keys_for(self, customer_ref: str) -> tuple[EnrolledDeviceKey, ...]:
            raise DeviceKeyStoreUnavailable("simulated enrolment store outage")

    app = build_app(settings, key_pair, device_key_store=UnreachableStore())
    record = await seed(clean, f"{PREFIX}outage")

    response = await approve(
        app,
        f"{PREFIX}outage",
        {"signature": sign_row(OWNER_PRIVATE, record)},
        bearer(key_pair, OWNER),
        as_a_server_would=True,
    )

    assert response.status_code == 500
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}outage") == "pending"

    (row,) = await rows(clean)
    assert row.detail == "DeviceKeyStoreUnavailable"
    assert row.detail != DETAIL_DEVICE_NOT_ENROLLED


async def test_a_store_that_is_not_wired_at_all_fails_closed(
    settings: ConfirmSettings, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """The branch ``services/confirm/device_signature.py`` deliberately does
    NOT write: an app whose state carries no store raises ``AttributeError``,
    which becomes a 500 and an audit row, rather than returning "no keys" and
    reading as a customer who has not enrolled."""
    app = build_app(settings, key_pair)
    del app.state.postern_device_key_store
    record = await seed(clean, f"{PREFIX}unwired")

    response = await approve(
        app,
        f"{PREFIX}unwired",
        {"signature": sign_row(OWNER_PRIVATE, record)},
        bearer(key_pair, OWNER),
        as_a_server_would=True,
    )

    assert response.status_code == 500
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}unwired") == "pending"
    (row,) = await rows(clean)
    assert row.detail == "AttributeError"


async def test_an_uncanonicalisable_challenge_refuses_without_moving_anything(
    app: Starlette, clean: Database, backend: Backend, key_pair: RSAKeyPair
) -> None:
    """A payload the encoder refuses is a defect in whatever wrote the row,
    not something a caller did. It fails the request with a 500, records the
    exception type, and leaves the challenge ``pending`` -- never an approval
    over bytes nobody can reproduce."""
    await seed(clean, f"{PREFIX}float", payload={"amount": 340.0})

    response = await approve(
        app,
        f"{PREFIX}float",
        {"signature": "A" * 86},
        bearer(key_pair, OWNER),
        as_a_server_would=True,
    )

    assert response.status_code == 500
    assert backend.calls == []
    assert await status_of(clean, f"{PREFIX}float") == "pending"
    (row,) = await rows(clean)
    assert row.detail == "UncanonicalChallengeError"


# ---------------------------------------------------------------------------
# 7. Wiring.
# ---------------------------------------------------------------------------


def test_the_composition_root_wires_the_store_it_was_given(
    settings: ConfirmSettings, key_pair: RSAKeyPair
) -> None:
    """``app.state.postern_device_key_store`` is the name
    ``services/confirm/device_signature.py`` reads, and a rename on either
    side would otherwise surface as a 500 in production rather than here."""
    store = enrolled_store(OWNER, OWNER_PUBLIC)
    app = build_app(settings, key_pair, device_key_store=store)

    assert app.state.postern_device_key_store is store
    assert isinstance(app.state.postern_device_key_store, InMemoryDeviceKeyStore)


def test_module_is_running_against_a_real_database(pg_url: str) -> None:
    """Every assertion above about a challenge staying ``pending`` is a claim
    about what PostgreSQL did. Against a mock they would mean nothing."""
    assert pg_url.startswith("postgresql+asyncpg://"), pg_url
    assert os.environ.get("POSTERN_DATABASE_URL", "").startswith("postgresql+asyncpg://")

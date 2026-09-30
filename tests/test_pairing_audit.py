"""The device grant's audit trail, against a real Postgres.

WHAT THIS MODULE EXISTS FOR. Until 2026-09-26 ``services/confirm/device_auth
.py`` wrote no ``audit_log`` row on any branch of any of its three endpoints.
Every occurrence of the string ``audit`` in that file was prose about audit
findings C-01 and C-04, not a call that wrote a row. So a payment approval
through ``POST /challenges/{challenge_id}/approve`` left two correlated rows,
and the pairing that authorises a client to reach that endpoint at all left
none: an attacker who paired a rogue client was visible only in the payments
that followed it, and only if any followed.

THE CHAIN, AND WHICH LINKS ARE RECORDED. ``POST /approve`` and
``POST /token`` each write one row, so a pairing and each exchange attempted
off the back of it are both countable and join on
``arguments['device_code_handle']``. Since 2026-09-30 the exchange row is the
``issuance_disabled`` refusal, because ``POST /token`` mints nothing until the
layer-1 session token exists.
``POST /device_authorization`` writes none, deliberately, and
``test_device_authorization_writes_nothing`` is where that is asserted rather
than assumed. So is most of ``POST /token``: at the configured 5-second poll
interval and 900-second code lifetime a browser can poll 180 times, and none
of those polls resolves a customer, so none of them writes a row.
``services/confirm/audit.py``'s ``PairingAudit`` carries the rule that
partitions them.

THE TWO ASSERTIONS THAT MATTER MOST, because they are the two an
implementation can satisfy in appearance and miss in substance:

1. ``test_a_pairing_that_cannot_be_audited_does_not_stand`` counts the DEVICE
   CODE'S STATE, not the status code. A handler that answered 500 and left
   ``approved=True`` on the code would pass every status assertion here and
   fail closed in name only -- ``POST /token`` would still treat the code as
   approved for a customer no pairing row records.
2. ``test_the_row_names_no_raw_device_code`` reads the whole row back as JSON
   and asserts the 43-character device code appears nowhere in it. The code is
   a bearer credential; ``audit_log`` is append-only and outlives it by years.

Every test drives the assembled app over ASGI through ``create_confirm_app``
and reads the rows back out of Postgres, for the reason
``tests/test_write_audit.py`` gives: the properties asserted here are
properties of the database (a CHECK constraint accepts the row; the row is
durable) and not of a mock.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections.abc import AsyncGenerator, Generator
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
    OUTCOME_REACHING,
    OUTCOME_RETURNED,
    AuditEntry,
)
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_ALREADY_APPROVED,
    DETAIL_DEVICE_CODE_NOT_FOUND,
    DETAIL_DEVICE_CODE_SPENT,
    DETAIL_INVALID_SUBJECT,
    DETAIL_ISSUANCE_DISABLED,
    DETAIL_NOT_SCANNED,
    DETAIL_REVOKED,
    DETAIL_SCANNED_BY_OTHER,
    DETAIL_STORED_IDENTITY_MALFORMED,
    DETAIL_USER_CODE_BUDGET_EXHAUSTED,
    DETAIL_USER_CODE_MISMATCH,
    DETAIL_USER_CODE_NOT_FOUND,
    PAIRING_ROUTE,
    PAIRING_TOOL_NAME,
    TOKEN_ROUTE,
    TOKEN_TOOL_NAME,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import (
    ISSUANCE_DISABLED_BODY,
    jwt_shaped_strings,
    overwrite_in_memory,
    scan_in_store,
)
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
CUSTOMER = "cust_7f3a"
#: The client the browser names at ``POST /device_authorization``. Recorded on
#: the pairing row because it is the only answer this system has to "which
#: client did this customer authorise", and it is caller-supplied, which is
#: why the row scrubs it like every other caller-influenced value.
BROWSER_CLIENT = "claude-desktop-42"


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_url() -> Generator[str]:
    """Module-scoped Postgres, mirroring ``tests/test_write_audit.py``.

    Restores ``POSTERN_DATABASE_URL`` on the way out, because leaving it
    pointed at a torn-down container poisons every ``from_env()`` in whatever
    module runs next.
    """
    import docker
    from testcontainers.community.postgres import PostgresContainer

    try:
        docker.from_env().ping()
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping pairing-audit tests: {exc}")

    previous = os.environ.get("POSTERN_DATABASE_URL")
    with PostgresContainer("postgres:17-alpine", driver="asyncpg") as pg:
        url = pg.get_connection_url()
        os.environ["POSTERN_DATABASE_URL"] = url
        from alembic import command
        from alembic.config import Config

        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        try:
            yield url
        finally:
            if previous is None:
                os.environ.pop("POSTERN_DATABASE_URL", None)
            else:
                os.environ["POSTERN_DATABASE_URL"] = previous


@pytest.fixture()
def settings(pg_url: str) -> ConfirmSettings:
    return replace(ConfirmSettings.for_testing(), database_url=pg_url)


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
def app(settings: ConfirmSettings, key_pair: RSAKeyPair) -> Starlette:
    """The composition root, never a hand-assembled app.

    ``no_enrolled_devices`` because nothing here approves a CHALLENGE: the
    device grant and the device signature are different stores for different
    questions, and ``create_confirm_app`` refuses to build without the second
    one whether or not a test reaches it.
    """
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
    )


@pytest.fixture()
def db(settings: ConfirmSettings) -> Database:
    return Database(settings.database_url)


@pytest.fixture()
async def clean(db: Database) -> AsyncGenerator[Database, None]:
    """Empty ``audit_log`` either side of every test.

    Both ends: the app under test commits through its own pool, so nothing a
    fixture rolls back can undo those rows, and without the post-test clear
    the last test here leaves its rows for whatever reads the table next.
    """
    await _wipe(db)
    yield db
    await _wipe(db)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def bearer(key_pair: RSAKeyPair, subject: str = CUSTOMER) -> dict[str, str]:
    token = key_pair.create_token(subject=subject, issuer=ISSUER, audience=AUDIENCE)
    return {"Authorization": f"Bearer {token}"}


async def issue(
    app: Starlette, client_id: str = BROWSER_CLIENT, *, scanned_by: str | None = CUSTOMER
) -> DeviceCode:
    """One device code, created through the store the app actually holds.

    Scanned by ``scanned_by`` through the store, as ``POST /scan`` would have,
    because ``POST /approve`` approves only a code the approving customer
    scanned; ``None`` leaves it unscanned. Through the store and not over
    HTTP so the scan's own row does not join the ones these tests count.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await store.create_device_code(
        client_id=client_id,
        scopes="accounts:read",
        verification_uri="https://auth.test.invalid/verify",
    )
    if scanned_by is not None:
        await scan_in_store(app, code.user_code, scanned_by)
    return code


async def approve(
    app: Starlette,
    body: Any,
    headers: dict[str, str] | None = None,
    *,
    as_a_server_would: bool = False,
    extra_headers: dict[str, str] | None = None,
) -> httpx2.Response:
    """POST an approval over ASGI.

    ``as_a_server_would`` sets ``raise_app_exceptions=False``, which is what
    makes the fail-closed test meaningful: Starlette's ``ServerErrorMiddleware``
    re-raises so the ASGI server can answer, and under the default transport
    that exception would surface in the test as a crash rather than as the
    500 a real client receives.
    """
    sent = dict(headers or {})
    sent.update(extra_headers or {})
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=not as_a_server_would),
        base_url="http://t",
    ) as c:
        return await c.post("/approve", json=body, headers=sent)


async def rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(select(AuditEntry).order_by(AuditEntry.id))
        return list(result.scalars().all())


async def one_row(db: Database) -> AuditEntry:
    entries = await rows(db)
    assert len(entries) == 1, f"expected exactly one audit row, got {len(entries)}"
    return entries[0]


def handle_of(device_code: str) -> str:
    """The digest the row is expected to carry in place of the credential."""
    return hashlib.sha256(device_code.encode("utf-8")).hexdigest()[:16]


async def unwrap(store: DeviceCodeStoreBase, device_code: str) -> DeviceCode:
    """The stored code, for tests that have to bend one out of shape.

    Re-read rather than reusing the object ``issue`` returned, because
    ``POST /approve`` has rewritten three of its fields by the time these
    tests run and ``dataclasses.replace`` on the stale copy would silently
    un-approve the code it is trying to corrupt.
    """
    stored = await store.get_device_code(device_code)
    assert stored is not None
    return stored


# ---------------------------------------------------------------------------
# 1. The successful pairing.
# ---------------------------------------------------------------------------


async def test_a_successful_pairing_writes_one_row(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Which customer paired which client, when, and from where.

    Every column asserted here is one an investigator reads. ``tool_name``
    carries a literal that is not a registered MCP tool, so
    ``WHERE tool_name = 'device_grant.approve'`` is by itself the
    "show me every pairing" query and can never collide with a
    ``services/api`` row.
    """
    code = await issue(app)

    resp = await approve(
        app,
        {"user_code": code.user_code_display},
        bearer(key_pair),
    )
    assert resp.status_code == 200

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RETURNED
    assert row.detail is None
    assert row.customer_ref == CUSTOMER
    assert row.customer_ref_absence_reason is None
    assert row.tool_name == PAIRING_TOOL_NAME
    assert row.call_id is not None and len(row.call_id) == 36
    assert row.duration_ms is not None and row.duration_ms >= 0
    assert row.arguments["route"] == PAIRING_ROUTE
    assert row.arguments["device_code_handle"] == handle_of(code.device_code)
    assert row.arguments["paired_client_id"] == BROWSER_CLIENT


async def test_the_row_is_one_and_not_the_read_paths_pair(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """No entry row, and the reason is structural rather than a preference.

    ``outcome='reaching'`` means the operator was about to reach a backend
    endpoint, and ``ck_audit_log_reaching_at_matches_outcome`` ties
    ``reaching_at`` to exactly that value. A pairing reaches no backend: it
    writes one field on a device code held in this deployment's own store. A
    ``reaching`` row here would put a second meaning into a closed vocabulary
    a CHECK constraint enforces, and every existing query for backend touches
    would start returning pairings.
    """
    code = await issue(app)
    await approve(
        app,
        {"user_code": code.user_code_display},
        bearer(key_pair),
    )

    written = await rows(clean)
    assert len(written) == 1
    assert written[0].reaching_at is None
    assert [r.outcome for r in written] == [OUTCOME_RETURNED]
    assert OUTCOME_REACHING not in {r.outcome for r in written}


async def test_the_row_names_no_raw_device_code(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The credential never lands in the table; a digest of it does.

    ``device_code`` is 43 characters of ``secrets.token_urlsafe`` entropy and
    is the entire authority to exchange at ``POST /token``. ``audit_log``
    outlives it by years and is read by people who are not the operator's
    on-call engineer. The handle is 16 hex characters of its SHA-256, which is
    enough for two rows about the same pairing to join and for an operator
    holding the code to confirm the match, and is not enough to replay it.
    """
    code = await issue(app)
    await approve(
        app,
        {"user_code": code.user_code_display},
        bearer(key_pair),
    )

    row = await one_row(clean)
    serialised = json.dumps(
        {
            "arguments": row.arguments,
            "detail": row.detail,
            "tool_name": row.tool_name,
            "client_id": row.client_id,
            "customer_ref": row.customer_ref,
        }
    )
    assert code.device_code not in serialised
    assert code.user_code not in serialised
    assert handle_of(code.device_code) in serialised


async def test_the_row_records_the_address_the_request_came_from(
    pg_url: str, key_pair: RSAKeyPair
) -> None:
    """``from where``, derived the one way this repository derives it.

    ``postern_core.net``'s ``client_ip`` reads ``X-Forwarded-For`` from the
    RIGHT with ``trusted_proxy_hops`` entries trusted, so a caller cannot pin
    their apparent address by writing the leftmost entry. This app is built
    with one trusted hop, so ``198.51.100.7`` -- the value the caller wrote --
    is discarded and ``203.0.113.9``, the one a proxy appended, is recorded.
    """
    settings = replace(ConfirmSettings.for_testing(), database_url=pg_url, trusted_proxy_hops=1)
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    app = create_confirm_app(
        settings, assertion_verifier=verifier, device_key_store=no_enrolled_devices()
    )
    db = Database(pg_url)
    await _wipe(db)
    try:
        code = await issue(app)
        resp = await approve(
            app,
            {"user_code": code.user_code_display},
            bearer(key_pair),
            extra_headers={"X-Forwarded-For": "198.51.100.7, 203.0.113.9"},
        )
        assert resp.status_code == 200

        row = await one_row(db)
        assert row.arguments["client_ip"] == "203.0.113.9"
    finally:
        await _wipe(db)


# ---------------------------------------------------------------------------
# 2. The refusals that are a conclusion about a customer or a device code.
# ---------------------------------------------------------------------------


async def test_an_unknown_user_code_is_recorded(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The enumeration signal, and the branch with no pairing to name.

    A ``user_code`` is 30 bits, so guessing one is cheap, and the row is the
    only place the attempts are countable: N rows of ``user_code_not_found``
    under one ``customer_ref`` is somebody walking the code space. The row
    names no device code, because the guess named none.
    """
    resp = await approve(app, {"user_code": "ZZZ-ZZZ"}, bearer(key_pair))
    assert resp.status_code == 400
    assert resp.json()["error"] == "invalid_grant"

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_USER_CODE_NOT_FOUND
    assert row.customer_ref == CUSTOMER
    assert "device_code_handle" not in row.arguments
    assert "paired_client_id" not in row.arguments


async def test_an_unscanned_code_is_recorded_as_not_scanned(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """An app skipping ``POST /scan``, or something guessing codes that
    happened to hit a live one. Either way nothing is approved."""
    code = await issue(app, scanned_by=None)

    resp = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert resp.status_code == 400

    row = await one_row(clean)
    assert row.detail == DETAIL_NOT_SCANNED
    assert row.arguments["device_code_handle"] == handle_of(code.device_code)
    assert row.arguments["paired_client_id"] == BROWSER_CLIENT
    stored = await unwrap(app.state.device_code_store, code.device_code)
    assert stored.approved is False


async def test_a_code_another_customer_scanned_is_recorded_as_scanned_by_other(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Scanned by A, approved by B: refused, and the row says so under B."""
    code = await issue(app, scanned_by="cust_a11ce")

    resp = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert resp.status_code == 400

    row = await one_row(clean)
    assert row.detail == DETAIL_SCANNED_BY_OTHER
    assert row.customer_ref == CUSTOMER
    stored = await unwrap(app.state.device_code_store, code.device_code)
    assert stored.approved is False
    assert stored.scanned_by == "cust_a11ce"


async def test_a_repeat_approval_by_the_scanner_is_recorded_as_already_approved(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Normally a retried request. Both rows name the same pairing."""
    code = await issue(app)
    first = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert first.status_code == 200

    second = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert second.status_code == 400

    written = await rows(clean)
    assert [r.outcome for r in written] == [OUTCOME_RETURNED, OUTCOME_RAISED]
    assert written[1].detail == DETAIL_ALREADY_APPROVED
    assert (
        written[0].arguments["device_code_handle"] == (written[1].arguments["device_code_handle"])
    ), "both rows name the same pairing, which is what makes the pair readable"


@pytest.mark.parametrize("vanishes_by", ["revocation", "expiry"])
async def test_a_row_gone_between_the_lookup_and_the_refusal_is_user_code_not_found(
    app: Starlette,
    clean: Database,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    vanishes_by: str,
) -> None:
    """Section 6's first label: gone or expired by the time it is re-read.

    The window is forced by replacing ``approve_scanned`` with one that makes
    the row vanish and then refuses, which is the order a real race would
    produce: the lookup found a live row, the compare-and-set did not approve
    it, and the re-read finds nothing live.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await issue(app)

    async def vanish_then_refuse(device_code: str, customer_ref: str) -> bool:
        if vanishes_by == "revocation":
            await store.revoke_device_code(device_code)
        else:
            stored = await unwrap(store, device_code)
            past = datetime.now(UTC) - timedelta(seconds=1)
            overwrite_in_memory(app, replace(stored, expires_at=past))
        return False

    monkeypatch.setattr(store, "approve_scanned", vanish_then_refuse)

    resp = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    assert resp.status_code == 400

    row = await one_row(clean)
    assert row.detail == DETAIL_USER_CODE_NOT_FOUND
    assert row.arguments["device_code_handle"] == handle_of(code.device_code)


async def test_a_scan_racing_a_refused_approval_is_still_the_identical_refusal(
    app: Starlette,
    clean: Database,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The re-read finds a row ``approve_scanned`` would have approved.

    On Redis the refused compare-and-set and the re-read are two round trips,
    so the same customer's ``POST /scan`` can commit between them. The re-read
    then shows a row scanned by this customer, unexpired and unapproved. That
    is still a refusal, and it must answer the one ``invalid_grant`` body
    rather than a 500. Forced here by an ``approve_scanned`` that refuses a
    row the store already holds in exactly that shape.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await issue(app)

    async def refuse(device_code: str, customer_ref: str) -> bool:
        return False

    monkeypatch.setattr(store, "approve_scanned", refuse)

    unknown = await approve(app, {"user_code": "ZZZ-ZZZ"}, bearer(key_pair))
    await _wipe(clean)
    resp = await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))

    assert resp.status_code == 400
    assert resp.json() == unknown.json()
    row = await one_row(clean)
    assert row.detail == DETAIL_NOT_SCANNED
    stored = await unwrap(store, code.device_code)
    assert stored.approved is False


async def test_a_refusal_whose_re_read_fails_is_still_the_identical_refusal(
    app: Starlette,
    clean: Database,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The store goes away between the refused compare-and-set and the re-read.

    The re-read only labels the row, so its failure must not change the
    answer: until 2026-09-30 it propagated and a refusal the spec answers
    with the one ``invalid_grant`` body became a 500, a second response shape.
    The row is labelled ``not_scanned``, the label that describes a refusal
    whose row could not be read and decides nothing, and a WARNING names the
    exception type.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await issue(app)
    unknown = await approve(app, {"user_code": "ZZZ-ZZZ"}, bearer(key_pair))
    await _wipe(clean)

    async def refuse(device_code: str, customer_ref: str) -> bool:
        return False

    async def outage(device_code: str) -> DeviceCode | None:
        raise ConnectionError("store gone")

    monkeypatch.setattr(store, "approve_scanned", refuse)
    monkeypatch.setattr(store, "get_device_code", outage)

    with caplog.at_level(logging.WARNING, logger="services.confirm.device_auth"):
        resp = await approve(
            app,
            {"user_code": code.user_code_display},
            bearer(key_pair),
            as_a_server_would=True,
        )

    assert resp.status_code == 400
    assert resp.content == unknown.content
    row = await one_row(clean)
    assert row.detail == DETAIL_NOT_SCANNED
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("ConnectionError" in m for m in warnings), warnings


async def test_every_refusal_about_a_pairing_answers_one_identical_body(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Unknown, unscanned, scanned by another, already approved: four
    different rows and one response, so the response is not an oracle."""
    unscanned = await issue(app, scanned_by=None)
    someone_elses = await issue(app, scanned_by="cust_a11ce")
    approved = await issue(app)
    assert (
        await approve(app, {"user_code": approved.user_code_display}, bearer(key_pair))
    ).status_code == 200
    await _wipe(clean)

    bodies = []
    for user_code in (
        "ZZZ-ZZZ",
        unscanned.user_code_display,
        someone_elses.user_code_display,
        approved.user_code_display,
    ):
        resp = await approve(app, {"user_code": user_code}, bearer(key_pair))
        assert resp.status_code == 400
        bodies.append(resp.json())

    assert all(body == bodies[0] for body in bodies), bodies
    assert [r.detail for r in await rows(clean)] == [
        DETAIL_USER_CODE_NOT_FOUND,
        DETAIL_NOT_SCANNED,
        DETAIL_SCANNED_BY_OTHER,
        DETAIL_ALREADY_APPROVED,
    ]


def test_the_retired_literals_stay_defined_for_the_rows_that_carry_them() -> None:
    """``audit_log`` is append-only, so rows carrying these exist and nothing
    in the tree may stop naming them, though nothing writes them any more."""
    assert DETAIL_DEVICE_CODE_NOT_FOUND == "device_code_not_found"
    assert DETAIL_USER_CODE_MISMATCH == "user_code_mismatch"
    assert DETAIL_USER_CODE_BUDGET_EXHAUSTED == "user_code_budget_exhausted"
    assert DETAIL_USER_CODE_NOT_FOUND == "user_code_not_found"
    assert DETAIL_NOT_SCANNED == "not_scanned"
    assert DETAIL_SCANNED_BY_OTHER == "scanned_by_other"


async def test_a_revoked_customer_is_recorded_with_the_challenge_paths_literal(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """ZT-7, under the same ``detail`` the challenge approval writes.

    One literal across both write-path endpoints means
    ``WHERE detail = 'revoked'`` is the whole answer to "did my revocation take
    effect", rather than an answer that silently omits pairings.
    """
    store: RevocationStoreBase = app.state.postern_revocation_store
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=BROWSER_CLIENT)
    code = await issue(app)

    resp = await approve(
        app,
        {"user_code": code.user_code_display},
        bearer(key_pair),
    )
    assert resp.status_code == 403

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_REVOKED
    assert row.customer_ref == CUSTOMER
    # The revocation is decided before the body is read, so this row names no
    # device code. That ordering is the one `services/confirm/callback.py`
    # already documents for the same check and is not changed here.
    assert "device_code_handle" not in row.arguments

    stored = await app.state.device_code_store.get_device_code(code.device_code)
    assert stored is not None and stored.approved is False


async def test_a_subject_that_is_not_a_customer_reference_is_recorded_as_an_absence(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The compromised-issuer signal, with the offending value never stored.

    ``postern_core.identity`` warns that an issuer under attacker control can
    mint a ``sub`` shaped like a bare PAN. The row records the CLASS of
    absence in ``customer_ref_absence_reason`` and leaves ``customer_ref``
    NULL, which is what ``ck_audit_log_customer_ref_xor_absence`` requires and
    what keeps a PAN-shaped string out of the longest-lived table here.
    """
    pan_shaped = "4111111111111111"

    resp = await approve(
        app,
        {"user_code": "ABC-DEF"},
        bearer(key_pair, subject=pan_shaped),
    )
    assert resp.status_code == 403

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_INVALID_SUBJECT
    assert row.customer_ref is None
    assert row.customer_ref_absence_reason == ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF
    assert pan_shaped not in json.dumps(
        {"arguments": row.arguments, "detail": row.detail, "client_id": row.client_id}
    )


# ---------------------------------------------------------------------------
# 3. The requests that write nothing, which is the other half of the rule.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param([1, 2, 3], id="a JSON array rather than an object"),
        pytest.param({}, id="no user_code"),
        pytest.param({"user_code": ""}, id="user_code is empty"),
        pytest.param({"user_code": 123}, id="user_code is a number"),
        pytest.param({"user_code": ["x"]}, id="user_code is a list"),
        pytest.param(
            dict(device_code="abc", user_code="ABC-DEF"),
            id="the removed device_code is still sent",
        ),
    ],
)
async def test_a_malformed_request_writes_no_row(
    app: Starlette, clean: Database, key_pair: RSAKeyPair, body: Any
) -> None:
    """The rule's other half, stated as a test rather than only in prose.

    A row records what the server CONCLUDED about a customer or a device code.
    None of these reached a conclusion about either: each is answered by
    looking at the request and nothing else. Recording them would hand a
    caller holding one valid assertion an INSERT per malformed body, and would
    fill a regulator-facing table with rows naming no device code and no
    decision.
    """
    resp = await approve(app, body, bearer(key_pair))
    assert resp.status_code == 400
    assert await rows(clean) == []


async def test_a_request_with_no_assertion_writes_no_row(app: Starlette, clean: Database) -> None:
    """No verified subject, so no customer for a row to be about.

    ``AppAssertionMiddleware`` refuses before routing and logs its own
    refusal, which is the record of this event. A row would have to name a
    class of absence and this service's writer reaches only one of the three
    the column admits.
    """
    resp = await approve(app, {"user_code": "ABC-DEF"})
    assert resp.status_code == 401
    assert await rows(clean) == []


# ---------------------------------------------------------------------------
# 4. Fail closed, and what that has to mean on a path with no backend.
# ---------------------------------------------------------------------------


async def test_a_pairing_that_cannot_be_audited_does_not_stand(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Asserts on the DEVICE CODE, not on the status code.

    Decision 0006 is fail closed on every path, and on the money path that
    means a 500 over a backend write that already happened, because a payment
    cannot be unmade from here. A pairing can: the device code lives in this
    deployment's own store and ``revoke_device_code`` undoes it. So fail
    closed here means the pairing is withdrawn, not merely reported as
    failed -- otherwise ``POST /token`` treats the code as approved for a
    customer no pairing row names: it reads that customer off the code, runs
    the ZT-7 check against them and writes ``issuance_disabled`` rows under
    their name. It hands out no token today only because issuance is
    disabled; the pending session-token change would hand one out.
    """
    code = await issue(app)

    async def unavailable(session: Any, **kw: Any) -> None:
        raise RuntimeError("audit store unavailable")

    with patch.object(audit_store, "append", unavailable):
        resp = await approve(
            app,
            {"user_code": code.user_code_display},
            bearer(key_pair),
            as_a_server_would=True,
        )

    assert resp.status_code == 500
    assert await rows(clean) == []

    stored = await app.state.device_code_store.get_device_code(code.device_code)
    assert stored is None or stored.approved is False, (
        "the pairing survived an audit write it could not make; "
        "POST /token would treat it as approved for a customer no pairing row names"
    )


async def test_an_approval_whose_store_write_fails_ambiguously_is_withdrawn(
    app: Starlette,
    clean: Database,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A store error after the server may have committed the approval.

    On Redis ``pipe.execute()`` can raise a timeout after ``EXEC`` ran, so an
    exception out of ``approve_scanned`` does not mean nothing was written.
    Forced here by an ``approve_scanned`` that approves and then raises. The
    response is the 500 it always was, and the pairing is revoked so the
    browser cannot be handed a read token the row says was refused.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await issue(app)
    real_approve = store.approve_scanned

    async def approve_then_time_out(device_code: str, customer_ref: str) -> bool:
        assert await real_approve(device_code, customer_ref) is True
        raise TimeoutError("reply lost after EXEC")

    monkeypatch.setattr(store, "approve_scanned", approve_then_time_out)

    resp = await approve(
        app,
        {"user_code": code.user_code_display},
        bearer(key_pair),
        as_a_server_would=True,
    )

    assert resp.status_code == 500
    assert await store.get_device_code(code.device_code) is None
    row = await one_row(clean)
    assert row.detail == "TimeoutError"


async def test_a_contended_approval_is_not_withdrawn(
    app: Starlette,
    clean: Database,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``DeviceCodeStoreContended`` means the write did not happen.

    Every ``WATCH`` was beaten, so the transaction never committed and there
    is no approval to withdraw. Revoking would only end a live pending pairing
    the customer can still complete on a retry.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await issue(app)

    async def contended(device_code: str, customer_ref: str) -> bool:
        raise DeviceCodeStoreContended("an approval was beaten by another writer 3 times")

    monkeypatch.setattr(store, "approve_scanned", contended)

    resp = await approve(
        app,
        {"user_code": code.user_code_display},
        bearer(key_pair),
        as_a_server_would=True,
    )

    assert resp.status_code == 500
    stored = await store.get_device_code(code.device_code)
    assert stored is not None and stored.approved is False
    row = await one_row(clean)
    assert row.detail == "DeviceCodeStoreContended"


async def test_a_failed_withdrawal_after_an_ambiguous_write_names_the_store_cause(
    app: Starlette,
    clean: Database,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The double failure on the store path, and what the ERROR line says.

    The approval commits and its reply is lost, then the revocation fails
    too. The row carries the ORIGINAL store exception, and the log line names
    the ambiguous store write rather than an audit failure that never
    happened: the row was written, so "no audit_log row" would be false.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await issue(app)
    real_approve = store.approve_scanned

    async def approve_then_time_out(device_code: str, customer_ref: str) -> bool:
        assert await real_approve(device_code, customer_ref) is True
        raise TimeoutError("reply lost after EXEC")

    async def revoke_fails(device_code: str) -> None:
        raise ConnectionError("store gone")

    monkeypatch.setattr(store, "approve_scanned", approve_then_time_out)
    monkeypatch.setattr(store, "revoke_device_code", revoke_fails)

    with caplog.at_level(logging.ERROR, logger="services.confirm.device_auth"):
        resp = await approve(
            app,
            {"user_code": code.user_code_display},
            bearer(key_pair),
            as_a_server_would=True,
        )

    assert resp.status_code == 500
    row = await one_row(clean)
    assert row.detail == "TimeoutError"
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    withdrawal = [m for m in errors if "could not be withdrawn" in m]
    assert len(withdrawal) == 1, errors
    assert "may be approved" in withdrawal[0]
    assert "could not be audited" not in withdrawal[0]


# ---------------------------------------------------------------------------
# 5. POST /token -- the middle link of the chain, refused since 2026-09-30.
# ---------------------------------------------------------------------------


async def exchange(
    app: Starlette, device_code: str, *, as_a_server_would: bool = False
) -> httpx2.Response:
    """``POST /token`` with the device-code grant, over ASGI.

    Form-encoded, because that is what RFC 8628 §3.4 specifies and what
    ``token_endpoint`` reads. ``as_a_server_would`` has the same meaning it
    has in ``approve`` above and is what makes the fail-closed test below
    assert on the response a real client receives.
    """
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=not as_a_server_would),
        base_url="http://t",
    ) as c:
        return await c.post(
            "/token", data={"grant_type": "device_code", "device_code": device_code}
        )


async def paired(app: Starlette, key_pair: RSAKeyPair) -> DeviceCode:
    """A device code that has been through ``POST /approve`` successfully."""
    code = await issue(app)
    resp = await approve(
        app,
        {"user_code": code.user_code_display},
        bearer(key_pair),
    )
    assert resp.status_code == 200
    return code


async def test_an_approved_code_is_refused_503_unspent_and_recorded_as_issuance_disabled(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Issuance is disabled until the layer-1 session token lands.

    The token this endpoint used to return was a layer-2 backend token, signed
    with the read key ``services/api`` publishes, so a public client that
    completed a pairing held a credential the accounts backend accepts. Three
    properties of the refusal that replaced it: the body is the fixed 503, the
    minter is never called, and the code is not spent -- a poll after the
    interval gets the same answer and a second row, not the spent-code
    refusal. The pacing is pinned in the next test.
    """
    code = await paired(app, key_pair)

    class MustNotBeCalled:
        """Stands in for the read minter. A stand-in rather than
        ``patch.object``, because ``InternalTokenMinter`` is a frozen
        dataclass."""

        calls = 0

        def mint(self, **kwargs: Any) -> str:
            MustNotBeCalled.calls += 1
            raise AssertionError("POST /token reached the read minter")

    app.state.read_minter = MustNotBeCalled()

    first = await exchange(app, code.device_code)
    assert first.status_code == 503, first.text
    assert first.json() == ISSUANCE_DISABLED_BODY

    written = await rows(clean)
    assert [r.tool_name for r in written] == [PAIRING_TOOL_NAME, TOKEN_TOOL_NAME]
    refusal = written[1]
    assert refusal.outcome == OUTCOME_RAISED
    assert refusal.detail == DETAIL_ISSUANCE_DISABLED
    assert refusal.customer_ref == CUSTOMER
    assert refusal.arguments["route"] == TOKEN_ROUTE
    assert refusal.arguments["device_code_handle"] == handle_of(code.device_code)

    stored = await unwrap(app.state.device_code_store, code.device_code)
    assert stored.exchanged_at is None, "a refused exchange spent the device code"

    interval_ago(app, code.device_code)
    second = await exchange(app, code.device_code)
    assert second.status_code == 503, second.text
    assert second.json() == ISSUANCE_DISABLED_BODY
    assert [r.detail for r in await rows(clean)][1:] == [DETAIL_ISSUANCE_DISABLED] * 2
    assert MustNotBeCalled.calls == 0


def interval_ago(app: Starlette, device_code: str) -> None:
    """Move an approved code's last recorded poll one interval into the past,
    as if the browser had waited, without the test sleeping for it."""
    polls = app.state._approved_poll_times
    polls[device_code] -= timedelta(seconds=app.state.settings.device_poll_interval_seconds)


async def test_polls_of_an_approved_code_are_paced_at_the_interval(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Two polls inside the interval: the 503 once, then ``slow_down``, one row.

    Without pacing, a client honouring the retryable 503 would come straight
    back at the address-bucket limiter's pace until the code's TTL, each poll
    an ``audit_log`` INSERT and a revocation read. ``Retry-After`` tells it
    the interval, which is the pace this endpoint enforces.
    """
    code = await paired(app, key_pair)
    interval = app.state.settings.device_poll_interval_seconds

    first = await exchange(app, code.device_code)
    second = await exchange(app, code.device_code)

    assert first.status_code == 503, first.text
    assert first.json() == ISSUANCE_DISABLED_BODY
    assert first.headers["retry-after"] == str(interval)
    assert second.status_code == 400, second.text
    assert second.json()["error"] == "slow_down"
    token_rows = [r for r in await rows(clean) if r.tool_name == TOKEN_TOOL_NAME]
    assert [r.detail for r in token_rows] == [DETAIL_ISSUANCE_DISABLED]


async def test_the_first_poll_after_approval_is_not_paced_by_the_last_pending_one(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """A browser polls, the customer approves a moment later, the browser
    polls again inside the interval: it gets its answer, not ``slow_down``,
    because pending and approved polls are paced on separate clocks."""
    code = await issue(app)
    assert (await exchange(app, code.device_code)).json()["error"] == "authorization_pending"
    assert (
        await approve(app, {"user_code": code.user_code_display}, bearer(key_pair))
    ).status_code == 200

    after = await exchange(app, code.device_code)

    assert after.status_code == 503, after.text
    assert after.json() == ISSUANCE_DISABLED_BODY


async def test_a_token_exchange_writes_one_row(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The exchange, which until 2026-09-26 was the one link with no record.

    ``tool_name`` is its own literal rather than the pairing's, so an operator
    can ask "which pairings completed" and "which exchanges were attempted"
    separately. Both are ``device_grant.*``, neither is a registered MCP tool.
    Since 2026-09-30 the row records the issuance-disabled refusal, because no
    token is minted.
    """
    code = await paired(app, key_pair)

    resp = await exchange(app, code.device_code)
    assert resp.status_code == 503
    assert "access_token" not in resp.json()

    written = await rows(clean)
    assert [r.tool_name for r in written] == [PAIRING_TOOL_NAME, TOKEN_TOOL_NAME]
    mint = written[1]
    assert mint.outcome == OUTCOME_RAISED
    assert mint.detail == DETAIL_ISSUANCE_DISABLED
    assert mint.customer_ref == CUSTOMER
    assert mint.reaching_at is None
    assert mint.arguments["route"] == TOKEN_ROUTE
    assert mint.arguments["paired_client_id"] == BROWSER_CLIENT
    # No verified client made this call -- the caller holds a device code and
    # nothing else -- so the column that names a verified client is NULL and
    # the unauthenticated one it did supply is in `arguments`.
    assert mint.client_id is None


async def test_the_two_rows_of_one_pairing_join_on_the_device_code_handle(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The chain an investigator actually walks.

    ``call_id`` deliberately does NOT join them: they are two requests,
    minutes apart, from two different parties -- the banking app and the
    browser -- and that column means one request. The handle is the join, and
    it is the same handle the read path's rows can be tied back to through the
    client the pairing named.
    """
    code = await paired(app, key_pair)
    await exchange(app, code.device_code)

    pairing, mint = await rows(clean)
    assert pairing.arguments["device_code_handle"] == handle_of(code.device_code)
    assert mint.arguments["device_code_handle"] == handle_of(code.device_code)
    assert pairing.call_id != mint.call_id
    assert pairing.customer_ref == mint.customer_ref == CUSTOMER


async def test_the_token_row_names_no_credential(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Nothing of a credential reaches the table from the token endpoint.

    Until 2026-09-30 this took the minted token apart segment by segment and
    asserted none of it was on the row. No token is minted now, so the body
    is asserted to hold nothing JWT-shaped, and the one credential this
    request did carry, the device code, is asserted absent from the row.
    """
    code = await paired(app, key_pair)
    resp = await exchange(app, code.device_code)
    assert jwt_shaped_strings(resp.text) == []

    _, mint = await rows(clean)
    serialised = json.dumps(
        {
            "arguments": mint.arguments,
            "detail": mint.detail,
            "tool_name": mint.tool_name,
            "client_id": mint.client_id,
        }
    )
    assert jwt_shaped_strings(serialised) == []
    assert code.device_code not in serialised


# ---------------------------------------------------------------------------
# 6. Polling is not an event. This is the volume argument, as tests.
# ---------------------------------------------------------------------------


async def test_polling_before_approval_writes_nothing(app: Starlette, clean: Database) -> None:
    """``authorization_pending`` is a browser waiting, not a decision.

    At the configured 5-second interval and 900-second lifetime, a browser
    whose customer never picks up their phone polls up to 180 times. A row per
    poll would make this table mostly a record of waiting, and the 180 rows
    would carry no customer: ``customer_ref`` is only read off the device code
    after the approval check, so none of these polls has resolved anybody.
    """
    code = await issue(app)

    first = await exchange(app, code.device_code)
    assert first.json()["error"] == "authorization_pending"
    # The second poll inside the interval is refused with `slow_down`, which
    # is the same non-event one step louder.
    second = await exchange(app, code.device_code)
    assert second.json()["error"] == "slow_down"

    assert await rows(clean) == []


async def test_an_expired_device_code_writes_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The ordinary end of an abandoned pairing, and it resolves nobody.

    The expiry check runs before the identity is read, so this exit has no
    customer even when the code had been approved. It also REVOKES the code,
    which is a state change with no customer attached -- exactly the shape the
    rule excludes.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await paired(app, key_pair)
    await _wipe(clean)
    overwrite_in_memory(
        app,
        replace(
            await unwrap(store, code.device_code),
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        ),
    )

    resp = await exchange(app, code.device_code)
    assert resp.json()["error"] == "expired_token"
    assert await rows(clean) == []


async def test_an_unknown_device_code_at_the_token_endpoint_writes_nothing(
    app: Starlette, clean: Database
) -> None:
    """The deliberate asymmetry with ``POST /approve``, which records its miss.

    ``/approve`` takes a ``user_code`` now, not a device code, and an unknown
    one is written as ``user_code_not_found``. Same shape, opposite answer,
    and the difference is authentication. At ``/approve`` an unknown pairing
    code is a conclusion about a customer the assertion already named, so it
    is the enumeration signal. Here the caller
    holds nothing at all, so there is nobody to attribute the guess to, and a
    row would be an INSERT an unauthenticated caller can drive 300 times a
    minute per address bucket.
    """
    resp = await exchange(app, "no-such-device-code")
    assert resp.json()["error"] == "invalid_grant"

    missing_grant = await exchange(app, "")
    assert missing_grant.json()["error"] == "invalid_request"

    assert await rows(clean) == []


async def test_device_authorization_writes_nothing(app: Starlette, clean: Database) -> None:
    """The unauthenticated endpoint records nothing, by rule and not by omission.

    ``POST /device_authorization`` is in ``PUBLIC_PATHS`` because the browser
    holds no credential by the device grant's premise. It resolves no
    identity, so no row: ``customer_ref`` would be NULL on every row it ever
    wrote and ``customer_ref_absence_reason`` would read ``no_access_token``
    on every one of them, which is a column whose value is constant across the
    endpoint's whole population and therefore tells a reader nothing. What it
    creates is bounded by the 10,000-code store cap and the 60-per-minute
    address bucket, not by this table.
    """
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        resp = await c.post("/device_authorization", json={"client_id": BROWSER_CLIENT})
    assert resp.status_code == 200
    assert "device_code" in resp.json()

    assert await rows(clean) == []


# ---------------------------------------------------------------------------
# 7. The refusals at /token that ARE events.
# ---------------------------------------------------------------------------


async def test_a_revoked_customer_at_the_token_endpoint_is_recorded_and_mints_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """ZT-7 at the mint, under the literal both other write paths already use.

    The browser is told ``access_denied``, which is indistinguishable from the
    customer declining on their phone, so a party holding only a device code
    learns nothing about anyone's revocation state. The row is where the
    operator learns it, and it is the only place: this endpoint has no client
    id to put in a log line.
    """
    store: RevocationStoreBase = app.state.postern_revocation_store
    code = await paired(app, key_pair)
    await _wipe(clean)
    await store.revoke_customer_client(customer_ref=CUSTOMER, client_id=BROWSER_CLIENT)

    resp = await exchange(app, code.device_code)
    assert resp.status_code == 400
    assert resp.json()["error"] == "access_denied"
    assert "access_token" not in resp.json()

    row = await one_row(clean)
    assert row.tool_name == TOKEN_TOOL_NAME
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_REVOKED
    assert row.customer_ref == CUSTOMER
    assert row.arguments["device_code_handle"] == handle_of(code.device_code)


async def test_an_unreachable_revocation_store_is_recorded_and_mints_nothing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """ "We tried to decide and could not" is a conclusion about this customer.

    Reporting an outage as "not revoked" would un-revoke every entry the
    operator holds at the moment they most believe they have acted, so the
    endpoint answers 503 and mints nothing. The row names the exception type,
    which is how an operator tells this apart from a real refusal -- the
    caller cannot, and must not.
    """
    code = await paired(app, key_pair)
    await _wipe(clean)

    class Unavailable:
        async def is_customer_revoked(self, customer_ref: str) -> bool:
            raise RevocationStoreUnavailable("the revocation store is gone")

    app.state.postern_revocation_store = Unavailable()

    resp = await exchange(app, code.device_code)
    assert resp.status_code == 503
    assert "access_token" not in resp.json()

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == "RevocationStoreUnavailable"
    assert row.customer_ref == CUSTOMER


async def test_a_stored_identity_that_is_not_a_customer_reference_is_recorded(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """A distinct literal from ``/approve``'s, because the provenance differs.

    At ``/approve`` a non-conforming subject means the operator's app backend
    minted the wrong claim. Here the value was read back off a stored device
    code that ``/approve`` had already validated, so it means the stored row
    is wrong or something other than ``/approve`` wrote it. Those are
    different incidents and a reader must not have to guess which one a row
    describes.
    """
    store: DeviceCodeStoreBase = app.state.device_code_store
    code = await paired(app, key_pair)
    await _wipe(clean)
    overwrite_in_memory(
        app,
        replace(await unwrap(store, code.device_code), customer_ref="4111111111111111"),
    )

    resp = await exchange(app, code.device_code)
    assert resp.status_code == 500
    assert "access_token" not in resp.json()

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_STORED_IDENTITY_MALFORMED
    assert row.customer_ref is None
    assert row.customer_ref_absence_reason == ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF
    assert "4111111111111111" not in json.dumps({"arguments": row.arguments, "detail": row.detail})


# ---------------------------------------------------------------------------
# 8. Fail closed at the token endpoint (decision 0006).
# ---------------------------------------------------------------------------


async def test_a_token_that_cannot_be_audited_is_never_returned(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The ordering decision, asserted on the RESPONSE BODY rather than the status.

    Since 2026-09-30 the exchange mints nothing, so what fails closed here is
    the issuance-disabled refusal: its row cannot be written, the request
    answers 500, and nothing reaches the caller. The order below is kept
    because the session-token change will mint here again.

    ``/approve`` fails closed by withdrawing the pairing, because the pairing
    is in this deployment's own store. A mint cannot be withdrawn: the token is
    signed and nothing here can revoke it inside its 60-second life. So the
    order is mint, then commit the row, then return -- and the token is only
    ever serialised to a caller after the row is durable. An implementation
    that wrote the row first would refuse a customer who did nothing wrong
    whenever the store blinked; one that returned before writing would hand out
    a token no row accounts for, which is the fail-open shape this repository
    already rejected one endpoint over.
    """
    code = await paired(app, key_pair)
    await _wipe(clean)

    async def unavailable(session: Any, **kw: Any) -> None:
        raise RuntimeError("audit store unavailable")

    with patch.object(audit_store, "append", unavailable):
        resp = await exchange(app, code.device_code, as_a_server_would=True)

    assert resp.status_code == 500
    assert "access_token" not in resp.text, (
        "a token reached the caller with no audit_log row behind it"
    )
    assert await rows(clean) == []


async def test_a_signing_key_that_would_fail_is_never_reached(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The minter is wired and not called, so its failure cannot surface.

    Until 2026-09-30 this asserted that a mint which raised left a ``raised``
    row naming the exception rather than a ``returned`` row claiming a token.
    Issuance is disabled now, so a minter that raises on every call is the
    sharpest witness that ``/token`` never reaches it: the answer is the
    issuance-disabled 503 and the row says so, with no success row claiming
    a mint.
    """
    code = await paired(app, key_pair)
    await _wipe(clean)

    class Unsignable:
        """Stands in for the minter. A stand-in rather than ``patch.object``:
        ``InternalTokenMinter`` is a frozen dataclass, so patching an attribute
        on an instance raises ``FrozenInstanceError`` when the patch unwinds."""

        def mint(self, **kwargs: Any) -> str:
            raise RuntimeError("the signing key source is unavailable")

    app.state.read_minter = Unsignable()

    resp = await exchange(app, code.device_code, as_a_server_would=True)

    assert resp.status_code == 503
    assert resp.json() == ISSUANCE_DISABLED_BODY

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED, "a row claimed a mint that never happened"
    assert row.detail == DETAIL_ISSUANCE_DISABLED
    assert row.customer_ref == CUSTOMER


# ---------------------------------------------------------------------------
# 9. A replay against a spent code, which is this table's most interesting row.
# ---------------------------------------------------------------------------


async def test_a_replay_of_a_spent_device_code_is_recorded(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Both halves of ``PairingAudit``'s rule are met, so a row is owed.

    The identity is resolved -- ``customer_ref`` is read off the code, written
    there by a verified assertion at ``POST /approve`` -- and the server then
    concludes something about that identity's authority: this grant is spent
    and will not mint again. That is not a browser waiting, which is what the
    unrecorded exits of this endpoint all are.

    It is also the only place the event is visible. The browser is told
    ``invalid_grant`` in exactly the body an unknown code gets, so the
    response says nothing; and `services/confirm/device_auth.py` has no
    client id to put in a log line, which is the argument
    ``services/confirm/revocation.py``'s ``log_refusal`` already makes for the
    revocation refusal beside it.

    WHY THE ROW EXISTS AT ALL rather than the code being revoked: revoking
    deletes the store row, a replay is then answered by the unknown-code
    branch before any identity is read, and this row is the thing that would
    be lost.

    SPENT THROUGH THE STORE since 2026-09-30, because no exchange spends a
    code any more; a code an earlier build spent is how this row still
    arises, in a shared store that outlives the deploy.
    """
    code = await paired(app, key_pair)
    store: DeviceCodeStoreBase = app.state.device_code_store
    assert await store.consume_device_code(code.device_code) is True
    await _wipe(clean)

    replay = await exchange(app, code.device_code)
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    assert "access_token" not in replay.json()

    row = await one_row(clean)
    assert row.tool_name == TOKEN_TOOL_NAME
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_DEVICE_CODE_SPENT
    assert row.customer_ref == CUSTOMER
    assert row.reaching_at is None
    assert row.arguments["route"] == TOKEN_ROUTE
    assert row.arguments["device_code_handle"] == handle_of(code.device_code)
    assert row.arguments["paired_client_id"] == BROWSER_CLIENT


async def test_a_replayed_code_produces_one_row_per_attempt_under_one_handle(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """What the handle buys here, which is counting the attempts on one pairing.

    ``device_code_handle``'s own docstring makes the claim -- "a caller
    guessing codes produces many handles and a caller retrying one produces
    one" -- and a replay is the retrying case. Three rows, one handle, three
    distinct ``call_id`` values, because three requests arrived.
    """
    code = await paired(app, key_pair)
    store: DeviceCodeStoreBase = app.state.device_code_store
    assert await store.consume_device_code(code.device_code) is True
    await _wipe(clean)

    for _ in range(3):
        assert (await exchange(app, code.device_code)).status_code == 400

    written = await rows(clean)
    assert [r.detail for r in written] == [DETAIL_DEVICE_CODE_SPENT] * 3
    assert {r.arguments["device_code_handle"] for r in written} == {handle_of(code.device_code)}
    assert len({r.call_id for r in written}) == 3

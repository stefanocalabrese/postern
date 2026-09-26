"""``POST /approve`` -- the device-grant pairing -- against a real Postgres.

WHAT THIS MODULE EXISTS FOR. Until 2026-09-26 ``services/confirm/device_auth
.py`` wrote no ``audit_log`` row on any branch of ``POST /approve``. Every
occurrence of the string ``audit`` in that file was prose about audit findings
C-01 and C-04, not a call that wrote a row. So a payment approval through
``POST /challenges/{challenge_id}/approve`` left two correlated rows, and the
pairing that authorises a client to reach that endpoint at all left none: an
attacker who paired a rogue client was visible only in the payments that
followed it, and only if any followed.

THE TWO ASSERTIONS THAT MATTER MOST, because they are the two an
implementation can satisfy in appearance and miss in substance:

1. ``test_a_pairing_that_cannot_be_audited_does_not_stand`` counts the DEVICE
   CODE'S STATE, not the status code. A handler that answered 500 and left
   ``approved=True`` on the code would pass every status assertion here and
   fail closed in name only -- the browser polling ``POST /token`` would still
   be handed a read token, for a pairing no row records.
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
import os
from collections.abc import AsyncGenerator, Generator
from dataclasses import replace
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import DeviceCode, DeviceCodeStoreBase
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.revocation import RevocationStoreBase
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
    DETAIL_INVALID_SUBJECT,
    DETAIL_REVOKED,
    DETAIL_USER_CODE_BUDGET_EXHAUSTED,
    DETAIL_USER_CODE_MISMATCH,
    PAIRING_ROUTE,
    PAIRING_TOOL_NAME,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
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


async def issue(app: Starlette, client_id: str = BROWSER_CLIENT) -> DeviceCode:
    """One device code, created through the store the app actually holds."""
    store: DeviceCodeStoreBase = app.state.device_code_store
    return await store.create_device_code(
        client_id=client_id,
        scopes="accounts:read",
        verification_uri="https://auth.test.invalid/verify",
    )


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
        {"device_code": code.device_code, "user_code": code.user_code_display},
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
        {"device_code": code.device_code, "user_code": code.user_code_display},
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
        {"device_code": code.device_code, "user_code": code.user_code_display},
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
            {"device_code": code.device_code, "user_code": code.user_code_display},
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


async def test_an_unknown_device_code_is_recorded(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The enumeration signal, and the one branch with no device code to name.

    A caller guessing device codes gets an identical 400 for every guess. The
    row is the only place the attempts are countable, and it carries the
    handle of the value that was tried, so N rows with N distinct handles
    under one ``customer_ref`` is a scan and N rows with one handle is a
    retry.
    """
    resp = await approve(
        app,
        {"device_code": "no-such-device-code", "user_code": "ABC-DEF"},
        bearer(key_pair),
    )
    assert resp.status_code == 400

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_DEVICE_CODE_NOT_FOUND
    assert row.customer_ref == CUSTOMER
    assert row.arguments["device_code_handle"] == handle_of("no-such-device-code")
    assert "paired_client_id" not in row.arguments


async def test_a_wrong_pairing_code_is_recorded(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """A2, at its cheapest: somebody holds the device code and is guessing.

    The pairing code is the half of the A2 control only a human at the browser
    can supply, so a mismatch against a code the caller already holds is the
    relay attempt this endpoint exists to refuse.
    """
    code = await issue(app)

    resp = await approve(
        app,
        {"device_code": code.device_code, "user_code": "ZZZ-ZZZ"},
        bearer(key_pair),
    )
    assert resp.status_code == 400

    row = await one_row(clean)
    assert row.outcome == OUTCOME_RAISED
    assert row.detail == DETAIL_USER_CODE_MISMATCH
    assert row.arguments["device_code_handle"] == handle_of(code.device_code)
    assert row.arguments["paired_client_id"] == BROWSER_CLIENT


async def test_exhausting_the_pairing_code_budget_is_a_different_detail(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Three guesses, three rows, and the last one is not the other two.

    ``user_code_max_attempts`` defaults to 3 and the third wrong code REVOKES
    the device code, which ends that pairing for the legitimate user as well.
    Filing that under the same literal as an ordinary slip would bury the one
    event on this endpoint an operator should be paged for.
    """
    code = await issue(app)
    attempts = ConfirmSettings().user_code_max_attempts

    for _ in range(attempts):
        resp = await approve(
            app,
            {"device_code": code.device_code, "user_code": "ZZZ-ZZZ"},
            bearer(key_pair),
        )
        assert resp.status_code == 400

    written = await rows(clean)
    assert len(written) == attempts
    assert [r.detail for r in written] == (
        [DETAIL_USER_CODE_MISMATCH] * (attempts - 1) + [DETAIL_USER_CODE_BUDGET_EXHAUSTED]
    )
    assert {r.call_id for r in written} == {r.call_id for r in written} and len(
        {r.call_id for r in written}
    ) == attempts, "each request is its own call, so no two rows share a call_id"


async def test_a_second_approval_of_an_approved_code_is_recorded(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The swap attempt the ``already_approved`` check exists to stop.

    A caller holding a valid assertion of their own, who reaches a code the
    victim already approved, would otherwise rewrite ``customer_ref`` to
    themselves in the window before the browser polls ``POST /token``. The
    refusal is recorded because the attempt is the signal, not the outcome.
    """
    code = await issue(app)
    first = await approve(
        app,
        {"device_code": code.device_code, "user_code": code.user_code_display},
        bearer(key_pair),
    )
    assert first.status_code == 200

    second = await approve(
        app,
        {"device_code": code.device_code, "user_code": code.user_code_display},
        bearer(key_pair, subject="cust_9e21"),
    )
    assert second.status_code == 400

    written = await rows(clean)
    assert [r.outcome for r in written] == [OUTCOME_RETURNED, OUTCOME_RAISED]
    assert written[1].detail == DETAIL_ALREADY_APPROVED
    assert written[0].customer_ref == CUSTOMER
    assert written[1].customer_ref == "cust_9e21"
    assert (
        written[0].arguments["device_code_handle"] == (written[1].arguments["device_code_handle"])
    ), "both rows name the same pairing, which is what makes the pair readable"


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
        {"device_code": code.device_code, "user_code": code.user_code_display},
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
        {"device_code": "anything", "user_code": "ABC-DEF"},
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
        pytest.param({}, id="neither field present"),
        pytest.param({"device_code": "abc"}, id="no user_code"),
        pytest.param({"device_code": 123, "user_code": "ABC-DEF"}, id="device_code is a number"),
        pytest.param({"device_code": "abc", "user_code": ["x"]}, id="user_code is a list"),
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
    resp = await approve(app, {"device_code": "abc", "user_code": "ABC-DEF"})
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
    failed -- otherwise the browser polls ``POST /token``, is handed a read
    token, and no row anywhere says who authorised it.
    """
    code = await issue(app)

    async def unavailable(session: Any, **kw: Any) -> None:
        raise RuntimeError("audit store unavailable")

    with patch.object(audit_store, "append", unavailable):
        resp = await approve(
            app,
            {"device_code": code.device_code, "user_code": code.user_code_display},
            bearer(key_pair),
            as_a_server_would=True,
        )

    assert resp.status_code == 500
    assert await rows(clean) == []

    stored = await app.state.device_code_store.get_device_code(code.device_code)
    assert stored is None or stored.approved is False, (
        "the pairing survived an audit write it could not make; "
        "POST /token would mint a read token no row accounts for"
    )

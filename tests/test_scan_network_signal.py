"""``POST /scan`` records where the pairing was created against where it was scanned.

Sections 4 and 5 of ``dev-docs/pairing-network-signal-spec.md``, over ASGI
and read back out of Postgres, for the reason ``tests/test_scan.py`` gives.

WHY EVERY REQUEST HERE CARRIES ``X-Forwarded-For``. Under the default of
zero trusted hops both addresses are the transport's peer, which for
``httpx2.ASGITransport`` is ``127.0.0.1`` on every request, so every relation
would be ``same_ip`` and the test would measure the transport. The app is
built with one trusted hop instead, and each request names its client in the
header the way one real proxy would.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import DeviceCode
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RAISED, OUTCOME_RETURNED, AuditEntry
from sqlalchemy import select
from starlette.applications import Starlette

from services.confirm.audit import (
    DETAIL_ALREADY_APPROVED,
    DETAIL_ALREADY_SCANNED,
    DETAIL_QR_INVALID,
    DETAIL_QR_STALE,
    DETAIL_SCAN_CONFLICT,
    DETAIL_USER_CODE_NOT_FOUND,
    SCAN_TOOL_NAME,
)
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import device_store_of, qr_for, stored_code
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

ISSUER = "https://app.test.invalid"
AUDIENCE = "postern-confirm"
ALICE = "cust_a11ce"
BOB = "cust_b0b0"
BROWSER_CLIENT = "claude-desktop-42"

LAPTOP = "198.51.100.7"
LAPTOP_NEIGHBOUR = "198.51.100.200"
PHONE = "203.0.113.45"
PHONE_ON_WIFI = "198.51.100.7"


# ---------------------------------------------------------------------------
# Fixtures and helpers.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def build(pg_url: str, key_pair: RSAKeyPair, *, hops: int = 1, **kwargs: Any) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        replace(ConfirmSettings.for_testing(), database_url=pg_url, trusted_proxy_hops=hops),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
        **kwargs,
    )


@pytest.fixture()
def app(pg_url: str, key_pair: RSAKeyPair) -> Starlette:
    """No enricher, whatever is installed, and one trusted hop."""
    return build(pg_url, key_pair, network_enricher=None)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
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
    forwarded_for: str | None = None,
) -> httpx2.Response:
    all_headers = dict(headers or {})
    if forwarded_for is not None:
        all_headers["X-Forwarded-For"] = forwarded_for
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as c:
        if form is not None:
            return await c.post(path, data=form, headers=all_headers)
        return await c.post(path, json=json_body, headers=all_headers)


async def start(app: Starlette, *, forwarded_for: str | None) -> DeviceCode:
    resp = await post(
        app,
        "/device_authorization",
        json_body={"client_id": BROWSER_CLIENT},
        forwarded_for=forwarded_for,
    )
    assert resp.status_code == 200, resp.text
    return await stored_code(app, resp.json()["user_code"])


async def scan(
    app: Starlette,
    key_pair: RSAKeyPair,
    customer: str,
    code: DeviceCode,
    *,
    forwarded_for: str | None,
    qr: str | None = None,
) -> httpx2.Response:
    return await post(
        app,
        "/scan",
        json_body={
            "user_code": code.user_code_display,
            "qr": qr if qr is not None else qr_for(code),
        },
        headers=bearer(key_pair, customer),
        forwarded_for=forwarded_for,
    )


async def rows(db: Database) -> list[AuditEntry]:
    async with db.sessionmaker() as s:
        result = await s.execute(select(AuditEntry).order_by(AuditEntry.id))
        return list(result.scalars().all())


def expected_signal(relation: str, hops: int = 1, **matches: Any) -> list[dict[str, Any]]:
    details: dict[str, Any] = {"relation": relation, "proxy_hops": hops}
    details.update(matches)
    return [
        {
            "code": "PAIRING_NETWORK",
            "severity": "LOW",
            "description": f"pairing creator and scanner network relation: {relation}",
            "details": details,
        }
    ]


# ---------------------------------------------------------------------------
# The success rows.
# ---------------------------------------------------------------------------

RELATIONS = [
    (LAPTOP, LAPTOP, "same_ip"),
    (LAPTOP, LAPTOP_NEIGHBOUR, "same_prefix"),
    (LAPTOP, PHONE, "different"),
    (None, PHONE, "unknown"),
]


@pytest.mark.parametrize(("creator", "scanner", "relation"), RELATIONS)
async def test_a_first_scan_row_carries_the_relation_and_the_hop_count(
    app: Starlette,
    clean: Database,
    key_pair: RSAKeyPair,
    creator: str | None,
    scanner: str,
    relation: str,
) -> None:
    code = await start(app, forwarded_for=creator)

    resp = await scan(app, key_pair, ALICE, code, forwarded_for=scanner)

    assert resp.status_code == 200, resp.text
    (row,) = await rows(clean)
    assert row.tool_name == SCAN_TOOL_NAME
    assert row.outcome == OUTCOME_RETURNED
    assert row.detail is None
    assert row.arguments["client_ip"] == scanner
    assert row.risk_signals == expected_signal(relation)


async def test_the_claim_records_the_scanners_address_on_the_pairing(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app, forwarded_for=LAPTOP)

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200

    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None
    assert stored.creator_ip == LAPTOP
    assert stored.scanner_ip == PHONE


@pytest.mark.parametrize(
    ("hops", "peer", "forwarded_for"),
    [
        (0, PHONE, None),
        (1, "10.0.0.2", PHONE),
    ],
    ids=["zero-hops-direct-peer", "one-hop-forwarded"],
)
async def test_the_stored_scanner_ip_is_the_scanning_clients_address(
    pg_url: str,
    clean: Database,
    key_pair: RSAKeyPair,
    hops: int,
    peer: str,
    forwarded_for: str | None,
) -> None:
    """The assembled app, driven from a transport whose peer is set, so the
    address under zero hops is a known one and not the transport's default."""
    app = build(pg_url, key_pair, hops=hops, network_enricher=None)
    code = await start(app, forwarded_for=LAPTOP if hops else None)
    headers = bearer(key_pair, ALICE)
    if forwarded_for is not None:
        headers["X-Forwarded-For"] = forwarded_for
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, client=(peer, 4321)), base_url="http://t"
    ) as c:
        resp = await c.post(
            "/scan",
            json={"user_code": code.user_code_display, "qr": qr_for(code)},
            headers=headers,
        )

    assert resp.status_code == 200, resp.text
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None
    assert stored.scanner_ip == PHONE
    (row,) = await rows(clean)
    assert row.arguments["client_ip"] == PHONE


async def test_a_repeat_scan_row_compares_its_own_address_not_the_stored_one(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The phone moved from Wi-Fi to mobile data between the two scans. The
    repeat's row describes the repeat; the pairing keeps the first address."""
    code = await start(app, forwarded_for=LAPTOP)
    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE_ON_WIFI)).status_code == 200

    resp = await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)

    assert resp.status_code == 200
    first, repeat = await rows(clean)
    assert first.risk_signals == expected_signal("same_ip")
    assert repeat.detail == DETAIL_ALREADY_SCANNED
    assert repeat.arguments["client_ip"] == PHONE
    assert repeat.risk_signals == expected_signal("different")
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanner_ip == PHONE_ON_WIFI


async def test_the_success_body_is_identical_for_every_relation(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    bodies = []
    for creator, scanner, _ in RELATIONS:
        code = await start(app, forwarded_for=creator)
        resp = await scan(app, key_pair, ALICE, code, forwarded_for=scanner)
        assert resp.status_code == 200
        body = resp.json()
        assert body["user_code"] == code.user_code_display
        bodies.append({k: v for k, v in body.items() if k not in ("user_code", "expires_at")})
    assert all(body == bodies[0] for body in bodies)
    assert set(bodies[0]) == {"client_id", "client_id_verified", "scopes"}


async def test_under_zero_hops_the_row_says_so(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    """``proxy_hops`` 0 is how a reader filters out the rows that compare a
    load balancer with itself."""
    app = build(pg_url, key_pair, hops=0, network_enricher=None)
    code = await start(app, forwarded_for=LAPTOP)

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200

    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal("same_ip", hops=0)


# ---------------------------------------------------------------------------
# Every other row stays NULL.
# ---------------------------------------------------------------------------


async def test_every_refusal_row_keeps_null(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app, forwarded_for=LAPTOP)
    slot, mac = qr_for(code).split(".")
    forged = f"{slot}.{('B' if mac[0] == 'A' else 'A') + mac[1:]}"
    stale = qr_for(code, slot_offset=-20)
    unknown = replace(code, user_code="ZZZ999")

    assert (
        await scan(app, key_pair, ALICE, code, forwarded_for=PHONE, qr=forged)
    ).status_code == 400
    assert (
        await scan(app, key_pair, ALICE, code, forwarded_for=PHONE, qr=stale)
    ).status_code == 400
    assert (await scan(app, key_pair, ALICE, unknown, forwarded_for=PHONE)).status_code == 400
    assert (await scan(app, key_pair, BOB, code, forwarded_for=PHONE)).status_code == 200
    conflict = await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)
    assert conflict.json()["error"] == "scan_conflict"

    entries = await rows(clean)
    details = [(r.outcome, r.detail) for r in entries]
    assert details == [
        (OUTCOME_RAISED, DETAIL_QR_INVALID),
        (OUTCOME_RAISED, DETAIL_QR_STALE),
        (OUTCOME_RAISED, DETAIL_USER_CODE_NOT_FOUND),
        (OUTCOME_RETURNED, None),
        (OUTCOME_RAISED, DETAIL_SCAN_CONFLICT),
    ]
    assert [r.risk_signals is None for r in entries] == [True, True, True, False, True]


async def test_the_approvers_repeat_and_the_approve_and_token_rows_keep_null(
    app: Starlette, clean: Database, key_pair: RSAKeyPair
) -> None:
    code = await start(app, forwarded_for=LAPTOP)
    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200
    approved = await post(
        app,
        "/approve",
        json_body={"user_code": code.user_code_display},
        headers=bearer(key_pair, ALICE),
        forwarded_for=PHONE,
    )
    assert approved.status_code == 200, approved.text
    repeat = await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)
    assert repeat.status_code == 200
    token = await post(
        app,
        "/token",
        form={"grant_type": "device_code", "device_code": code.device_code},
        forwarded_for=LAPTOP,
    )
    assert token.status_code == 200, token.text

    first_scan, approve_row, approved_mine, token_row = await rows(clean)
    assert first_scan.risk_signals == expected_signal("different")
    assert approve_row.tool_name != SCAN_TOOL_NAME and approve_row.risk_signals is None
    assert approved_mine.detail == DETAIL_ALREADY_APPROVED
    assert approved_mine.risk_signals is None
    assert token_row.detail is None
    assert token_row.risk_signals is None


# ---------------------------------------------------------------------------
# Over-counted hops: documented behaviour, not prevented.
# ---------------------------------------------------------------------------


async def test_over_counted_hops_let_the_creator_forge_the_most_benign_row(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    """THIS IS THE FORGERY section 6 of the spec warns about, pinned so that
    nobody mistakes the row it produces for evidence.

    Two hops are configured and only one proxy really appends. The attacker
    creating the pairing writes the victim's address into ``X-Forwarded-For``
    himself, the one real proxy appends the attacker's own, and the second
    entry from the right is the attacker's choice. The victim's scan arrives
    through an upstream forward proxy that appends the phone's address before
    the operator's one proxy appends its own, which is the case in which the
    scanner side still has two entries to read; with only one, the scanner's
    address is ``None`` and the relation is ``unknown``.
    """
    attacker = "192.0.2.66"
    victim = PHONE
    victims_forward_proxy = "203.0.113.1"
    app = build(pg_url, key_pair, hops=2, network_enricher=None)

    code = await start(app, forwarded_for=f"{victim}, {attacker}")
    resp = await scan(
        app, key_pair, ALICE, code, forwarded_for=f"{victim}, {victims_forward_proxy}"
    )

    assert resp.status_code == 200
    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal("same_ip", hops=2)


async def test_with_one_real_proxy_the_honest_scanner_reads_as_unknown_under_two_hops(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    """The companion to the forgery above: a phone reaching the one real proxy
    directly carries one entry, fewer than the two hops trusted, so ``client_ip``
    records no address and the relation is ``unknown``."""
    app = build(pg_url, key_pair, hops=2, network_enricher=None)
    code = await start(app, forwarded_for=f"{PHONE}, 192.0.2.66")

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200

    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal("unknown", hops=2)

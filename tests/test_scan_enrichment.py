"""The pairing network enricher inside ``POST /scan``: budget, cap, failures, cancellation.

Section 3's failure rules and section 4's cancellation handling of
``dev-docs/pairing-network-signal-spec.md``, over ASGI and read back out of
Postgres. The providers here are test doubles handed to
``create_confirm_app``'s ``network_enricher``; how an installed one is found
is ``tests/test_enricher_seam.py``'s subject. ``tests/test_scan_network_signal.py``
explains why every request carries ``X-Forwarded-For``.

A PROVIDER THAT NEVER YIELDS IS NOT TESTED HERE, and deliberately. It blocks
the event loop for its whole duration, and a test cannot assert that the loop
was blocked without being flaky. It is a documented limitation of the seam,
not a behaviour this code has.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import replace
from typing import Any

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import DeviceCodeStoreBase
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.risk.pairing_network import NetworkFacts
from postern_core.store.engine import Database
from postern_core.store.models import OUTCOME_RETURNED
from starlette.applications import Starlette

from services.confirm.audit import DETAIL_ALREADY_SCANNED, PairingAudit, device_code_handle
from services.confirm.device_auth import PAIRING_ENRICHMENT_SLOTS
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.device_grant_helpers import device_store_of
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.test_scan_network_signal import (
    ALICE,
    AUDIENCE,
    ISSUER,
    LAPTOP,
    LAPTOP_NEIGHBOUR,
    PHONE,
    expected_signal,
    rows,
    scan,
    start,
)

LOGGER = "services.confirm.device_auth"


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.commit()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    await _wipe(database)
    yield database
    await _wipe(database)


def build(pg_url: str, key_pair: RSAKeyPair, enricher: Any, *, budget: float = 0.25) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    settings = replace(
        ConfirmSettings.for_testing(),
        database_url=pg_url,
        trusted_proxy_hops=1,
        pairing_enricher_timeout_seconds=budget,
    )
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
        network_enricher=enricher,
    )


class Table:
    """Answers from a fixed table, recording every address it was asked about."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.asked: list[str] = []

    async def lookup(self, ip: str) -> Any:
        self.asked.append(ip)
        return self.answers.get(ip)


class Raises:
    """Raises with the address in its message, which must never reach a log."""

    async def lookup(self, ip: str) -> NetworkFacts | None:
        raise RuntimeError(f"provider could not resolve {ip}")


class Sleeps:
    async def lookup(self, ip: str) -> NetworkFacts | None:
        await asyncio.sleep(5)
        return NetworkFacts(asn=64500, country="ES")


class MustNotBeCalled:
    async def lookup(self, ip: str) -> NetworkFacts | None:
        pytest.fail(f"no lookup may be made for an unknown relation, got {ip}")


class CancelsItself:
    """Raises ``CancelledError`` from inside ``lookup``, as a provider whose own
    client library cancels an internal task can. Nobody cancelled the request."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    async def lookup(self, ip: str) -> NetworkFacts | None:
        self.asked.append(ip)
        raise asyncio.CancelledError


class _HostileFacts(NetworkFacts):
    """A ``NetworkFacts`` whose ``asn`` raises when read."""

    def __init__(self) -> None:
        pass

    @property
    def asn(self) -> int | None:
        raise RuntimeError("provider state for 198.51.100.7")


class Blocks:
    """Parks on an event the test controls, after saying it has been entered."""

    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def lookup(self, ip: str) -> NetworkFacts | None:
        self.entered.set()
        await self.release.wait()
        return None


def enrichment_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == LOGGER and "pairing network enrichment" in r.getMessage()
    ]


# ---------------------------------------------------------------------------
# Completed lookups.
# ---------------------------------------------------------------------------


async def test_two_lookups_within_budget_record_true_and_false(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    provider = Table(
        {
            LAPTOP: NetworkFacts(asn=64500, country="es"),
            PHONE: NetworkFacts(asn=64501, country="ES"),
        }
    )
    app = build(pg_url, key_pair, provider)
    code = await start(app, forwarded_for=LAPTOP)

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200

    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal("different", asn_match=False, country_match=True)
    assert sorted(provider.asked) == sorted([LAPTOP, PHONE])


async def test_same_prefix_makes_two_lookups_too(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    provider = Table(
        {
            LAPTOP: NetworkFacts(asn=64500, country="ES"),
            LAPTOP_NEIGHBOUR: NetworkFacts(asn=64500, country="ES"),
        }
    )
    app = build(pg_url, key_pair, provider)
    code = await start(app, forwarded_for=LAPTOP)

    assert (
        await scan(app, key_pair, ALICE, code, forwarded_for=LAPTOP_NEIGHBOUR)
    ).status_code == 200

    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal("same_prefix", asn_match=True, country_match=True)
    assert len(provider.asked) == 2


async def test_same_ip_makes_exactly_one_lookup_and_trusts_only_returned_fields(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    provider = Table({LAPTOP: NetworkFacts(asn=64500, country=None)})
    app = build(pg_url, key_pair, provider)
    code = await start(app, forwarded_for=LAPTOP)

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=LAPTOP)).status_code == 200

    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal("same_ip", asn_match=True, country_match="unknown")
    assert provider.asked == [LAPTOP]


async def test_same_ip_with_no_answer_records_unknown_for_both(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    provider = Table({})
    app = build(pg_url, key_pair, provider)
    code = await start(app, forwarded_for=LAPTOP)

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=LAPTOP)).status_code == 200

    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal(
        "same_ip", asn_match="unknown", country_match="unknown"
    )
    assert provider.asked == [LAPTOP]


async def test_no_lookup_is_made_for_an_unknown_relation(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    app = build(pg_url, key_pair, MustNotBeCalled())
    code = await start(app, forwarded_for=None)

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200

    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal(
        "unknown", asn_match="unknown", country_match="unknown"
    )


async def test_the_body_is_the_same_with_and_without_an_enricher(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    provider = Table({LAPTOP: NetworkFacts(asn=1, country="ES")})
    bodies = []
    for enricher in (None, provider, Raises()):
        app = build(pg_url, key_pair, enricher)
        code = await start(app, forwarded_for=LAPTOP)
        resp = await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)
        assert resp.status_code == 200
        body = resp.json()
        bodies.append({k: v for k, v in body.items() if k not in ("user_code", "expires_at")})
    assert bodies[0] == bodies[1] == bodies[2]


# ---------------------------------------------------------------------------
# Every failure is "unknown", a 200 and one log line naming no address.
# ---------------------------------------------------------------------------

FAILURES = [
    (Raises(), "RuntimeError", ("unknown", "unknown")),
    (Sleeps(), "timeout", ("unknown", "unknown")),
    (Table({LAPTOP: "AS64500", PHONE: NetworkFacts(asn=1)}), "wrong_type", ("unknown", "unknown")),
    (
        Table(
            {
                LAPTOP: NetworkFacts(asn=4_294_967_296, country="ES"),
                PHONE: NetworkFacts(asn=64500, country="ES"),
            }
        ),
        "invalid_field",
        ("unknown", True),
    ),
    (
        Table(
            {
                LAPTOP: NetworkFacts(asn=64500, country="ESP"),
                PHONE: NetworkFacts(asn=64500, country="ES"),
            }
        ),
        "invalid_field",
        (True, "unknown"),
    ),
]


@pytest.mark.parametrize(
    ("provider", "reason", "matches"),
    FAILURES,
    ids=["raises", "sleeps-past-budget", "wrong-type", "asn-out-of-range", "three-letter-country"],
)
async def test_a_failing_provider_records_unknown_and_logs_one_line_with_no_address(
    pg_url: str,
    clean: Database,
    key_pair: RSAKeyPair,
    caplog: pytest.LogCaptureFixture,
    provider: Any,
    reason: str,
    matches: tuple[Any, Any],
) -> None:
    app = build(pg_url, key_pair, provider, budget=0.05)
    code = await start(app, forwarded_for=LAPTOP)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        resp = await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)

    assert resp.status_code == 200
    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RETURNED and row.detail is None
    assert row.risk_signals == expected_signal(
        "different", asn_match=matches[0], country_match=matches[1]
    )
    warnings = enrichment_warnings(caplog)
    assert len(warnings) == 1, [w.getMessage() for w in warnings]
    line = warnings[0]
    assert line.getMessage() == f"pairing network enrichment: {reason}"
    assert line.exc_info is None
    assert LAPTOP not in line.getMessage() and PHONE not in line.getMessage()


async def test_a_provider_that_raises_leaves_the_pairing_claimed_and_the_row_returned(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    """Section 4's premise: nothing after a successful claim raises, so the
    exception branch that records a refusal and withdraws nothing is safe."""
    app = build(pg_url, key_pair, Raises())
    code = await start(app, forwarded_for=LAPTOP)

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200

    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE
    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RETURNED


async def test_a_budget_expiry_after_the_claim_leaves_it_claimed(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    """THE NESTING TEST. ``asyncio.timeout`` cancels the task to enforce the
    budget; with the withdrawal handler inside it that cancellation would
    withdraw a legitimate claim every time a provider was slow."""
    app = build(pg_url, key_pair, Sleeps(), budget=0.05)
    code = await start(app, forwarded_for=LAPTOP)

    resp = await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)

    assert resp.status_code == 200
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE
    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal(
        "different", asn_match="unknown", country_match="unknown"
    )


async def test_a_timeout_on_the_single_same_ip_lookup_records_unknown(
    pg_url: str, clean: Database, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    app = build(pg_url, key_pair, Sleeps(), budget=0.05)
    code = await start(app, forwarded_for=LAPTOP)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        resp = await scan(app, key_pair, ALICE, code, forwarded_for=LAPTOP)

    assert resp.status_code == 200
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE
    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal(
        "same_ip", asn_match="unknown", country_match="unknown"
    )
    assert [w.getMessage() for w in enrichment_warnings(caplog)] == [
        "pairing network enrichment: timeout"
    ]


async def test_one_side_answering_none_on_two_lookups_records_unknown_without_a_warning(
    pg_url: str, clean: Database, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    """``None`` is "no data for this address", the normal answer for a private
    range, so it is an ``"unknown"`` comparison and not a provider failure."""
    provider = Table({LAPTOP: NetworkFacts(asn=64500, country="ES")})
    app = build(pg_url, key_pair, provider)
    code = await start(app, forwarded_for=LAPTOP)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        resp = await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)

    assert resp.status_code == 200
    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal(
        "different", asn_match="unknown", country_match="unknown"
    )
    assert sorted(provider.asked) == sorted([LAPTOP, PHONE])
    assert enrichment_warnings(caplog) == []


@pytest.mark.parametrize(
    ("scanned_from", "relation"),
    [(PHONE, "different"), (LAPTOP, "same_ip")],
    ids=["two-lookups", "one-lookup"],
)
async def test_a_provider_raising_cancelled_itself_records_unknown_and_keeps_the_claim(
    pg_url: str,
    clean: Database,
    key_pair: RSAKeyPair,
    caplog: pytest.LogCaptureFixture,
    scanned_from: str,
    relation: str,
) -> None:
    """A ``CancelledError`` the provider raises while the request task is not
    being cancelled is a failed lookup, not a cancelled scan: it must not
    withdraw a legitimate claim or fail the scan."""
    provider = CancelsItself()
    app = build(pg_url, key_pair, provider, budget=1.0)
    code = await start(app, forwarded_for=LAPTOP)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        resp = await scan(app, key_pair, ALICE, code, forwarded_for=scanned_from)

    assert resp.status_code == 200
    assert provider.asked
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE
    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RETURNED and row.detail is None
    assert row.risk_signals == expected_signal(
        relation, asn_match="unknown", country_match="unknown"
    )
    assert [w.getMessage() for w in enrichment_warnings(caplog)] == [
        "pairing network enrichment: CancelledError"
    ]
    slots: asyncio.Semaphore = app.state.pairing_network_slots
    assert slots._value == PAIRING_ENRICHMENT_SLOTS


async def test_a_facts_object_whose_field_raises_is_an_invalid_field_not_a_failed_scan(
    pg_url: str, clean: Database, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    provider = Table({LAPTOP: _HostileFacts(), PHONE: NetworkFacts(asn=64500, country="ES")})
    app = build(pg_url, key_pair, provider)
    code = await start(app, forwarded_for=LAPTOP)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        resp = await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)

    assert resp.status_code == 200
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE
    (row,) = await rows(clean)
    assert row.outcome == OUTCOME_RETURNED and row.detail is None
    assert row.risk_signals == expected_signal(
        "different", asn_match="unknown", country_match="unknown"
    )
    messages = [w.getMessage() for w in enrichment_warnings(caplog)]
    assert messages == ["pairing network enrichment: invalid_field"]


async def test_the_provider_is_asked_about_the_address_classify_compares(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    """An IPv4-mapped creator is classified as its IPv4 address, so it is
    looked up as that address too, not in the mapped form the pairing stores."""
    provider = Table(
        {
            "1.2.3.4": NetworkFacts(asn=64500, country="ES"),
            PHONE: NetworkFacts(asn=64500, country="ES"),
        }
    )
    app = build(pg_url, key_pair, provider)
    code = await start(app, forwarded_for="::ffff:1.2.3.4")

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200

    assert sorted(provider.asked) == sorted(["1.2.3.4", PHONE])
    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal("different", asn_match=True, country_match=True)


async def test_a_saturated_cap_records_unknown_without_waiting(
    pg_url: str, clean: Database, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    """All eight slots are held, as a stalled provider would hold them. The
    ninth scan does not wait for one: it records ``"unknown"`` at once, and
    the provider is never asked."""
    app = build(pg_url, key_pair, MustNotBeCalled(), budget=1.0)
    slots: asyncio.Semaphore = app.state.pairing_network_slots
    for _ in range(PAIRING_ENRICHMENT_SLOTS):
        await slots.acquire()
    code = await start(app, forwarded_for=LAPTOP)

    try:
        with caplog.at_level(logging.WARNING, logger=LOGGER):
            resp = await asyncio.wait_for(
                scan(app, key_pair, ALICE, code, forwarded_for=PHONE), timeout=3.0
            )
    finally:
        for _ in range(PAIRING_ENRICHMENT_SLOTS):
            slots.release()

    assert resp.status_code == 200
    (row,) = await rows(clean)
    assert row.risk_signals == expected_signal(
        "different", asn_match="unknown", country_match="unknown"
    )
    assert [w.getMessage() for w in enrichment_warnings(caplog)] == [
        "pairing network enrichment: saturated"
    ]


# ---------------------------------------------------------------------------
# Cancellation from outside the step.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scanned_from", [PHONE, LAPTOP], ids=["two-lookups", "one-lookup"])
async def test_a_request_cancelled_after_the_claim_withdraws_it_and_re_raises(
    pg_url: str, clean: Database, key_pair: RSAKeyPair, scanned_from: str
) -> None:
    provider = Blocks()
    app = build(pg_url, key_pair, provider, budget=1.0)
    slots: asyncio.Semaphore = app.state.pairing_network_slots
    code = await start(app, forwarded_for=LAPTOP)

    request = asyncio.create_task(scan(app, key_pair, ALICE, code, forwarded_for=scanned_from))
    await asyncio.wait_for(provider.entered.wait(), timeout=5)
    # The blocked lookup holds exactly one slot, for the whole scan.
    assert slots._value == PAIRING_ENRICHMENT_SLOTS - 1
    request.cancel()

    with pytest.raises(asyncio.CancelledError):
        await request
    assert slots._value == PAIRING_ENRICHMENT_SLOTS
    assert await device_store_of(app).get_device_code(code.device_code) is None
    assert await rows(clean) == []


async def test_a_request_cancelled_during_the_success_row_write_withdraws_the_claim(
    pg_url: str, clean: Database, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row write is the last ``await`` after a committed claim. A
    cancellation there is not an ``Exception``, and without its own handler it
    would leave the code claimed with no row naming it."""
    entered = asyncio.Event()

    async def blocked(self: PairingAudit, **kwargs: Any) -> None:
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(PairingAudit, "approved", blocked)
    app = build(pg_url, key_pair, None)
    code = await start(app, forwarded_for=LAPTOP)

    request = asyncio.create_task(scan(app, key_pair, ALICE, code, forwarded_for=PHONE))
    await asyncio.wait_for(entered.wait(), timeout=5)
    request.cancel()

    with pytest.raises(asyncio.CancelledError):
        await request
    assert await device_store_of(app).get_device_code(code.device_code) is None
    assert await rows(clean) == []


async def test_a_request_cancelled_after_a_repeat_leaves_the_claim_standing(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    """After ``ALREADY_MINE`` there is nothing to withdraw: the claim was made,
    and recorded, by the earlier request."""
    provider = Blocks()
    app = build(pg_url, key_pair, provider, budget=1.0)
    code = await start(app, forwarded_for=LAPTOP)
    await device_store_of(app).claim_scan(code.device_code, ALICE, scanner_ip=PHONE)

    request = asyncio.create_task(scan(app, key_pair, ALICE, code, forwarded_for=PHONE))
    await asyncio.wait_for(provider.entered.wait(), timeout=5)
    request.cancel()

    with pytest.raises(asyncio.CancelledError):
        await request
    stored = await device_store_of(app).get_device_code(code.device_code)
    assert stored is not None and stored.scanned_by == ALICE


async def test_a_failed_withdrawal_after_a_cancellation_says_cancelled(
    pg_url: str,
    clean: Database,
    key_pair: RSAKeyPair,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    provider = Blocks()
    app = build(pg_url, key_pair, provider, budget=1.0)
    store: DeviceCodeStoreBase = device_store_of(app)
    code = await start(app, forwarded_for=LAPTOP)

    async def revoke_fails(device_code: str) -> None:
        raise ConnectionError("store gone")

    monkeypatch.setattr(store, "revoke_device_code", revoke_fails)

    with caplog.at_level(logging.ERROR, logger=LOGGER):
        request = asyncio.create_task(scan(app, key_pair, ALICE, code, forwarded_for=PHONE))
        await asyncio.wait_for(provider.entered.wait(), timeout=5)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request

    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    withdrawal = [m for m in errors if "could not be withdrawn" in m]
    assert len(withdrawal) == 1, errors
    assert "was cancelled before its audit_log row was confirmed" in withdrawal[0]
    assert "may be claimed with no audit_log row behind it" in withdrawal[0]
    assert "store write failed ambiguously" not in withdrawal[0]
    assert device_code_handle(code.device_code) in withdrawal[0]


async def test_a_repeat_row_carries_the_enriched_signal(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    provider = Table(
        {
            LAPTOP: NetworkFacts(asn=64500, country="ES"),
            PHONE: NetworkFacts(asn=64500, country="ES"),
        }
    )
    app = build(pg_url, key_pair, provider)
    code = await start(app, forwarded_for=LAPTOP)
    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200

    assert (await scan(app, key_pair, ALICE, code, forwarded_for=PHONE)).status_code == 200

    first, repeat = await rows(clean)
    assert repeat.detail == DETAIL_ALREADY_SCANNED
    assert first.risk_signals == repeat.risk_signals
    assert repeat.risk_signals == expected_signal("different", asn_match=True, country_match=True)

# Pairing Network Signal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** On every successful `POST /scan`, record on the scan's `audit_log` row how the address that created the pairing relates to the address that scanned it (`same_ip`, `same_prefix`, `different`, `unknown`), with optional ASN and country matches from an installed enricher, exactly as `dev-docs/pairing-network-signal-spec.md` specifies. Nothing is refused and no response changes.

**Architecture:** A pure classifier module in `postern_core.risk` (relation, facts comparison, signal builder, enricher Protocol) plus `signal_to_json` beside `RiskSignal`. The device-code store records `scanner_ip` in the same compare-and-set as `scanned_by`. An entry-point loader in `postern_core.modules` finds at most one enricher, and `create_confirm_app` holds it with an 8-slot semaphore. `services/confirm/device_auth.py` builds the signal on `CLAIMED` and `ALREADY_MINE`, enriches it under a 250 ms budget, withdraws a claim whose request is cancelled mid-enrichment, and hands the serialized signal to `PairingAudit`, which writes it into the existing `risk_signals` JSONB column. No migration.

**Tech Stack:** Python 3.12 (`ipaddress`, `asyncio.timeout`, `asyncio.TaskGroup`, `importlib.metadata`), Starlette routes on the existing `services/confirm` app, `httpx2` ASGI tests, testcontainers Postgres and Redis already started by `tests/conftest.py`.

---

## Before you start: rules that apply to every task

1. **Work in a worktree, never on `main`.** Every commit below lands on the worktree branch. Do not push.
2. **`make ci` must exit 0 before every commit.** It needs Docker running (Postgres and Redis containers) and took about four minutes per run while this plan was validated (the test step alone, 213 to 229 seconds). The last step of every task runs it.
3. **Format with `uv run ruff format packages services tests`, never `make fmt`.** `make fmt` is unscoped and rewrites the Python code fences inside the markdown design documents, this plan included.
4. **The plan file itself is scanned by `make citations`.** `tools/check_citations.py` resolves every anchored citation (the pytest node-id form and the backticked possessive form) in every tracked file. The code below names every NEW symbol with double backticks or by name, never in an anchored form, so it passes before and after each task. Keep it that way when you paste it. `uv run pytest tests/<file>.py::<test> -q` commands are exempt because `pytest` precedes the node id on the same line; keep each on one line.
5. **No em-dashes in any prose or comment you write.** The existing code uses ` -- ` in comments; do the same.
6. **Paste the code as given.** Every block below was applied to a copy of the tree at `07053c6` and passed `make ci` there (see "Validation" at the end). The comment density is already the codebase's; do not add more.
7. **A "replace" step is an exact-text substitution.** The quoted old text occurs exactly once in the file at that point in the plan. If it does not, stop: the tree has moved and the step needs re-deriving, not guessing.
8. **TDD in every task:** write the failing test, run it and see the stated failure, implement, run it and see it pass, run `make ci`, commit. Task 8 is documentation and has no test of its own.

## Verified facts this plan depends on

All measured on 30 September 2026 against `07053c6` and the project's CPython 3.12 virtualenv.

- **`httpx2.ASGITransport` gives every request a peer.** `inspect.signature(httpx2.ASGITransport.__init__)` prints `client: 'tuple[str, int]' = ('127.0.0.1', 123)`. Under zero trusted hops both addresses in a test are therefore `127.0.0.1` and every relation is `same_ip`, not `unknown`. Every `/scan` test here sets `trusted_proxy_hops` and sends `X-Forwarded-For`, as the spec's Testing section asks, but for this reason and not the one it gives (see discrepancy 2).
- **`ipaddress` behaviour the classifier relies on:** `ip_address("::ffff:1.2.3.4").ipv4_mapped` is `IPv4Address('1.2.3.4')`; `ip_address("64:ff9b::1.2.3.4").ipv4_mapped` is `None`; `ip_address("64:ff9b::102:304") in ip_network("64:ff9b::/96")` is `True`; `ip_network("fe80::1%eth0/48", strict=False)` is `fe80::/48` (a scoped address does not raise).
- **ruff targets py312 and enables `UP040`**, so a type alias is written with the `type` statement, not `TypeAlias`.
- **The confirm service's middleware is pure ASGI throughout** (`AppAssertionMiddleware`, `BodySizeLimit`, `RateLimit`, `CustomerRateLimit`; none subclasses `BaseHTTPMiddleware`), so a request task's cancellation is edge-triggered asyncio cancellation and `_withdraw_pairing` can still await inside the handler. The cancellation tests in Task 7 depend on this.
- **Every `claim_scan` call outside `packages`** is in `tests/test_device_code_pairing_store.py` (21 calls), `tests/test_redis_backed_stores.py` (19), `tests/device_grant_helpers.py` (1), `tests/test_verify_page.py` (1), plus three test doubles in `tests/test_scan.py` and the one production call in `services/confirm/device_auth.py`. No other class implements `DeviceCodeStoreBase`.
- **The inventory counts** `tests/test_settings_bounds.py` pins move from `KNOWN_ENV` 73, `BOUNDED_NAMES` 39, reader union 46, `names_read_by("confirm")` 57 to 74, 40, 47, 58 in Task 3. `READ_AS_STRING` stays 27, `FLAGS` 3, `names_read_by("api")` 38.

## File structure

Created:

| File | Responsibility |
|---|---|
| `packages/postern-core/src/postern_core/risk/pairing_network.py` | Pure: `NetworkRelation`, `classify`, `NetworkFacts`, `MatchResult`, `sanitised`, `compare_facts`, `pairing_network_signal`, the `NetworkEnricher` Protocol. No I/O, no environment. |
| `packages/postern-core/src/postern_core/modules/enrichers.py` | `ENRICHER_GROUP`, `EnricherSeamViolation`, `load_network_enricher`: at most one enricher, from entry points, refused at composition. |
| `tests/test_pairing_network.py` | Classifier table, `compare_facts`, `sanitised`, the signal JSON, and `signal_to_json` against the read path's inline serialization. |
| `tests/test_device_code_scanner_ip.py` | `scanner_ip` on both store backends and in serialization. |
| `tests/test_enricher_seam.py` | The loader with real on-disk distributions, and composition refusals. |
| `tests/test_pairing_audit_risk_signals.py` | `PairingAudit` writes the signal it is handed and NULL otherwise. |
| `tests/test_scan_network_signal.py` | `/scan` rows over ASGI with no enricher: every relation, the repeat, every NULL row, over-counted hops. |
| `tests/test_scan_enrichment.py` | `/scan` with test-double enrichers: lookups, every failure, the cap, the budget nesting, cancellation. |

Modified:

| File | Responsibility of the change |
|---|---|
| `packages/postern-core/src/postern_core/risk/types.py` | `signal_to_json`. |
| `packages/postern-core/src/postern_core/auth/device_codes.py` | `scanner_ip` field and serialization; `claim_scan(..., *, scanner_ip)` on the base and both backends; `creator_ip` docstring. |
| `services/confirm/device_auth.py` | `PAIRING_ENRICHMENT_SLOTS`; scanner address computed once; `_Scanned.risk_signals`; signal building, enrichment and cancellation withdrawal in `_scan`; `_withdraw_pairing`'s `"cancelled"` cause; the `creator_ip` comment. |
| `services/confirm/audit.py` | `risk_signals` keyword on `PairingAudit.approved` and `approved_again`, passed through `_write`; the column comment. |
| `services/confirm/settings.py` | `pairing_enricher_timeout_seconds`, its ceiling and `from_env` read. |
| `services/confirm/main.py` | `network_enricher` keyword with a sentinel default; enricher and semaphore on `app.state`. |
| `packages/postern-core/src/postern_core/env_inventory.py` | One row and its count comment. |
| `tests/test_settings_bounds.py` | One `Bounded` row and the counts. |
| `tests/test_device_code_pairing_store.py`, `tests/test_redis_backed_stores.py`, `tests/test_verify_page.py`, `tests/device_grant_helpers.py`, `tests/test_scan.py` | Every `claim_scan` call and test double gains `scanner_ip`. |
| `docs/user-guide/getting-started.md`, `docs/user-guide/components/confirm-service.md` | Spec section 6. |

---

### Task 1: The pure classifier, the facts comparison, the signal, and `signal_to_json`

Spec section 2 in full, section 3's Protocol, section 4's `signal_to_json`, and section 5's JSON shape. Pure code, so it lands first and everything later imports it.

**Files:**
- Create: `packages/postern-core/src/postern_core/risk/pairing_network.py` (`IPV4_SITE_PREFIX_BITS`, `IPV6_SITE_PREFIX_BITS`, `MAX_ASN`, `SIGNAL_CODE`, `NetworkRelation`, `MatchResult`, `NetworkFacts`, `NetworkEnricher`, `classify`, `sanitised`, `compare_facts`, `pairing_network_signal`)
- Modify: `packages/postern-core/src/postern_core/risk/types.py` (add `signal_to_json`)
- Test: `tests/test_pairing_network.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_pairing_network.py` with:

```python
"""The pairing network classifier, the facts comparison and the signal, in isolation.

``postern_core.risk.pairing_network`` is pure: two addresses in, one of four
relations out; two enricher answers in, two tri-state matches out. So every
row of section 2 of ``dev-docs/pairing-network-signal-spec.md`` is checked
here without an app, a store or a network, and ``signal_to_json`` is checked
against the read path's own serialization rather than against a copy of it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from postern_core.risk.context import RiskContext
from postern_core.risk.pairing_network import (
    MAX_ASN,
    SIGNAL_CODE,
    MatchResult,
    NetworkFacts,
    NetworkRelation,
    classify,
    compare_facts,
    pairing_network_signal,
    sanitised,
)
from postern_core.risk.session import set_current_session
from postern_core.risk.types import Severity, signal_to_json

SAME_IP = NetworkRelation.SAME_IP
SAME_PREFIX = NetworkRelation.SAME_PREFIX
DIFFERENT = NetworkRelation.DIFFERENT
UNKNOWN = NetworkRelation.UNKNOWN

#: Every row of section 2's table, and every case its Testing section names.
CLASSIFY_TABLE: list[tuple[str | None, str | None, NetworkRelation]] = [
    # same_ip
    ("203.0.113.9", "203.0.113.9", SAME_IP),
    ("2001:db8::7", "2001:db8::7", SAME_IP),
    ("2001:DB8:0:0::7", "2001:db8::7", SAME_IP),
    # same_prefix: one /24, one /48, and two /64s of one /48
    ("203.0.113.9", "203.0.113.200", SAME_PREFIX),
    ("2001:db8:1:1::1", "2001:db8:1:ffff::2", SAME_PREFIX),
    ("2001:db8:1:aaaa::1", "2001:db8:1:bbbb::1", SAME_PREFIX),
    # different: adjacent /24s, adjacent /48s, mixed families
    ("203.0.113.9", "203.0.114.9", DIFFERENT),
    ("2001:db8:1::1", "2001:db8:2::1", DIFFERENT),
    ("203.0.113.9", "2001:db8::7", DIFFERENT),
    ("2001:db8::7", "203.0.113.9", DIFFERENT),
    # IPv4-mapped: unwrapped before any row is tested
    ("::ffff:1.2.3.4", "1.2.3.4", SAME_IP),
    ("1.2.3.4", "::ffff:1.2.3.4", SAME_IP),
    ("::ffff:1.2.3.4", "::ffff:9.9.9.9", DIFFERENT),
    ("::ffff:1.2.3.4", "::ffff:1.2.3.200", SAME_PREFIX),
    ("::ffff:1.2.3.4", "1.2.3.200", SAME_PREFIX),
    # NAT64 on either side
    ("64:ff9b::102:304", "1.2.3.4", UNKNOWN),
    ("1.2.3.4", "64:ff9b::102:304", UNKNOWN),
    ("64:ff9b::102:304", "64:ff9b::102:304", UNKNOWN),
    # absent or unparsable
    (None, "203.0.113.9", UNKNOWN),
    ("203.0.113.9", None, UNKNOWN),
    (None, None, UNKNOWN),
    ("not an address", "203.0.113.9", UNKNOWN),
    ("203.0.113.9", "999.1.1.1", UNKNOWN),
    ("", "203.0.113.9", UNKNOWN),
    ("203.0.113.9/24", "203.0.113.9", UNKNOWN),
]


@pytest.mark.parametrize(("creator", "scanner", "expected"), CLASSIFY_TABLE)
def test_classify(creator: str | None, scanner: str | None, expected: NetworkRelation) -> None:
    assert classify(creator, scanner) is expected


def test_the_relation_vocabulary_is_exactly_four_values() -> None:
    assert [r.value for r in NetworkRelation] == ["same_ip", "same_prefix", "different", "unknown"]


def test_classify_raises_for_no_input_in_the_table() -> None:
    """Totality, stated as its own test so a raise is reported as that."""
    for creator, scanner, _ in CLASSIFY_TABLE:
        classify(creator, scanner)
        classify(scanner, creator)


def test_two_unrelated_mapped_addresses_are_not_the_benign_answer() -> None:
    """The case the literal reading got wrong: left mapped, both sit in ``::/48``."""
    assert classify("::ffff:1.2.3.4", "::ffff:9.9.9.9") is not SAME_PREFIX


# ---------------------------------------------------------------------------
# compare_facts: every combination of present, None and field-None.
# ---------------------------------------------------------------------------

FULL = NetworkFacts(asn=64500, country="ES")
FULL_OTHER = NetworkFacts(asn=64501, country="IT")
NO_ASN = NetworkFacts(asn=None, country="ES")
NO_COUNTRY = NetworkFacts(asn=64500, country=None)
EMPTY = NetworkFacts()

COMPARE_TABLE: list[
    tuple[NetworkFacts | None, NetworkFacts | None, tuple[MatchResult, MatchResult]]
] = [
    (FULL, FULL, (True, True)),
    (FULL, FULL_OTHER, (False, False)),
    (FULL, NetworkFacts(asn=64500, country="IT"), (True, False)),
    (FULL, NetworkFacts(asn=64501, country="ES"), (False, True)),
    (None, FULL, ("unknown", "unknown")),
    (FULL, None, ("unknown", "unknown")),
    (None, None, ("unknown", "unknown")),
    (NO_ASN, FULL, ("unknown", True)),
    (FULL, NO_ASN, ("unknown", True)),
    (NO_COUNTRY, FULL, (True, "unknown")),
    (FULL, NO_COUNTRY, (True, "unknown")),
    (EMPTY, FULL, ("unknown", "unknown")),
    (FULL, EMPTY, ("unknown", "unknown")),
    (EMPTY, EMPTY, ("unknown", "unknown")),
    (NO_ASN, NO_COUNTRY, ("unknown", "unknown")),
]


@pytest.mark.parametrize(("creator", "scanner", "expected"), COMPARE_TABLE)
def test_compare_facts(
    creator: NetworkFacts | None,
    scanner: NetworkFacts | None,
    expected: tuple[MatchResult, MatchResult],
) -> None:
    assert compare_facts(creator, scanner) == expected


def test_country_is_compared_case_insensitively() -> None:
    assert compare_facts(NetworkFacts(country="es"), NetworkFacts(country="ES"))[1] is True


def test_one_answer_passed_twice_is_true_only_for_returned_fields() -> None:
    """How the host treats ``same_ip``: one lookup, the answer on both sides."""
    assert compare_facts(NO_COUNTRY, NO_COUNTRY) == (True, "unknown")


# ---------------------------------------------------------------------------
# sanitised: a field that fails validation becomes None for that field only.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("facts", "expected", "discarded"),
    [
        (NetworkFacts(asn=64500, country="ES"), NetworkFacts(asn=64500, country="ES"), False),
        (NetworkFacts(), NetworkFacts(), False),
        (NetworkFacts(asn=0, country="es"), NetworkFacts(asn=0, country="es"), False),
        (NetworkFacts(asn=MAX_ASN), NetworkFacts(asn=MAX_ASN), False),
        (NetworkFacts(asn=MAX_ASN + 1, country="ES"), NetworkFacts(country="ES"), True),
        (NetworkFacts(asn=-1, country="ES"), NetworkFacts(country="ES"), True),
        (NetworkFacts(asn=True, country="ES"), NetworkFacts(country="ES"), True),
        (NetworkFacts(asn="64500", country="ES"), NetworkFacts(country="ES"), True),  # type: ignore[arg-type]
        (NetworkFacts(asn=64500, country="ESP"), NetworkFacts(asn=64500), True),
        (NetworkFacts(asn=64500, country="E1"), NetworkFacts(asn=64500), True),
        (NetworkFacts(asn=64500, country="ÉS"), NetworkFacts(asn=64500), True),
        (NetworkFacts(asn=64500, country=""), NetworkFacts(asn=64500), True),
        (NetworkFacts(asn=64500, country=34), NetworkFacts(asn=64500), True),  # type: ignore[arg-type]
    ],
)
def test_sanitised(facts: NetworkFacts, expected: NetworkFacts, discarded: bool) -> None:
    assert sanitised(facts) == (expected, discarded)


# ---------------------------------------------------------------------------
# The signal and its JSON.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("relation", list(NetworkRelation))
def test_the_signal_without_an_enricher_has_no_match_keys(relation: NetworkRelation) -> None:
    assert signal_to_json(pairing_network_signal(relation, 2)) == {
        "code": "PAIRING_NETWORK",
        "severity": "LOW",
        "description": f"pairing creator and scanner network relation: {relation.value}",
        "details": {"relation": relation.value, "proxy_hops": 2},
    }


@pytest.mark.parametrize("relation", list(NetworkRelation))
def test_the_signal_with_an_enricher_carries_both_matches(relation: NetworkRelation) -> None:
    signal = pairing_network_signal(relation, 0, asn_match=False, country_match="unknown")
    assert signal_to_json(signal) == {
        "code": "PAIRING_NETWORK",
        "severity": "LOW",
        "description": f"pairing creator and scanner network relation: {relation.value}",
        "details": {
            "relation": relation.value,
            "proxy_hops": 0,
            "asn_match": False,
            "country_match": "unknown",
        },
    }


def test_the_signal_is_low_and_carries_the_code() -> None:
    signal = pairing_network_signal(DIFFERENT, 1, True, True)
    assert signal.code == SIGNAL_CODE == "PAIRING_NETWORK"
    assert signal.severity is Severity.LOW


def test_the_json_round_trips_the_mixed_types_the_column_is_queried_by() -> None:
    """``details->>'asn_match'`` must read ``true``, ``false`` or ``unknown``."""
    cases: list[tuple[MatchResult, str]] = [
        (True, "true"),
        (False, "false"),
        ("unknown", '"unknown"'),
    ]
    for match, text in cases:
        encoded = json.dumps(signal_to_json(pairing_network_signal(DIFFERENT, 1, match, match)))
        assert f'"asn_match": {text}' in encoded


@pytest.mark.parametrize(("creator", "scanner", "relation"), CLASSIFY_TABLE)
def test_no_input_reaches_the_serialized_signal(
    creator: str | None, scanner: str | None, relation: NetworkRelation
) -> None:
    """No address, ASN number or country code in the JSON, for any input."""
    facts_a = NetworkFacts(asn=64512, country="FR")
    facts_b = NetworkFacts(asn=65001, country="DE")
    asn_match, country_match = compare_facts(facts_a, facts_b)
    text = json.dumps(
        signal_to_json(
            pairing_network_signal(classify(creator, scanner), 3, asn_match, country_match)
        )
    )
    for needle in (creator, scanner, "64512", "65001", "FR", "DE"):
        if needle:
            assert needle not in text


@dataclass(frozen=True)
class _CapturedWrite:
    risk_signals: list[dict[str, Any]] | None


class _MockContext:
    def __init__(self) -> None:
        self.message = MagicMock()
        self.message.name = "test_tool"
        self.message.arguments = {}
        self.timestamp = None
        self.fastmcp_context = None


async def test_signal_to_json_matches_what_the_read_path_writes_for_the_same_signal() -> None:
    """The read path serializes inline in ``AuditMiddleware``; ``.importlinter``
    keeps ``services.confirm`` from importing it, so the two copies are pinned
    against each other here rather than trusted to agree."""
    from services.api.middleware.audit import AuditMiddleware

    signal = pairing_network_signal(DIFFERENT, 2, True, "unknown")
    middleware = AuditMiddleware(db=None)  # type: ignore[arg-type]
    captured: list[_CapturedWrite] = []

    async def call_next(context: Any) -> Any:
        return MagicMock()

    async def capture_write(*args: Any, **kwargs: Any) -> None:
        captured.append(_CapturedWrite(risk_signals=args[13]))

    ctx = RiskContext(session_id="pairing-network-signal")
    ctx.record_signals([signal])
    set_current_session(ctx)
    try:
        with patch.object(middleware, "_write", capture_write):
            await middleware.on_call_tool(_MockContext(), call_next)  # type: ignore[arg-type]
    finally:
        set_current_session(None)

    assert len(captured) == 1
    written = captured[0].risk_signals
    assert written is not None and len(written) == 1
    assert list(written[0]) == list(signal_to_json(signal))
    assert written[0] == signal_to_json(signal)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_pairing_network.py -q`
Expected: collection error, `ModuleNotFoundError: No module named 'postern_core.risk.pairing_network'`.

- [ ] **Step 3: Implement**

3a. Create `packages/postern-core/src/postern_core/risk/pairing_network.py` with:

```python
"""Where a pairing was created, against where it was scanned.

PURE, AND THAT IS THE CONTRACT. This module imports ``ipaddress``, ``enum``,
``dataclasses``, ``typing`` and ``postern_core.risk.types``, reads no
environment, performs no I/O and holds no state. The one thing here that
could reach a network, an enricher, is a Protocol: this module says what one
must look like and ``postern_core.modules.enrichers`` finds the installed one.

WHAT THE RELATION IS FOR. The two phishing forms ``dev-docs/qr-page-spec.md``
names -- the consent lure and the live relay -- create the pairing on the
attacker's network and scan it on the victim's. The only server-side trace
either leaves is that the two networks differ, so ``POST /scan`` records the
comparison on every successful scan. It refuses nothing: a legitimate laptop
on home Wi-Fi paired with a phone on mobile data is ``different`` too, and
``dev-docs/pairing-network-signal-spec.md`` lists the other benign causes.

/24 AND /48, NOT ``postern_core.net``'s /64. That function answers "which
rate-limit counter does this address spend"; this one answers "could these
two requests plausibly be the same site". A /48 is the allocation commonly
given to one end site and a /64 is one link inside it, so a laptop on
Ethernet and a phone on Wi-Fi in one house can sit in two /64s of one /48.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol

from postern_core.risk.types import RiskSignal, Severity

__all__ = [
    "IPV4_SITE_PREFIX_BITS",
    "IPV6_SITE_PREFIX_BITS",
    "MAX_ASN",
    "SIGNAL_CODE",
    "MatchResult",
    "NetworkEnricher",
    "NetworkFacts",
    "NetworkRelation",
    "classify",
    "compare_facts",
    "pairing_network_signal",
    "sanitised",
]

#: The prefix two IPv4 addresses must share to be ``same_prefix``.
IPV4_SITE_PREFIX_BITS = 24

#: The prefix two IPv6 addresses must share to be ``same_prefix``.
IPV6_SITE_PREFIX_BITS = 48

#: The largest autonomous system number: ASNs are 32-bit (RFC 6793).
MAX_ASN = 4_294_967_295

#: The ``code`` of the one signal ``POST /scan`` records, upper case like the
#: read path's ``IMPOSSIBLE_TRAVEL``.
SIGNAL_CODE = "PAIRING_NETWORK"

#: RFC 6052's well-known NAT64 prefix. An address inside it names the NAT64
#: gateway, not a subscriber, and its /48 is shared by every client behind
#: every such gateway, so it has no truthful classification here.
_NAT64_WELL_KNOWN = ipaddress.IPv6Network("64:ff9b::/96")

type _Address = ipaddress.IPv4Address | ipaddress.IPv6Address


class NetworkRelation(StrEnum):
    """How the creator's address relates to the scanner's. Four values, closed."""

    SAME_IP = "same_ip"
    SAME_PREFIX = "same_prefix"
    DIFFERENT = "different"
    UNKNOWN = "unknown"


#: ``True``, ``False`` or the string ``"unknown"``, so that
#: ``details->>'asn_match'`` reads back as the text ``true``, ``false`` or
#: ``unknown`` uniformly.
type MatchResult = bool | Literal["unknown"]


@dataclass(frozen=True)
class NetworkFacts:
    """What an enricher knows about one address. Either field may be ``None``."""

    asn: int | None = None
    country: str | None = None


class NetworkEnricher(Protocol):
    """An installed provider of ASN and country facts for an address.

    ``None`` means "no data for this address", which is the normal answer for
    a private or reserved range. ASYNC, AND ALL I/O THROUGH ASYNC CLIENTS: a
    ``lookup`` that never yields, or that calls blocking I/O inside
    ``async def``, holds the event loop for every request on the replica, and
    the time budget ``POST /scan`` puts around it cannot stop that.
    """

    async def lookup(self, ip: str) -> NetworkFacts | None: ...


def _normalised(raw: str | None) -> _Address | None:
    """Parse ``raw`` and unwrap an IPv4-mapped address, or ``None``.

    UNWRAPPED BEFORE ANYTHING IS COMPARED, because every IPv4-mapped address
    has 80 zero bits before its ``ffff`` and so falls in ``::/48``: left
    mapped, any two unrelated IPv4 clients reaching a dual-stack socket would
    classify as ``same_prefix``, the benign-looking answer, which is the one
    direction this signal must not err in.
    """
    if raw is None:
        return None
    try:
        address = ipaddress.ip_address(raw)
    except (ValueError, TypeError):
        return None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _site(address: _Address) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    bits = IPV4_SITE_PREFIX_BITS if address.version == 4 else IPV6_SITE_PREFIX_BITS
    return ipaddress.ip_network(f"{address}/{bits}", strict=False)


def classify(creator_ip: str | None, scanner_ip: str | None) -> NetworkRelation:
    """The relation between two addresses. Total: it never raises.

    ``unknown`` when either is ``None``, either will not parse, or either lies
    in the NAT64 well-known prefix after normalisation. An unparsable string is
    ``unknown`` rather than an exception because ``creator_ip`` is read back
    out of a store, and a corrupted value must not fail a scan. Mixed families
    are always ``different``.
    """
    creator = _normalised(creator_ip)
    scanner = _normalised(scanner_ip)
    if creator is None or scanner is None:
        return NetworkRelation.UNKNOWN
    for address in (creator, scanner):
        if isinstance(address, ipaddress.IPv6Address) and address in _NAT64_WELL_KNOWN:
            return NetworkRelation.UNKNOWN
    if creator == scanner:
        return NetworkRelation.SAME_IP
    if creator.version != scanner.version:
        return NetworkRelation.DIFFERENT
    if _site(creator) == _site(scanner):
        return NetworkRelation.SAME_PREFIX
    return NetworkRelation.DIFFERENT


def sanitised(facts: NetworkFacts) -> tuple[NetworkFacts, bool]:
    """``facts`` with every field that fails validation set to ``None``.

    Returns the cleaned facts and whether anything was discarded. ``asn`` must
    be an ``int`` that is not a ``bool`` and lies in 0 to ``MAX_ASN``;
    ``country`` must be two ASCII letters. A discarded value is never stored
    and never logged: the caller learns only that something was dropped.
    """
    asn = facts.asn
    country = facts.country
    asn_ok = asn is None or (
        isinstance(asn, int) and not isinstance(asn, bool) and 0 <= asn <= MAX_ASN
    )
    country_ok = country is None or (
        isinstance(country, str) and len(country) == 2 and country.isascii() and country.isalpha()
    )
    cleaned = NetworkFacts(
        asn=asn if asn_ok else None,
        country=country if country_ok else None,
    )
    return cleaned, not (asn_ok and country_ok)


def _match(creator: object, scanner: object) -> MatchResult:
    if creator is None or scanner is None:
        return "unknown"
    return creator == scanner


def compare_facts(
    creator: NetworkFacts | None, scanner: NetworkFacts | None
) -> tuple[MatchResult, MatchResult]:
    """``(asn_match, country_match)`` for two enricher answers.

    Per field: ``True`` when both sides carry a value and they are equal,
    ``False`` when both carry one and they differ, ``"unknown"`` otherwise.
    Country codes are compared after ``str.upper()``. For ``same_ip`` the
    caller passes the one answer as both arguments, so a returned field is
    ``True`` and a missing one ``"unknown"``.
    """
    if creator is None or scanner is None:
        return "unknown", "unknown"
    creator_country = creator.country.upper() if creator.country is not None else None
    scanner_country = scanner.country.upper() if scanner.country is not None else None
    return _match(creator.asn, scanner.asn), _match(creator_country, scanner_country)


def pairing_network_signal(
    relation: NetworkRelation,
    proxy_hops: int,
    asn_match: MatchResult | None = None,
    country_match: MatchResult | None = None,
) -> RiskSignal:
    """The one ``RiskSignal`` a successful scan records.

    ``severity`` is always ``LOW``, the severity whose ``RiskAction`` is to
    log: grading ``different`` higher would announce a policy nobody has
    decided. A match argument of ``None`` means no enricher is installed and
    omits its key, which a reader tells apart from ``"unknown"`` (an enricher
    was installed and could not answer) with ``details ? 'asn_match'``.

    NO ADDRESS, ASN OR COUNTRY IN ANY VALUE. The details carry only
    comparisons and a closed vocabulary chosen by this code, so nothing in
    them comes from a caller or a provider.
    """
    details: dict[str, object] = {"relation": relation.value, "proxy_hops": proxy_hops}
    if asn_match is not None:
        details["asn_match"] = asn_match
    if country_match is not None:
        details["country_match"] = country_match
    return RiskSignal(
        code=SIGNAL_CODE,
        description=f"pairing creator and scanner network relation: {relation.value}",
        severity=Severity.LOW,
        details=details,
    )
```

3b. Append to `packages/postern-core/src/postern_core/risk/types.py`:

```python
def signal_to_json(signal: RiskSignal) -> dict[str, Any]:
    """The object one ``RiskSignal`` becomes in ``audit_log.risk_signals``.

    Four keys, in the order ``services/api/middleware/audit.py`` writes them
    inline for the read path, with ``severity`` as the member's name. It lives
    here, beside the type, because ``.importlinter`` forbids
    ``services.confirm`` from importing ``services.api``, and one query shape
    must read both services' rows. ``tests/test_pairing_network.py`` pins the
    two against each other.
    """
    return {
        "code": signal.code,
        "severity": signal.severity.name,
        "description": signal.description,
        "details": dict(signal.details),
    }
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_pairing_network.py -q`
Expected: 94 passed.

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add packages/postern-core/src/postern_core/risk/pairing_network.py packages/postern-core/src/postern_core/risk/types.py tests/test_pairing_network.py
git commit -m "feat(risk): classify the pairing creator's network against the scanner's" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `scanner_ip` on the pairing, written by the claim

Spec section 1 in full, and section 4's first sentence (the scanner's address computed once in `scan_callback` and passed both to `PairingAudit` and to `_scan`). The signature change and every caller land in one commit, because a required keyword breaks every call that lacks it.

**Files:**
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py` (`DeviceCode` docstring and field; `DeviceCodeStoreBase.claim_scan`; `InMemoryDeviceCodeStore.claim_scan`; `RedisDeviceCodeStore.claim_scan`; `_device_code_to_dict`; `_device_code_from_dict`)
- Modify: `services/confirm/device_auth.py` (`scan_callback`, `_scan`)
- Modify: `tests/test_device_code_pairing_store.py`, `tests/test_redis_backed_stores.py`, `tests/test_verify_page.py`, `tests/device_grant_helpers.py` (every `claim_scan` call), `tests/test_scan.py` (three test doubles)
- Test: `tests/test_device_code_scanner_ip.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_device_code_scanner_ip.py` with:

```python
"""``scanner_ip`` on a device code: written by the claim, on both backends, once.

Section 1 of ``dev-docs/pairing-network-signal-spec.md``. The address of the
``POST /scan`` request that claimed a pairing is written in the same
compare-and-set as ``scanned_by`` and ``scanned_at`` and in no other write, so
every ``ScanClaim`` result is driven here and the stored row read back. The
Redis half runs against the container ``make ci`` already starts, through a
second connection, because the two backends share a contract and no code.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
import pytest_asyncio
from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    InMemoryDeviceCodeStore,
    RedisDeviceCodeStore,
    ScanClaim,
)

VERIFY_URI = "https://auth.test.invalid/verify"
ALICE = "cust_a11ce"
BOB = "cust_b0b0"
FIRST = "198.51.100.7"
SECOND = "203.0.113.200"


@pytest_asyncio.fixture(params=["memory", "redis"])
async def pair(request: pytest.FixtureRequest) -> AsyncIterator[tuple[Any, Any]]:
    """A writer and a reader over one backend.

    For Redis they are two connections under one fresh key prefix, so a value
    read back has crossed the server; for memory they are the same object.
    """
    if request.param == "memory":
        store = InMemoryDeviceCodeStore()
        yield store, store
        return
    url: str = request.getfixturevalue("redis_url")
    prefix = f"t{uuid4().hex[:12]}:"
    writer = RedisDeviceCodeStore(url=url, default_ttl=900, key_prefix=prefix, max_codes=10_000)
    reader = RedisDeviceCodeStore(url=url, default_ttl=900, key_prefix=prefix, max_codes=10_000)
    yield writer, reader
    await writer.close()
    await reader.close()


async def _create(store: Any) -> DeviceCode:
    code: DeviceCode = await store.create_device_code(
        client_id="vendor-a",
        scopes="accounts:read",
        verification_uri=VERIFY_URI,
        creator_ip="192.0.2.1",
    )
    return code


async def _read(store: Any, device_code: str) -> DeviceCode | None:
    code: DeviceCode | None = await store.get_device_code(device_code)
    return code


async def test_a_new_code_has_no_scanner(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    code = await _create(writer)
    assert code.scanner_ip is None
    stored = await _read(reader, code.device_code)
    assert stored is not None and stored.scanner_ip is None


async def test_the_claim_writes_the_address_with_the_scan_fields(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    code = await _create(writer)

    assert await writer.claim_scan(code.device_code, ALICE, scanner_ip=FIRST) is ScanClaim.CLAIMED

    stored = await _read(reader, code.device_code)
    assert stored is not None
    assert stored.scanned_by == ALICE
    assert stored.scanned_at is not None
    assert stored.scanner_ip == FIRST
    assert stored.creator_ip == "192.0.2.1"


async def test_a_claim_with_no_address_stores_none(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    code = await _create(writer)

    assert await writer.claim_scan(code.device_code, ALICE, scanner_ip=None) is ScanClaim.CLAIMED

    stored = await _read(reader, code.device_code)
    assert stored is not None and stored.scanned_by == ALICE and stored.scanner_ip is None


async def test_a_retry_from_another_network_does_not_move_the_address(
    pair: tuple[Any, Any],
) -> None:
    """First scan wins: ``ALREADY_MINE`` writes nothing."""
    writer, reader = pair
    code = await _create(writer)
    await writer.claim_scan(code.device_code, ALICE, scanner_ip=FIRST)
    before = await _read(reader, code.device_code)

    assert (
        await reader.claim_scan(code.device_code, ALICE, scanner_ip=SECOND)
        is ScanClaim.ALREADY_MINE
    )

    after = await _read(writer, code.device_code)
    assert after == before
    assert after is not None and after.scanner_ip == FIRST


async def test_a_repeat_after_approval_does_not_move_the_address(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    code = await _create(writer)
    await writer.claim_scan(code.device_code, ALICE, scanner_ip=FIRST)
    assert await writer.approve_scanned(code.device_code, ALICE) is True
    before = await _read(reader, code.device_code)

    assert (
        await reader.claim_scan(code.device_code, ALICE, scanner_ip=SECOND)
        is ScanClaim.APPROVED_MINE
    )
    assert await _read(writer, code.device_code) == before


async def test_a_conflict_on_an_exchanged_code_does_not_move_the_address(
    pair: tuple[Any, Any],
) -> None:
    writer, reader = pair
    code = await _create(writer)
    await writer.claim_scan(code.device_code, BOB, scanner_ip=FIRST)
    await writer.approve_scanned(code.device_code, BOB)
    await writer.consume_device_code(code.device_code)
    before = await _read(reader, code.device_code)

    assert (
        await reader.claim_scan(code.device_code, ALICE, scanner_ip=SECOND)
        is ScanClaim.CONFLICT_EXCHANGED
    )
    after = await _read(writer, code.device_code)
    assert after == before
    assert after is not None and after.scanner_ip == FIRST


async def test_a_conflict_on_an_unexchanged_code_leaves_no_row_to_carry_it(
    pair: tuple[Any, Any],
) -> None:
    """``CONFLICT_REVOKED`` deletes the pairing, so the second customer's
    address is written nowhere."""
    writer, reader = pair
    code = await _create(writer)
    await writer.claim_scan(code.device_code, BOB, scanner_ip=FIRST)

    assert (
        await reader.claim_scan(code.device_code, ALICE, scanner_ip=SECOND)
        is ScanClaim.CONFLICT_REVOKED
    )
    assert await _read(writer, code.device_code) is None


async def test_a_missing_code_is_gone_and_nothing_is_written(pair: tuple[Any, Any]) -> None:
    writer, reader = pair
    assert await writer.claim_scan("never-existed", ALICE, scanner_ip=FIRST) is ScanClaim.GONE
    assert await _read(reader, "never-existed") is None


async def test_claim_scan_without_an_address_is_a_type_error(pair: tuple[Any, Any]) -> None:
    """Required and keyword-only, so no caller can record "no address" by omission."""
    writer, _ = pair
    code = await _create(writer)
    with pytest.raises(TypeError):
        await writer.claim_scan(code.device_code, ALICE)
    with pytest.raises(TypeError):
        await writer.claim_scan(code.device_code, ALICE, FIRST)


def test_the_abstract_signature_makes_the_address_required_and_keyword_only() -> None:
    parameter = inspect.signature(DeviceCodeStoreBase.claim_scan).parameters["scanner_ip"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is inspect.Parameter.empty


# ---------------------------------------------------------------------------
# Serialization.
# ---------------------------------------------------------------------------


def _bare(**overrides: Any) -> DeviceCode:
    fields: dict[str, Any] = {
        "device_code": "dc-bare",
        "user_code": "ABC234",
        "verification_uri": VERIFY_URI,
        "expires_at": datetime.now(UTC) + timedelta(minutes=15),
    }
    fields.update(overrides)
    return DeviceCode(**fields)


def test_the_address_round_trips_through_json() -> None:
    back = DeviceCode.from_json(_bare(scanner_ip="2001:db8::9").to_json())
    assert back.scanner_ip == "2001:db8::9"


def test_an_absent_address_is_serialized_as_null() -> None:
    serialized = _bare().to_dict()
    assert "scanner_ip" in serialized
    assert serialized["scanner_ip"] is None
    assert DeviceCode.from_dict(serialized).scanner_ip is None


def test_a_record_written_before_the_field_existed_has_no_scanner() -> None:
    legacy = _bare(scanned_by=ALICE, scanned_at=datetime.now(UTC)).to_dict()
    del legacy["scanner_ip"]

    code = DeviceCode.from_dict(legacy)

    assert code.scanner_ip is None
    assert code.scanned_by == ALICE
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_device_code_scanner_ip.py -q`
Expected: 22 failed. The claim tests on both backends with `TypeError: InMemoryDeviceCodeStore.claim_scan() got an unexpected keyword argument 'scanner_ip'` (and the `RedisDeviceCodeStore` twin), the two missing-argument cases with `Failed: DID NOT RAISE TypeError`, the field and serialization tests with `AttributeError: 'DeviceCode' object has no attribute 'scanner_ip'`, `TypeError: DeviceCode.__init__() got an unexpected keyword argument 'scanner_ip'` or `KeyError: 'scanner_ip'`, and the signature test with `KeyError: 'scanner_ip'`.

- [ ] **Step 3: Implement the store change**

In `packages/postern-core/src/postern_core/auth/device_codes.py`:

3a. In the `DeviceCode` docstring, replace:

```python
        scanned_at: When that scan was claimed.

```

with:

```python
        scanned_at: When that scan was claimed.
        scanner_ip: The address of the ``POST /scan`` request that claimed
            the pairing, written in the same compare-and-set as
            ``scanned_by`` and ``scanned_at`` and never after. ``None`` until
            scanned, and on a record the previous release wrote, which
            recorded no scanner address. Recorded only; nothing reads it back.

```

3b. Replace:

```python
    scanned_at: datetime | None = None

    @property
```

with:

```python
    scanned_at: datetime | None = None
    scanner_ip: str | None = None

    @property
```

3c. On `DeviceCodeStoreBase`, replace:

```python
    @abstractmethod
    async def claim_scan(self, device_code: str, customer_ref: str) -> ScanClaim:
        """Record the first scan of a code, or say why this one is not it.

        A COMPARE-AND-SET, modelled on ``consume_device_code``: one
        transaction reads the row, decides with ``_scan_verdict``, and writes
        only for ``CLAIMED`` (``scanned_by``, ``scanned_at``) and
        ``CONFLICT_REVOKED`` (the whole pairing, secondaries included). Every
        other result writes nothing. The same atomicity contract as
        ``consume_device_code`` holds, for the same reason: two phones
        scanning one QR on two replicas must not both win.

        Raises:
```

with:

```python
    @abstractmethod
    async def claim_scan(
        self, device_code: str, customer_ref: str, *, scanner_ip: str | None
    ) -> ScanClaim:
        """Record the first scan of a code, or say why this one is not it.

        A COMPARE-AND-SET, modelled on ``consume_device_code``: one
        transaction reads the row, decides with ``_scan_verdict``, and writes
        only for ``CLAIMED`` (``scanned_by``, ``scanned_at``, ``scanner_ip``) and
        ``CONFLICT_REVOKED`` (the whole pairing, secondaries included). Every
        other result writes nothing. The same atomicity contract as
        ``consume_device_code`` holds, for the same reason: two phones
        scanning one QR on two replicas must not both win.

        ``scanner_ip`` IS REQUIRED AND NULLABLE, for the reason
        ``postern_core.store.audit.append`` gives for its ``client_id``: a
        default would let a future caller record "no address" for a scan that
        had one. First scan wins: ``ALREADY_MINE`` writes nothing, so a retry
        from another network does not move the address the claim was made from.

        Raises:
```

3d. On `InMemoryDeviceCodeStore`, replace:

```python
    async def claim_scan(self, device_code: str, customer_ref: str) -> ScanClaim:
        """Record the first scan, or say why this one is not it.

        ATOMIC BY NOT YIELDING, for the reason ``consume_device_code`` gives:
```

with:

```python
    async def claim_scan(
        self, device_code: str, customer_ref: str, *, scanner_ip: str | None
    ) -> ScanClaim:
        """Record the first scan, or say why this one is not it.

        ATOMIC BY NOT YIELDING, for the reason ``consume_device_code`` gives:
```

and in the same method replace:

```python
            self._codes[device_code] = dataclasses.replace(
                existing, scanned_by=customer_ref, scanned_at=datetime.now(UTC)
            )
```

with:

```python
            self._codes[device_code] = dataclasses.replace(
                existing,
                scanned_by=customer_ref,
                scanned_at=datetime.now(UTC),
                scanner_ip=scanner_ip,
            )
```

3e. On `RedisDeviceCodeStore`, replace:

```python
    async def claim_scan(self, device_code: str, customer_ref: str) -> ScanClaim:
        """Record the first scan, or say why this one is not it.

        ``WATCH``/``MULTI`` on the primary, the shape ``consume_device_code``
```

with:

```python
    async def claim_scan(
        self, device_code: str, customer_ref: str, *, scanner_ip: str | None
    ) -> ScanClaim:
        """Record the first scan, or say why this one is not it.

        ``WATCH``/``MULTI`` on the primary, the shape ``consume_device_code``
```

and in the same method replace:

```python
                        scanned = dataclasses.replace(
                            code, scanned_by=customer_ref, scanned_at=datetime.now(UTC)
                        )
```

with:

```python
                        scanned = dataclasses.replace(
                            code,
                            scanned_by=customer_ref,
                            scanned_at=datetime.now(UTC),
                            scanner_ip=scanner_ip,
                        )
```

3f. In `_device_code_to_dict`, replace:

```python
        "scanned_at": dc.scanned_at.timestamp() if dc.scanned_at else None,
    }
```

with:

```python
        "scanned_at": dc.scanned_at.timestamp() if dc.scanned_at else None,
        "scanner_ip": dc.scanner_ip,
    }
```

3g. In `_device_code_from_dict`, replace:

```python
    raw_creator_ip = data.get("creator_ip")
```

with:

```python
    raw_creator_ip = data.get("creator_ip")
    raw_scanner_ip = data.get("scanner_ip")
```

and replace:

```python
        scanned_at=scanned_at,
    )
```

with:

```python
        scanned_at=scanned_at,
        # ABSENT MEANS NONE, and here that is the TRUE reading rather than a
        # fail-closed default: the previous release recorded no scanner
        # address, so there is none.
        scanner_ip=str(raw_scanner_ip) if raw_scanner_ip is not None else None,
    )
```

- [ ] **Step 4: Compute the scanner's address once and pass it to the claim**

In `services/confirm/device_auth.py`:

4a. In `scan_callback`, replace:

```python
    audit = PairingAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=subject,
        claims=verified_claims(request),
        client_ip_value=pairing_client_ip(request, settings.trusted_proxy_hops),
        tool_name=SCAN_TOOL_NAME,
        route=SCAN_ROUTE,
    )

    try:
        outcome = await _scan(request, audit, store=store, subject=subject)
```

with:

```python
    # COMPUTED ONCE, and handed both to the row and to the claim. Two reads
    # could disagree if they ever diverged, and then the address the row
    # records would not be the address the pairing was claimed from.
    scanner_ip = pairing_client_ip(request, settings.trusted_proxy_hops)
    audit = PairingAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=subject,
        claims=verified_claims(request),
        client_ip_value=scanner_ip,
        tool_name=SCAN_TOOL_NAME,
        route=SCAN_ROUTE,
    )

    try:
        outcome = await _scan(request, audit, store=store, subject=subject, scanner_ip=scanner_ip)
```

4b. In `_scan`'s signature, replace:

```python
    store: DeviceCodeStoreBase,
    subject: str,
) -> _Scanned:
```

with:

```python
    store: DeviceCodeStoreBase,
    subject: str,
    scanner_ip: str | None,
) -> _Scanned:
```

4c. In `_scan`, replace:

```python
        claim = await store.claim_scan(code.device_code, customer.value)
```

with:

```python
        claim = await store.claim_scan(code.device_code, customer.value, scanner_ip=scanner_ip)
```

- [ ] **Step 5: Update every existing caller in the tests**

5a. Every existing call passes no address, which is what those tests were written against. Run exactly:

```bash
perl -0pi -e 's/\.claim_scan\(([^()]*?)\)/.claim_scan($1, scanner_ip=None)/g' tests/test_device_code_pairing_store.py tests/test_redis_backed_stores.py tests/test_verify_page.py tests/device_grant_helpers.py
```

Then check it: `rg -c "scanner_ip=None" tests` must report 21 matching lines in `tests/test_device_code_pairing_store.py`, 19 in `tests/test_redis_backed_stores.py`, 1 in `tests/test_verify_page.py` and 1 in `tests/device_grant_helpers.py`, and `rg -n "claim_scan\(" tests | rg -v "scanner_ip="` must print nothing.

5b. In `tests/test_scan.py`, the two identical test doubles named `claim_then_time_out` (in `test_a_claim_whose_reply_is_lost_is_withdrawn_and_recorded_as_the_store_error` and `test_a_failed_withdrawal_of_an_ambiguous_claim_says_claimed_and_the_store_cause`) each change from:

```python
    async def claim_then_time_out(device_code: str, customer_ref: str) -> Any:
        await real_claim(device_code, customer_ref)
        raise TimeoutError("reply lost after EXEC")
```

to:

```python
    async def claim_then_time_out(
        device_code: str, customer_ref: str, *, scanner_ip: str | None
    ) -> Any:
        await real_claim(device_code, customer_ref, scanner_ip=scanner_ip)
        raise TimeoutError("reply lost after EXEC")
```

(this old text occurs twice; replace both), and in `test_a_contended_claim_withdraws_nothing` replace:

```python
    async def contended(device_code: str, customer_ref: str) -> Any:
```

with:

```python
    async def contended(device_code: str, customer_ref: str, *, scanner_ip: str | None) -> Any:
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run ruff format packages services tests && uv run pytest tests/test_device_code_scanner_ip.py tests/test_device_code_pairing_store.py tests/test_redis_backed_stores.py tests/test_scan.py tests/test_verify_page.py tests/test_device_grant.py -q`
Expected: all pass (312 at validation). `ruff format` rewraps the lines the perl substitution lengthened.

- [ ] **Step 7: Run the gate**

Run: `make ci`
Expected: exit 0.

- [ ] **Step 8: Commit**

```bash
git add packages/postern-core/src/postern_core/auth/device_codes.py services/confirm/device_auth.py tests/test_device_code_scanner_ip.py tests/test_device_code_pairing_store.py tests/test_redis_backed_stores.py tests/test_verify_page.py tests/device_grant_helpers.py tests/test_scan.py
git commit -m "feat(core): record the scanner's address on the claim that makes it" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS`

Spec section 3, "The time budget": the field, its `from_env` read through `float_from_env` with the required `because=` sentence, the 1.0 ceiling `from_env` enforces itself, and the `env_inventory` row. Nothing reads the value until Task 7.

**Files:**
- Modify: `services/confirm/settings.py` (`MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS`, `_PAIRING_ENRICHER_TIMEOUT_BECAUSE`, `_pairing_enricher_timeout`, `ConfirmSettings.pairing_enricher_timeout_seconds`, `ConfirmSettings.from_env`)
- Modify: `packages/postern-core/src/postern_core/env_inventory.py` (`INVENTORY` row and its comment)
- Test: `tests/test_settings_bounds.py` (one `BOUNDED` row, module docstring, `TestEveryEnvironmentReadNamesAnInventoriedVariable` counts)

- [ ] **Step 1: Write the failing test**

In `tests/test_settings_bounds.py`:

1a. In the module docstring, replace:

```python
shares, the variable's NAME at the read site. The swept tree names 73
``POSTERN_*`` variables in two disjoint populations: 27 read directly, all of
them strings, and 46 handed to a reader, which are `BOUNDED`'s 39,
```

with:

```python
shares, the variable's NAME at the read site. The swept tree names 74
``POSTERN_*`` variables in two disjoint populations: 27 read directly, all of
them strings, and 47 handed to a reader, which are `BOUNDED`'s 40,
```

1b. In `BOUNDED`, replace:

```python
    # The only row here with a CEILING as well as a floor: 3601 is refused.
    # `services/confirm/settings.py` carries why the ceiling is 3600.
    Bounded(
        "POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS",
        "app_assertion_max_lifetime_seconds",
        "confirm",
        300,
        ("0", "-1", "3601", "86400"),
        ("1", "300", "3600"),
    ),
```

with:

```python
    # One of two rows here with a CEILING as well as a floor: 3601 is refused.
    # `services/confirm/settings.py` carries why the ceiling is 3600.
    Bounded(
        "POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS",
        "app_assertion_max_lifetime_seconds",
        "confirm",
        300,
        ("0", "-1", "3601", "86400"),
        ("1", "300", "3600"),
    ),
    # The other: above zero and at most one second. The ceiling is 1.0 because
    # the budget is added to a successful scan's latency while the customer
    # holds their phone; `services/confirm/settings.py` carries the rest.
    Bounded(
        "POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS",
        "pairing_enricher_timeout_seconds",
        "confirm",
        0.25,
        ("0", "0.0", "-1", "-0.25", "nan", "inf", "1.01", "30"),
        ("0.001", "0.25", "1.0", "1"),
    ),
```

1c. In `TestEveryEnvironmentReadNamesAnInventoriedVariable`'s docstring, replace:

```python
    WHAT THE TREE ACTUALLY HOLDS, counted rather than assumed: 73 distinct
```

with:

```python
    WHAT THE TREE ACTUALLY HOLDS, counted rather than assumed: 74 distinct
```

and replace:

```python
    two comma-separated lists of names. 46 are handed to a reader as its ``name``
    argument, and those are the 39 in `BOUNDED`, the 2 in `STORE_BOUNDED`, the
```

with:

```python
    two comma-separated lists of names. 47 are handed to a reader as its ``name``
    argument, and those are the 40 in `BOUNDED`, the 2 in `STORE_BOUNDED`, the
```

1d. In `test_the_two_inventories_are_the_whole_tree`, replace the docstring line:

```python
        """72 variables, 27 read directly and 45 through a reader, disjoint."""
```

with:

```python
        """74 variables, 27 read directly and 47 through a reader, disjoint."""
```

and replace:

```python
        assert direct | through == set(KNOWN_ENV)
        assert len(KNOWN_ENV) == 73
```

with:

```python
        assert direct | through == set(KNOWN_ENV)
        assert len(KNOWN_ENV) == 74
```

1e. In `test_the_counts_the_docstrings_quote`, replace:

```python
        assert len(KNOWN_ENV) == 73
        assert len(READ_AS_STRING) == 27
        assert len(FLAGS) == 3
        assert len(BOUNDED_NAMES) == 39
```

with:

```python
        assert len(KNOWN_ENV) == 74
        assert len(READ_AS_STRING) == 27
        assert len(FLAGS) == 3
        assert len(BOUNDED_NAMES) == 40
```

and replace:

```python
        assert len(BOUNDED_NAMES | STORE_BOUNDED_NAMES | VAULT_BOUNDED_NAMES | FLAGS) == 46
        assert len(names_read_by("api")) == 38
        assert len(names_read_by("confirm")) == 57
```

with:

```python
        assert len(BOUNDED_NAMES | STORE_BOUNDED_NAMES | VAULT_BOUNDED_NAMES | FLAGS) == 47
        assert len(names_read_by("api")) == 38
        assert len(names_read_by("confirm")) == 58
```

The 72 in 1d was already stale against the 73 its own assertion held; it moves to the true number with the rest.

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_settings_bounds.py -q`
Expected: 8 failed, 360 passed. The six parametrized cases for the new row, with `AttributeError: 'ConfirmSettings' object has no attribute 'pairing_enricher_timeout_seconds'` or a refusal that does not raise, and `test_the_two_inventories_are_the_whole_tree` and `test_the_counts_the_docstrings_quote`.

- [ ] **Step 3: Implement**

3a. In `services/confirm/settings.py`, replace:

```python
#: Re-exported from `postern_core.auth.device_codes`, which is where the
```

with:

```python
#: The most a successful pairing scan may wait for the network enricher.
#:
#: A CEILING, which ``float_from_env`` cannot state, so ``from_env`` refuses a
#: larger value itself through ``_pairing_enricher_timeout``. It exists for
#: two reasons: the budget is added to a successful scan's latency while the
#: customer holds their phone, and it widens the window between a committed
#: claim and its ``audit_log`` row.
MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS = 1.0

_PAIRING_ENRICHER_TIMEOUT_BECAUSE = (
    "It bounds how long a successful pairing scan waits for the network enricher; "
    "at zero no lookup could ever complete."
)


def _pairing_enricher_timeout(value: float) -> float:
    """Refuse an enricher budget above ``MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS``.

    ``float_from_env`` states a floor and no ceiling, so ``from_env`` reads the
    variable through it with ``minimum=0, exclusive=True`` and passes the
    result here for the upper bound, the shape ``_assertion_max_lifetime``
    already has.
    """
    if value > MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS:
        raise ValueError(
            f"POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS must be at most "
            f"{MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS}, got {value}. "
            f"{_PAIRING_ENRICHER_TIMEOUT_BECAUSE}"
        )
    return value


#: Re-exported from `postern_core.auth.device_codes`, which is where the
```

3b. In `ConfirmSettings`, replace:

```python
    trusted_proxy_hops: int = 0
    # The ceiling on how many device codes the store will hold, enforced by
```

with:

```python
    trusted_proxy_hops: int = 0
    # How long, in seconds, a successful ``POST /scan`` waits for the pairing
    # network enricher's two lookups before recording ``"unknown"``. Above 0
    # and at most `MAX_PAIRING_ENRICHER_TIMEOUT_SECONDS`. 250 ms is a choice,
    # not a measurement: no provider ships here to measure.
    pairing_enricher_timeout_seconds: float = 0.25
    # The ceiling on how many device codes the store will hold, enforced by
```

3c. In `ConfirmSettings.from_env`, replace:

```python
            # FLOOR OF ONE. Measured on 2026-09-25: at zero
            # ``InMemoryDeviceCodeStore``'s ``len(self._codes) >=
```

with:

```python
            pairing_enricher_timeout_seconds=_pairing_enricher_timeout(
                float_from_env(
                    "POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS",
                    0.25,
                    minimum=0,
                    exclusive=True,
                    because=_PAIRING_ENRICHER_TIMEOUT_BECAUSE,
                )
            ),
            # FLOOR OF ONE. Measured on 2026-09-25: at zero
            # ``InMemoryDeviceCodeStore``'s ``len(self._codes) >=
```

3d. In `packages/postern-core/src/postern_core/env_inventory.py`, replace:

```python
    EnvVar("POSTERN_CONFIRM_MAX_BODY_BYTES", "number", ("confirm",)),
```

with:

```python
    EnvVar("POSTERN_CONFIRM_MAX_BODY_BYTES", "number", ("confirm",)),
    EnvVar("POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS", "number", ("confirm",)),
```

and in the comment above `INVENTORY` replace:

```python
#: against it by `tests/test_settings_bounds.py` on every run. 73 rows since
#: 2026-09-30: 27 strings (25 settings plus this guard's own two lists), 43
#: numbers, 3 flags. The eight ``POSTERN_VAULT_*`` rows below the device-code
```

with:

```python
#: against it by `tests/test_settings_bounds.py` on every run. 74 rows since
#: 2026-09-30: 27 strings (25 settings plus this guard's own two lists), 44
#: numbers, 3 flags. The eight ``POSTERN_VAULT_*`` rows below the device-code
```

and replace:

```python
#: ``POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS`` arrived later that day.
```

with:

```python
#: ``POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS`` arrived later that day,
#: and ``POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS`` after it.
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_settings_bounds.py tests/test_unknown_env_guard.py tests/test_confirm_app_link_setting.py -q`
Expected: all pass (479 at validation).

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add services/confirm/settings.py packages/postern-core/src/postern_core/env_inventory.py tests/test_settings_bounds.py
git commit -m "feat(confirm): bound the pairing network enricher's time budget" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: The enricher seam, loaded once at composition

Spec section 3, "Discovery" and "A concurrency cap, per process": the entry-point group, the loader and its four refusals, `create_confirm_app`'s keyword with a sentinel default, and the 8-slot semaphore. Nothing uses either until Task 7.

**Files:**
- Create: `packages/postern-core/src/postern_core/modules/enrichers.py` (`ENRICHER_GROUP`, `EnricherSeamViolation`, `load_network_enricher`)
- Modify: `services/confirm/device_auth.py` (`PAIRING_ENRICHMENT_SLOTS`)
- Modify: `services/confirm/main.py` (imports, `_FromEntryPoints`, `create_confirm_app`)
- Test: `tests/test_enricher_seam.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_enricher_seam.py` with:

```python
"""The pairing network enricher seam: what is found, and what refuses to start.

Section 3 of ``dev-docs/pairing-network-signal-spec.md``. The distributions
here are REAL, in the sense ``tests/test_module_seam.py`` means it: a
``.dist-info`` directory with an ``entry_points.txt`` beside a module on a
temporary ``sys.path`` entry, which is what ``importlib.metadata`` reads.
Nothing under ``services/`` and nothing in either ``pyproject.toml`` is
touched to make one register.
"""

from __future__ import annotations

import asyncio
import importlib
import sys
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.modules.enrichers import (
    ENRICHER_GROUP,
    EnricherSeamViolation,
    load_network_enricher,
)
from postern_core.risk.pairing_network import NetworkFacts
from starlette.applications import Starlette

from services.confirm.device_auth import PAIRING_ENRICHMENT_SLOTS
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings

ASYNC_SOURCE = """
    from postern_core.risk.pairing_network import NetworkFacts

    class Enricher:
        async def lookup(self, ip: str) -> NetworkFacts | None:
            return NetworkFacts(asn=64500, country="ES")

    ENRICHER = Enricher()
"""

SYNC_SOURCE = """
    class Enricher:
        def lookup(self, ip):
            return None

    ENRICHER = Enricher()
"""

CLASS_SOURCE = """
    class Enricher:
        async def lookup(self, ip):
            return None

    ENRICHER = Enricher
"""

NO_LOOKUP_SOURCE = """
    ENRICHER = object()
"""

BROKEN_SOURCE = """
    raise ImportError("this provider's data file is missing")
"""


def _write_distribution(root: Path, *, dist_name: str, module_name: str, source: str) -> None:
    """One importable module and the ``.dist-info`` declaring it in ``ENRICHER_GROUP``."""
    (root / f"{module_name}.py").write_text(textwrap.dedent(source))
    info = root / f"{dist_name.replace('-', '_')}-0.0.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {dist_name}\nVersion: 0.0.0\n")
    (info / "entry_points.txt").write_text(
        f"[{ENRICHER_GROUP}]\n{module_name} = {module_name}:ENRICHER\n"
    )


@pytest.fixture
def installed(tmp_path: Path) -> Iterator[Path]:
    """A temporary ``sys.path`` entry, with the metadata caches invalidated on
    both edges for the reason ``tests/test_module_seam.py``'s fixture gives."""
    sys.path.insert(0, str(tmp_path))
    importlib.invalidate_caches()
    try:
        yield tmp_path
    finally:
        sys.path.remove(str(tmp_path))
        importlib.invalidate_caches()
        for name in [n for n in sys.modules if n.startswith("fixture_enricher_")]:
            del sys.modules[name]


def _app(**kwargs: object) -> Starlette:
    key_pair = RSAKeyPair.generate()
    verifier = JWTVerifier(
        public_key=key_pair.public_key, issuer="https://app.test.invalid", audience="x"
    )
    return create_confirm_app(
        ConfirmSettings.for_testing(),
        assertion_verifier=verifier,
        device_key_store=no_enrolled_devices(),
        **kwargs,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# The loader.
# ---------------------------------------------------------------------------


def test_the_shipped_tree_installs_no_enricher() -> None:
    assert load_network_enricher() is None


def test_one_installed_enricher_is_the_one_returned(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )

    enricher = load_network_enricher()

    assert enricher is not None
    assert type(enricher).__name__ == "Enricher"
    assert asyncio.run(enricher.lookup("192.0.2.1")) == NetworkFacts(asn=64500, country="ES")


def test_two_installed_enrichers_refuse_naming_both(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )
    _write_distribution(
        installed, dist_name="geo-two", module_name="fixture_enricher_two", source=ASYNC_SOURCE
    )

    with pytest.raises(EnricherSeamViolation) as refused:
        load_network_enricher()

    assert "fixture_enricher_one" in str(refused.value)
    assert "fixture_enricher_two" in str(refused.value)


def test_an_enricher_that_will_not_import_refuses(installed: Path) -> None:
    _write_distribution(
        installed,
        dist_name="geo-broken",
        module_name="fixture_enricher_broken",
        source=BROKEN_SOURCE,
    )

    with pytest.raises(EnricherSeamViolation, match="could not be imported"):
        load_network_enricher()


def test_a_synchronous_lookup_refuses(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-sync", module_name="fixture_enricher_sync", source=SYNC_SOURCE
    )

    with pytest.raises(EnricherSeamViolation, match="not an async method"):
        load_network_enricher()


def test_an_object_with_no_lookup_refuses(installed: Path) -> None:
    _write_distribution(
        installed,
        dist_name="geo-none",
        module_name="fixture_enricher_none",
        source=NO_LOOKUP_SOURCE,
    )

    with pytest.raises(EnricherSeamViolation, match="not an async method"):
        load_network_enricher()


def test_an_entry_point_naming_a_class_refuses(installed: Path) -> None:
    """The value resolves to an instance, as a module's resolves to its ``MODULE``."""
    _write_distribution(
        installed, dist_name="geo-class", module_name="fixture_enricher_class", source=CLASS_SOURCE
    )

    with pytest.raises(EnricherSeamViolation, match="must resolve to an instance"):
        load_network_enricher()


# ---------------------------------------------------------------------------
# Composition.
# ---------------------------------------------------------------------------


def test_the_app_holds_no_enricher_when_none_is_installed() -> None:
    app = _app()
    assert app.state.pairing_network_enricher is None


def test_the_app_holds_the_installed_enricher(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )
    app = _app()
    assert type(app.state.pairing_network_enricher).__name__ == "Enricher"


def test_an_explicit_none_wins_over_an_installed_enricher(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )
    app = _app(network_enricher=None)
    assert app.state.pairing_network_enricher is None


def test_a_supplied_enricher_is_used_as_given() -> None:
    class Supplied:
        async def lookup(self, ip: str) -> NetworkFacts | None:
            return None

    supplied = Supplied()
    app = _app(network_enricher=supplied)
    assert app.state.pairing_network_enricher is supplied


def test_the_app_holds_one_semaphore_of_eight_slots() -> None:
    app = _app()
    slots = app.state.pairing_network_slots
    assert isinstance(slots, asyncio.Semaphore)
    assert PAIRING_ENRICHMENT_SLOTS == 8
    assert slots._value == 8


@pytest.mark.parametrize(
    ("source", "match"),
    [
        (BROKEN_SOURCE, "could not be imported"),
        (SYNC_SOURCE, "not an async method"),
        (NO_LOOKUP_SOURCE, "not an async method"),
        (CLASS_SOURCE, "must resolve to an instance"),
    ],
    ids=["broken", "sync", "no-lookup", "class"],
)
def test_each_refusal_lands_at_composition(installed: Path, source: str, match: str) -> None:
    _write_distribution(
        installed, dist_name="geo-bad", module_name="fixture_enricher_bad", source=source
    )

    with pytest.raises(EnricherSeamViolation, match=match):
        _app()


def test_two_enrichers_refuse_at_composition(installed: Path) -> None:
    _write_distribution(
        installed, dist_name="geo-one", module_name="fixture_enricher_one", source=ASYNC_SOURCE
    )
    _write_distribution(
        installed, dist_name="geo-two", module_name="fixture_enricher_two", source=ASYNC_SOURCE
    )

    with pytest.raises(EnricherSeamViolation, match="at most one may be"):
        _app()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_enricher_seam.py -q`
Expected: collection error, `ModuleNotFoundError: No module named 'postern_core.modules.enrichers'`.

- [ ] **Step 3: Implement**

3a. Create `packages/postern-core/src/postern_core/modules/enrichers.py` with:

```python
"""How the confirm service finds the one installed pairing network enricher, if any.

An enricher answers "which autonomous system and which country is this
address in" for ``POST /scan``'s creator-versus-scanner comparison
(``postern_core.risk.pairing_network``). None ships here. An operator who
wants one installs a distribution declaring an entry point:

    [project.entry-points."postern.pairing_network_enrichers"]
    geo = "operator_geo:ENRICHER"      # an instance with ``async def lookup``

The value resolves to an INSTANCE, the way a module's entry point resolves to
its ``MODULE`` rather than to a class, and it is found by the mechanism
decision 0018 chose for modules: ``importlib.metadata`` at composition, out
of what the image installs.

WHAT THE LOADER REFUSES, each at composition and never at a request:

- More than one installed. Two providers disagreeing about one address have
  no correct resolution, and choosing by installation order is the failure
  decision 0018 refuses for write routing.
- An entry point that will not import.
- One that resolves to a class, or to an object whose ``lookup`` is not a
  coroutine function. A ``runtime_checkable`` Protocol check is not enough:
  it tests that the attribute exists, not that it is async, and a
  synchronous ``lookup`` would block the event loop every scan runs on.

TRUST. An enricher runs inside ``services/confirm``, which holds the write
signing key, and it is handed every creator and scanner address. This
package's ``__init__`` docstring on what a module can do applies without
softening: installing one is as consequential as merging a commit into this
repository.

THE GROUP NAME IS NOT IN ``postern_core.modules.groups``. That module exists
to keep the write group's name reachable from the read path without the write
half's types, and no such constraint applies to this group.
"""

from __future__ import annotations

import inspect
from importlib.metadata import EntryPoint, entry_points
from typing import cast

from postern_core.risk.pairing_network import NetworkEnricher

__all__ = [
    "ENRICHER_GROUP",
    "EnricherSeamViolation",
    "load_network_enricher",
]

#: Where an operator's distribution declares its enricher. The value resolves
#: to an instance satisfying ``postern_core.risk.pairing_network.NetworkEnricher``.
ENRICHER_GROUP = "postern.pairing_network_enrichers"


class EnricherSeamViolation(RuntimeError):
    """An installed enricher set the confirm service refuses to start with.

    Raised during composition, never during a request: every condition it
    covers is a property of what is installed.
    """


def _named(point: EntryPoint) -> str:
    return f"{point.name!r} = {point.value!r}"


def load_network_enricher() -> NetworkEnricher | None:
    """The one installed enricher, ``None`` when none is, or refuse to start.

    Raises:
        EnricherSeamViolation: for more than one entry point in
            ``ENRICHER_GROUP``, naming every one; for one that will not import;
            and for one that resolves to a class or to an object whose
            ``lookup`` is not a coroutine function.
    """
    points = sorted(entry_points(group=ENRICHER_GROUP), key=lambda p: (p.name, p.value))
    if not points:
        return None
    if len(points) > 1:
        raise EnricherSeamViolation(
            f"{len(points)} pairing network enrichers are installed "
            f"({', '.join(_named(p) for p in points)}); at most one may be. Two "
            "providers disagreeing about one address have no correct resolution, "
            "and choosing by installation order would make the recorded match "
            "depend on how the image was built."
        )
    point = points[0]
    try:
        loaded = point.load()
    except Exception as exc:  # noqa: BLE001 -- re-raised, with the entry point named
        raise EnricherSeamViolation(
            f"pairing network enricher entry point {_named(point)} could not be "
            f"imported: {type(exc).__name__}: {exc}"
        ) from exc
    if isinstance(loaded, type):
        raise EnricherSeamViolation(
            f"pairing network enricher entry point {_named(point)} resolved to the "
            f"class {loaded.__name__}; it must resolve to an instance"
        )
    lookup = getattr(loaded, "lookup", None)
    if lookup is None or not inspect.iscoroutinefunction(lookup):
        raise EnricherSeamViolation(
            f"pairing network enricher entry point {_named(point)} resolved to "
            f"{type(loaded).__name__}, whose lookup is not an async method. A "
            "synchronous lookup would block every request on the replica while "
            "it ran, and the time budget around it could not stop that."
        )
    return cast(NetworkEnricher, loaded)
```

3b. In `services/confirm/device_auth.py`, replace:

```python
logger = logging.getLogger(__name__)

```

with:

```python
logger = logging.getLogger(__name__)

#: How many successful scans per process may be waiting on the pairing network
#: enricher at once. A scan that finds every slot taken does not wait: it
#: records ``"unknown"`` for both matches and logs ``saturated``.
#:
#: A CODE CONSTANT, NOT A SETTING, because the number is a bound and not a
#: tuning knob. It exists for a provider that is slow but cooperative: without
#: it every successful scan during a provider stall parks a task for the whole
#: budget, and the per-address and per-customer scan limits bound each caller,
#: not their sum. With it at most eight scans per replica ever wait, and a
#: provider that ignores cancellation and keeps its slots eventually holds all
#: eight, after which every scan records ``"unknown"`` at once instead of
#: piling on. A healthy local-database provider answers far inside the budget,
#: so eight are exhausted only by eight scans arriving within one lookup's
#: duration. It is no defence against a provider that never yields: that one
#: blocks the loop before the semaphore matters.
PAIRING_ENRICHMENT_SLOTS = 8

```

3c. In `services/confirm/main.py`, replace:

```python
from pathlib import Path

from fastmcp.server.auth.providers.jwt import JWTVerifier
```

with:

```python
import asyncio
import enum
from pathlib import Path

from fastmcp.server.auth.providers.jwt import JWTVerifier
```

replace:

```python
from postern_core.env_inventory import enforce_known_environment
```

with:

```python
from postern_core.env_inventory import enforce_known_environment
from postern_core.modules.enrichers import load_network_enricher
from postern_core.risk.pairing_network import NetworkEnricher
```

replace:

```python
from services.confirm.device_auth import device_auth_routes
```

with:

```python
from services.confirm.device_auth import PAIRING_ENRICHMENT_SLOTS, device_auth_routes
```

replace:

```python
def _assertion_verifier(settings: ConfirmSettings) -> AssertionVerifier:
```

with:

```python
class _FromEntryPoints(enum.Enum):
    """The default of ``create_confirm_app``'s ``network_enricher``.

    A sentinel rather than ``None``, because ``None`` is a meaningful value
    there: "no enricher", which a test passes to build an app that records
    the relation and no match keys whatever is installed.
    """

    LOAD = enum.auto()


def _assertion_verifier(settings: ConfirmSettings) -> AssertionVerifier:
```

replace:

```python
    device_key_store: DeviceKeyStoreBase | None = None,
) -> Starlette:
```

with:

```python
    device_key_store: DeviceKeyStoreBase | None = None,
    network_enricher: NetworkEnricher | None | _FromEntryPoints = _FromEntryPoints.LOAD,
) -> Starlette:
```

replace:

```python
            the guard below.

    Raises:
```

with:

```python
            the guard below.
        network_enricher: Overrides the pairing network enricher loaded from
            the ``postern.pairing_network_enrichers`` entry-point group.
            ``None`` means no enricher, which is not the default: omitted, the
            installed distributions decide. Keyword-only with no environment
            variable behind it, like the two above.

    Raises:
```

replace:

```python
            than by remembering to configure one.
    """
```

with:

```python
            than by remembering to configure one.
        EnricherSeamViolation: if the installed enricher set is refused by
            ``load_network_enricher``: more than one, one that will not
            import, or one whose ``lookup`` is not async.
    """
```

replace:

```python
    # --- Write key / minter (existing path) ---
```

with:

```python
    # THE PAIRING NETWORK ENRICHER, LOADED ONCE AND BEFORE ANY KEY IS BUILT,
    # so a refused installed set lands at composition like every other
    # installed-distribution refusal in this repository, and a process about
    # to refuse does not first generate an RSA key.
    enricher = (
        load_network_enricher() if network_enricher is _FromEntryPoints.LOAD else network_enricher
    )

    # --- Write key / minter (existing path) ---
```

and replace:

```python
    app.state.settings = settings

    return app
```

with:

```python
    app.state.settings = settings
    # Read by `services/confirm/device_auth.py` on a successful ``POST /scan``.
    # The semaphore bounds how many scans per process wait on the enricher at
    # once; that module's ``PAIRING_ENRICHMENT_SLOTS`` carries why eight.
    app.state.pairing_network_enricher = enricher
    app.state.pairing_network_slots = asyncio.Semaphore(PAIRING_ENRICHMENT_SLOTS)

    return app
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_enricher_seam.py tests/test_module_seam.py -q`
Expected: all pass.

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add packages/postern-core/src/postern_core/modules/enrichers.py services/confirm/device_auth.py services/confirm/main.py tests/test_enricher_seam.py
git commit -m "feat(confirm): load at most one pairing network enricher at composition" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `PairingAudit` carries a signal to the success row

Spec section 5, "Writer change": a keyword on `approved` and on `approved_again`, passed to `_write` as `risk_signals`, and the rewritten column comment. No caller passes it until Task 6.

**Files:**
- Modify: `services/confirm/audit.py` (`PairingAudit.approved`, `PairingAudit.approved_again`, `PairingAudit._write`)
- Test: `tests/test_pairing_audit_risk_signals.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_pairing_audit_risk_signals.py` with:

```python
"""``PairingAudit`` carries a serialized signal to the row it is handed to, and only there.

Section 5 of ``dev-docs/pairing-network-signal-spec.md``, at the writer. The
handler that hands it over is ``tests/test_scan_network_signal.py``'s subject;
this file pins that ``approved`` and ``approved_again`` write what they are
given into ``risk_signals``, and that every other row, and every call without
the keyword, keeps the column NULL. Read back out of Postgres, because the
column's type is a property of the database and not of a mock.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry
from sqlalchemy import select, text

from services.confirm.audit import (
    DETAIL_ALREADY_APPROVED,
    DETAIL_ALREADY_SCANNED,
    DETAIL_QR_STALE,
    SCAN_ROUTE,
    SCAN_TOOL_NAME,
    PairingAudit,
)
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)

CUSTOMER = "cust_s1gnal"

SIGNAL: list[dict[str, Any]] = [
    {
        "code": "PAIRING_NETWORK",
        "severity": "LOW",
        "description": "pairing creator and scanner network relation: different",
        "details": {
            "relation": "different",
            "proxy_hops": 2,
            "asn_match": False,
            "country_match": "unknown",
        },
    }
]


async def _wipe(database: Database) -> None:
    async with database.sessionmaker() as session:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(
            session, AuditEntry.customer_ref == CUSTOMER
        )
        await session.commit()


@pytest.fixture()
async def clean(database: Database) -> AsyncIterator[Database]:
    await _wipe(database)
    yield database
    await _wipe(database)


def _audit(database: Database) -> PairingAudit:
    return PairingAudit(
        db=database,
        call_id="00000000-0000-4000-8000-00000000516e",
        at=datetime.now(UTC),
        started=0.0,
        subject=CUSTOMER,
        claims={},
        client_ip_value="198.51.100.7",
        tool_name=SCAN_TOOL_NAME,
        route=SCAN_ROUTE,
    )


async def _only_row(database: Database) -> AuditEntry:
    async with database.sessionmaker() as session:
        result = await session.execute(
            select(AuditEntry).where(AuditEntry.customer_ref == CUSTOMER)
        )
        entries = list(result.scalars().all())
    assert len(entries) == 1, f"expected exactly one row, got {len(entries)}"
    return entries[0]


async def test_approved_writes_the_signal_it_is_handed(clean: Database) -> None:
    await _audit(clean).approved(risk_signals=SIGNAL)

    row = await _only_row(clean)
    assert row.detail is None
    assert row.risk_signals == SIGNAL


async def test_approved_again_writes_the_signal_it_is_handed(clean: Database) -> None:
    await _audit(clean).approved_again(DETAIL_ALREADY_SCANNED, risk_signals=SIGNAL)

    row = await _only_row(clean)
    assert row.detail == DETAIL_ALREADY_SCANNED
    assert row.risk_signals == SIGNAL


async def test_approved_without_the_keyword_keeps_null(clean: Database) -> None:
    await _audit(clean).approved()
    assert (await _only_row(clean)).risk_signals is None


async def test_the_already_approved_repeat_keeps_null(clean: Database) -> None:
    await _audit(clean).approved_again()

    row = await _only_row(clean)
    assert row.detail == DETAIL_ALREADY_APPROVED
    assert row.risk_signals is None


async def test_a_refusal_keeps_null(clean: Database) -> None:
    await _audit(clean).refused(DETAIL_QR_STALE)
    assert (await _only_row(clean)).risk_signals is None


async def test_a_mint_keeps_null(clean: Database) -> None:
    await _audit(clean).minted()
    assert (await _only_row(clean)).risk_signals is None


async def test_the_signal_is_readable_by_the_query_the_spec_promises(clean: Database) -> None:
    """One JSONB predicate answers "completed from somewhere else"."""
    await _audit(clean).approved(risk_signals=SIGNAL)

    async with clean.engine.connect() as conn:
        result = await conn.execute(
            text(
                "SELECT risk_signals->0->'details'->>'relation', "
                "risk_signals->0->'details'->>'asn_match', "
                "risk_signals->0->'details'->>'country_match', "
                "jsonb_exists(risk_signals->0->'details', 'asn_match') "
                "FROM audit_log WHERE customer_ref = :customer"
            ),
            {"customer": CUSTOMER},
        )
        assert result.one() == ("different", "false", "unknown", True)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_pairing_audit_risk_signals.py -q`
Expected: 3 failed, 4 passed. The three that pass a signal fail with `TypeError: PairingAudit.approved() got an unexpected keyword argument 'risk_signals'` (or `approved_again()`); the four NULL cases pass already.

- [ ] **Step 3: Implement**

In `services/confirm/audit.py`, replace:

```python
    async def approved(self) -> None:
        """Record that this pairing was granted."""
        await self._write(OUTCOME_RETURNED, None)

    async def approved_again(self, detail: str = DETAIL_ALREADY_APPROVED) -> None:
        """Record a repeat that is answered with the first request's 200.
```

with:

```python
    async def approved(self, *, risk_signals: list[dict[str, Any]] | None = None) -> None:
        """Record that this pairing was granted.

        ``risk_signals`` is passed by ``POST /scan`` alone, for a first scan:
        the one serialized ``PAIRING_NETWORK`` signal. Every other caller
        leaves it ``None`` and the column NULL.
        """
        await self._write(OUTCOME_RETURNED, None, risk_signals)

    async def approved_again(
        self,
        detail: str = DETAIL_ALREADY_APPROVED,
        *,
        risk_signals: list[dict[str, Any]] | None = None,
    ) -> None:
        """Record a repeat that is answered with the first request's 200.
```

replace:

```python
        literal's comment carries the reasoning.
        """
        await self._write(OUTCOME_RETURNED, detail)
```

with:

```python
        literal's comment carries the reasoning.

        ``risk_signals`` is passed by ``POST /scan`` for the
        ``DETAIL_ALREADY_SCANNED`` repeat, whose row compares the creator with
        that repeat's own address; without it those rows would silently lose
        the signal. The ``DETAIL_ALREADY_APPROVED`` repeat passes none.
        """
        await self._write(OUTCOME_RETURNED, detail, risk_signals)
```

replace:

```python
    async def _write(self, outcome: str, detail: str | None) -> None:
```

with:

```python
    async def _write(
        self,
        outcome: str,
        detail: str | None,
        risk_signals: list[dict[str, Any]] | None = None,
    ) -> None:
```

and replace:

```python
                # NULL, not ``[]``: ``[]`` means a risk session ran and no
                # signal fired. ``RiskEngine`` and ``IpAnomalyDetector`` are
                # wired into ``services/api``'s tool middleware and nothing in
                # this service establishes a session, so NULL is the true
                # statement.
                risk_signals=None,
```

with:

```python
                # NULL on every row but a successful scan, and never ``[]``:
                # ``[]`` means a risk session ran and no signal fired.
                # ``RiskEngine`` and ``IpAnomalyDetector`` are wired into
                # ``services/api``'s tool middleware and nothing in this
                # service establishes a session, so NULL is still the true
                # statement everywhere else. A successful ``POST /scan`` row
                # carries exactly one signal, ``PAIRING_NETWORK``, and no
                # session: the comparison of where the pairing was created
                # with where it was scanned.
                risk_signals=risk_signals,
```

The old text of that last block occurs once: `ApprovalAudit`'s two `risk_signals=None` lines carry different comments and are not touched.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/test_pairing_audit_risk_signals.py tests/test_pairing_audit.py -q`
Expected: all pass.

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add services/confirm/audit.py tests/test_pairing_audit_risk_signals.py
git commit -m "feat(confirm): let a pairing row carry the scan's network signal" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `/scan` records the relation on every successful scan

Spec section 4 steps 2 and 3 without enrichment, section 5's rows, and section 6's two code comments that become false. The enricher Task 4 loads is not consulted yet, and no `await` sits between the claim and the return, so there is nothing yet for a cancellation to interrupt; Task 7 adds both.

**Files:**
- Modify: `services/confirm/device_auth.py` (imports; the `creator_ip` comment in `device_authorization`; `_Scanned.risk_signals`; `scan_callback`; `_scan`; new `_pairing_network_signals`)
- Modify: `packages/postern-core/src/postern_core/auth/device_codes.py` (`DeviceCode` docstring for `creator_ip`)
- Test: `tests/test_scan_network_signal.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_scan_network_signal.py` with:

```python
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
    DETAIL_ISSUANCE_DISABLED,
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
    assert token.status_code == 503

    first_scan, approve_row, approved_mine, token_row = await rows(clean)
    assert first_scan.risk_signals == expected_signal("different")
    assert approve_row.tool_name != SCAN_TOOL_NAME and approve_row.risk_signals is None
    assert approved_mine.detail == DETAIL_ALREADY_APPROVED
    assert approved_mine.risk_signals is None
    assert token_row.detail == DETAIL_ISSUANCE_DISABLED
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_scan_network_signal.py -q`
Expected: 10 failed, 2 passed. Every test that reads `risk_signals` from a success row fails with `assert None == [{'code': 'PAIRING_NETWORK', ...}]`; `test_the_success_body_is_identical_for_every_relation` and `test_the_claim_records_the_scanners_address_on_the_pairing` pass already, the second because Task 2 records the address.

- [ ] **Step 3: Implement**

In `services/confirm/device_auth.py`:

3a. Replace:

```python
from typing import Literal

from postern_core.auth.device_codes import (
```

with:

```python
from typing import Any, Literal

from postern_core.auth.device_codes import (
```

and replace:

```python
from postern_core.identity import CustomerRef
```

with:

```python
from postern_core.identity import CustomerRef
from postern_core.risk.pairing_network import classify, pairing_network_signal
from postern_core.risk.types import signal_to_json
```

3b. In `device_authorization`, replace:

```python
            # RECORDED AND READ BY NOTHING YET. The creator-versus-scanner
            # comparison that would use it is a later spec's; recording it
            # now is what gives that spec something to compare. Under the
            # default of zero trusted hops this is the direct peer, which
            # behind a load balancer is the balancer's address.
```

with:

```python
            # READ BY `POST /scan`, which compares it with the scanner's
            # address and records the relation on the scan's audit row. It
            # lives only on this row, for the pairing's lifetime. Under the
            # default of zero trusted hops this is the direct peer, which
            # behind a load balancer is the balancer's address on both sides
            # of that comparison, so the relation then means nothing.
```

3c. In `_Scanned`, replace:

```python
    #: approving, ``DETAIL_ALREADY_APPROVED`` after. ``None`` on every other exit.
    repeat_detail: str | None = None
```

with:

```python
    #: approving, ``DETAIL_ALREADY_APPROVED`` after. ``None`` on every other exit.
    repeat_detail: str | None = None
    #: The serialized ``PAIRING_NETWORK`` signal for the row, on ``CLAIMED``
    #: and ``ALREADY_MINE`` and on no other exit: ``APPROVED_MINE`` and every
    #: refusal keep ``risk_signals`` NULL.
    risk_signals: list[dict[str, Any]] | None = None
```

3d. In `scan_callback`, replace:

```python
        if outcome.repeat_detail is not None:
            await audit.approved_again(outcome.repeat_detail)
        elif outcome.detail is None:
            await audit.approved()
```

with:

```python
        if outcome.repeat_detail is not None:
            await audit.approved_again(outcome.repeat_detail, risk_signals=outcome.risk_signals)
        elif outcome.detail is None:
            await audit.approved(risk_signals=outcome.risk_signals)
```

3e. In `_scan`, replace:

```python
    if claim is ScanClaim.CLAIMED:
        return _Scanned(_scan_context_response(code), claimed_device_code=code.device_code)
    if claim is ScanClaim.ALREADY_MINE:
        return _Scanned(_scan_context_response(code), repeat_detail=DETAIL_ALREADY_SCANNED)
```

with:

```python
    if claim is ScanClaim.CLAIMED:
        # `code` is the row read before the claim, and that is the right one
        # to read `creator_ip` from: it is written once, at creation.
        signals = await _pairing_network_signals(request, code.creator_ip, scanner_ip)
        return _Scanned(
            _scan_context_response(code),
            claimed_device_code=code.device_code,
            risk_signals=signals,
        )
    if claim is ScanClaim.ALREADY_MINE:
        # THIS request's address, not the stored `scanner_ip`, so the row
        # describes the request it records: the `client_ip` beside it in
        # `arguments` is the address the relation was computed from.
        signals = await _pairing_network_signals(request, code.creator_ip, scanner_ip)
        return _Scanned(
            _scan_context_response(code),
            repeat_detail=DETAIL_ALREADY_SCANNED,
            risk_signals=signals,
        )
```

3f. Replace the route-assembly banner:

```python
# ---------------------------------------------------------------------------
# Route assembly.
# ---------------------------------------------------------------------------
```

with:

```python
async def _pairing_network_signals(
    request: Request, creator_ip: str | None, scanner_ip: str | None
) -> list[dict[str, Any]]:
    """The one-element ``risk_signals`` array a successful scan's row carries.

    Where the pairing was created against where it was scanned
    (``postern_core.risk.pairing_network``). It refuses nothing and changes no
    response: the 200 body is the same for every relation.

    MUST NOT RAISE AN ``Exception``. ``scan_callback``'s exception branch
    records a refusal and withdraws nothing, on the premise that nothing after
    a successful claim can raise; ``classify`` is total, so this keeps it.
    """
    settings: ConfirmSettings = request.app.state.settings
    relation = classify(creator_ip, scanner_ip)
    signal = pairing_network_signal(relation, settings.trusted_proxy_hops)
    return [signal_to_json(signal)]


# ---------------------------------------------------------------------------
# Route assembly.
# ---------------------------------------------------------------------------
```

3g. In `packages/postern-core/src/postern_core/auth/device_codes.py`'s `DeviceCode` docstring, replace:

```python
        creator_ip: The address ``POST /device_authorization`` came from.
            Recorded for the creator-versus-scanner comparison a later spec
            owns; nothing reads it yet.
```

with:

```python
        creator_ip: The address ``POST /device_authorization`` came from.
            Read by ``POST /scan``, which compares it with the scanning
            request's address and records only the relation on its audit
            row. Lives here and nowhere else, so it is gone when the row is.
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_scan_network_signal.py tests/test_scan.py tests/test_pairing_audit.py -q`
Expected: all pass.

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add services/confirm/device_auth.py packages/postern-core/src/postern_core/auth/device_codes.py tests/test_scan_network_signal.py
git commit -m "feat(confirm): record the creator-versus-scanner relation on every successful scan" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Enrichment under a budget and a cap, and withdrawal on cancellation

Spec section 3 "The time budget", "A concurrency cap", "Failure is never a refused scan" and "How many lookups each relation spends", and section 4's cancellation handling, handler nesting and `_withdraw_pairing` branch. The riskiest task: it adds the only `await` between a committed claim and its row.

**Files:**
- Modify: `services/confirm/device_auth.py` (imports; `_withdraw_pairing`; `_scan`'s `CLAIMED` branch; `_pairing_network_signals`; new `_UNKNOWN_MATCHES`, `_enrichment_failed`, `_failure_name`, `_enriched_matches`)
- Test: `tests/test_scan_enrichment.py`

- [ ] **Step 1: Write the failing test**

Create `tests/test_scan_enrichment.py` with:

```python
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

from services.confirm.audit import DETAIL_ALREADY_SCANNED, device_code_handle
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
                scan(app, key_pair, ALICE, code, forwarded_for=PHONE), timeout=0.9
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


async def test_a_request_cancelled_after_the_claim_withdraws_it_and_re_raises(
    pg_url: str, clean: Database, key_pair: RSAKeyPair
) -> None:
    provider = Blocks()
    app = build(pg_url, key_pair, provider, budget=1.0)
    code = await start(app, forwarded_for=LAPTOP)

    request = asyncio.create_task(scan(app, key_pair, ALICE, code, forwarded_for=PHONE))
    await asyncio.wait_for(provider.entered.wait(), timeout=5)
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
    assert "was cancelled before its audit_log row" in withdrawal[0]
    assert "is claimed with no audit_log row" in withdrawal[0]
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
```

- [ ] **Step 2: Run it to verify it fails**

Run: `uv run pytest tests/test_scan_enrichment.py -q`
Expected: 16 failed, 2 passed. Every row assertion fails because the match keys are absent (Task 6 ignores the enricher); the three cancellation tests fail with `TimeoutError` after five seconds each, because nothing calls the provider, so `entered` is never set. `test_the_body_is_the_same_with_and_without_an_enricher` and `test_a_provider_that_raises_leaves_the_pairing_claimed_and_the_row_returned` pass already.

- [ ] **Step 3: Implement**

In `services/confirm/device_auth.py`:

3a. Replace:

```python
from __future__ import annotations

import dataclasses
```

with:

```python
from __future__ import annotations

import asyncio
import dataclasses
```

and replace:

```python
from postern_core.risk.pairing_network import classify, pairing_network_signal
```

with:

```python
from postern_core.risk.pairing_network import (
    MatchResult,
    NetworkEnricher,
    NetworkFacts,
    NetworkRelation,
    classify,
    compare_facts,
    pairing_network_signal,
    sanitised,
)
```

3b. In `_withdraw_pairing`'s signature, replace:

```python
    *,
    cause: Literal["audit", "store"],
    state: Literal["approved", "claimed"],
) -> None:
```

with:

```python
    *,
    cause: Literal["audit", "store", "cancelled"],
    state: Literal["approved", "claimed"],
) -> None:
```

in its docstring replace:

```python
    ``cause`` and ``state`` say which of the four callers this is, because
```

with:

```python
    ``cause`` and ``state`` say which of the five callers this is, because
```

and replace:

```python
    - ``_scan``, ``cause="store"``: ``claim_scan`` raised. The code MAY be
      claimed, and a row recording the store's exception as a refusal will
      follow.
```

with:

```python
    - ``_scan``, ``cause="store"``: ``claim_scan`` raised. The code MAY be
      claimed, and a row recording the store's exception as a refusal will
      follow.
    - ``_scan``, ``cause="cancelled"``: the request was cancelled while the
      pairing network enrichment was awaited after a ``CLAIMED`` result. The
      code IS claimed and NO row names it.
```

and in its body replace:

```python
                revoke_exc,
                exc_info=revoke_exc,
            )
        else:
            logger.error(
                "a device pairing's store write failed ambiguously AND it could not be "
```

with:

```python
                revoke_exc,
                exc_info=revoke_exc,
            )
        elif cause == "cancelled":
            logger.error(
                "a device pairing's scan claim was cancelled before its audit_log row "
                "AND could not be withdrawn; device code %s is %s with no audit_log row "
                "behind it (the request was cancelled): %s",
                device_code_handle(device_code_value),
                state,
                revoke_exc,
                exc_info=revoke_exc,
            )
        else:
            logger.error(
                "a device pairing's store write failed ambiguously AND it could not be "
```

3c. In `_scan`, replace:

```python
    if claim is ScanClaim.CLAIMED:
        # `code` is the row read before the claim, and that is the right one
        # to read `creator_ip` from: it is written once, at creation.
        signals = await _pairing_network_signals(request, code.creator_ip, scanner_ip)
        return _Scanned(
```

with:

```python
    if claim is ScanClaim.CLAIMED:
        # `code` is the row read before the claim, and that is the right one
        # to read `creator_ip` from: it is written once, at creation.
        #
        # A CANCELLATION HERE WITHDRAWS THE CLAIM AND RE-RAISES. A
        # `CancelledError` from a client disconnect or a shutdown, arriving
        # while the enricher is awaited, is not an `Exception`, so
        # `scan_callback`'s branch would not see it and a committed claim
        # would stand with no row at all: the fail-open shape `PairingAudit`
        # rejects. This handler sits OUTSIDE the enrichment step and
        # `asyncio.timeout` sits inside it, so the budget's own cancellation
        # has already become an "unknown" result by the time anything reaches
        # here, and a slow provider never withdraws a legitimate claim.
        # `_withdraw_pairing` swallows its own failure, so what propagates is
        # still the cancellation; a second cancellation during the withdrawal
        # is the residual `_pair` accepts around `approve_scanned`.
        try:
            signals = await _pairing_network_signals(request, code.creator_ip, scanner_ip)
        except BaseException:
            await _withdraw_pairing(store, code.device_code, cause="cancelled", state="claimed")
            raise
        return _Scanned(
```

3d. Replace the whole of Task 6's `_pairing_network_signals`:

```python
async def _pairing_network_signals(
    request: Request, creator_ip: str | None, scanner_ip: str | None
) -> list[dict[str, Any]]:
    """The one-element ``risk_signals`` array a successful scan's row carries.

    Where the pairing was created against where it was scanned
    (``postern_core.risk.pairing_network``). It refuses nothing and changes no
    response: the 200 body is the same for every relation.

    MUST NOT RAISE AN ``Exception``. ``scan_callback``'s exception branch
    records a refusal and withdraws nothing, on the premise that nothing after
    a successful claim can raise; ``classify`` is total, so this keeps it.
    """
    settings: ConfirmSettings = request.app.state.settings
    relation = classify(creator_ip, scanner_ip)
    signal = pairing_network_signal(relation, settings.trusted_proxy_hops)
    return [signal_to_json(signal)]
```

with:

```python
async def _pairing_network_signals(
    request: Request, creator_ip: str | None, scanner_ip: str | None
) -> list[dict[str, Any]]:
    """The one-element ``risk_signals`` array a successful scan's row carries.

    Where the pairing was created against where it was scanned
    (``postern_core.risk.pairing_network``), with the ASN and country matches
    when an enricher is installed and without those keys when none is. It
    refuses nothing and changes no response: the 200 body is the same for
    every relation and every enrichment outcome.

    MUST NOT RAISE AN ``Exception``. ``scan_callback``'s exception branch
    records a refusal and withdraws nothing, on the premise that nothing after
    a successful claim can raise. ``classify`` and ``compare_facts`` are total
    and ``_enriched_matches`` turns every lookup failure into ``"unknown"``,
    which is what keeps that premise true. A ``CancelledError`` from outside
    is not converted: ``_scan`` withdraws the claim for it.
    """
    settings: ConfirmSettings = request.app.state.settings
    relation = classify(creator_ip, scanner_ip)
    enricher: NetworkEnricher | None = request.app.state.pairing_network_enricher
    if enricher is None:
        signal = pairing_network_signal(relation, settings.trusted_proxy_hops)
    else:
        asn_match, country_match = await _enriched_matches(
            enricher,
            request.app.state.pairing_network_slots,
            relation,
            creator_ip,
            scanner_ip,
            budget=settings.pairing_enricher_timeout_seconds,
        )
        signal = pairing_network_signal(
            relation, settings.trusted_proxy_hops, asn_match, country_match
        )
    return [signal_to_json(signal)]


_UNKNOWN_MATCHES: tuple[MatchResult, MatchResult] = ("unknown", "unknown")


def _enrichment_failed(reason: str) -> tuple[MatchResult, MatchResult]:
    """One WARNING, then ``"unknown"`` for both matches.

    ``reason`` is ``timeout``, ``saturated``, ``wrong_type`` or an exception's
    type name, and nothing else: no ``exc_info``, no exception message and no
    traceback, because a provider's message can quote the address it was
    asked about, and never either address.
    """
    logger.warning("pairing network enrichment: %s", reason)
    return _UNKNOWN_MATCHES


def _failure_name(exc: Exception) -> str:
    """The type name to log, looking through the group a ``TaskGroup`` raises."""
    while isinstance(exc, ExceptionGroup) and exc.exceptions:
        exc = exc.exceptions[0]
    return type(exc).__name__


async def _enriched_matches(
    enricher: NetworkEnricher,
    slots: asyncio.Semaphore,
    relation: NetworkRelation,
    creator_ip: str | None,
    scanner_ip: str | None,
    *,
    budget: float,
) -> tuple[MatchResult, MatchResult]:
    """``(asn_match, country_match)`` from the enricher, under the budget and the cap.

    NO LOOKUP FOR ``unknown``: there is no pair to compare. ONE for
    ``same_ip``, for that one address, passed to ``compare_facts`` on both
    sides so a match is ``True`` only for a field the provider returned. TWO
    otherwise, concurrently, inside one ``asyncio.timeout``; a lookup that
    finished while the other did not is discarded, because a comparison needs
    both sides.

    THE CAP DOES NOT WAIT. ``slots.locked()`` and ``async with slots`` have no
    ``await`` between them, so on one event loop the check cannot race, and a
    scan that finds every slot taken records ``"unknown"`` at once.

    WHAT THE BUDGET CANNOT STOP. ``asyncio.timeout`` cancels only at an
    ``await`` that yields. A ``lookup`` that never yields, or calls blocking
    I/O inside ``async def``, holds the loop for every request on the replica
    and the budget fires only after it returns. Nothing in this process can
    prevent that short of a subprocess, which is why the provider contract
    requires async I/O throughout.
    """
    if relation is NetworkRelation.UNKNOWN or creator_ip is None or scanner_ip is None:
        return _UNKNOWN_MATCHES
    if slots.locked():
        return _enrichment_failed("saturated")
    answers: list[object]
    async with slots:
        try:
            async with asyncio.timeout(budget):
                if relation is NetworkRelation.SAME_IP:
                    one = await enricher.lookup(scanner_ip)
                    answers = [one, one]
                else:
                    async with asyncio.TaskGroup() as group:
                        creator_lookup = group.create_task(enricher.lookup(creator_ip))
                        scanner_lookup = group.create_task(enricher.lookup(scanner_ip))
                    answers = [creator_lookup.result(), scanner_lookup.result()]
        except TimeoutError:
            return _enrichment_failed("timeout")
        except Exception as exc:  # noqa: BLE001 -- every provider failure is "unknown"
            return _enrichment_failed(_failure_name(exc))
    facts: list[NetworkFacts | None] = []
    discarded = False
    for answer in answers:
        if answer is None:
            facts.append(None)
            continue
        if not isinstance(answer, NetworkFacts):
            return _enrichment_failed("wrong_type")
        cleaned, dropped = sanitised(answer)
        discarded = discarded or dropped
        facts.append(cleaned)
    if discarded:
        logger.warning("pairing network enrichment: invalid_field")
    return compare_facts(facts[0], facts[1])
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `uv run pytest tests/test_scan_enrichment.py tests/test_scan_network_signal.py tests/test_scan.py tests/test_pairing_audit.py tests/test_device_grant.py tests/test_verify_page.py -q`
Expected: all pass. Run `uv run pytest tests/test_scan_enrichment.py -q` five times as well; it passed 5 of 5 at validation, and a flake here would be in the cancellation tests, which wait on an event and never on a sleep.

- [ ] **Step 5: Format, then run the gate**

Run: `uv run ruff format packages services tests && make ci`
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add services/confirm/device_auth.py tests/test_scan_enrichment.py
git commit -m "feat(confirm): enrich the pairing network signal under a budget, a cap and a withdrawal on cancel" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Operator documentation

Spec section 6: one sentence on `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS`'s row, a row for the new variable, and a section in the confirm service guide with the JSON shape, the entry-point group, the trust statement and the two warnings. The two code comments section 6 names were rewritten in Task 6. Also two lines section 6 does not name and Task 2 makes false: the `claim_scan` signature in the session store guide and the `DeviceCode` listing in the confirm service guide, which lacks `scanner_ip`. No test: nothing in the suite parses these documents.

**Files:**
- Modify: `docs/user-guide/getting-started.md` (the write-path variables table)
- Modify: `docs/user-guide/components/confirm-service.md` (new `### Pairing network signal` section before `### Device Code Model`; one line in the `DeviceCode` listing)
- Modify: `docs/user-guide/components/session-store.md` (the `claim_scan` line of the `DeviceCodeStoreBase` listing)

- [ ] **Step 1: The variables table**

In `docs/user-guide/getting-started.md`, replace the row:

```markdown
| `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` | No | `0` | Proxies in front of this service that append to `X-Forwarded-For`. **Zero or greater**; zero trusts the header for nothing and uses the socket peer |
```

with:

```markdown
| `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` | No | `0` | Proxies in front of this service that append to `X-Forwarded-For`. **Zero or greater**; zero trusts the header for nothing and uses the socket peer. The pairing network signal compares addresses taken through this setting, so under the default both are the load balancer's and the recorded relation means nothing |
| `POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS` | No | `0.25` | How long a successful `/scan` waits for an installed pairing network enricher before recording `"unknown"`. **Above 0 and at most 1.0**; the budget is added to the scan's latency. Unused when no enricher is installed |
```

- [ ] **Step 2: The confirm service guide**

In `docs/user-guide/components/confirm-service.md`, replace:

```markdown
### Device Code Model (`packages/postern-core/src/postern_core/auth/device_codes.py`)
```

with:

````markdown
### Pairing network signal

Every successful `/scan`, the first scan and the same customer's repeat before
approving, records where the pairing was created against where it was scanned.
The creator's address is the one `/device_authorization` recorded on the device
code; the scanner's is the `/scan` request's own, also written on the code by
the claim. Both are taken through `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS`. The
row's `risk_signals` column carries one object, and no address, ASN number or
country code:

```json
[{"code": "PAIRING_NETWORK", "severity": "LOW",
  "description": "pairing creator and scanner network relation: different",
  "details": {"relation": "different", "proxy_hops": 2,
              "asn_match": false, "country_match": true}}]
```

`relation` is `same_ip`, `same_prefix` (one IPv4 /24 or one IPv6 /48),
`different` or `unknown`. `proxy_hops` is the hop count when the row was
written; `0` marks a row that compares a load balancer with itself. The two
match keys are `true`, `false` or `"unknown"`, and are absent when no enricher
is installed. It refuses nothing and changes no response, and `different` is
the normal case for a laptop on home Wi-Fi paired with a phone on mobile data.
Refusal rows and the approver's repeat after approving keep `risk_signals` NULL.

An enricher supplies ASN and country facts. None ships here. A distribution
declares one in the entry-point group `postern.pairing_network_enrichers`,
resolving to an instance with an `async def lookup(self, ip)` that returns
`NetworkFacts(asn, country)` or `None`. The service refuses to start with more
than one installed, or with one whose `lookup` is not async. Lookups share one
time budget (`POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS`) and at most 8
scans per process enrich at once; a timeout, a full cap, an exception or a
malformed answer records `"unknown"` and one WARNING line that names neither
address.

An enricher runs inside the service that holds the write signing key and sees
every creator and scanner address. Installing one is as consequential as
merging a commit into this repository. A provider that calls an HTTP API needs
an egress exception, which ZT-8's default-deny egress exists to refuse, and
sends customers' addresses to a third party. It must read its own configuration
under its own prefix, because the service refuses unknown `POSTERN_` variables.

- **An enricher must do all I/O through async clients.** A `lookup` that never
  yields, or that calls blocking I/O inside `async def`, blocks every request
  on the replica, and the time budget cannot stop it.
- **Over-counting trusted hops is worse than under-counting.** With
  `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` larger than the number of proxies that
  really append to `X-Forwarded-For`, the address is read from an entry the
  caller wrote. In both phishing forms the pairing's creator is the attacker, so
  the attacker then chooses the creator's address and can forge the most
  benign-looking row available: `same_ip` if they have learned the victim's
  address (a tracking image in the lure email is enough), or `same_prefix` for a
  guessed carrier range. Under-counting only makes both addresses the proxy's,
  which `proxy_hops` already marks as noise.

### Device Code Model (`packages/postern-core/src/postern_core/auth/device_codes.py`)
````

- [ ] **Step 3: The `DeviceCode` listing**

In `docs/user-guide/components/confirm-service.md`, replace:

```python
    scanned_at: datetime | None  # When
```

with:

```python
    scanned_at: datetime | None  # When
    scanner_ip: str | None    # Where the claiming /scan came from, set only by the claim
```

- [ ] **Step 4: The `claim_scan` signature in the session store guide**

In `docs/user-guide/components/session-store.md`, replace:

```python
    async def claim_scan(self, device_code: str, customer_ref: str) -> ScanClaim: ...
```

with:

```python
    async def claim_scan(
        self, device_code: str, customer_ref: str, *, scanner_ip: str | None
    ) -> ScanClaim: ...
```

- [ ] **Step 5: Run the gate**

Run: `make ci`
Expected: exit 0. `make citations` scans all three documents; none adds an anchored citation.

- [ ] **Step 6: Commit**

```bash
git add docs/user-guide/getting-started.md docs/user-guide/components/confirm-service.md docs/user-guide/components/session-store.md
git commit -m "docs: document the pairing network signal and its enricher seam" -m "Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Spec coverage

Every section of `dev-docs/pairing-network-signal-spec.md` and every item of its Testing section, and the task that implements or tests it.

| Spec item | Task |
|---|---|
| §1 `DeviceCode.scanner_ip`, serialized like `creator_ip`, absent key reads `None` | 2 |
| §1 `claim_scan(..., *, scanner_ip)` required and nullable on the base and both backends | 2 |
| §1 written on `CLAIMED` only, in the same `dataclasses.replace`; `ALREADY_MINE` and every other result write nothing; `_scan_verdict` unchanged | 2 |
| §1 retention (creator and scanner address on the device-code row only) | 2, 6 (no code copies either address anywhere else) |
| §2 `NetworkRelation`, four values; `classify` total; /24 and /48 via `ip_network(..., strict=False)` | 1 |
| §2 IPv4-mapped unwrapped before any row; NAT64 `64:ff9b::/96` is `unknown` | 1 |
| §2 `NetworkFacts`, `MatchResult`, `compare_facts` with case-insensitive country | 1 |
| §2 `pairing_network_signal`, match keys omitted when `None` | 1 |
| §3 `NetworkEnricher` Protocol, async | 1 |
| §3 discovery by entry point, group `postern.pairing_network_enrichers`, instance not class, loader in `postern_core.modules`, not in `groups.py` | 4 |
| §3 zero installed gives `None`; more than one refuses naming all; import failure refuses; non-coroutine `lookup` refuses | 4 |
| §3 called once in `create_confirm_app`, stored on `app.state`, keyword with a private sentinel default | 4 |
| §3 `pairing_enricher_timeout_seconds`, `float_from_env` with the `because=` sentence, ceiling 1.0 in `from_env`, `env_inventory` row | 3 |
| §3 8-slot semaphore, code constant, `locked()` then `async with` with no `await` between | 4 (created), 7 (used) |
| §3 every failure is `"unknown"`: budget, saturation, any `Exception`, wrong type | 7 |
| §3 field validation: ASN int not bool in range, country two ASCII letters | 1 (`sanitised`), 7 (applied) |
| §3 one WARNING per failure, type name or literal, no `exc_info`, no message, no address | 7 |
| §3 outside cancellation not converted | 7 |
| §3 no lookup for `unknown`, one for `same_ip`, two concurrently otherwise | 7 |
| §3 trust statement, egress and inventory consequences | 8 |
| §4 scanner address computed once and passed to the row and to `_scan` | 2 |
| §4 signal on `CLAIMED` and `ALREADY_MINE` only, from the pre-claim row's `creator_ip` | 6 |
| §4 `signal_to_json` in `postern_core.risk.types`, on `_Scanned`, handed to the writer | 1, 6 |
| §4 `ALREADY_MINE` compares with this request's address | 6 |
| §4 the signal step raises no `Exception` | 6, 7 |
| §4 cancellation after `CLAIMED` withdraws with `cause="cancelled"` and re-raises; handler outside the budget | 7 |
| §4 `_withdraw_pairing` third logging branch and fifth docstring entry | 7 |
| §4 refusals and `APPROVED_MINE` keep `risk_signals` NULL | 6 |
| §5 `risk_signals` column, one-element array, four keys, `severity` `LOW`, fixed description, `proxy_hops` | 1, 6 |
| §5 absent versus `"unknown"`; no addresses, ASNs or countries in the JSON | 1, 7 |
| §5 `PairingAudit.approved` and `approved_again` keyword; other rows NULL; column comment rewritten | 5 |
| §5 success body byte-identical | 6, 7 |
| §6 getting-started sentence and row; confirm-service section with both warnings | 8 |
| §6 the `DeviceCode` docstring and the `device_authorization` comment rewritten | 6 |
| Not in §6, made false by Task 2: the `claim_scan` signature in `session-store.md` and the `DeviceCode` listing in `confirm-service.md` | 8 |
| Testing: classifier table incl. mapped, NAT64, unparsable, totality | 1 |
| Testing: `compare_facts` combinations, case-insensitive | 1 |
| Testing: signal JSON with and without an enricher, no input in the output | 1 |
| Testing: store on both backends, every `ScanClaim` result, `None`, round trip, legacy record, `TypeError` | 2 |
| Testing: loader with fake distributions, five outcomes, composition refusals | 4 |
| Testing: enrichment in `/scan`: raises, sleeps, wrong type, out-of-range ASN, three-letter country, true and false, no lookup for `unknown`, one for `same_ip`, saturation, log lines | 7 |
| Testing: cancellation after `CLAIMED`, after `ALREADY_MINE`, budget expiry leaves the claim, failed revocation wording | 7 |
| Testing: `signal_to_json` against `AuditMiddleware` | 1 |
| Testing: over-counted hops pinned as documented behaviour | 6 (see discrepancy 1) |
| Testing: non-yielding provider is a documented limitation, not a test | 7 (module docstring of `tests/test_scan_enrichment.py`), 8 |
| Testing: `/scan` rows over ASGI with hops and `X-Forwarded-For`, every NULL row, `/approve` and `/token` NULL, identical body | 6 |
| Testing: the §4 premise | 7 |
| Testing: settings default, inventory entry, refusals at 0, negative, `nan`, `inf`, 1.01 | 3 |
| Existing tests that change: every `claim_scan` call and double; `tests/test_settings_bounds.py` | 2, 3 |

## Spec discrepancies found while planning

Each is a point where the spec and the code at `07053c6` disagree, or where the spec leaves a case open. None changes the design; the plan takes the most conservative reading and says so.

1. **The over-counted-hops test cannot produce `same_ip` as the spec words it.** The Testing section asks for "`POSTERN_CONFIRM_TRUSTED_PROXY_HOPS=2` behind one real proxy, a creator request carrying a caller-written `X-Forwarded-For` entry equal to the scanner's address produces a `same_ip` row". The creator half works: the attacker writes the victim's address, the one proxy appends the attacker's, and `packages/postern-core/src/postern_core/net.py::client_ip` reads `parts[-2]`, the forged entry. The scanner half does not: an honest phone reaching the one real proxy directly arrives with one entry, fewer than the two hops trusted, and `client_ip` returns `None` (it logs "fewer than the 2 trusted hops"), so the relation is `unknown`, not `same_ip`. **Plan:** Task 6 pins both. `test_over_counted_hops_let_the_creator_forge_the_most_benign_row` routes the victim's scan through an upstream forward proxy that appends the phone's address, which is the case in which the forgery yields `same_ip`, and says so in its docstring; `test_with_one_real_proxy_the_honest_scanner_reads_as_unknown_under_two_hops` pins the literal setup's actual outcome. Section 6's warning stays true: over-counting still lets the creator choose `creator_ip`.

2. **The in-process client has a peer.** The Testing section says the `/scan` row tests need hops and `X-Forwarded-For` "because the in-process client has no peer and under zero hops both addresses are `None`". `httpx2.ASGITransport` defaults `client` to `('127.0.0.1', 123)` (Verified facts), so under zero hops both addresses are `127.0.0.1` and the relation is `same_ip`. The conclusion survives, the reason does not. **Plan:** every `/scan` test sets hops and the header; `test_under_zero_hops_the_row_says_so` pins the zero-hop row as `same_ip` with `proxy_hops` 0. `services/confirm/audit.py::pairing_client_ip`'s docstring makes the same "no peer" claim; this plan does not touch it (see Concerns).

3. **Two failure outcomes have no log vocabulary.** Section 3 says each failure's WARNING carries "only `type(exc).__name__`, or the literal `timeout` or `saturated`". A wrong-type answer is not an exception, and an out-of-range field is not a whole-lookup failure, yet the Testing section requires "one log line" for each. **Plan:** two more closed literals, `wrong_type` and `invalid_field`, in the same message format (`pairing network enrichment: <reason>`). Neither carries a value from the provider. An `ExceptionGroup` from `asyncio.TaskGroup` is logged as its first leaf's type name, so a provider's `RuntimeError` is logged as `RuntimeError` whichever lookup raised it.

4. **An entry point naming a class is not listed as a refusal.** Section 3 says the value "resolves to an instance" and lists refusals for import failure and a non-coroutine `lookup`. A class whose `lookup` is `async def` passes `inspect.iscoroutinefunction(Class.lookup)`. **Plan:** refuse it explicitly (`must resolve to an instance`), tested at the loader and at composition.

5. **The withdrawal handler catches every `BaseException`, `Exception` included.** Section 4 says the enrichment step "must not raise an `Exception`" and runs "inside a `BaseException` handler that calls `_withdraw_pairing` with `state="claimed"` and a new cause, `"cancelled"`". If an `Exception` ever escaped the step despite the rule, `except BaseException` would withdraw the claim and label it `cancelled`. **Plan:** keep `except BaseException` as written. The alternative, catching only non-`Exception` types, would leave a claim standing behind a refusal row for exactly that bug, which is the fail-open direction; the mislabel only surfaces if the revocation also fails.

6. **Where field validation lives.** Section 2 lists the pure module's contents and section 3 states the validation rules without placing them. **Plan:** `sanitised` in `postern_core.risk.pairing_network` (pure, tested in Task 1), called from `_enriched_matches` in Task 7.

## Validation

Every task above was applied in order to a clone of this repository at `07053c6`, in a scratch directory outside the worktree, and committed there. The code blocks in this plan were taken from those commits; whole files through a script reading `git show <commit>:<path>`, and every replace step was then re-applied mechanically from this document to a second fresh clone and compared with the first (`git diff` empty at every task boundary).

This plan file was not in the scratch tree during those runs. With it added, `tools/check_citations.py` and `ruff check .` both pass on the tree at `07053c6` and on the tree after Task 8.

`make ci` results in the scratch copy, Docker up:

| After task | `make ci` exit | Tests |
|---|---|---|
| 1 | 0 | 3354 passed, 0 failed |
| 2 | 0 | 3376 passed, 0 failed |
| 3 | 0 | 3382 passed, 0 failed |
| 4 | 0 | 3399 passed, 0 failed |
| 5 | 0 | 3406 passed, 0 failed |
| 6 | 0 | 3418 passed, 0 failed |
| 7 | 0 | 3436 passed, 0 failed |
| 8 | 0 | 3436 passed, 0 failed |

The baseline at `07053c6`, before Task 1, was exit 0 with 3260 passed. Every run is the full `make ci`: lint, fmt-check, type, imports, lock, citations, test.

## Concerns for the reviewer

- **Two documents go stale at Task 2 and are fixed only at Task 8.** The `claim_scan` signature in `docs/user-guide/components/session-store.md` and the `DeviceCode` listing in `docs/user-guide/components/confirm-service.md`. Section 6 of the spec does not name them; they were added to Task 8 at the coordinator's request. Nothing checks either document's prose, so every commit in between stays green.
- **`services/confirm/audit.py::pairing_client_ip`'s docstring says an in-process test client has no peer.** It has one (discrepancy 2). Pre-existing and out of scope.
- **The saturation test holds the semaphore directly.** The spec describes eight slots "held by a provider blocked on an event the test controls". Driving eight concurrent scans into a blocked provider needs every one of them to reach the lookup inside the budget, which under `make ci` load is a timing race; `test_a_saturated_cap_records_unknown_without_waiting` acquires the eight slots itself instead, which is the same state with no race, and asserts the provider is never called.
- **Between Task 4 and Task 7 an installed enricher is loaded and ignored.** None ships, so no deployment of an intermediate commit changes behaviour, but a reviewer reading Task 4 alone sees a semaphore nothing acquires.
- **`asyncio.TaskGroup` cancels the sibling lookup when one raises.** That is what makes "a lookup that finished while the other did not is discarded" true for errors as well as for the budget; `asyncio.gather` would leave the sibling running past the scan.
- **A non-yielding provider is untested by design** (the spec's own call), and the budget cannot bound it. The warning Task 8 adds to the confirm service guide is the only control.

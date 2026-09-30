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

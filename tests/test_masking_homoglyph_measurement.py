"""Originally a measurement harness comparing three candidate mitigations of
the homoglyph leak in `_redact_free_text` (masking.py). **Capo has since
decided: approach B (a confusables skeleton) shipped into production --
first as whole-value transliteration, then, after capo's own measurement
found that version corrupting legitimate Greek and Cyrillic text
('ΜΑΡΙΑ ΠΑΠΑΔΟΠΟΥΛΟΥ' -> 'MAPIA ΠAΠAΔOΠOYΛOY'), as a position-preserving
splice.** This file now serves two purposes:

1. Historical record of the measurement that led to that decision -- A and
   C are kept, unchanged in shape, as the rejected alternatives.
2. The regression suite for the shipped fix: the leak-closure corpus below
   must stay fully closed, and the false-positive corpus (widened to seven
   scripts after the Spanish/Catalan-only version was found unable to
   express the failure mode that matters -- see that corpus's own comment)
   must stay at zero.

The leak: `_IBAN_IN_TEXT_RE` / `_PAN_IN_TEXT_RE` are ASCII-only
(`[A-Za-z0-9]`), so a single non-ASCII codepoint inside an otherwise-ASCII
IBAN or PAN splits the token below the scan's own length floor and the
checksum pass never runs. `masking.py` now DOES do something about this --
`_redact_free_text` calls `_delookalike` internally to build a skeleton for
matching, then splices any resulting mask back onto the untransliterated
original (`_sub_preserving_original`) -- so `baseline` below
(`_redact_free_text` with no wrapper at all) is now the shipped, fixed
behaviour, not the historical unfixed one. `approach_b`'s own explicit
pre-transliteration is NOT redundant with shipped code the way it briefly
was when the whole-value version shipped: see `approach_b`'s own docstring
for why it now serves as a regression canary instead. `A` and `C` remain
genuinely independent, self-contained implementations that do NOT touch
masking.py, so they remain meaningful points of comparison against what
shipped.

Run to see the tables (they are printed, not just asserted):

    uv run pytest tests/test_masking_homoglyph_measurement.py -s -q

Vocabulary used throughout the printed tables, chosen deliberately to avoid
the trap the original measurement task was built to avoid -- "a `••••`
appeared" is NOT evidence of masking, only `_IBAN_MASKED_RE` matching the
EXACT expected country code and last four is:

  properly_masked -- output contains the real `XX•• •••• YYYY` shape for
                     THIS case's own true IBAN. The intended outcome, and
                     now what `baseline` (shipped code) must produce for
                     every case in the scored corpus.
  degraded        -- the raw IBAN is NOT recoverable from the output (see
                     `_leaks` below), but not via the proper IBAN mask
                     either -- e.g. a bare `_MASK` marker, or the digit-run
                     PAN scan incidentally eating part of the number. Safe
                     on the leak axis, but not "masked" in the sense the
                     golden test or a human auditor would expect.
  leaked          -- the raw IBAN (or a functionally identical rendering of
                     it, see `_leaks`) is recoverable from the output.

"closed" in the fraction reported for measurement 1 means NOT leaked, i.e.
`properly_masked + degraded`, per the original task's explicit instruction:
assert absence of the raw IBAN, never that a mask appeared.
"""

from __future__ import annotations

import re
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

from postern_core.domain.masking import (
    _HAND_CYRILLIC_LOOKALIKES,
    _HAND_GREEK_LOOKALIKES,
    _HAND_MISC_LOOKALIKES,
    _IBAN_MASKED_RE,
    _LOOKALIKE_TABLE,
    _MASK,
    _build_enclosed_alphanumeric_lookalikes,
    _build_fullwidth_lookalikes,
    _build_math_alphanumeric_lookalikes,
    _delookalike,
    _redact_free_text,
)

# Aliases onto the REAL, shipped tables -- this file used to build its own
# copies of these (three algorithmic builder functions plus two hand
# tables) to keep the measurement's "calls through the real pipeline, never
# a reimplementation" rule honest for approach B specifically. Now that B
# IS the real pipeline, importing masking.py's own tables directly is what
# that same rule requires: a hand-copied duplicate here could silently
# drift from what actually shipped, which is exactly the kind of gap
# `test_baseline_and_shipped_approach_b_now_agree` below exists to make
# impossible.
_FULLWIDTH_TABLE = _build_fullwidth_lookalikes()
_MATH_ALNUM_TABLE = _build_math_alphanumeric_lookalikes()
_ENCLOSED_TABLE = _build_enclosed_alphanumeric_lookalikes()
_HAND_CYRILLIC = _HAND_CYRILLIC_LOOKALIKES
_HAND_GREEK = _HAND_GREEK_LOOKALIKES
_HAND_MISC = _HAND_MISC_LOOKALIKES
_HAND_TABLE: dict[str, str] = {**_HAND_CYRILLIC, **_HAND_GREEK, **_HAND_MISC}
_CONFUSABLES_TABLE: dict[str, str] = _LOOKALIKE_TABLE

# ---------------------------------------------------------------------------
# Ground-truth IBAN fixtures (real ISO 13616 examples, mod-97 verified below)
# ---------------------------------------------------------------------------

NL_IBAN = "NL91ABNA0417164300"  # Wikipedia's own NL/ABN AMRO example
MT_IBAN = "MT92MALT01100ABCDEFGH1234IJKL56"  # already used throughout masking.py's own comments
GB_IBAN = (
    "GB29NWBK60161331926819"  # Wikipedia's own GB/NatWest example -- illustrative only, see below
)

# country(2) + check(2) + bank code(4) = 8-char "identifying prefix" is the
# same width across all three shapes above, which is what makes the GB
# digit-run illustration comparable to the NL/MT scored corpus at all.
_POSITION_CLASSES = {
    "NL": {"country_code": (0, 2), "bank_code": (4, 8), "account_body": (8, len(NL_IBAN))},
    "MT": {"country_code": (0, 2), "bank_code": (4, 8), "account_body": (8, len(MT_IBAN))},
}


def _mod97_ok(compact: str) -> bool:
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def test_fixtures_are_valid_ibans() -> None:
    """The corpus is worthless if the ground truth itself doesn't checksum."""
    assert _mod97_ok(NL_IBAN)
    assert _mod97_ok(MT_IBAN)
    assert _mod97_ok(GB_IBAN)


# ---------------------------------------------------------------------------
# Approach A: NFKC normalisation ahead of the real scan
# ---------------------------------------------------------------------------


def approach_a(value: str) -> str:
    return _redact_free_text(unicodedata.normalize("NFKC", value))


# ---------------------------------------------------------------------------
# Approach B: shipped. `_redact_free_text` now does this internally.
# ---------------------------------------------------------------------------


def approach_b(value: str) -> str:
    """B shipped into `masking.py` itself, TWICE: first as a whole-value
    transliteration (`_redact_free_text` ran `_delookalike` once, up front,
    and scanned/masked the transliterated copy directly), then -- after
    capo's own measurement found that version corrupting legitimate Greek
    and Cyrillic text ('ΜΑΡΙΑ ΠΑΠΑΔΟΠΟΥΛΟΥ' -> 'MAPIA ΠAΠAΔOΠOYΛOY') -- as a
    position-preserving splice (`_sub_preserving_original`), which is what
    ships today. See `_delookalike`'s docstring in masking.py for the full
    account of that reversal, the cost it changed, and the residual gap.

    This wrapper's own explicit pre-transliteration (`_delookalike(value)`,
    BEFORE `_redact_free_text` ever sees the value) is NOT redundant with
    shipped code the way it was when the whole-value version shipped: it
    destroys the very thing the position-preserving splice exists to
    preserve, by transliterating confusable characters OUTSIDE any IBAN/PAN
    match before `_redact_free_text`'s own splice logic ever gets a chance
    to leave them alone. `test_baseline_and_approach_b_agree_on_the_iban_
    only_corpus` below confirms the two still agree on the narrow corpus
    that has no confusable text outside the disguised IBAN itself;
    `test_approach_b_wrapper_reintroduces_whole_value_corruption` confirms,
    just as directly, that they no longer agree in general -- kept
    specifically as a regression canary for "did this module accidentally
    go back to whole-value transliteration", not as a claim that this
    wrapper is safe to use."""
    return _redact_free_text(_delookalike(value))


# ---------------------------------------------------------------------------
# Approach C: mixed-script rule, no mapping -- bare-mask any 14+-char
# alphanumeric token that mixes an ASCII alnum character with a non-ASCII one
# ---------------------------------------------------------------------------

# Same boundary trick `_IBAN_IN_TEXT_RE` uses (an explicit "not a word
# character" test on both sides, not `\b`, which is defined against `\w`
# and would treat an underscore as part of the token) extended to Unicode
# "word" characters via `[^\W_]`, per the task's own suggestion.
_MIXED_SCRIPT_TOKEN_RE = re.compile(r"(?<![^\W_])[^\W_]{14,}(?![^\W_])")


def _is_mixed_script(token: str) -> bool:
    has_ascii_alnum = any(ch.isascii() and ch.isalnum() for ch in token)
    has_nonascii = any(not ch.isascii() for ch in token)
    return has_ascii_alnum and has_nonascii


def _bare_mask_mixed_script_tokens(value: str) -> str:
    return _MIXED_SCRIPT_TOKEN_RE.sub(
        lambda m: _MASK if _is_mixed_script(m.group(0)) else m.group(0), value
    )


def approach_c(value: str) -> str:
    return _redact_free_text(_bare_mask_mixed_script_tokens(value))


def baseline(value: str) -> str:
    """Unmodified main: `_redact_free_text` with no preprocessing."""
    return _redact_free_text(value)


APPROACHES: dict[str, Callable[[str], str]] = {
    "baseline": baseline,
    "A (NFKC)": approach_a,
    "B (confusables)": approach_b,
    "C (mixed-script)": approach_c,
}


def test_confusables_table_excludes_accented_latin_by_construction() -> None:
    """The false-positive corpus below relies on this. If it ever breaks,
    every other number in this file is measuring the wrong thing."""
    accented = "áéíóúñçèòàïüÁÉÍÓÚÑÇÈÒÀÏÜ"
    overlap = [ch for ch in accented if ch in _CONFUSABLES_TABLE]
    assert overlap == [], f"accented Latin leaked into the confusables table: {overlap}"


def test_confirmed_characters_map_to_the_expected_ascii_base() -> None:
    """The ten characters the task confirmed leak on main today, checked
    against both tables that claim to handle any of them."""
    expectations = {
        "А": "A",
        "Е": "E",
        "М": "M",
        "Т": "T",  # Cyrillic
        "Ａ": "A",
        "１": "1",  # fullwidth
        "\U0001d400": "A",
        "\U0001d7ce": "0",  # math bold
        "ı": "i",  # dotless i
        "①": "1",  # circled 1
    }
    for ch, expected in expectations.items():
        assert _CONFUSABLES_TABLE.get(ch) == expected, (
            f"U+{ord(ch):04X} -> {_CONFUSABLES_TABLE.get(ch)!r}"
        )


# ---------------------------------------------------------------------------
# Measurement 1: leak closure
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LeakCase:
    label: str
    text: str
    true_iban: str


def _substitute_first(
    iban: str, start: int, end: int, ascii_char: str, homoglyph: str
) -> str | None:
    segment = iban[start:end]
    idx = segment.find(ascii_char)
    if idx == -1:
        return None
    pos = start + idx
    return iban[:pos] + homoglyph + iban[pos + 1 :]


def _substitute_all(iban: str, ascii_char: str, homoglyph: str) -> str | None:
    if ascii_char not in iban:
        return None
    return iban.replace(ascii_char, homoglyph)


# name, homoglyph, ascii base -- the ten characters the task confirmed leak
# on main today, unchanged from its wording.
_CONFIRMED_CHARS: list[tuple[str, str, str]] = [
    ("cyrillic A", "А", "A"),
    ("cyrillic E", "Е", "E"),
    ("cyrillic M", "М", "M"),
    ("cyrillic T", "Т", "T"),
    ("fullwidth A", "Ａ", "A"),
    ("fullwidth 1", "１", "1"),
    ("math bold A", "\U0001d400", "A"),
    ("math bold 0", "\U0001d7ce", "0"),
    ("dotless i (into an uppercase I)", "ı", "I"),
    ("circled 1", "①", "1"),
]


def _build_single_substitution_corpus() -> list[LeakCase]:
    cases: list[LeakCase] = []
    for iban_label, iban in (("NL", NL_IBAN), ("MT", MT_IBAN)):
        for position_class, (start, end) in _POSITION_CLASSES[iban_label].items():
            for char_name, homoglyph, ascii_base in _CONFIRMED_CHARS:
                # dotless-i's ascii base is upper "I" here (the character
                # that actually appears in MT's account body, "...IJKL56");
                # NL has no "I" at all, so this combination is correctly
                # absent for NL rather than silently skipped.
                substituted = _substitute_first(iban, start, end, ascii_base, homoglyph)
                if substituted is None:
                    continue
                cases.append(
                    LeakCase(
                        label=f"{iban_label}/{position_class}/{char_name}",
                        text=f"Payment reference {substituted} thanks",
                        true_iban=iban,
                    )
                )
    return cases


def _build_multi_substitution_corpus() -> list[LeakCase]:
    cases: list[LeakCase] = []
    # Every occurrence of one confirmed character, same IBAN.
    for iban_label, iban in (("NL", NL_IBAN), ("MT", MT_IBAN)):
        for char_name, homoglyph, ascii_base in _CONFIRMED_CHARS:
            substituted = _substitute_all(iban, ascii_base, homoglyph)
            if substituted is None or substituted == iban:
                continue
            cases.append(
                LeakCase(
                    label=f"{iban_label}/all-occurrences/{char_name}",
                    text=f"Payment reference {substituted} thanks",
                    true_iban=iban,
                )
            )
    # Three different confirmed characters substituted simultaneously in
    # one IBAN (MT has both 'M', 'A' and 'T' more than once).
    mt_multi = MT_IBAN
    mt_multi = mt_multi.replace("M", "М").replace("A", "А").replace("T", "Т")
    cases.append(
        LeakCase(
            label="MT/three-char-types-simultaneously",
            text=f"Payment reference {mt_multi} thanks",
            true_iban=MT_IBAN,
        )
    )
    # Fully non-ASCII: every letter AND every digit replaced, so the token
    # contains not one remaining ASCII alphanumeric character. Constructed
    # rather than found in NL/MT because neither has letters outside
    # {A,B,E,H,K,M,O,P,C,T,X,Y,J,S} (the set with a clean Cyrillic capital
    # look-alike) -- 'N' and 'L' do not have one in this table, so NL/MT
    # cannot be substituted to 100% non-ASCII without inventing a mapping
    # this table deliberately does not contain. AT (Austria, n16, digits
    # only after the two letters) can be, and both its letters are in the
    # set. Its own check digits are computed directly, not guessed:
    # AT741234500000012345 mod-97 verified in test_fixtures_are_valid_ibans
    # by proxy (mod-97 is the same function for every ISO 13616 country).
    fully_non_ascii_iban = "AT741234500000012345"
    assert _mod97_ok(fully_non_ascii_iban)
    digit_to_fullwidth = str.maketrans("0123456789", "０１２３４５６７８９")
    fully_non_ascii = (
        fully_non_ascii_iban.replace("A", "А").replace("T", "Т").translate(digit_to_fullwidth)
    )
    assert fully_non_ascii.isascii() is False
    assert not any(ch.isascii() for ch in fully_non_ascii)
    cases.append(
        LeakCase(
            label="AT/fully-non-ascii (zero remaining ASCII alnum chars)",
            text=f"Payment reference {fully_non_ascii} thanks",
            true_iban=fully_non_ascii_iban,
        )
    )
    # Lowercase Cyrillic glued into an otherwise-uppercase IBAN -- the hand
    # table's own stated limitation (uppercase-only), exercised directly.
    # MT_IBAN's account body is all-uppercase, so substituting the ASCII
    # target has to happen manually rather than via `_substitute_first`
    # (which would look for a lowercase "a" and find nothing).
    account_body = MT_IBAN[8:]
    if "A" in account_body:
        idx = account_body.find("A")
        lowered = MT_IBAN[: 8 + idx] + "а" + MT_IBAN[8 + idx + 1 :]
        cases.append(
            LeakCase(
                label="MT/account_body/lowercase cyrillic а (hand table is uppercase-only)",
                text=f"Payment reference {lowered} thanks",
                true_iban=MT_IBAN,
            )
        )
    return cases


def _compact(iban: str) -> str:
    return iban.replace(" ", "").upper()


# This USED to be its own table, deliberately BROADER than approach B's own
# (which was uppercase-Cyrillic/Greek-only): a checker sharing the exact
# table of the thing it checks can hide a leak the same way the leak itself
# hides from an ASCII-chunk comparison, and that is exactly what happened
# here before it was fixed -- a lowercase Cyrillic а substituted into
# MT_IBAN's account body reached baseline's output completely unchanged (a
# full, unambiguous leak), and `_visual_canon` still called it merely
# "degraded" because it shared approach B's own uppercase-only blind spot.
# `_LOOKALIKE_TABLE` now includes both cases (that gap is what this file's
# extension closed -- see `_HAND_CYRILLIC_LOOKALIKES`'s docstring in
# masking.py), so reusing the real, shipped table here is no longer
# narrower than what it is checking; `_CONFUSABLES_TABLE` (imported at the
# top of this file) IS `_LOOKALIKE_TABLE`.
_STRICT_CANON_TRANS = str.maketrans(_CONFUSABLES_TABLE)


def _visual_canon(s: str) -> str:
    """The strongest canonicalisation this file has available, applied only
    to OUTPUT for leak detection -- never used by any of the three
    approaches themselves. Union of NFKC and the shipped lookalike table, so
    a check built on this cannot be fooled by exactly the trap the original
    task warned about: comparing ASCII chunks of the original against
    output that still contains the substituted character, letting the
    substitution hide the leak from the checker the same way it caused the
    leak in the first place."""
    if s.isascii():
        canon = s
    else:
        canon = s.translate(_STRICT_CANON_TRANS)
    return unicodedata.normalize("NFKC", canon).upper()


def _classify(output: str, true_iban: str) -> str:
    compact = _compact(true_iban)
    canon_output = _visual_canon(output)
    expected_mask = f"{compact[:2]}•• •••• {compact[-4:]}"
    if expected_mask in output:
        return "properly_masked"
    if compact in canon_output:
        return "leaked"
    return "degraded"


def test_leak_closure() -> None:
    single = _build_single_substitution_corpus()
    multi = _build_multi_substitution_corpus()
    corpus = single + multi
    assert len(corpus) >= 20, "corpus too small to be a meaningful measurement"

    results: dict[str, dict[str, int]] = {
        name: {"properly_masked": 0, "degraded": 0, "leaked": 0} for name in APPROACHES
    }
    per_case: dict[str, dict[str, str]] = {}

    for case in corpus:
        per_case[case.label] = {}
        for name, fn in APPROACHES.items():
            output = fn(case.text)
            outcome = _classify(output, case.true_iban)
            results[name][outcome] += 1
            per_case[case.label][name] = outcome

    print(f"\n=== Measurement 1: leak closure ({len(corpus)} cases, NL/MT shapes) ===")
    header = (
        f"{'approach':<20}{'properly_masked':>16}{'degraded':>10}{'leaked':>8}{'closed_frac':>13}"
    )
    print(header)
    for name in APPROACHES:
        r = results[name]
        total = sum(r.values())
        closed = r["properly_masked"] + r["degraded"]
        print(
            f"{name:<20}{r['properly_masked']:>16}{r['degraded']:>10}{r['leaked']:>8}"
            f"{closed / total:>13.1%}"
        )

    print("\n--- per-case detail ---")
    print(f"{'case':<70}{'baseline':<12}{'A':<12}{'B':<12}{'C':<12}")
    for label, outcomes in per_case.items():
        print(
            f"{label:<70}{outcomes['baseline']:<12}{outcomes['A (NFKC)']:<12}"
            f"{outcomes['B (confusables)']:<12}{outcomes['C (mixed-script)']:<12}"
        )

    # THE regression gate: B has shipped, so `baseline` (unmodified
    # `_redact_free_text`, no wrapper) must now produce the actual correct
    # `XX•• •••• YYYY` mask for EVERY case in this corpus, including --
    # explicitly, by name -- the lowercase-Cyrillic case that was still
    # `leaked` on shipped code before this file's hand table grew a
    # lowercase half. This inverts the pre-fix self-check on purpose: before
    # B shipped, this test asserted baseline was NEVER `properly_masked`
    # (that was the leak); now it asserts baseline is ALWAYS `properly_masked`
    # (that is the fix). If this ever regresses, the leak this module was
    # built to close is open again.
    baseline_not_properly_masked = [
        label for label, outcomes in per_case.items() if outcomes["baseline"] != "properly_masked"
    ]
    assert baseline_not_properly_masked == [], (
        f"shipped code failed to properly mask: {baseline_not_properly_masked}"
    )

    lowercase_label = next(label for label in per_case if "lowercase cyrillic" in label)
    assert per_case[lowercase_label]["baseline"] == "properly_masked", (
        "the lowercase-Cyrillic gap this table's lowercase extension was "
        "supposed to close is still open on shipped code"
    )


def test_baseline_and_approach_b_agree_on_the_iban_only_corpus() -> None:
    """The scored 40-case corpus has no confusable character anywhere
    outside the disguised IBAN itself (every case is "Payment reference
    {iban} thanks"), so `approach_b`'s own whole-value pre-transliteration
    has nothing to corrupt: it turns the disguised IBAN into a clean ASCII
    one before `_redact_free_text` ever runs, `_redact_free_text` then finds
    and masks that same IBAN via its own splice, and the two land on
    identical output. NOT a general claim -- see `approach_b`'s own
    docstring and `test_approach_b_wrapper_reintroduces_whole_value_
    corruption` immediately below for why this does not extend past this
    specific corpus shape."""
    corpus = _build_single_substitution_corpus() + _build_multi_substitution_corpus()
    mismatches = [case.label for case in corpus if baseline(case.text) != approach_b(case.text)]
    assert mismatches == [], f"baseline and approach_b diverged on: {mismatches}"


def test_approach_b_wrapper_reintroduces_whole_value_corruption() -> None:
    """The regression canary `approach_b`'s docstring promises: text with a
    confusable character OUTSIDE any IBAN/PAN match is exactly where
    `approach_b`'s own pre-transliteration and shipped `baseline` diverge.
    `baseline` (position-preserving, shipped) must leave it untouched;
    `approach_b` (whole-value pre-transliteration, the wrapper only) must
    NOT -- if this assertion ever starts failing because `approach_b` stops
    corrupting it, check whether shipped `_redact_free_text` quietly went
    back to whole-value transliteration, because that would make this
    canary fire for the wrong reason.
    """
    text = "ΜΑΡΙΑ ΠΑΠΑΔΟΠΟΥΛΟΥ"
    assert baseline(text) == text, "shipped code must preserve legitimate Greek text untouched"
    assert approach_b(text) != text, (
        "approach_b's own whole-value pre-transliteration was expected to "
        "corrupt this -- if it no longer does, re-check what changed"
    )


def test_gb_digit_run_trap_illustration() -> None:
    """Illustrative only -- NOT part of the scored NL/MT corpus above, and
    deliberately excluded from its "fraction closed" arithmetic. Demonstrates
    trap #2 from the original task: a single-character substitution in a GB
    IBAN whose longest digit run (14) already qualifies for
    `_PAN_IN_TEXT_RE`'s incidental `\\d{12,}` match, so baseline's OWN
    output can contain a `••••` from the unrelated PAN scan, not from any
    IBAN-aware masking, while identifying information stays legible.

    The substituted character here is Cyrillic Н (U+041D), which is a
    look-alike for Latin "H", not "N" -- so this specific case does not
    represent a genuine disguised GB IBAN even after `_delookalike` runs
    (it delookalikes to "GB29HWBK...", which does not checksum against the
    real "GB29NWBK..." at all, since the bank code was never actually
    preserved). Kept exactly as originally measured, illustrating the trap
    on a corrupted-but-still-not-properly-masked string; a SECOND case
    below substitutes a genuine look-alike (Cyrillic В for Latin B, which
    this table does cover) to confirm the shipped fix also closes this
    shape when the disguise is a real one.
    """
    # cyrillic Н looks like "H", not "N": not a genuine disguise
    corrupted = GB_IBAN[:4] + "Н" + GB_IBAN[5:]
    text = f"Payment reference {corrupted} thanks"
    print("\n=== GB digit-run trap illustration (not scored) ===")
    for name, fn in APPROACHES.items():
        output = fn(text)
        outcome = _classify(output, GB_IBAN)
        print(f"{name:<20}{outcome:<16}{output!r}")
    baseline_output = baseline(text)
    assert "••••" in baseline_output, "expected the incidental PAN-scan bullet on baseline"
    assert not _IBAN_MASKED_RE.search(baseline_output), (
        "baseline must NOT have produced a proper IBAN mask here"
    )
    assert _classify(baseline_output, GB_IBAN) != "properly_masked"

    # A genuine disguise of the same GB IBAN, using a covered look-alike:
    # Cyrillic В (U+0412) for Latin "B", the third letter of "NWBK".
    disguised = GB_IBAN[:6] + "В" + GB_IBAN[7:]
    disguised_text = f"Payment reference {disguised} thanks"
    disguised_output = baseline(disguised_text)
    print(f"genuine disguise    properly_masked {disguised_output!r}")
    assert _classify(disguised_output, GB_IBAN) == "properly_masked", (
        "a genuinely disguised GB IBAN (covered look-alike) must be properly "
        f"masked by shipped code: {disguised_output!r}"
    )


# ---------------------------------------------------------------------------
# Measurement 2: false positives on legitimate Spanish/Catalan text
# ---------------------------------------------------------------------------

# Widened after a real gap was found in review: a corpus of Spanish and
# Catalan text alone is structurally incapable of showing the failure mode
# that matters here, for the same reason an ES/GB-only IBAN corpus could not
# show the digit-run trap earlier in this file's own history -- Spanish and
# Catalan are Latin script with diacritics and are NEVER mixed-script, so
# any rule built around "non-ASCII is suspicious" scores near-zero on it BY
# CONSTRUCTION, regardless of whether that rule is actually safe. A corpus
# that cannot express the failure mode returns a clean number, and the
# clean number is worthless. Below is the original 53-entry Spanish/Catalan
# corpus, unchanged (it is real coverage for this deployment's home
# market and the diacritic path specifically), PLUS six more scripts this
# deployment's `FreeText` fields genuinely see traffic in -- SEPA remittance
# information and counterparty names are not confined to Spain -- chosen
# specifically to stress what the confusables table treats as hostile:
#
#   Greek     -- Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ are the exact codepoints
#                _HAND_GREEK_LOOKALIKES maps to a Latin letter; a Greek
#                name or merchant descriptor is made almost entirely of them.
#   Bulgarian -- standard Cyrillic, wall-to-wall confusables
#                (_HAND_CYRILLIC_LOOKALIKES) while being single-script, not
#                mixed-script.
#   Serbian   -- a DIFFERENT Cyrillic alphabet from Bulgarian's, including
#                Ј (U+0408), which this table maps to Latin "J" -- Serbian
#                names routinely contain it (Јован, Ђорђе).
#   Turkish   -- dotless ı (U+0131) is simultaneously the tenth confirmed
#                attack character in this table AND a mandatory letter of
#                the Turkish alphabet ("Işık", "Yıldırım", "Kadıköy"). If
#                any rule in this codebase ever treated that codepoint as
#                inherently hostile rather than "hostile only inside a span
#                that actually checksums", this corpus is what would show it.
#   CJK       -- no space-delimited tokens the way every script above has;
#                exercises a script `_LOOKALIKE_TABLE` does not cover at all.
#   Arabic    -- right-to-left text direction, contextual letter forms, a
#                script `_LOOKALIKE_TABLE` does not cover at all. Letters
#                and prose only, deliberately -- an Arabic-Indic PAN
#                (`٤٤١٧...`) already masks via `_PAN_IN_TEXT_RE`'s
#                Unicode-aware `\d` for a reason that has nothing to do with
#                this table (see that pattern's own comment in masking.py),
#                so digit-shaped Arabic text would not test what this
#                corpus exists to test.
#
# Reported PER-SCRIPT below, not as one aggregate: an aggregate is exactly
# the kind of number that would hide false-positive cost landing unevenly
# across scripts, which is its own question this file states but does not
# resolve (see `test_false_positives_on_legitimate_text`'s own comment).
SPANISH_CATALAN_CORPUS: list[str] = [
    "CAFÈ DE L'ÒPERA BCN",
    "FARMÀCIA GÜELL",
    "JOSÉ MUÑOZ SÁNCHEZ",
    "MERCADONA S.A. SABADELL",
    "L'ILLA DIAGONAL",
    "BAR RESTAURANT CA LA MARIA",
    "PANADERIA MUÑOZ TORRELLES",
    "FARMÀCIA LLOBET I FILLS S.L.",
    "CARNISSERIA CAN JOAN VIC",
    "SUPERMERCAT BONPREU ESPLUGUES",
    "PEIXATERIA COSTA BRAVA BADALONA",
    "RESTAURANT EL RACÓ DEL GÒTIC",
    "PERRUQUERIA MONTSERRAT PLA",
    "TALLER MECÀNIC GIRONÈS",
    "ÒPTICA UNIVERSITÀRIA GRÀCIA",
    "LLIBRERIA ÀBAC BARCELONA",
    "FORN DE PA SANT JORDI",
    "CLÍNICA DENTAL SOMRIURE",
    "GELATERIA ITALIANA CIUTADELLA",
    "BUGADERIA SELF SERVICE POBLENOU",
    "ADVOCATS ASSOCIATS BALCELLS I MUÑOZ",
    "ASSEGURANCES CATALUNYA S.A.",
    "IMMOBILIÀRIA SAGRADA FAMÍLIA",
    "TAXI RÀPID AEROPORT EL PRAT",
    "FLORISTERIA JARDÍ D'HIVERN",
    "JOIERIA RELLOTGERIA MONTBLANC",
    "PASTISSERIA ESCRIBÀ RAMBLA",
    "FERRETERIA CAN MASSÓ",
    "BODEGA VINÍCOLA PENEDÈS",
    "AUTOESCOLA CONDUEIX-TE BÉ",
    "GIMNÀS METROPOLITAN DIAGONAL",
    "VETERINÀRIA POTES CONTENTES",
    "COPISTERIA UNIVERSITAT AUTÒNOMA",
    "MUSEU PICASSO ENTRADES",
    "FUNDACIÓ JOAN MIRÓ DONATIU",
    "BIBLIOTECA MUNICIPAL SANT CUGAT",
    "CENTRE CÍVIC SANTS-MONTJUÏC",
    "ESCOLA BRESSOL ELS PATUFETS",
    "RESIDÈNCIA AVIS L'ONADA",
    "NOTARIA GONZÁLEZ-PEÑA",
    "GESTORIA ADMINISTRATIVA MUÑOZ",
    "CAIXA D'ESTALVIS PENEDÈS",
    "SUPERMERCADOS DÍA SABADELL",
    "ÒPERA DEL LICEU ABONAMENT",
    "PISCINES MUNICIPALS MONTJUÏC",
    # order codes / IBAN-adjacent references, accented text glued to a code
    "REF FRA2024-00219438 MUÑOZ",
    "TRANSFERENCIA NOMINA JOSÉ MUÑOZ SÁNCHEZ FEBRERO",
    "ORDRE COMPRA OC-2024-0891 FARMÀCIA GÜELL",
    "DEVOLUCIÓ COMANDA ÒPERA Nº445210",
    "PAGAMENT REBUT LLOGUER GRÀCIA ABRIL2024",
    # deliberately long single tokens (14+ chars, one accent, rest ASCII
    # alnum) -- the shape most likely to trip approach C's mixed-script
    # rule, since it alone doesn't require a CONFUSABLE, just "not ASCII"
    "URBANITZACIÓ1234567890",
    "CONDOMINIREF00219438À",
    "REFERÈNCIA20240912BCN",
    # Ordinal indicators and superscripts glued into a long alphanumeric
    # run. Added after review found a REGRESSION these would have caught
    # and the corpus did not: U+00BA and U+00AA are Script=Latin, live in
    # Latin-1 Supplement, and are `isalnum()`, but their Unicode NAMES are
    # "MASCULINE/FEMININE ORDINAL INDICATOR" with no "LATIN" in them, so
    # the first version of `_is_script_intrusion` bridged across them and
    # masked all three of these. "DEVOLUCIÓ COMANDA ÒPERA Nº445210" above
    # passed throughout, but only because "Nº445210" has seven ASCII
    # alphanumerics against a floor of fourteen -- it passed for the wrong
    # reason, which is why these three are long enough to clear the floors.
    "FACTURANº20240912",
    "1ªPLANTAEDIFICI2026",
]
# "superficie120m²parcela4455" is deliberately NOT in the corpus above: it
# is ALREADY COVERED twice over, so adding it would buy nothing. The
# regression it demonstrates is pinned in this corpus by the two "Nº"/"1ª"
# entries, and U+00B2 itself is pinned by
# `test_the_exemption_set_covers_the_characters_review_named` in
# tests/test_masking_confusables.py, which also carries the string as a
# fixture. Keeping it out additionally avoids having to widen the
# NFKC-casualty filter in `test_false_positives_on_legitimate_text` (which
# exempts ordinal indicators) to admit superscripts -- but that is a
# convenience, not the reason: that filter is an enumeration of a rejected
# approach's known casualties, so widening it would not have weakened it.

# Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ -- every one of these is a key in
# _HAND_GREEK_LOOKALIKES. Realistic merchant descriptors, payee names and
# bank/branch references, not cherry-picked to dodge those letters.
GREEK_CORPUS: list[str] = [
    "ΤΑΒΕΡΝΑ ΑΘΗΝΑ",
    "ΚΑΦΕ ΜΠΑΡ ΒΟΛΟΣ",
    "ΙΩΑΝΝΗΣ ΠΑΠΑΔΟΠΟΥΛΟΣ",
    "ΤΡΑΠΕΖΑ ΠΕΙΡΑΙΩΣ ΘΕΣΣΑΛΟΝΙΚΗ",
    "ΟΠΤΙΚΑ ΑΘΗΝΩΝ ΚΕΝΤΡΟ",
    "ΦΑΡΜΑΚΕΙΟ ΝΙΚΗ ΠΑΤΡΑ",
    "ΕΣΤΙΑΤΟΡΙΟ ΜΥΚΟΝΟΣ",
    "ΞΕΝΟΔΟΧΕΙΟ ΚΡΗΤΗ ΗΡΑΚΛΕΙΟ",
    "ΕΛΕΝΗ ΚΩΝΣΤΑΝΤΙΝΟΥ",
    "ΖΑΧΑΡΟΠΛΑΣΤΕΙΟ ΑΘΗΝΑ",
]

# Standard (Bulgarian) Cyrillic -- single-script, zero Latin characters,
# wall-to-wall confusables (_HAND_CYRILLIC_LOOKALIKES covers roughly half of
# any given word here) while being ordinary legitimate text throughout.
BULGARIAN_CYRILLIC_CORPUS: list[str] = [
    "ИВАН ПЕТРОВ",
    "СОФИЯ БЪЛГАРИЯ",
    "ПЛОВДИВ ЦЕНТЪР",
    "МАГАЗИН ЕВРОПА",
    "ХРИСТО СТОЯНОВ",
    "РЕСТОРАНТ ВАРНА",
    "АПТЕКА ЗДРАВЕ БУРГАС",
    "ВЕЛИКО ТЪРНОВО ПАЗАР",
]

# Serbian Cyrillic -- a DIFFERENT alphabet from Bulgarian's, not the same
# text relabelled: Ј, Ђ, Ћ are Serbian-specific letters absent from Russian
# and Bulgarian orthography. Ј (U+0408) is itself a _HAND_CYRILLIC_
# LOOKALIKES key (-> Latin "J"), so this script hits the table from a
# second, distinct direction from Bulgarian.
SERBIAN_CYRILLIC_CORPUS: list[str] = [
    "БЕОГРАД ЦЕНТАР",
    "НОВИ САД ПИЈАЦА",
    "ЈОВАН ЈОВАНОВИЋ",
    "ПЕКАРА ДУШАН",
    "ЂОРЂЕ ПЕТРОВИЋ",
    "НИШ РЕСТОРАН",
    "МИЛОШ ЈОВИЋ",
    "КРАГУЈЕВАЦ ПИЈАЦА",
]

# Turkish -- dotless ı (U+0131) is simultaneously this table's tenth
# confirmed attack character and a mandatory letter of the Turkish
# alphabet. Genuine dotless ı survives into a word only outside an
# ALL-CAPS, word-initial position: Turkish uppercases dotless ı to plain
# ASCII "I" (and dotted i to İ, U+0130, a different letter entirely), so
# "IŞIK" in full caps contains no dotless ı at all, while "Işık" in Title
# Case does (its THIRD character). Both shapes are included below,
# deliberately, because both are realistic (merchant descriptors skew
# ALL-CAPS, personal payee names skew Title Case) and they behave
# differently at the codepoint level for the exact reason this table cares
# about.
TURKISH_CORPUS: list[str] = [
    "Ayşe Işık",
    "Mehmet Yıldırım",
    "Kadıköy Çarşısı İstanbul",
    "Çınar Eczanesi Ankara",
    "IŞIKLAR MARKET ANKARA",  # ALL-CAPS: no genuine dotless ı survives here
    "Fatma Çelik Bursa",
    "Kırşehir Un Fabrikası",
    "Diyarbakır Pazarı",
]

# No script here shares a single codepoint with _LOOKALIKE_TABLE -- included
# to cover a script class the table does not touch at all, not to stress
# any specific mapping. No spaces the way every script above has some.
CJK_CORPUS: list[str] = [
    "北京烤鸭店",
    "上海贸易有限公司",
    "東京レストラン",
    "深圳科技公司",
    "大阪商店街",
    "广州茶餐厅",
]

# Arabic -- right-to-left text direction and contextual letter forms (a
# given Arabic letter changes glyph shape depending on its position in a
# word), another script _LOOKALIKE_TABLE does not cover. Letters and prose
# only, deliberately no digits: an Arabic-Indic PAN already masks via
# `_PAN_IN_TEXT_RE`'s own Unicode-aware `\d` (see that pattern's comment in
# masking.py) for a reason that has nothing to do with this table, so a
# digit-shaped entry here would not test what this corpus exists to test.
ARABIC_CORPUS: list[str] = [
    "مطعم دمشق",
    "صيدلية النور",
    "محمد أحمد الشامي",
    "شركة الأمل للتجارة",
    "سوق الحميدية دمشق",
    "مقهى القاهرة",
    "بنك القاهرة فرع الزمالك",
    "مكتبة الفرقان",
]

FALSE_POSITIVE_CORPUS_BY_SCRIPT: dict[str, list[str]] = {
    "Spanish/Catalan": SPANISH_CATALAN_CORPUS,
    "Greek": GREEK_CORPUS,
    "Bulgarian Cyrillic": BULGARIAN_CYRILLIC_CORPUS,
    "Serbian Cyrillic": SERBIAN_CYRILLIC_CORPUS,
    "Turkish": TURKISH_CORPUS,
    "CJK": CJK_CORPUS,
    "Arabic": ARABIC_CORPUS,
}
FALSE_POSITIVE_CORPUS: list[str] = [
    text for corpus in FALSE_POSITIVE_CORPUS_BY_SCRIPT.values() for text in corpus
]


def test_false_positive_corpus_has_at_least_40_entries() -> None:
    assert len(FALSE_POSITIVE_CORPUS) >= 40


def test_false_positive_corpus_covers_at_least_seven_scripts() -> None:
    """The 40+ entry count alone would still pass on a Spanish/Catalan-only
    corpus -- this is the assertion that actually guards against
    re-narrowing back to a single script, which is the exact gap review
    found in this corpus after the first version shipped."""
    assert len(FALSE_POSITIVE_CORPUS_BY_SCRIPT) >= 7
    for script, corpus in FALSE_POSITIVE_CORPUS_BY_SCRIPT.items():
        assert len(corpus) >= 6, f"{script} corpus too small to be meaningful: {len(corpus)}"


def test_false_positives_on_legitimate_text() -> None:
    """Reported PER SCRIPT, not as one aggregate across all 103 entries --
    an aggregate is exactly the kind of number that would hide false-positive
    cost landing unevenly across scripts (see the fairness note in this
    file's own module docstring and in the report this test's numbers feed).
    A single "false positives: 0.0%" line across a corpus dominated by
    Spanish/Catalan entries would still read as "safe for everyone" even if
    every single Greek or Arabic entry were altered; per-script rows cannot
    hide that the way one combined percentage could.
    """
    print(
        f"\n=== Measurement 2: false positives, {len(FALSE_POSITIVE_CORPUS)} entries, by script ==="
    )

    # {approach: {script: [altered entries]}}
    per_approach_per_script: dict[str, dict[str, list[str]]] = {
        name: {script: [] for script in FALSE_POSITIVE_CORPUS_BY_SCRIPT} for name in APPROACHES
    }
    for name, fn in APPROACHES.items():
        for script, corpus in FALSE_POSITIVE_CORPUS_BY_SCRIPT.items():
            for text in corpus:
                if fn(text) != text:
                    per_approach_per_script[name][script].append(text)

    for name in APPROACHES:
        print(f"\n{name}:")
        print(f"  {'script':<20}{'altered':>10}{'total':>8}{'fraction':>12}")
        for script, corpus in FALSE_POSITIVE_CORPUS_BY_SCRIPT.items():
            altered = per_approach_per_script[name][script]
            fraction = len(altered) / len(corpus)
            print(f"  {script:<20}{len(altered):>10}{len(corpus):>8}{fraction:>12.1%}")

    print("\n--- entries altered, per approach, per script ---")
    for name in APPROACHES:
        any_altered = False
        for script in FALSE_POSITIVE_CORPUS_BY_SCRIPT:
            altered = per_approach_per_script[name][script]
            if not altered:
                continue
            any_altered = True
            print(f"{name} / {script}:")
            for text in altered:
                print(f"    {text!r} -> {APPROACHES[name](text)!r}")
        if not any_altered:
            print(f"{name}: none")

    # THE regression gate: shipped code (`baseline`, no wrapper) must not
    # touch this corpus AT ALL, in ANY script. Every entry is either plain
    # ASCII, precomposed accented Latin (excluded from the lookalike table
    # by construction), or a script `_LOOKALIKE_TABLE` DOES cover
    # (Greek/Cyrillic) where position preservation means a non-matching
    # span is never rewritten -- see `_sub_preserving_original`. Confirms,
    # at full corpus scale rather than the single-string spot-check
    # elsewhere in this file, exactly the property capo's own measurement
    # asked to see: a Greek, Bulgarian, Serbian or Turkish name does not
    # checksum as an IBAN or PAN, so no span matches and nothing is
    # spliced. If this ever fails on a NON-Spanish/Catalan script
    # specifically, that is the uneven-cost finding this widened corpus
    # exists to catch, and it must be reported, not fixed quietly.
    for script in FALSE_POSITIVE_CORPUS_BY_SCRIPT:
        altered = per_approach_per_script["baseline"][script]
        assert altered == [], f"shipped code altered legitimate {script} text: {altered}"

    # B's own wrapper is the OPPOSITE assertion, on purpose: it is expected,
    # not merely tolerated, to corrupt every non-Latin script here except
    # CJK and Arabic (which `_LOOKALIKE_TABLE` never touches at all,
    # regardless of whole-value vs position-preserving). This is the
    # regression canary from `approach_b`'s own docstring, run against the
    # full widened corpus rather than one hand-picked string: if B's
    # wrapper ever STOPS corrupting these, something about `_delookalike`'s
    # own scope changed and needs re-checking, because this wrapper's
    # pre-transliteration step has no position-preserving logic of its own.
    for script in ("Greek", "Bulgarian Cyrillic", "Serbian Cyrillic", "Turkish"):
        altered = per_approach_per_script["B (confusables)"][script]
        assert altered, (
            f"expected approach_b's whole-value pre-transliteration to corrupt "
            f"{script} text as a known canary -- it did not, re-check what changed"
        )
    for script in ("CJK", "Arabic"):
        altered = per_approach_per_script["B (confusables)"][script]
        assert altered == [], f"unexpected: B's wrapper altered {script} text: {altered}"

    # A is NOT asserted to be empty, on purpose -- it found a real false
    # positive this file did not go looking for: 'Nº445210' loses its 'º'
    # (MASCULINE ORDINAL INDICATOR, U+00BA) to 'o', because NFKC is a
    # COMPATIBILITY normalisation and º has a compatibility decomposition to
    # plain "o" (verified: `unicodedata.normalize("NFKC", "º") == "o"`).
    # Accented Latin itself (á, ñ, ç, è, ü, ò, ...) is confirmed untouched --
    # every remaining Spanish/Catalan entry round-trips through A unchanged
    # -- but "Nº", "1º", "2ª" (floor/ordinal abbreviations genuinely common
    # in Spanish/Catalan addresses and invoice line items) are a
    # false-positive SURFACE this file did not design for and NFKC does not
    # exempt. This is reported, not hidden: see the printed "entries
    # altered" list above and the report this test's numbers feed. NFKC is
    # confirmed to leave every OTHER script in this corpus untouched too
    # (Greek/Cyrillic/Turkish/CJK/Arabic have no compatibility
    # decomposition in play here), asserted below alongside the Spanish/
    # Catalan-specific exemption.
    for script in FALSE_POSITIVE_CORPUS_BY_SCRIPT:
        if script == "Spanish/Catalan":
            continue
        altered = per_approach_per_script["A (NFKC)"][script]
        assert altered == [], f"NFKC altered legitimate {script} text unexpectedly: {altered}"
    accented_only_altered = [
        text
        for text in per_approach_per_script["A (NFKC)"]["Spanish/Catalan"]
        if "º" not in text and "ª" not in text
    ]
    assert accented_only_altered == [], (
        "NFKC altered something in the Spanish/Catalan corpus other than an "
        f"ordinal indicator (º/ª): {accented_only_altered}"
    )


# ---------------------------------------------------------------------------
# Measurement 3: cost
# ---------------------------------------------------------------------------


def _time_ms(fn: Callable[[str], str], value: str, repeats: int, inner: int = 1) -> float:
    """Minimum wall-clock time in milliseconds across `repeats` trials, each
    running `fn(value)` `inner` times back to back. Minimum, not mean/median:
    the question is "how cheap can this be made to run", and OS scheduling
    noise only ever pushes a trial slower than its true cost, never faster."""
    best = float("inf")
    for _ in range(repeats):
        start = time.perf_counter()
        for _ in range(inner):
            fn(value)
        elapsed = (time.perf_counter() - start) * 1000
        best = min(best, elapsed)
    return best / inner


REALISTIC_MEMO = "Transferència nòmina mensual Josep Martí ref 2024-09 Sabadell"

_JUNK_TOKEN = "AB12" * 32  # 128 chars, the module's own documented adversarial shape
_WORST_CASE_TOKEN_COUNT = (
    8128  # matches the "8,128 tokens, 128 chars each" ~1 MiB row in masking.py's own comments
)
WORST_CASE_ADVERSARIAL = " ".join([_JUNK_TOKEN] * _WORST_CASE_TOKEN_COUNT)

# Same shape, but every 4th character (each 'A' opener) replaced with a
# Cyrillic look-alike -- under the UNMODIFIED ASCII scan this SHRINKS the
# scanned candidate length to 3-char fragments (below `_IBAN_MIN_LEN`), so
# baseline/C see nothing to checksum in this token at all; approaches A/B
# reassemble the full 128-char token before scanning, restoring the exact
# shape masking.py's own comments call out as the worst case.
_JUNK_TOKEN_HOMOGLYPHED = _JUNK_TOKEN.replace("A", "А")
WORST_CASE_HOMOGLYPHED = " ".join([_JUNK_TOKEN_HOMOGLYPHED] * _WORST_CASE_TOKEN_COUNT)


def test_cost() -> None:
    kib = len(WORST_CASE_ADVERSARIAL) / 1024
    print(f"\n=== Measurement 3: cost (min of 5 trials; {kib:.0f} KiB adversarial payloads) ===")
    print(
        f"{'approach':<20}{'memo (us)':>12}{'adversarial ASCII (ms)':>26}"
        f"{'adversarial homoglyphed (ms)':>32}"
    )
    for name, fn in APPROACHES.items():
        memo_ms = _time_ms(fn, REALISTIC_MEMO, repeats=5, inner=2000)
        adversarial_ms = _time_ms(fn, WORST_CASE_ADVERSARIAL, repeats=5)
        homoglyphed_ms = _time_ms(fn, WORST_CASE_HOMOGLYPHED, repeats=5)
        print(f"{name:<20}{memo_ms * 1000:>12.2f}{adversarial_ms:>26.2f}{homoglyphed_ms:>32.2f}")


# ---------------------------------------------------------------------------
# Measurement 4: maintenance (approach B specifically)
# ---------------------------------------------------------------------------


def test_table_sizes_and_maintenance_notes() -> None:
    print("\n=== Measurement 4: shipped lookalike table size and provenance ===")
    print(f"{'source':<45}{'entries':>10}")
    print(f"{'fullwidth (formula, +0xFEE0 offset)':<45}{len(_FULLWIDTH_TABLE):>10}")
    print(f"{'math alphanumeric (derived via unicodedata.name)':<45}{len(_MATH_ALNUM_TABLE):>10}")
    print(f"{'enclosed alphanumeric (derived via unicodedata.name)':<45}{len(_ENCLOSED_TABLE):>10}")
    print(f"{'hand-enumerated Cyrillic (14 upper + 14 lower)':<45}{len(_HAND_CYRILLIC):>10}")
    print(f"{'hand-enumerated Greek (14 upper + 14 lower)':<45}{len(_HAND_GREEK):>10}")
    print(f"{'hand-enumerated misc (dotless i, Kelvin sign)':<45}{len(_HAND_MISC):>10}")
    print(f"{'TOTAL hand-maintained (cyrillic+greek+misc)':<45}{len(_HAND_TABLE):>10}")
    print(f"{'TOTAL table (all four sources, deduplicated)':<45}{len(_CONFUSABLES_TABLE):>10}")
    print(f"\nunicodedata.unidata_version in this interpreter: {unicodedata.unidata_version}")
    assert len(_HAND_TABLE) == 58, "hand-maintained table drifted from the count this report cites"


def test_second_drift_gate_now_covers_the_lookalike_table() -> None:
    """This USED to assert the opposite: that no test covered the
    confusables table, because it did not exist on main. It does now --
    `test_bundled_unicode_version_matches_the_version_the_lookalike_table_
    was_derived_against` (tests/test_masking_types.py) is its own,
    separately-scoped version-pin gate, not a free ride on the
    Default_Ignorable one. This just confirms it exists and is scoped to
    the right names, so this file does not silently go stale the next time
    someone reads its own claim about test coverage."""
    import inspect

    from tests import test_masking_types as existing_tests

    gate_source = inspect.getsource(
        existing_tests.test_bundled_unicode_version_matches_the_version_the_lookalike_table_was_derived_against
    )
    assert "_HAND_CYRILLIC_LOOKALIKES" in gate_source
    assert "_HAND_GREEK_LOOKALIKES" in gate_source
    assert "_HAND_LOOKALIKE_TABLE_DERIVED_AGAINST_UNICODE_VERSION" in gate_source
    # And it says so, rather than proving it: this gate cannot mechanically
    # verify completeness (see the gate's own docstring for why not), so its
    # failure message must say that plainly rather than imply otherwise.
    assert "not a completeness check" in gate_source.lower()
    print(
        "\n=== Measurement 4: drift gate scope ===\n"
        "test_bundled_unicode_version_matches_the_version_the_lookalike_table_was_derived_against "
        "(tests/test_masking_types.py) is scoped to _HAND_CYRILLIC_LOOKALIKES/"
        "_HAND_GREEK_LOOKALIKES, separately from the pre-existing Default_Ignorable gate."
    )

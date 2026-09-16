"""Measurement harness for three candidate mitigations of the homoglyph leak
in `_redact_free_text` (masking.py) -- **not** a fix, and not a recommendation.

The leak: `_IBAN_IN_TEXT_RE` / `_PAN_IN_TEXT_RE` are ASCII-only
(`[A-Za-z0-9]`), so a single non-ASCII codepoint inside an otherwise-ASCII
IBAN or PAN splits the token below the scan's own length floor and the
checksum pass never runs. `masking.py` is UNCHANGED by this file: every
approach below is a thin preprocessing wrapper that calls straight through
to the real `_redact_free_text`, `_MASK`, `_IBAN_MASKED_RE` and friends,
never a reimplementation of the scan or the mask shape.

Run to see the tables (they are printed, not just asserted):

    uv run pytest tests/test_masking_homoglyph_measurement.py -s -q

Vocabulary used throughout the printed tables, chosen deliberately to avoid
the trap the task that produced this file was built to avoid -- "a `••••`
appeared" is NOT evidence of masking, only `_IBAN_MASKED_RE` matching the
EXACT expected country code and last four is:

  properly_masked -- output contains the real `XX•• •••• YYYY` shape for
                     THIS case's own true IBAN. The intended outcome.
  degraded        -- the raw IBAN is NOT recoverable from the output (see
                     `_leaks` below), but not via the proper IBAN mask
                     either -- e.g. a bare `_MASK` marker, or the digit-run
                     PAN scan incidentally eating part of the number. Safe
                     on the leak axis, but not "masked" in the sense the
                     golden test or a human auditor would expect.
  leaked          -- the raw IBAN (or a functionally identical rendering of
                     it, see `_leaks`) is recoverable from the output.

"closed" in the fraction reported for measurement 1 means NOT leaked, i.e.
`properly_masked + degraded`, per the task's explicit instruction: assert
absence of the raw IBAN, never that a mask appeared.
"""

from __future__ import annotations

import re
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

from postern_core.domain.masking import (
    _IBAN_MASKED_RE,
    _MASK,
    _redact_free_text,
)

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
# Approach B: a small, hand-plus-derived UTS #39-style confusables skeleton
# ---------------------------------------------------------------------------

_DIGIT_WORDS = {
    "ZERO": "0",
    "ONE": "1",
    "TWO": "2",
    "THREE": "3",
    "FOUR": "4",
    "FIVE": "5",
    "SIX": "6",
    "SEVEN": "7",
    "EIGHT": "8",
    "NINE": "9",
}
_MATH_ALNUM_LETTER_RE = re.compile(r"^MATHEMATICAL [A-Z][A-Z -]* (CAPITAL|SMALL) ([A-Z])$")
_MATH_ALNUM_DIGIT_RE = re.compile(
    r"^MATHEMATICAL [A-Z][A-Z -]* DIGIT (" + "|".join(_DIGIT_WORDS) + ")$"
)
_CIRCLED_LETTER_RE = re.compile(r"^CIRCLED (LATIN CAPITAL|LATIN SMALL) LETTER ([A-Z])$")
_CIRCLED_DIGIT_RE = re.compile(r"^CIRCLED DIGIT (" + "|".join(_DIGIT_WORDS) + ")$")


def _build_fullwidth_table() -> dict[str, str]:
    """Fullwidth Latin letters and digits: a fixed +0xFEE0 offset from ASCII
    ('Ａ' - 'A' == '１' - '1' == 0xFEE0), verified directly, not
    assumed. No name-parsing needed for this block."""
    table: dict[str, str] = {}
    for cp in range(0xFF21, 0xFF3B):  # fullwidth A-Z
        table[chr(cp)] = chr(cp - 0xFEE0)
    for cp in range(0xFF41, 0xFF5B):  # fullwidth a-z
        table[chr(cp)] = chr(cp - 0xFEE0)
    for cp in range(0xFF10, 0xFF1A):  # fullwidth 0-9
        table[chr(cp)] = chr(cp - 0xFEE0)
    return table


def _build_math_alphanumeric_table() -> dict[str, str]:
    """Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF), derived by
    parsing `unicodedata.name()` rather than hand-listing ~700 codepoints.
    Deliberately restricted to names ending in '(CAPITAL|SMALL) <letter>' or
    'DIGIT <word>' -- the math-styled GREEK letters in the same block
    (MATHEMATICAL BOLD CAPITAL ALPHA, etc.) are excluded by the same regex,
    on purpose: they are not ASCII look-alikes in the way a math-bold LATIN
    letter is, and folding them in would be scope creep on a block this
    table only needs for its Latin/digit members."""
    table: dict[str, str] = {}
    for cp in range(0x1D400, 0x1D800):
        try:
            name = unicodedata.name(chr(cp))
        except ValueError:
            continue
        m = _MATH_ALNUM_LETTER_RE.match(name)
        if m:
            case, letter = m.groups()
            table[chr(cp)] = letter.lower() if case == "SMALL" else letter
            continue
        m = _MATH_ALNUM_DIGIT_RE.match(name)
        if m:
            table[chr(cp)] = _DIGIT_WORDS[m.group(1)]
    return table


def _build_enclosed_alphanumeric_table() -> dict[str, str]:
    """Enclosed Alphanumerics (U+2460-U+24FF) only -- not the Enclosed
    Alphanumeric Supplement (U+1F100-U+1F1FF, "negative circled"/"squared"
    forms), which is a different, much larger block and a materially
    different visual shape. Two-digit forms ("CIRCLED NUMBER TEN"..
    "TWENTY") are skipped: mapping one codepoint to a two-character string
    breaks the 1:1 codepoint correspondence every other entry in this table
    keeps, for a handful of characters no realistic IBAN/PAN substitution
    needs."""
    table: dict[str, str] = {}
    for cp in range(0x2460, 0x2500):
        try:
            name = unicodedata.name(chr(cp))
        except ValueError:
            continue
        m = _CIRCLED_LETTER_RE.match(name)
        if m:
            case, letter = m.groups()
            table[chr(cp)] = letter.lower() if "SMALL" in case else letter
            continue
        m = _CIRCLED_DIGIT_RE.match(name)
        if m:
            table[chr(cp)] = _DIGIT_WORDS[m.group(1)]
    return table


# Hand-enumerated: UPPERCASE Cyrillic and Greek letters visually identical
# (not merely similar) to a Latin capital, plus dotless i. Uppercase-only by
# construction -- ISO 13616 IBANs are conventionally rendered uppercase, and
# this keeps the hand-maintained boundary a simple, statable rule ("only the
# capitals") rather than a cherry-picked list. This is also this table's
# most honest limitation: a LOWERCASE Cyrillic homoglyph glued into an
# otherwise-uppercase IBAN is NOT covered (see the dedicated corpus case
# below), even though it splits the ASCII scan exactly the same way.
#
# Every precomposed accented Latin letter (a-with-acute, n-with-tilde,
# c-with-cedilla, ...) is excluded BY CONSTRUCTION: none of the three tables
# above touches the Latin-1 Supplement or Latin Extended-A blocks at all, so
# there is no code path through which "ñ", "ç", "à" could ever enter this
# table by accident.
_HAND_CYRILLIC = {
    "А": "A",
    "В": "B",
    "Е": "E",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Т": "T",
    "У": "Y",
    "Х": "X",
    "Ѕ": "S",
    "Ј": "J",
}
_HAND_GREEK = {
    "Α": "A",
    "Β": "B",
    "Ε": "E",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "Κ": "K",
    "Μ": "M",
    "Ν": "N",
    "Ο": "O",
    "Ρ": "P",
    "Τ": "T",
    "Υ": "Y",
    "Χ": "X",
}
_HAND_MISC = {
    "ı": "i",  # LATIN SMALL LETTER DOTLESS I
}


def _build_hand_table() -> dict[str, str]:
    table: dict[str, str] = {}
    table.update(_HAND_CYRILLIC)
    table.update(_HAND_GREEK)
    table.update(_HAND_MISC)
    return table


_FULLWIDTH_TABLE = _build_fullwidth_table()
_MATH_ALNUM_TABLE = _build_math_alphanumeric_table()
_ENCLOSED_TABLE = _build_enclosed_alphanumeric_table()
_HAND_TABLE = _build_hand_table()

_CONFUSABLES_TABLE: dict[str, str] = {
    **_FULLWIDTH_TABLE,
    **_MATH_ALNUM_TABLE,
    **_ENCLOSED_TABLE,
    **_HAND_TABLE,
}
_CONFUSABLES_TRANS = str.maketrans(_CONFUSABLES_TABLE)


def _skeleton(value: str) -> str:
    if value.isascii():
        return value
    return value.translate(_CONFUSABLES_TRANS)


def approach_b(value: str) -> str:
    return _redact_free_text(_skeleton(value))


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


# Checker-only, deliberately BROADER than approach B's own table: lowercase
# counterparts of the same 14+14 Cyrillic/Greek letters. Approach B excludes
# these (uppercase-only, see `_HAND_TABLE`'s docstring) -- reusing that same
# narrower table here would let a lowercase homoglyph hide from the leak
# check the exact way the task warned about, since the very thing under
# test would also be the tool measuring it. First measured wrong: a
# lowercase Cyrillic а substituted into MT_IBAN's account body reached
# baseline's output completely unchanged (a full, unambiguous leak: no
# character of the true IBAN was even touched), and without this table
# `_visual_canon` still classified it as merely "degraded", because it
# shared approach B's own blind spot. See `test_leak_closure`'s per-case
# table for the "lowercase cyrillic" row this fixed.
_CHECKER_ONLY_LOWERCASE_CYRILLIC = {k.lower(): v.lower() for k, v in _HAND_CYRILLIC.items()}
_CHECKER_ONLY_LOWERCASE_GREEK = {
    "α": "a",
    "β": "b",
    "ε": "e",
    "ζ": "z",
    "η": "h",
    "ι": "i",
    "κ": "k",
    "μ": "m",
    "ν": "n",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "υ": "y",
    "χ": "x",
}
_STRICT_CANON_TABLE: dict[str, str] = {
    **_CONFUSABLES_TABLE,
    **_CHECKER_ONLY_LOWERCASE_CYRILLIC,
    **_CHECKER_ONLY_LOWERCASE_GREEK,
}
_STRICT_CANON_TRANS = str.maketrans(_STRICT_CANON_TABLE)


def _visual_canon(s: str) -> str:
    """The strongest canonicalisation this file has available, applied only
    to OUTPUT for leak detection -- never used by any of the three
    approaches themselves. Union of NFKC and a confusables table BROADER
    than approach B's own (see `_STRICT_CANON_TABLE`), so a check built on
    this cannot be fooled by exactly the trap the task warned about:
    comparing ASCII chunks of the original against output that still
    contains the substituted character, letting the substitution hide the
    leak from the checker the same way it caused the leak in the first
    place."""
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

    # Self-check, deliberately weaker than "baseline always fully leaks":
    # one corpus case (AT/fully-non-ascii) has baseline landing on
    # "degraded" rather than "leaked", NOT because the leak is closed but
    # because `\d` is itself Unicode-aware and happens to match the
    # fullwidth digit run incidentally (trap #1 from the task, reproduced
    # directly -- see `test_gb_digit_run_trap_illustration` for the same
    # mechanism on a different shape) -- confirmed directly, not assumed:
    # baseline's own output for that case is
    # 'Payment reference АТ•••• ２３４５ thanks', a `_PAN_IN_TEXT_RE` hit,
    # not an IBAN-aware one. What baseline must NEVER do, on any case in
    # this corpus, is produce the actual correct `XX•• •••• YYYY` mask --
    # that would mean the open leak this file measures does not exist.
    baseline_properly_masked = [
        label for label, outcomes in per_case.items() if outcomes["baseline"] == "properly_masked"
    ]
    assert baseline_properly_masked == [], (
        "unmodified main correctly masked a homoglyph-substituted IBAN -- "
        f"the leak this file measures may already be closed: {baseline_properly_masked}"
    )


def test_gb_digit_run_trap_illustration() -> None:
    """Illustrative only -- NOT part of the scored NL/MT corpus above, and
    deliberately excluded from its "fraction closed" arithmetic. Demonstrates
    trap #2 from the task: a single Cyrillic substitution in a GB IBAN whose
    longest digit run (14) already qualifies for `_PAN_IN_TEXT_RE`'s
    incidental `\\d{12,}` match, so baseline's OWN output contains a `••••`
    -- from the unrelated PAN scan, not from any IBAN-aware masking -- while
    the country code and bank sort code identifying the account holder's
    bank stay fully legible via the substituted glyph.
    """
    substituted = GB_IBAN[:4] + "Н" + GB_IBAN[5:]  # cyrillic Н in place of ASCII N
    text = f"Payment reference {substituted} thanks"
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


# ---------------------------------------------------------------------------
# Measurement 2: false positives on legitimate Spanish/Catalan text
# ---------------------------------------------------------------------------

# 45 realistic merchant descriptors, payee names and payment references, all
# either accented Latin (legitimate, must NOT be touched by construction) or
# plain ASCII. Included in full per the task's instruction, so the numbers
# below can be audited against the actual strings.
FALSE_POSITIVE_CORPUS: list[str] = [
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
]


def test_false_positive_corpus_has_at_least_40_entries() -> None:
    assert len(FALSE_POSITIVE_CORPUS) >= 40


def test_false_positives_on_legitimate_text() -> None:
    n = len(FALSE_POSITIVE_CORPUS)
    print(f"\n=== Measurement 2: false positives on {n} legitimate Spanish/Catalan strings ===")
    header = f"{'approach':<20}{'altered':>10}{'fraction':>12}"
    print(header)

    per_approach_altered: dict[str, list[str]] = {name: [] for name in APPROACHES}
    for name, fn in APPROACHES.items():
        for text in FALSE_POSITIVE_CORPUS:
            output = fn(text)
            if output != text:
                per_approach_altered[name].append(text)

    for name in APPROACHES:
        altered = per_approach_altered[name]
        print(f"{name:<20}{len(altered):>10}{len(altered) / len(FALSE_POSITIVE_CORPUS):>12.1%}")

    print("\n--- entries altered, per approach ---")
    for name in APPROACHES:
        altered = per_approach_altered[name]
        if not altered:
            print(f"{name}: none")
            continue
        print(f"{name}:")
        for text in altered:
            print(f"    {text!r} -> {APPROACHES[name](text)!r}")

    # B must not touch this corpus AT ALL: every entry is either plain ASCII
    # or precomposed accented Latin, and accented Latin is excluded from the
    # confusables table by construction (`test_confusables_table_excludes_
    # accented_latin_by_construction` above). If this fails, that
    # construction claim is false and this measurement's B numbers
    # throughout the file need re-deriving.
    assert per_approach_altered["B (confusables)"] == [], per_approach_altered["B (confusables)"]

    # A is NOT asserted to be empty, on purpose -- it found a real false
    # positive this file did not go looking for: 'Nº445210' loses its 'º'
    # (MASCULINE ORDINAL INDICATOR, U+00BA) to 'o', because NFKC is a
    # COMPATIBILITY normalisation and º has a compatibility decomposition to
    # plain "o" (verified: `unicodedata.normalize("NFKC", "º") == "o"`).
    # Accented Latin itself (á, ñ, ç, è, ü, ò, ...) is confirmed untouched --
    # every remaining entry in the corpus round-trips through A unchanged --
    # but "Nº", "1º", "2ª" (floor/ordinal abbreviations genuinely common in
    # Spanish/Catalan addresses and invoice line items) are a false-positive
    # SURFACE this file did not design for and NFKC does not exempt. This is
    # reported, not hidden: see the printed "entries altered" list above and
    # the report this test's numbers feed.
    accented_only_altered = [
        text for text in per_approach_altered["A (NFKC)"] if "º" not in text and "ª" not in text
    ]
    assert accented_only_altered == [], (
        "NFKC altered something in the corpus other than an ordinal indicator "
        f"(º/ª) -- re-check the false-positive analysis above: {accented_only_altered}"
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
    print("\n=== Measurement 4: approach B table size and provenance ===")
    print(f"{'source':<45}{'entries':>10}")
    print(f"{'fullwidth (formula, +0xFEE0 offset)':<45}{len(_FULLWIDTH_TABLE):>10}")
    print(f"{'math alphanumeric (derived via unicodedata.name)':<45}{len(_MATH_ALNUM_TABLE):>10}")
    print(f"{'enclosed alphanumeric (derived via unicodedata.name)':<45}{len(_ENCLOSED_TABLE):>10}")
    print(f"{'hand-enumerated Cyrillic':<45}{len(_HAND_CYRILLIC):>10}")
    print(f"{'hand-enumerated Greek':<45}{len(_HAND_GREEK):>10}")
    print(f"{'hand-enumerated misc (dotless i)':<45}{len(_HAND_MISC):>10}")
    print(f"{'TOTAL hand-maintained (cyrillic+greek+misc)':<45}{len(_HAND_TABLE):>10}")
    print(f"{'TOTAL table (all four sources, deduplicated)':<45}{len(_CONFUSABLES_TABLE):>10}")
    print(f"\nunicodedata.unidata_version in this interpreter: {unicodedata.unidata_version}")
    assert len(_HAND_TABLE) == 29, "hand-maintained table drifted from the count this report cites"


def test_existing_drift_gate_does_not_cover_the_confusables_table() -> None:
    """Verifies, rather than assumes, that
    `test_bundled_unicode_version_matches_the_version_the_ranges_were_derived_against`
    (tests/test_masking_types.py) is scoped to
    `_DEFAULT_IGNORABLE_UNASSIGNED_RANGES` (the invisible-character strip)
    and has no knowledge of a confusables table -- because none exists on
    main today. A hand-maintained confusables table shipped as approach B
    would need its OWN version-pinned drift test, of the same shape, not a
    free ride on the existing one: a future Unicode version could reassign
    or add a Cyrillic/Greek character with a new Latin-confusable mapping,
    and nothing in the current test suite would notice.
    """
    import inspect

    from tests import test_masking_types as existing_tests

    source = inspect.getsource(
        existing_tests.test_bundled_unicode_version_matches_the_version_the_ranges_were_derived_against
    )
    assert "confusable" not in source.lower()
    assert (
        "_DEFAULT_IGNORABLE_UNASSIGNED_RANGES" in source
        or "_RANGES_DERIVED_AGAINST_UNICODE_VERSION" in source
    )
    print(
        "\n=== Measurement 4: existing drift gate scope ===\n"
        "test_bundled_unicode_version_matches_the_version_the_ranges_were_derived_against "
        "is scoped to _DEFAULT_IGNORABLE_UNASSIGNED_RANGES only. It does not, and cannot, "
        "cover a hand-maintained confusables table -- that data does not exist on main. "
        "Shipping approach B would need a second, differently-scoped version-pin test."
    )

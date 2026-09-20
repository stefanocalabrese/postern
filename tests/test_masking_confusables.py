"""Regression tests for the shipped homoglyph fix (`_delookalike` +
`_sub_preserving_original`, `postern_core.domain.masking`).

`tests/test_masking_homoglyph_measurement.py` carries the full 40-case
NL/MT leak-closure corpus and the (widened, seven-script) false-positive
corpus as its own regression gates (`test_leak_closure`,
`test_false_positives_on_legitimate_text`) -- this file does not duplicate
those. It covers what that measurement-turned-regression file does not:
the public `FreeText` entry point exercised through a real Pydantic model
(not just the private `_redact_free_text` function), the specific gap this
change closed (lowercase Cyrillic/Greek), the residual gap it deliberately
left open, and the position-preserving splice `_delookalike`'s own
docstring commits to -- including the reversal from an earlier whole-value
version that shipped first and was replaced after corrupting legitimate
non-Latin text.
"""

import itertools
import unicodedata

import pytest
from postern_core.domain.masking import (
    _HAND_CYRILLIC_LOOKALIKES,
    _HAND_GREEK_LOOKALIKES,
    _HAND_MISC_LOOKALIKES,
    _IBAN_MASKED_RE,
    _LATIN_SCRIPT_EXEMPTIONS,
    _LOOKALIKE_TABLE,
    FreeText,
    _delookalike,
    _is_script_intrusion,
    _strip_invisible,
)
from pydantic import BaseModel, ConfigDict

from tests.test_masking_homoglyph_measurement import (
    FALSE_POSITIVE_CORPUS,
    MT_IBAN,
    NL_IBAN,
    WORST_CASE_HOMOGLYPHED,
    _build_multi_substitution_corpus,
    _build_single_substitution_corpus,
)


class Memo(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    text: FreeText


def _mod97_ok(compact: str) -> bool:
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def _luhn_ok(digits: str) -> bool:
    """Luhn check (ISO/IEC 7812-1 Annex B), so that the short-PAN fixtures
    below are real card numbers rather than digit strings of the right
    length."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


# --- The gap this change closed: lowercase Cyrillic/Greek -------------------


def test_lowercase_cyrillic_homoglyph_is_now_properly_masked() -> None:
    """The exact case measured broken before this change: a single
    lowercase Cyrillic а (U+0430) substituted into MT_IBAN's account body
    reached `_redact_free_text`'s output completely unchanged under the
    (then uppercase-only) hand table -- not merely degraded, a full,
    unambiguous leak. Exercised here through the public `FreeText` field on
    a real Pydantic model, not the private function directly.
    """
    account_body = MT_IBAN[8:]
    idx = account_body.index("A")
    lowered = MT_IBAN[: 8 + idx] + "а" + MT_IBAN[8 + idx + 1 :]
    text = f"Payment reference {lowered} thanks"

    out = Memo(text=text).text

    assert lowered not in out, "the lowercase-Cyrillic-disguised IBAN leaked verbatim"
    assert _IBAN_MASKED_RE.search(out), f"expected a proper IBAN mask, got {out!r}"
    compact = MT_IBAN.upper()
    assert f"{compact[:2]}•• •••• {compact[-4:]}" in out


def test_lowercase_greek_homoglyph_is_masked_too() -> None:
    """Same gap, Greek side: lowercase α (U+03B1, visually "a") substituted
    for one of the ASCII "A"s in MT_IBAN's account body."""
    account_body = MT_IBAN[8:]
    idx = account_body.index("A")
    substituted = MT_IBAN[: 8 + idx] + "α" + MT_IBAN[8 + idx + 1 :]
    text = f"Payment reference {substituted} thanks"

    out = Memo(text=text).text

    assert substituted not in out
    assert _IBAN_MASKED_RE.search(out), f"expected a proper IBAN mask, got {out!r}"


@pytest.mark.parametrize(
    "hand_table",
    [_HAND_CYRILLIC_LOOKALIKES, _HAND_GREEK_LOOKALIKES],
    ids=["cyrillic", "greek"],
)
def test_hand_table_has_a_lowercase_entry_for_every_uppercase_one(
    hand_table: dict[str, str],
) -> None:
    """Structural check that the lowercase extension is actually complete
    for both scripts, not just spot-checked by the two tests above: every
    uppercase key's ASCII target has a corresponding lowercase key mapping
    to that target's own lowercase form."""
    uppercase_targets = {v for k, v in hand_table.items() if k.isupper()}
    lowercase_targets = {v for k, v in hand_table.items() if k.islower()}
    assert lowercase_targets == {t.lower() for t in uppercase_targets}


# --- The original ten confirmed characters, through the public API ---------


@pytest.mark.parametrize(
    ("label", "homoglyph", "ascii_base"),
    [
        ("cyrillic A", "А", "A"),
        ("cyrillic E", "Е", "E"),
        ("cyrillic M", "М", "M"),
        ("cyrillic T", "Т", "T"),
        ("fullwidth A", "Ａ", "A"),
        ("fullwidth 1", "１", "1"),
        ("math bold A", "\U0001d400", "A"),
        ("math bold 0", "\U0001d7ce", "0"),
        ("dotless i", "ı", "I"),
        ("circled 1", "①", "1"),
    ],
)
def test_each_confirmed_character_is_masked_on_the_mt_iban(
    label: str, homoglyph: str, ascii_base: str
) -> None:
    # Wherever the character first occurs in MT_IBAN -- position-class
    # coverage (country code / bank code / account body) is already
    # exhaustively covered by the 40-case corpus in
    # tests/test_masking_homoglyph_measurement.py; this test only needs one
    # substitution per confirmed character to prove the public `FreeText`
    # path masks it.
    idx = MT_IBAN.index(ascii_base)
    substituted = MT_IBAN[:idx] + homoglyph + MT_IBAN[idx + 1 :]
    text = f"Payment reference {substituted} thanks"

    out = Memo(text=text).text

    assert substituted not in out, f"{label} leaked verbatim"
    assert _IBAN_MASKED_RE.search(out), f"{label}: expected a proper IBAN mask, got {out!r}"


def test_latin_l_has_no_covered_hand_enumerated_lookalike() -> None:
    """Documents a real, stated boundary of the hand-enumerated tables,
    directly rather than by cross-reference: neither Cyrillic nor Greek
    contributes a letter mapping to Latin "L" (Greek DOES cover "N", via
    Ν/ν -- Nu -- which is why this module's leak-closure corpus can and
    does use MT's country code but never needed to claim "N" is
    uncovered). "L" is why NL's own country code ("NL") never appears as a
    country-code-position case in that corpus: neither of its two letters
    has a hand-enumerated look-alike, not because the corpus overlooked it."""
    assert "L" not in _HAND_CYRILLIC_LOOKALIKES.values()
    assert "L" not in _HAND_GREEK_LOOKALIKES.values()


# --- False positives, through the public API --------------------------------


def test_false_positive_corpus_is_untouched_through_the_public_api() -> None:
    """Same 53-entry corpus `test_masking_homoglyph_measurement.py` already
    checks against `_redact_free_text` directly; checked here through the
    public `FreeText` field instead, so this is a genuinely different code
    path (Pydantic's `AfterValidator` machinery), not a duplicate assertion."""
    altered = [text for text in FALSE_POSITIVE_CORPUS if Memo(text=text).text != text]
    assert altered == [], altered


def test_accented_latin_is_not_in_the_lookalike_table() -> None:
    accented = "áéíóúñçèòàïüÁÉÍÓÚÑÇÈÒÀÏÜ"
    overlap = [ch for ch in accented if ch in _LOOKALIKE_TABLE]
    assert overlap == [], f"accented Latin leaked into the shipped lookalike table: {overlap}"


# --- The residual gap, now closed for non-Latin scripts --------------------


def test_residual_gap_an_uncatalogued_cyrillic_letter_still_leaks() -> None:
    """WHAT CHANGED. This test used to assert the OPPOSITE: that Ж (U+0416,
    CYRILLIC CAPITAL LETTER ZHE) substituted into MT_IBAN's account body
    reached the output verbatim, because Ж has no Latin look-alike and so
    was never added to `_HAND_CYRILLIC_LOOKALIKES`. The whole class of
    uncatalogued splitters is now closed WITHOUT extending that table, by
    `_mask_bridged_runs` (masking.py): a non-ASCII alphanumeric character
    from a non-Latin script, sitting between two ASCII alphanumerics, no
    longer ends a token -- the scan bridges across it and bare-masks the
    whole run. The name is kept so this file's history stays greppable;
    only the assertion is inverted.

    Bare `_MASK`, not `XX•• •••• YYYY`, and that is the point rather than a
    shortfall: nothing here has been checksummed, so there is no identified
    IBAN to disclose a country code or a last four for -- the same refusal
    `_redact_iban_match` already makes for an ambiguous or over-long token.

    THE NEW RESIDUAL, in two named pieces, each demonstrated by its own
    test immediately below rather than asserted here:
      1. a non-ASCII LATIN-script letter (à, ø, ł, ß ...) used as the
         splitter -- exempted on purpose, see
         `test_new_residual_an_accented_latin_splitter_still_leaks`;
      2. a splitter at the EDGE of a token rather than between two ASCII
         alphanumerics -- see
         `test_new_residual_a_trailing_splitter_still_leaks`.
    """
    assert "Ж" not in _LOOKALIKE_TABLE
    idx = MT_IBAN.index("A", 8)
    substituted = MT_IBAN[:idx] + "Ж" + MT_IBAN[idx + 1 :]
    text = f"Payment reference {substituted} thanks"

    out = Memo(text=text).text

    assert substituted not in out, f"the Ж-disguised IBAN still leaks verbatim: {out!r}"
    assert out == "Payment reference •••• thanks", out


@pytest.mark.parametrize(
    ("script", "splitter"),
    [
        ("Cyrillic ZHE", "Ж"),
        ("Cyrillic BE", "Б"),
        ("Greek THETA", "Θ"),
        ("Armenian AYB", "Ա"),
        ("Georgian AN", "ა"),
        ("Hebrew ALEF", "א"),
        ("CJK ideograph", "北"),
        ("Katakana RE", "レ"),
        ("Thai KO KAI", "ก"),
        ("Devanagari A", "अ"),
        ("Arabic-Indic digit four", "٤"),
    ],
)
def test_every_non_latin_script_splitter_is_bridged(script: str, splitter: str) -> None:
    """The class, not the one demonstrated member: none of these characters
    is in `_LOOKALIKE_TABLE`, none was added to it by this change, and each
    would have split MT_IBAN's account body below `_IBAN_MIN_LEN` on the
    previous code. Armenian, Georgian and CJK are named in `_delookalike`'s
    own residual paragraph; the rest are here because a rule stated as "any
    non-Latin script" has to be checked against more than the scripts whose
    names were already written down.
    """
    assert splitter not in _LOOKALIKE_TABLE
    idx = MT_IBAN.index("A", 8)
    substituted = MT_IBAN[:idx] + splitter + MT_IBAN[idx + 1 :]

    out = Memo(text=f"Payment reference {substituted} thanks").text

    assert substituted not in out, f"{script} splitter leaked verbatim: {out!r}"
    assert out == "Payment reference •••• thanks", out


def test_an_inserted_splitter_leaves_no_fragment_of_the_iban() -> None:
    """The sharper shape than substitution: INSERTING an uncatalogued
    character rather than replacing one leaves the real IBAN completely
    intact inside the token, so every character of it is present in the
    input. Bridging has to consume the whole run, not just the fragment on
    one side of the insertion."""
    idx = MT_IBAN.index("A", 8)
    planted = MT_IBAN[:idx] + "Ж" + MT_IBAN[idx:]
    assert MT_IBAN in planted.replace("Ж", ""), "fixture does not actually keep the IBAN intact"

    out = Memo(text=f"Payment reference {planted} thanks").text

    assert "MT92MALT01100" not in out, f"an IBAN fragment survived: {out!r}"
    assert "ABCDEFGH1234IJKL56" not in out, f"an IBAN fragment survived: {out!r}"
    assert out == "Payment reference •••• thanks", out


def test_several_splitters_at_once_are_bridged() -> None:
    """One character per split point is all an attacker needs, but nothing
    stops them using more, in several scripts at once. Bridging is defined
    over a BLOCK of consecutive splitters, not a single character, so this
    must behave identically to the one-character case."""
    planted = "MT92MALTЖЖ01100ABCDEFGH北北北1234IJKL56"

    out = Memo(text=f"Payment reference {planted} thanks").text

    assert "ABCDEFGH" not in out, f"an IBAN fragment survived: {out!r}"
    assert out == "Payment reference •••• thanks", out


def test_an_uncatalogued_splitter_inside_a_pan_is_bridged() -> None:
    """The PAN side of the same class, and the one with the sharper
    consequence: `_PAN_IN_TEXT_RE` needs 12 contiguous digits, so a single
    uncatalogued character split "4111111111114417" into an 8-digit and an
    8-digit fragment and neither pass saw a card at all. Luhn recovers the
    hidden digit from the other fifteen uniquely (measured: exactly one
    candidate digit at every one of the sixteen positions), so what leaked
    was the whole card, not fifteen sixteenths of one."""
    out = Memo(text="card 41111111Ж11114417 thanks").text

    assert "41111111" not in out, f"a PAN fragment survived: {out!r}"
    assert "11114417" not in out, f"a PAN fragment survived: {out!r}"
    assert out == "card •••• thanks", out


def test_bridging_runs_before_the_pan_scan_not_after_it() -> None:
    """Ordering, pinned by its consequence rather than by reading the code.
    "411111111111Ж4417" has twelve contiguous digits before the splitter, so
    the PAN scan matches them on their own: run the bridge afterwards and
    the output is '•••• 1111Ж4417' (measured against the pre-change scan) --
    the mask's own last four set directly against four unconsumed digits of
    the same card, which is the reassembly shape `_PAN_IN_TEXT_RE`'s
    unbounded run pattern exists to avoid. Run it first and the whole run
    is masked once.
    """
    out = Memo(text="411111111111Ж4417").text

    assert out == "••••", out
    assert "1111Ж4417" not in out


def test_a_genuine_iban_after_a_bridged_run_is_still_properly_masked() -> None:
    """Bridging rewrites the value it hands on -- `_MASK` is four characters
    replacing a span of any length -- so the skeleton the IBAN and PAN
    passes match against has to be rebuilt afterwards, or every span they
    find is located at an offset that no longer means the same thing in the
    value they splice into. Exercised with a bridged run FIRST and a
    genuine, catalogued-look-alike IBAN after it, so a stale skeleton
    misaligns rather than merely being redundant.
    """
    idx = MT_IBAN.index("A", 8)
    uncatalogued = MT_IBAN[:idx] + "Ж" + MT_IBAN[idx + 1 :]
    catalogued = MT_IBAN[:idx] + "А" + MT_IBAN[idx + 1 :]  # Cyrillic А, in the table

    out = Memo(text=f"first {uncatalogued} second {catalogued} end").text

    compact = MT_IBAN.upper()
    assert out == f"first •••• second {compact[:2]}•• •••• {compact[-4:]} end", out


@pytest.mark.parametrize(
    ("pan", "kind"),
    [
        # 13-digit Visa, one digit SUBSTITUTED: 12 ASCII digits survive,
        # exactly `_PAN_MIN_DIGITS`.
        ("4222222222222", "substituted"),
        # 12-digit card, splitter INSERTED: all 12 digits survive.
        ("869926608025", "inserted"),
    ],
)
def test_a_short_pan_split_by_a_splitter_is_bridged(pan: str, kind: str) -> None:
    """The only shape the digit-count route into `_could_be_an_identifier`
    can reach on its own: both of these leave 12 ASCII digits and 12
    alphanumerics, so the IBAN route (which needs `_IBAN_MIN_LEN` of 14)
    cannot see them and only `_PAN_MIN_DIGITS` does. The 16-digit Visa
    elsewhere in this file clears both bars and would keep working if the
    digit route were deleted, which is why it cannot stand in for this.

    One case per mutation KIND on purpose. An earlier version of this test
    used insertion for both fixtures, which masked and so read as coverage
    -- but insertion preserves every digit, so it cannot show what
    substitution does to a card already at the floor. That case leaks; it
    is residual 6, tested immediately below.
    """
    assert _luhn_ok(pan), "fixture is not a Luhn-valid card number"
    planted = pan[:4] + "Ж" + (pan[5:] if kind == "substituted" else pan[4:])
    assert sum(ch.isdigit() for ch in planted) == 12, planted

    out = Memo(text=f"card {planted} thanks").text

    assert out == "card •••• thanks", out


def test_new_residual_one_substitution_defeats_a_twelve_digit_card() -> None:
    """Residual 6, and the sharpest of the six because `_PAN_MIN_DIGITS`
    has NO slack where `_IBAN_MIN_LEN` has a character of it. A 12-digit
    card is already at the floor, so substituting a single splitter for one
    of its digits leaves 11 ASCII digits (under `_PAN_MIN_DIGITS`) and 11
    alphanumerics (under `_IBAN_MIN_LEN`), failing both routes into
    `_could_be_an_identifier`.

    It leaks at every one of the ten interior positions, and Luhn restores
    the hidden digit with exactly one candidate at every position of the
    card, so what reaches the output is the whole card rather than
    eleven twelfths of one.
    """
    pan = "869926608025"
    assert _luhn_ok(pan) and len(pan) == 12

    leaking = [
        i
        for i in range(1, len(pan) - 1)
        for planted in [pan[:i] + "Ж" + pan[i + 1 :]]
        if planted in Memo(text=f"card {planted} thanks").text
    ]
    assert leaking == list(range(1, 11)), (
        f"expected all ten interior positions to leak, got {leaking}"
    )

    recoverable = [
        sum(1 for d in "0123456789" if _luhn_ok(pan[:i] + d + pan[i + 1 :]))
        for i in range(len(pan))
    ]
    assert recoverable == [1] * len(pan), recoverable


@pytest.mark.parametrize(
    "text",
    [
        "FACTURANº20240912",
        "1ªPLANTAEDIFICI2026",
        "superficie120m²parcela4455",
        "REFERENCIAʼ2024BCN",
    ],
)
def test_latin_script_characters_with_no_latin_in_their_name(text: str) -> None:
    """The regression review found, pinned at the unit it broke. U+00BA,
    U+00AA, U+00B2 and U+02BC are all Script=Latin and all `isalnum()`, but
    none has "LATIN" in its Unicode name, so the first version of
    `_is_script_intrusion` treated them as intrusions, bridged across them
    and masked ordinary Spanish and Catalan. `_LATIN_SCRIPT_EXEMPTIONS`
    closes exactly that gap between the Script property and the name test
    that stands in for it.
    """
    assert any(not ch.isascii() for ch in text), "fixture has no non-ASCII character"
    assert Memo(text=text).text == text


def test_the_exemption_set_covers_the_characters_review_named() -> None:
    """The hand-listed half is small and explicit, so pin its membership
    rather than trusting the construction expression above it. Not a
    completeness claim: anything Script=Latin and name-less that is NOT
    here is residual 1 on `_mask_bridged_runs`, which says so."""
    for ch in "ªºµ²³¹¼½¾ʼ":
        assert ch in _LATIN_SCRIPT_EXEMPTIONS, f"U+{ord(ch):04X} dropped from the exemption set"
        assert not _is_script_intrusion(ch)


def test_the_derived_half_of_the_exemption_set_is_present() -> None:
    """The U+02B0-U+02E4 generator, pinned separately from the hand-listed
    half. Deleting that generator entirely left every other test in this
    suite passing, which made the half the comment calls the principled one
    the half nothing checked. These five are Latin modifier letters whose
    compatibility decomposition is an ASCII letter, which is exactly what
    the generator selects for."""
    for ch in "ʰʲʳʷʸ":
        assert ch in _LATIN_SCRIPT_EXEMPTIONS, f"U+{ord(ch):04X} dropped from the derived half"
        assert not _is_script_intrusion(ch)
    derived = {ch for ch in _LATIN_SCRIPT_EXEMPTIONS if 0x02B0 <= ord(ch) <= 0x02E4}
    assert len(derived) >= 6, f"the derived half collapsed to {len(derived)} members"


def test_no_exemption_is_canonically_equivalent_to_ascii() -> None:
    """The rule that sorts `_LATIN_SCRIPT_EXEMPTIONS` from
    `_LOOKALIKE_TABLE`, held for the whole set rather than for the one
    character that broke it. Canonical equivalence to an ASCII letter is
    Unicode saying the character IS that letter, so such a character must
    be catalogued and mapped, never exempted from bridging -- U+212A
    KELVIN SIGN was exempted on a "Script=Latin, no LATIN in the name"
    argument and reopened a complete-IBAN leak. Compatibility equivalence
    (º to o, ² to 2) is the weaker relation the exemption set is for.
    """
    canonical = {
        ch
        for ch in _LATIN_SCRIPT_EXEMPTIONS
        if (norm := unicodedata.normalize("NFC", ch)) != ch
        and len(norm) == 1
        and norm.isascii()
        and norm.isalnum()
    }
    assert canonical == set(), (
        "these exemptions are canonically equivalent to an ASCII alphanumeric "
        f"and belong in _LOOKALIKE_TABLE instead: {sorted(canonical)!r}"
    )


def test_the_kelvin_sign_is_catalogued_rather_than_exempted() -> None:
    """The leak the exemption set briefly reopened, pinned at the value it
    produced. U+212A renders as an ASCII K, and substituting it for the
    "K" of MT_IBAN returned the complete IBAN unmasked and byte-identical
    to a reader. Catalogued, it does better than bridging would: the
    skeleton goes fully ASCII, so the IBAN pass earns a real country code
    and last four instead of the bare marker.
    """
    kelvin = "K"
    assert unicodedata.normalize("NFC", kelvin) == "K"
    assert kelvin not in _LATIN_SCRIPT_EXEMPTIONS
    assert _LOOKALIKE_TABLE[kelvin] == "K"

    idx = MT_IBAN.index("K")
    substituted = MT_IBAN[:idx] + kelvin + MT_IBAN[idx + 1 :]
    out = Memo(text=f"Payment reference {substituted} thanks").text

    assert substituted not in out, f"the Kelvin-disguised IBAN leaked verbatim: {out!r}"
    compact = MT_IBAN.upper()
    assert out == f"Payment reference {compact[:2]}•• •••• {compact[-4:]} thanks", out


def test_a_visible_non_ascii_separator_is_not_an_intrusion() -> None:
    """Why `_is_script_intrusion` tests `isalnum()` at all. A Catalan punt
    volat or an em dash between two long alphanumeric runs is a break a
    reader can see, which is this module's documented grouped-IBAN
    limitation rather than an evasion. Both fixtures clear
    `_could_be_an_identifier`'s floors, so dropping the `isalnum()` test
    masks them; the shorter examples elsewhere in this file would not
    show it.
    """
    for text in ("FACTURA2026·REFERENCIA4455", "REF12345678—PARTIDA4455"):
        assert Memo(text=text).text == text, f"a visible separator was bridged across: {text!r}"


def test_an_unnamed_codepoint_is_treated_as_an_intrusion() -> None:
    """`unicodedata.name(ch, "")` defaults to the empty string, which
    contains no "LATIN", so a codepoint with no Unicode name at all counts
    as an intrusion. That default is load-bearing rather than incidental:
    6,145 alphanumeric codepoints have no name (Unicode 15.0.0), and
    flipping the default to "LATIN" would exempt every one of them while
    passing every other test in this file. Tangut U+17000 is one of them.
    """
    tangut = "\U00017000"
    assert tangut.isalnum()
    assert unicodedata.name(tangut, "") == "", "fixture codepoint acquired a name"
    assert _is_script_intrusion(tangut)

    idx = MT_IBAN.index("A", 8)
    planted = MT_IBAN[:idx] + tangut + MT_IBAN[idx + 1 :]
    assert Memo(text=f"ref {planted} end").text == "ref •••• end"


def test_a_run_at_exactly_the_alphanumeric_floor_is_masked() -> None:
    """The floor is `>=`, not `>`, and the difference is invisible unless a
    fixture sits exactly on it: "MT92MALT01100Ж1" is 14 ASCII
    alphanumerics with 8 ASCII digits, the smallest run
    `_could_be_an_identifier` accepts through its IBAN route."""
    text = "MT92MALT01100Ж1"
    ascii_alnum = sum(1 for ch in text if ch.isascii() and ch.isalnum())
    assert ascii_alnum == 14, ascii_alnum

    assert Memo(text=text).text == "••••"


def test_residual_three_spacing_marks_now_masked() -> None:
    """Residual 3, closed. The 13 Me (enclosing mark), 452 Mc (spacing
    combining mark) and 125 Sk (modifier symbol) codepoints are all non-
    alphanumeric, so the original `_is_script_intrusion` rejected them.
    None of the three is a visible break the way a space is, so a reader
    still sees one continuous token. Closed by widening `_is_script_intrusion`
    to also return True for Me/Mc/Sk codepoints: bridging replaces the split
    with a bare `_MASK`.

    Demonstrated here with one representative from each category; the full
    census over all 590 is in the measurement harness
    (tests/test_masking_homoglyph_measurement.py) and was re-run after the
    widening: zero false positives on the seven-script corpus.
    """
    for label, ch in (
        ("Me enclosing mark", "҈"),
        ("Mc spacing combining mark", "ः"),
        ("Sk modifier symbol", "´"),
    ):
        assert unicodedata.category(ch) in {"Me", "Mc", "Sk"}, label
        assert not ch.isalnum(), label
        idx = MT_IBAN.index("A", 8)
        planted = MT_IBAN[:idx] + ch + MT_IBAN[idx:]
        out = Memo(text=f"ref {planted} end").text
        assert MT_IBAN not in out.replace(ch, ""), (
            f"{label} should have been bridged and masked: {out!r}"
        )


def test_new_residual_two_splitters_evade_the_short_norwegian_format() -> None:
    """Residual 4, the attacker's direct counter-move against
    `_could_be_an_identifier`'s floors. NO9386011117947 is 15 characters,
    the registry's shortest shape, with 13 ASCII digits and 2 letters.
    Hiding two of the digits leaves 11 (under `_PAN_MIN_DIGITS`) and 13
    alphanumerics (under `_IBAN_MIN_LEN`), so the run clears neither floor
    and is left as written.

    Pinned as a RATIO rather than a single case, because the interesting
    fact is that the floors still catch the pairs touching the format's one
    interior letter: 66 of 78 interior pairs evade, 12 are masked.
    """
    no_iban = "NO9386011117947"
    assert _mod97_ok(no_iban) and len(no_iban) == 15

    interior = list(itertools.combinations(range(1, len(no_iban) - 1), 2))
    evaded = [
        (i, j)
        for i, j in interior
        for planted in ["".join("Ж" if k in (i, j) else c for k, c in enumerate(no_iban))]
        if planted in Memo(text=f"ref {planted} end").text
    ]
    assert len(interior) == 78, len(interior)
    assert len(evaded) == 66, f"expected 66 of 78 interior pairs to evade, got {len(evaded)}"

    letters = {k for k, c in enumerate(no_iban) if c.isalpha()}
    assert all(not (set(pair) & letters) for pair in evaded), (
        "a pair touching the format's interior letter was expected to be masked, "
        "since that keeps the ASCII digit count at the floor"
    )


def test_new_residual_an_accented_latin_splitter_still_leaks() -> None:
    """Piece 1 of the new residual, demonstrated rather than claimed.
    Bridging deliberately exempts non-ASCII LATIN-script characters --
    `unicodedata.name` starting "LATIN" -- because that is exactly the set
    ordinary Spanish, Catalan, Turkish, Polish and Nordic text puts INSIDE
    an alphanumeric reference code ("REFERÈNCIA20240912BCN",
    "URBANITZACIÓ1234567890", both in this module's own false-positive
    corpus). Bridging across them is what would mask those, so À is left
    able to do what Ж no longer can.

    This is a narrower residual than the one it replaces, and the narrowing
    is the point: before, ANY non-ASCII codepoint outside `_LOOKALIKE_TABLE`
    worked; now only Unicode's Latin blocks do.
    """
    idx = MT_IBAN.index("A", 8)
    substituted = MT_IBAN[:idx] + "À" + MT_IBAN[idx + 1 :]

    out = Memo(text=f"Payment reference {substituted} thanks").text

    assert substituted in out, (
        "an accented-Latin splitter was expected to still leak -- if this "
        f"now fails, the Latin exemption changed and the false-positive "
        f"corpus needs re-measuring: {out!r}"
    )


def test_new_residual_a_trailing_splitter_still_leaks() -> None:
    """Piece 2 of the new residual: bridging requires an ASCII alphanumeric
    on BOTH sides of the splitter block, so a splitter at the very end (or
    start) of a token is not bridged. Replacing MT_IBAN's last character
    leaves a 30-character ASCII run that is scanned by the ordinary IBAN
    pass and does not checksum, so it is left as written -- 30 of the
    IBAN's 31 characters, from which mod-97 restores the 31st with one or
    two candidates.

    Not closed here on purpose: the only rule that would close it is "any
    14+-character ASCII run that touches a foreign character", which fires
    on every ordinary Latin word abutting CJK with no space between them.
    """
    substituted = MT_IBAN[:-1] + "Ж"

    out = Memo(text=f"Payment reference {substituted} thanks").text

    assert substituted in out, f"a trailing splitter was expected to still leak, unbridged: {out!r}"


# --- What bridging costs: legitimate mixed-script text ---------------------

# Mixed-script INSIDE one token, no separator -- the shape bridging is
# defined over, and therefore the only shape it can over-mask. Real traffic
# separates scripts with a space or punctuation ("Tokyo Station 東京"), which
# ends a run the way it always did; these are the no-separator versions,
# written to be as unfavourable as realistic text gets.
LEGITIMATE_MIXED_SCRIPT_CORPUS: list[str] = [
    "TokyoStation東京レストランShopping",
    "Москва2026офис",
    "БанкSofiaОфис",
    "iPhone14手机壳",
    "SAMSUNGGALAXYS24手机壳",
    "東京レストランTokyo",
    "ΑθήναTaverna",
    "مطعمDamascus",
    "Nº445210",
    "REF2024番号",
]


def test_legitimate_mixed_script_text_that_bridging_leaves_alone() -> None:
    """Measured, not asserted at zero: bridging bare-masks a run only when
    it could still have been an identifier (14+ ASCII alphanumerics of
    which 2+ are ASCII digits, or 12+ ASCII digits), so most mixed-script
    text is below both bars and survives byte-identically. The entries that
    DO get masked are listed by this test's own failure message rather than
    hidden -- over-redaction, which this module accepts, never rewriting,
    which it does not.
    """
    altered = {
        text: Memo(text=text).text
        for text in LEGITIMATE_MIXED_SCRIPT_CORPUS
        if Memo(text=text).text != text
    }
    assert altered == {}, f"bridging over-masked legitimate mixed-script text: {altered}"


# --- The whole-value-transliteration decision, demonstrated directly -------


def test_legitimate_greek_and_cyrillic_text_is_preserved_byte_identically() -> None:
    """The whole reason the whole-value approach was replaced: capo's own
    measurement against the (now former) whole-value version --
    'ΜΑΡΙΑ ΠΑΠΑΔΟΠΟΥΛΟΥ' -> 'MAPIA ΠAΠAΔOΠOYΛOY', 'payment to МОСКВА
    office' -> 'payment to MOCKBA office' -- half-transliterated gibberish
    in a field a customer and a model both read. `FreeText` covers SEPA
    remittance information and counterparty names, and SEPA includes
    Greece, Cyprus and Bulgaria: a Greek payee or a Bulgarian counterparty
    name is ordinary traffic here, not an exotic case. None of these
    values contain an IBAN or PAN anywhere, so none of them should be
    altered AT ALL by the position-preserving splice.
    """
    legitimate_non_latin_text = [
        "ΜΑΡΙΑ ΠΑΠΑΔΟΠΟΥΛΟΥ",
        "payment to МОСКВА office",
        "Ivan Petrov Иван Петров",  # Bulgarian payee name
        "Ταουέρνα Αθήνας",  # Greek merchant descriptor
    ]
    for text in legitimate_non_latin_text:
        out = Memo(text=text).text
        assert out == text, f"legitimate non-Latin text was altered: {text!r} -> {out!r}"


def test_disguised_iban_embedded_in_legitimate_greek_text_masks_only_the_iban() -> None:
    """The case the whole change exists for, and the one a splice bug would
    break: a real IBAN, disguised with a covered Cyrillic look-alike, sitting
    inside an otherwise-legitimate Greek sentence. The IBAN must be masked;
    every Greek character around it -- none of it a look-alike target, all
    of it outside the matched span -- must survive untouched.
    """
    idx = MT_IBAN.index("A", 8)
    disguised = MT_IBAN[:idx] + "А" + MT_IBAN[idx + 1 :]  # cyrillic А for the ASCII "A"
    prefix = "Πληρωμή για "  # "Πληρωμή για " (Payment for)
    suffix = " από Τράπεζα"  # "από Τράπεζα" (from Bank)
    text = f"{prefix}{disguised}{suffix}"

    out = Memo(text=text).text

    assert prefix in out, f"legitimate Greek prefix was altered: {out!r}"
    assert suffix in out, f"legitimate Greek suffix was altered: {out!r}"
    assert disguised not in out, "the disguised IBAN leaked verbatim"
    compact = MT_IBAN.upper()
    assert f"{compact[:2]}•• •••• {compact[-4:]}" in out


# --- Widened after review: Spanish/Catalan alone cannot show this failure --
#
# Spanish and Catalan are Latin script with diacritics and are NEVER
# mixed-script, so they cannot express the failure mode that matters here --
# a script `_LOOKALIKE_TABLE` treats as wall-to-wall hostile, or a codepoint
# that is simultaneously an attack character and a mandatory letter. Each
# test below is the same shape as the Greek/Cyrillic ones above, one script
# at a time, so a failure names exactly which script broke rather than
# disappearing into one aggregate.


def test_legitimate_bulgarian_cyrillic_text_is_preserved_byte_identically() -> None:
    """Standard (Bulgarian) Cyrillic: single-script, zero Latin characters,
    and roughly half of any given word here is a `_HAND_CYRILLIC_LOOKALIKES`
    key -- wall-to-wall confusables while being ordinary legitimate text."""
    legitimate_bulgarian_text = [
        "Иван Петров",
        "София, България",
        "Пловдив, център",
        "Ресторант Варна",
    ]
    for text in legitimate_bulgarian_text:
        out = Memo(text=text).text
        assert out == text, f"legitimate Bulgarian text was altered: {text!r} -> {out!r}"


def test_legitimate_serbian_cyrillic_text_is_preserved_byte_identically() -> None:
    """A DIFFERENT Cyrillic alphabet from Bulgarian's, not the same text
    relabelled: Ј (U+0408) is a Serbian-specific letter this module's hand
    table maps to Latin "J", and Serbian names routinely contain it."""
    legitimate_serbian_text = [
        "Београд, центар",
        "Нови Сад, пијаца",
        "Јован Јовановић",
        "Ђорђе Петровић",
    ]
    for text in legitimate_serbian_text:
        out = Memo(text=text).text
        assert out == text, f"legitimate Serbian text was altered: {text!r} -> {out!r}"


def test_legitimate_turkish_text_with_dotless_i_is_preserved_byte_identically() -> None:
    """The case the coordinator named specifically: dotless ı (U+0131) is
    simultaneously the tenth confirmed attack character in this table AND a
    mandatory letter of the Turkish alphabet. If any rule in this codebase
    ever treated that codepoint as inherently hostile -- rather than
    "hostile only inside a span that actually checksums" -- this is exactly
    what would break: "Işık", "Yıldırım" and "Kadıköy" all contain a
    genuine U+0131, not a look-alike planted by an attacker.
    """
    legitimate_turkish_text = [
        "Ayşe Işık",
        "Mehmet Yıldırım",
        "Kadıköy Çarşısı, İstanbul",
        "Çınar Eczanesi, Ankara",
    ]
    for text in legitimate_turkish_text:
        assert "ı" in text, f"test fixture does not actually contain dotless i: {text!r}"
        out = Memo(text=text).text
        assert out == text, f"legitimate Turkish text was altered: {text!r} -> {out!r}"


def test_disguised_iban_embedded_in_legitimate_turkish_text_masks_only_the_iban() -> None:
    """The sharpest version of the case `test_disguised_iban_embedded_in_
    legitimate_greek_text_masks_only_the_iban` already covers: here the
    surrounding legitimate text contains the EXACT SAME CODEPOINT
    (dotless ı, U+0131) the disguised IBAN uses as its attack character,
    by way of `_HAND_MISC_LOOKALIKES`. A splice bug that treated "this
    codepoint appeared somewhere in the value" as sufficient reason to
    transliterate would corrupt "Işık" while masking the IBAN; the correct
    behaviour is to do both correctly at once.
    """
    idx = MT_IBAN.index("I", 8)
    disguised = MT_IBAN[:idx] + "ı" + MT_IBAN[idx + 1 :]  # dotless i for the ASCII "I"
    prefix = "Ayşe Işık'a ödeme: "  # "Payment to Ayşe Işık: "
    suffix = " İstanbul şubesi"  # "Istanbul branch"
    text = f"{prefix}{disguised}{suffix}"

    out = Memo(text=text).text

    assert prefix in out, f"legitimate Turkish prefix (own dotless i) was altered: {out!r}"
    assert suffix in out, f"legitimate Turkish suffix was altered: {out!r}"
    assert disguised not in out, "the disguised IBAN leaked verbatim"
    compact = MT_IBAN.upper()
    assert f"{compact[:2]}•• •••• {compact[-4:]}" in out


def test_legitimate_cjk_text_is_preserved_byte_identically() -> None:
    """No codepoint here shares anything with `_LOOKALIKE_TABLE` -- included
    to cover a script class the table does not touch at all, and because it
    has no space-delimited tokens the way every Latin/Greek/Cyrillic/Turkish
    case above does."""
    legitimate_cjk_text = [
        "北京烤鸭店",
        "上海贸易有限公司",
        "東京レストラン",
        "深圳科技公司",
    ]
    for text in legitimate_cjk_text:
        out = Memo(text=text).text
        assert out == text, f"legitimate CJK text was altered: {text!r} -> {out!r}"


def test_legitimate_arabic_text_is_preserved_byte_identically() -> None:
    """Right-to-left text direction and contextual letter forms, another
    script `_LOOKALIKE_TABLE` does not cover. Letters and prose only,
    deliberately no digits: an Arabic-Indic PAN already masks via
    `_PAN_IN_TEXT_RE`'s own Unicode-aware `\\d` (see that pattern's comment
    in masking.py) for a reason that has nothing to do with this table."""
    legitimate_arabic_text = [
        "مطعم دمشق",
        "صيدلية النور",
        "محمد أحمد الشامي",
        "شركة الأمل للتجارة",
    ]
    for text in legitimate_arabic_text:
        out = Memo(text=text).text
        assert out == text, f"legitimate Arabic text was altered: {text!r} -> {out!r}"


def test_delookalike_is_idempotent() -> None:
    """Load-bearing for `_redact_free_text`'s own skeleton-reuse optimisation
    (see its comment: when the IBAN pass changes nothing, the same skeleton
    is reused for the PAN pass rather than rebuilt) and for `approach_b`'s
    wrapper in the measurement/regression file, which re-applies
    `_delookalike` explicitly before calling the real function: applying it
    twice must be identical to applying it once."""
    value = "MT92MАLT01100аBCDEFGH1234IJKL56"
    once = _delookalike(value)
    twice = _delookalike(once)
    assert once == twice


def test_pan_pass_still_finds_a_fullwidth_pan_when_iban_pass_changed_nothing() -> None:
    """The correctness this file's own performance comment on
    `_redact_free_text` depends on, not just its speed: when the IBAN pass
    finds nothing to mask, it reuses the FIRST skeleton for the PAN pass
    instead of rebuilding one. That is only safe because `value` did not
    change between the two passes -- checked here directly, with a value
    that has no IBAN-shaped content at all (so the IBAN pass is guaranteed
    to leave it untouched) but does have a PAN written entirely in
    fullwidth digits, which the reused skeleton must still correctly expose
    to the PAN scan.
    """
    digit_to_fullwidth = str.maketrans("0123456789", "０１２３４５６７８９")
    fullwidth_pan = "4111111111114417".translate(digit_to_fullwidth)
    text = f"no iban here just a card {fullwidth_pan} thanks"

    out = Memo(text=text).text

    assert fullwidth_pan not in out, "the fullwidth-digit PAN leaked verbatim"
    assert "•••• 4417" in out, f"expected the PAN's last four unmasked: {out!r}"


def test_delookalike_preserves_string_length() -> None:
    """The property `_sub_preserving_original`'s splice depends on: the
    skeleton `_delookalike` returns must be the SAME LENGTH as its input,
    character-for-character index-aligned, or a match span located in the
    skeleton would not mean the same thing in the original string. Backed by
    `test_lookalike_table_values_are_single_characters` below (the table
    property that makes this true), checked here as the actual consequence,
    on real mixed-script input rather than on the table alone."""
    values = [
        "MT92MАLT01100аBCDEFGH1234IJKL56",
        "ΜΑΡΙΑ ΠΑΠΑΔΟΠΟΥΛΟΥ",
        "payment to МОСКВА office",
        "plain ascii, no look-alikes at all",
        "ＡＢＣ fullwidth ①②③ circled \U0001d400\U0001d401 math",
    ]
    for value in values:
        assert len(_delookalike(value)) == len(value), f"length changed for {value!r}"


def test_lookalike_table_values_are_single_characters() -> None:
    """The table-level property `_delookalike`'s length-preservation (and
    therefore `_sub_preserving_original`'s whole splice) depends on,
    checked directly rather than trusted from masking.py's own import-time
    check: every VALUE in `_LOOKALIKE_TABLE` is exactly one character.
    masking.py raises `ValueError` at import time if this is ever false
    (see the comment immediately above `_LOOKALIKE_TRANS`); this test
    re-checks the same property so a change to that guard itself would
    still be caught here.
    """
    multi_or_zero_character = {k: v for k, v in _LOOKALIKE_TABLE.items() if len(v) != 1}
    assert multi_or_zero_character == {}, (
        f"non-single-character lookalike targets found: {multi_or_zero_character!r}"
    )


def test_skeleton_construction_order_does_not_affect_the_skeleton() -> None:
    """`_redact_free_text` runs `_strip_invisible` once, up front, on the
    untransliterated original (it must -- see the ordering comment on
    `_redact_free_text` itself for why running `_delookalike` first, as an
    earlier version of this function did for a real cost saving, would
    silently reintroduce whole-value transliteration through the splice
    target). What's still true, and still worth checking directly rather
    than trusting the category argument alone, is that `_delookalike` and
    `_strip_invisible` target disjoint Unicode general categories: applying
    them in EITHER order to build a skeleton produces the same skeleton.
    This is what makes it safe that different parts of this module apply
    them in different orders for different reasons (this test builds a
    skeleton the same way `_redact_free_text` does -- strip then delookalike
    -- and compares it against the reverse).
    """
    corpus_texts = [case.text for case in _build_single_substitution_corpus()]
    corpus_texts += [case.text for case in _build_multi_substitution_corpus()]
    values = [*FALSE_POSITIVE_CORPUS, *corpus_texts, WORST_CASE_HOMOGLYPHED]

    mismatches = [
        v for v in values if _delookalike(_strip_invisible(v)) != _strip_invisible(_delookalike(v))
    ]
    assert mismatches == [], f"{len(mismatches)} value(s) differ by preprocessing order"


# --- Maintenance / provenance sanity ----------------------------------------


def test_hand_tables_have_the_documented_size() -> None:
    assert len(_HAND_CYRILLIC_LOOKALIKES) == 28
    assert len(_HAND_GREEK_LOOKALIKES) == 28
    assert len(_HAND_MISC_LOOKALIKES) == 2


def test_fixtures_are_valid_ibans() -> None:
    assert _mod97_ok(NL_IBAN)
    assert _mod97_ok(MT_IBAN)

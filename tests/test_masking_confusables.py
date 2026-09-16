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

import pytest
from postern_core.domain.masking import (
    _HAND_CYRILLIC_LOOKALIKES,
    _HAND_GREEK_LOOKALIKES,
    _HAND_MISC_LOOKALIKES,
    _IBAN_MASKED_RE,
    _LOOKALIKE_TABLE,
    FreeText,
    _delookalike,
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


# --- The residual gap, stated for an auditor, demonstrated directly --------


def test_residual_gap_an_uncatalogued_cyrillic_letter_still_leaks() -> None:
    """`_delookalike` closes the leak for exactly the codepoints in
    `_LOOKALIKE_TABLE`. Ж (U+0416, CYRILLIC CAPITAL LETTER ZHE) has no Latin
    look-alike and was never added to `_HAND_CYRILLIC_LOOKALIKES` -- this is
    not an oversight, it is the stated boundary of a hand-enumerated table
    (see that table's own docstring in masking.py). Demonstrated directly,
    not asserted from reading the comment: substituting it into MT_IBAN's
    account body must still leak on shipped code, identically to main
    before this change.
    """
    assert "Ж" not in _LOOKALIKE_TABLE
    idx = MT_IBAN.index("A", 8)
    substituted = MT_IBAN[:idx] + "Ж" + MT_IBAN[idx + 1 :]
    text = f"Payment reference {substituted} thanks"

    out = Memo(text=text).text

    assert substituted in out, (
        "an uncatalogued Cyrillic letter with no Latin look-alike leaked as "
        f"expected -- if this now fails, either a mapping was silently added "
        f"or `_redact_free_text` changed in an unrelated way: {out!r}"
    )


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
    assert len(_HAND_MISC_LOOKALIKES) == 1


def test_fixtures_are_valid_ibans() -> None:
    assert _mod97_ok(NL_IBAN)
    assert _mod97_ok(MT_IBAN)

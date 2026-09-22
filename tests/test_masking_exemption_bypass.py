"""The `_LATIN_SCRIPT_EXEMPTIONS` bypass, closed (audit finding C-07, leak 2).

Every member of that 18-codepoint set splits an alphanumeric token for
`_IBAN_IN_TEXT_RE` and `_PAN_IN_TEXT_RE` -- none of them is `[A-Za-z0-9]` --
while `_is_script_intrusion` excludes them, so `_bridged_runs` never bridged
one either. One substituted character therefore defeated every pass in
`masking.py` at once, and `º`/`ª` sit on a Spanish keyboard in the market
this deployment serves.

The set itself is not the bug and is not narrowed here: it exists because
`unicodedata` exposes no Script property, and removing any member
re-breaks `FACTURANº20240912` and its corpus siblings. What was wrong was
its SCOPE -- exempt from the structural test `_could_be_an_identifier`
runs, never exempt from arithmetic. `_mask_exemption_bridged_runs` restores
that distinction by deleting the exempt codepoints from a bridged span and
running the real checksum on what is left.

`tests/test_masking_confusables.py` keeps the other half of this pair
intact: `test_latin_script_characters_with_no_latin_in_their_name` and the
corpora there must all still pass byte-identically, and they do.
"""

import pytest
from postern_core.domain.masking import (
    _LATIN_SCRIPT_EXEMPTIONS,
    _MASK,
    FreeText,
    _is_script_intrusion,
    _redact_free_text,
    redaction_budget,
)
from pydantic import BaseModel, ConfigDict

from tests.fixtures import backend_responses as fx

ES_IBAN = fx.FULL_IBAN  # 24 characters
MT_IBAN = "MT92MALT01100ABCDEFGH1234IJKL56"  # 31
NO_IBAN = "NO9386011117947"  # 15, the registry's shortest
PAN = fx.FULL_PAN  # 16 digits, NOT Luhn-valid
LUHN_PAN = fx.LUHN_PAN  # 16 digits, Luhn-valid

# Sorted by codepoint so a failure names the same member every run, and
# bound to a typed name because `pytest.mark.parametrize` takes
# `Iterable[object]`, which erases the element type `ord` needs.
EXEMPTIONS: list[str] = sorted(_LATIN_SCRIPT_EXEMPTIONS, key=ord)


class Memo(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    text: FreeText


def redact(text: str) -> str:
    with redaction_budget():
        return _redact_free_text(text)


def _insertions(value: str, char: str) -> list[str]:
    return [value[:i] + char + value[i:] for i in range(1, len(value))]


# --- The two rows the audit measured ----------------------------------------


def test_the_audit_s_own_two_reproductions() -> None:
    """Both were unchanged, byte for byte, before this change."""
    assert redact(f"PAGO TARJETA {fx.ORDINAL_PAN}") == f"PAGO TARJETA {_MASK} 4417"
    assert redact(f"ref {fx.ORDINAL_IBAN}") == f"ref ES•• {_MASK} 1332"


# --- The sweep: all 18 members, every interior offset ------------------------


@pytest.mark.parametrize("char", EXEMPTIONS)
@pytest.mark.parametrize(
    ("label", "value"),
    [("PAN-16", PAN), ("PAN-16-luhn", LUHN_PAN), ("IBAN-15", NO_IBAN), ("IBAN-24", ES_IBAN)],
)
def test_no_exemption_member_leaks_at_any_interior_offset(
    char: str, label: str, value: str
) -> None:
    """An INSERTION, which is how these characters are actually used: none of
    them is canonically equivalent to an ASCII alphanumeric
    (`test_no_exemption_is_canonically_equivalent_to_ascii` holds that for
    the whole set), so an attacker pushes one INTO a complete value rather
    than swapping one out. Deleting it recovers exactly what a reader sees,
    which is what makes one candidate enough and the rejected 36-way
    wildcard expansion unnecessary.

    Before this change every one of these leaked the whole value verbatim.
    """
    for planted in _insertions(value, char):
        out = redact(f"PAGO REF {planted} FIN")
        assert planted not in out, f"U+{ord(char):04X} in {label}: {planted!r} -> {out!r}"
        assert _MASK in out, f"U+{ord(char):04X} in {label}: {planted!r} -> {out!r}"


@pytest.mark.parametrize("char", EXEMPTIONS)
def test_substitution_into_a_long_iban_is_closed_by_the_over_length_rule(char: str) -> None:
    """SUBSTITUTION is not recovered by deletion -- one character of the value
    is gone -- so nothing here can checksum. The 24-character Spanish IBAN
    is closed anyway, by a different rule: its 22 contiguous digits survive
    the strip as a run of 21 or 22, which is over `_PAN_MAX_DIGITS`, and an
    over-long digit run has never been allowed out of this module in its
    contiguous spelling either.
    """
    for i in range(1, len(ES_IBAN) - 1):
        planted = ES_IBAN[:i] + char + ES_IBAN[i + 1 :]
        out = redact(f"PAGO REF {planted} FIN")
        assert planted not in out, f"U+{ord(char):04X} at {i}: {planted!r} -> {out!r}"


def test_residual_seven_substitution_into_a_letter_dense_iban_still_leaks() -> None:
    """THE RESIDUAL THIS CHANGE LEAVES, stated where it cannot be lost.

    Malta's 31-character format is letter-dense: its longest digit run is
    five, so the over-length rule above has nothing to fire on, and
    deletion leaves 30 characters that cannot checksum because one of the
    31 is genuinely gone. Every one of the 18 members leaks at every
    interior offset, exactly as an accented Latin splitter already does
    (residual 1 on `_mask_bridged_runs`).

    Closing it needs the 36-way wildcard expansion this module measured and
    rejected at ~35% of arbitrary spans satisfiable. Asserted as leaking so
    that a future change which closes it fails here and has to say so,
    rather than the residual quietly going stale.
    """
    leaking = [
        char
        for char in _LATIN_SCRIPT_EXEMPTIONS
        for i in [12]
        for planted in [MT_IBAN[:i] + char + MT_IBAN[i + 1 :]]
        if planted in redact(f"PAGO REF {planted} FIN")
    ]
    assert sorted(leaking) == sorted(_LATIN_SCRIPT_EXEMPTIONS), sorted(leaking)


# --- The exemption set is not narrowed, and the corpus it protects stands ----


@pytest.mark.parametrize(
    "text",
    [
        "FACTURANº20240912",
        "1ªPLANTAEDIFICI2026",
        "superficie120m²parcela4455",
        "REFERENCIAʼ2024BCN",
        "DEVOLUCIÓ COMANDA ÒPERA Nº445210",
    ],
)
def test_ordinary_spanish_and_catalan_still_passes_through_untouched(text: str) -> None:
    """The regression `_LATIN_SCRIPT_EXEMPTIONS` was created to fix, checked
    against the pass that now bridges across those same characters. A
    checksum is what makes this possible: `_could_be_an_identifier` counts
    `FACTURA20240912` as 15 alphanumerics with 8 digits and masks it, while
    mod-97 correctly says it is not an IBAN and there is no 12-digit run in
    it."""
    assert redact(text) == text
    assert Memo(text=text).text == text


def test_the_exemption_set_is_unchanged_and_still_not_an_intrusion() -> None:
    """The fix is a second pass, not a narrowing. If a future change
    "closes" this by moving members out of the set, ordinary Spanish breaks
    and this fails first."""
    assert len(_LATIN_SCRIPT_EXEMPTIONS) == 18
    for char in _LATIN_SCRIPT_EXEMPTIONS:
        assert not _is_script_intrusion(char), f"U+{ord(char):04X} became an intrusion"


def test_an_exemption_at_a_token_edge_is_not_bridged() -> None:
    """Residual 2 applies here unchanged: both sides of a block must be
    ASCII alphanumeric, because the only rule that bridges an edge fires on
    every word abutting an ordinal."""
    assert redact("PAGAMENT 3ª FASE") == "PAGAMENT 3ª FASE"


def test_two_qualifying_digit_runs_in_one_span_disclose_nothing() -> None:
    """Which run's last four would be disclosed is not knowable, so none is
    -- the same refusal `_find_iban_in_token` makes for two checksumming
    starts."""
    text = f"{PAN}º{LUHN_PAN}"
    out = redact(text)
    assert out == _MASK, out

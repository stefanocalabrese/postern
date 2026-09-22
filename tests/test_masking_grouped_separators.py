"""Separator-grouped PAN and IBAN redaction (audit finding C-07, leak 1).

`_PAN_IN_TEXT_RE` was `\\d{12,}` and `_IBAN_IN_TEXT_RE` was
`[A-Za-z0-9]{14,}`: both required an uninterrupted run, while
`masking._SEPARATORS` had always accepted the same groupings for
`MaskedPan`/`MaskedIban`. So the two halves of one module disagreed about
what a card number looks like, and the free-text half -- the half that sees
attacker-controllable memo text -- lost. Measured through the real
`_redact_free_text` before the fix, all four leaked verbatim:

    Card 4111 1111 1111 4417 x
    Card 4111-1111-1111-4417 x
    Card 4111.1111.1111.4417 x
    IBAN ES91 2100 0418 4502 0005 1332 x

The counterweight is `test_ordinary_grouped_digits_are_not_masked` and the
corpora in `tests/test_masking_homoglyph_measurement.py`: bridging a
separator is bridging a break a reader uses to tell two numbers apart, so
every rule here has to be checked against text that groups digits for
reasons that have nothing to do with cards.
"""

import pytest
from postern_core.domain.masking import (
    _FREE_TEXT_GROUP_SEPARATORS,
    _MASK,
    FreeText,
    _luhn_ok,
    _redact_free_text,
    redaction_budget,
)
from pydantic import BaseModel, ConfigDict

from tests.fixtures import backend_responses as fx


class Memo(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    text: FreeText


def redact(text: str) -> str:
    """Through an ambient budget, the way `AuditMiddleware.on_call_tool`
    calls this. A per-string fallback budget would also pass every test
    here; using the ambient one keeps the checksum spend visible to the
    same accounting the request path uses."""
    with redaction_budget():
        return _redact_free_text(text)


# --- The measured leak table, row by row ------------------------------------


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        (f"Card {fx.GROUPED_PAN} x", fx.GROUPED_PAN),
        (f"Card {fx.HYPHEN_PAN} x", fx.HYPHEN_PAN),
        (f"Card {fx.DOTTED_PAN} x", fx.DOTTED_PAN),
        (f"Card {fx.NBSP_PAN} x", fx.NBSP_PAN),
        (f"Card {fx.GROUPED_LUHN_PAN} x", fx.GROUPED_LUHN_PAN),
        (f"IBAN {fx.GROUPED_IBAN} x", fx.GROUPED_IBAN),
        (f"IBAN {fx.HYPHEN_IBAN} x", fx.HYPHEN_IBAN),
    ],
)
def test_a_grouped_value_no_longer_reaches_the_output(text: str, leaked: str) -> None:
    out = redact(text)
    assert leaked not in out, f"{text!r} -> {out!r}"
    assert _MASK in out, f"{text!r} -> {out!r} was not redacted at all"


def test_the_contiguous_forms_are_unchanged_by_the_grouped_path() -> None:
    """The one direction this change is not allowed to go. Every contiguous
    shape must produce byte-identically what it produced before C-07,
    including the last four the module discloses for a length-plausible run
    and the bare marker it refuses to decorate for an over-long one."""
    assert redact(f"Card {fx.FULL_PAN} purchase") == f"Card {_MASK} 4417 purchase"
    assert redact(f"Card {fx.LUHN_PAN} purchase") == f"Card {_MASK} 1111 purchase"
    assert redact(f"ref {fx.FULL_IBAN} end") == f"ref ES•• {_MASK} 1332 end"
    assert redact(f"ref {fx.LOWERCASE_IBAN} end") == f"ref ES•• {_MASK} 1332 end"
    # 30 digits: the reported leak that made the run pattern unbounded.
    assert redact("378282246310005378282246310005") == _MASK


def test_a_contiguous_run_inside_a_grouped_span_is_still_masked() -> None:
    """The regression the grouped path could most easily have introduced.
    "4111111111114417 2026" is ONE grouped run of twenty digits, which the
    grouped rule declines (over `_PAN_MAX_DIGITS`). Declining must mean
    falling back to the contiguous pattern inside the span, not leaving the
    span alone -- the sixteen contiguous digits in it were masked before
    this change existed."""
    out = redact(f"Card {fx.FULL_PAN} 2026 x")
    assert fx.FULL_PAN not in out, out
    assert out == f"Card {_MASK} 4417 2026 x", out


def test_grouped_masking_leaves_no_digit_against_the_mask() -> None:
    """The reassembly invariant, on the grouped path. Whatever is emitted,
    no digit may sit immediately against a mask -- that is the shape that
    let the PAN scan rebuild an AmEx number out of its own output."""
    for text in (
        f"{fx.GROUPED_PAN} 2026",
        f"2026 {fx.GROUPED_PAN}",
        f"x{fx.GROUPED_LUHN_PAN}x",
        "4111 1111 1111 4417 4111 1111 1111 4417",
    ):
        out = redact(text)
        for index, char in enumerate(out):
            if char != _MASK[0]:
                continue
            before = out[index - 1] if index else ""
            after = out[index + 1] if index + 1 < len(out) else ""
            assert not before.isdigit(), f"{text!r} -> {out!r}"
            assert not after.isdigit(), f"{text!r} -> {out!r}"


# --- The gate, and what it deliberately does not catch ----------------------


def test_the_fixture_pan_is_not_luhn_valid() -> None:
    """The fact the whole grouped-PAN gate design turns on, pinned so it
    cannot be rediscovered as a surprise. `FULL_PAN` is the value every row
    of the C-07 leak table is written with, and no payment network would
    accept it -- so a Luhn-only gate would have closed the leak for real
    cards while leaving the audit's own reproduction wide open."""
    assert not _luhn_ok(fx.FULL_PAN)
    assert _luhn_ok(fx.LUHN_PAN)


def test_a_luhn_valid_card_discloses_its_last_four() -> None:
    """Positive identification earns the disclosure `MaskedPan` is approved
    to make; nothing weaker does."""
    assert redact(f"pago {fx.GROUPED_LUHN_PAN} gracias") == f"pago {_MASK} 1111 gracias"


def test_a_card_shaped_run_that_does_not_checksum_discloses_nothing() -> None:
    """`FULL_PAN` grouped: card-shaped (opens with MII 4, sixteen digits,
    printed four-by-four) but not checksumming, so it is masked without a
    last four. Asserting anything about what it ends with would be the
    confident-and-wrong disclosure this module refuses elsewhere."""
    assert redact(f"pago {fx.GROUPED_PAN} gracias") == f"pago {_MASK} gracias"


@pytest.mark.parametrize(
    "text",
    [
        "FACTURA 2026-09-22 IMPORTE 1234.56",
        "PERIODE 01-09-2026 30-09-2026",
        "PEDIDO 2024 2025 2026 2027",
        "TELEFON 0034 612 345 678",
        "IMPORT 1.234.567.890,12 EUR",
        "PARKING 22.09.2026 09.15 A 18.45",
        "AMAZON PEDIDO 405 1234567 8901234",
        "RESERVA 2026 0922 1145 HOTEL BCN",
        "EXPEDIENT 2026-0912-000345",
        "CORREOS PQ 0012 3456 7890 ES",
    ],
)
def test_ordinary_grouped_digits_are_not_masked(text: str) -> None:
    """Ordinary Spanish and Catalan memo text that groups digits for reasons
    that have nothing to do with cards. Every one of these is masked by a
    grouped rule that only counts digits -- a date beside an amount is
    fourteen of them -- which is why the gate exists. Measured over 61 such
    memos: 34% masked with no gate, 4.9% with the shipped one."""
    assert redact(text) == text


def test_the_separator_set_excludes_vertical_whitespace() -> None:
    """A value grouped along one line is one value. Two values on adjacent
    lines are two, and welding a column of four-digit numbers into a
    sixteen-digit "card" is the failure this exclusion prevents. TAB is
    excluded with them: its job in real text is column separation.

    Checked on TAB, LF and CR only, and the other two are worth a sentence
    rather than a silent omission: VT (U+000B) and FF (U+000C) are also
    absent from the separator set, but `_strip_invisible` deletes them
    before either scan runs -- they are `Cc` and not in
    `_VISIBLE_WHITESPACE_CONTROLS` -- so a column joined by one arrives at
    the scan already contiguous and is masked. That is this module's
    pre-existing strip behaviour rather than anything this test's subject
    does, and it errs toward masking, so it is recorded here and not
    asserted as non-masking.
    """
    for char in "\t\n\r\v\f":
        assert char not in _FREE_TEXT_GROUP_SEPARATORS
    for char in "\t\n\r":
        column = char.join(["4111", "1111", "1111", "1111"])
        assert redact(column) == column, f"U+{ord(char):04X} welded a column"


def test_two_separators_in_a_row_do_not_bridge() -> None:
    """Exactly one separator between digits. A real grouping uses one;
    allowing runs of them only widens what an arbitrary pair of numbers can
    be welded into."""
    text = "4111  1111  1111  1111"
    assert redact(text) == text


# --- The grouped IBAN's shape, and why it is not the PAN rule ---------------


def test_prose_is_not_treated_as_a_grouped_iban() -> None:
    """The reason the grouped IBAN alternative matches only ISO 13616's
    print format instead of bridging any two alphanumerics. An IBAN token
    is alphanumeric, so a general rule makes a whole sentence one candidate
    -- and this module's own measurement of a full scan over an arbitrary
    31-character token is that it masks 19.8% of them."""
    for text in (
        "the quick brown fox jumps over the lazy dog again",
        "TRANSFERENCIA NOMINA JOSE MUNOZ SANCHEZ FEBRERO DOS MIL",
        "PAGO FRA REF NOTA ALTA BAJA ANUL DESC IMPO NETO BRUT",
    ):
        assert redact(text) == text, text


def test_a_grouped_iban_discloses_nothing_because_its_end_is_not_knowable() -> None:
    """Found by running the audit's own leak table against the first version
    of this change: "IBAN ES91 2100 0418 4502 0005 1332 x" came back as
    "IBAN ES.. .... 332X" -- the trailing " x" was consumed as a final
    group, and the 25-character reading mod-97-checksums exactly as the real
    24-character IBAN does, so the longest-at-a-start rule published a last
    four that is not any account's. A separator-delimited span has an
    identification but not a delimitation, and a disclosure needs both."""
    out = redact(f"IBAN {fx.GROUPED_IBAN} x")
    assert fx.GROUPED_IBAN not in out
    assert "332X" not in out and "1332" not in out, out
    assert out == f"IBAN {_MASK}", out


def test_a_word_after_a_grouped_iban_costs_at_most_the_word() -> None:
    """The accepted over-redaction, bounded and named. The whole matched
    span is replaced, so a four-character word directly after a grouped
    IBAN is deleted with it. The eight-group cap on the pattern is what
    keeps this at a word rather than a sentence."""
    out = redact(f"Transferencia {fx.GROUPED_IBAN} pago alquiler")
    assert fx.GROUPED_IBAN not in out
    assert out.startswith("Transferencia ")
    assert out.endswith(" alquiler"), out


def test_a_short_national_format_grouped_in_fours_is_still_found() -> None:
    """Norway's 15-character format groups as 4-4-4-3, so the optional short
    final group in the pattern is load-bearing rather than cosmetic: without
    it the match would end after twelve characters and the real IBAN would
    not be in it."""
    grouped = "NO93 8601 1117 947"
    out = redact(f"ref {grouped} end")
    assert grouped not in out
    assert _MASK in out, out


def test_the_public_field_agrees_with_the_private_function() -> None:
    """Everything above drives `_redact_free_text`. This is the same claim
    through Pydantic's `AfterValidator` machinery, which is what production
    actually runs."""
    assert fx.GROUPED_PAN not in Memo(text=f"Card {fx.GROUPED_PAN} x").text
    assert fx.GROUPED_IBAN not in Memo(text=f"IBAN {fx.GROUPED_IBAN} x").text

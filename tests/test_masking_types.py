import re

import pytest
from postern_core.domain.masking import (
    _IBAN_MASKED_RE,
    _MASK,
    _PAN_MASKED_RE,
    FreeText,
    MaskedIban,
    MaskedPan,
)
from pydantic import BaseModel, ConfigDict, ValidationError


class Memo(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    text: FreeText


class Card(BaseModel):
    # Masking is a type property, but Pydantic's own error formatting still
    # echoes the raw offending input via `input_value` in every
    # ValidationError unless the consuming model opts out. This scrubs
    # str()/repr() of the exception; it does NOT scrub errors()/.json() --
    # see the module docstring and the leak tests below. Any real model
    # built on MaskedPan/MaskedIban must set this too.
    model_config = ConfigDict(hide_input_in_errors=True)

    pan: MaskedPan


class Account(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    iban: MaskedIban


def test_pan_is_masked_on_construction() -> None:
    assert Card(pan="4111111111114417").pan == "•••• 4417"


def test_pan_masking_is_stable() -> None:
    assert Card(pan="4111 1111 1111 4417").pan == Card(pan="4111111111114417").pan


def test_pan_already_masked_is_idempotent() -> None:
    assert Card(pan="•••• 4417").pan == "•••• 4417"


def test_pan_too_short_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Card(pan="417")


def test_pan_with_nbsp_separators_is_masked() -> None:
    """A PAN copy-pasted from a rendered HTML statement is commonly grouped
    with non-breaking spaces, not plain ones."""
    assert Card(pan="4111\xa01111\xa01111\xa04417").pan == "•••• 4417"


def test_pan_with_non_breaking_hyphen_separators_is_masked() -> None:
    assert Card(pan="4111‑1111‑1111‑4417").pan == "•••• 4417"


def test_iban_keeps_country_code_and_last_four() -> None:
    assert Account(iban="ES9121000418450200051332").iban == "ES•• •••• 1332"


def test_iban_without_country_code_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Account(iban="9121000418450200051332")


def test_iban_already_masked_is_idempotent() -> None:
    assert Account(iban="ES•• •••• 1332").iban == "ES•• •••• 1332"
    # Maltese IBANs end in letters, not digits; a mask regex requiring
    # [0-9]{4} silently rejects an already-masked value like this one on
    # any re-validation (cache rehydration, model_validate(model_dump())).
    assert Account(iban="MT•• •••• 001S").iban == "MT•• •••• 001S"


def test_masked_pan_serializes_as_a_plain_string() -> None:
    assert Card(pan="4111111111114417").model_dump_json() == '{"pan":"•••• 4417"}'


def test_plain_errors_leaks_the_raw_input_by_design() -> None:
    """Pydantic attaches the raw input to the error object. The type cannot
    prevent this. Callers MUST use errors(include_input=False).

    This is a characterization test, not a regression test: it asserts the
    hazard exists, on purpose. Every other test in this file that checks
    `errors(include_input=False)` proves the safe call pattern is safe; none
    of them prove the unsafe default is unsafe, because a call that is
    clean by construction passes regardless of what the type does. If a
    future Pydantic version changes this behaviour, this test fails loudly
    and someone re-reads the rule in the module docstring, rather than the
    hazard silently disappearing (fine) or silently worsening (not fine)."""
    with pytest.raises(ValidationError) as exc_info:
        Card(pan="card 4111111111114417 exp 12/28")
    assert "4111111111114417" in repr(exc_info.value.errors())
    assert "4111111111114417" not in repr(exc_info.value.errors(include_input=False))


def test_pan_with_mask_prefix_and_appended_full_pan_is_rejected() -> None:
    """A value that merely starts with the mask marker must not be coerced
    into a well-formed mask. Strict-parse rejects it outright instead of
    accepting whatever digits happen to be attached after it. The raw PAN
    must not leak through any representation of the resulting error:
    str()/repr() are scrubbed by hide_input_in_errors, but errors() and
    .json() are not unless called with include_input=False -- that is a
    caller obligation the type cannot enforce, so this test locks in the
    call shape that actually closes the leak."""
    leaky = "•••• 4417 extra 4111111111114417"
    with pytest.raises(ValidationError) as exc_info:
        Card(pan=leaky)
    exc = exc_info.value
    assert "4111111111114417" not in str(exc)
    assert "4111111111114417" not in repr(exc.errors(include_input=False))
    assert "4111111111114417" not in exc.json(include_input=False)


def test_iban_with_mask_substring_and_appended_full_iban_is_rejected() -> None:
    """A value that merely contains the mask marker somewhere must not be
    coerced into a well-formed mask. Strict-parse rejects it outright."""
    leaky = "ES•••• 1332 ES9121000418450200051332"
    with pytest.raises(ValidationError) as exc_info:
        Account(iban=leaky)
    exc = exc_info.value
    assert "9121000418450200051332" not in str(exc)
    assert "9121000418450200051332" not in repr(exc.errors(include_input=False))
    assert "9121000418450200051332" not in exc.json(include_input=False)


def test_bogus_and_attacker_controlled_values_are_rejected() -> None:
    """Well-formed-looking garbage must not be coerced into a confident,
    wrong last-four. None of these are real card numbers or IBANs."""
    with pytest.raises(ValidationError):
        Account(iban="XX0000")
    with pytest.raises(ValidationError):
        Account(iban="hello world 1332")
    with pytest.raises(ValidationError):
        Card(pan="+34 600 123 456")
    with pytest.raises(ValidationError):
        Card(pan="card 4111111111114417 exp 12/28")


def test_two_pans_sharing_last_four_render_identically() -> None:
    """Deliberate under minimization: last-4 masking cannot distinguish two
    cards that happen to share their last four digits. Do not widen this to
    more digits to "fix" the collision; the collision is the point."""
    assert Card(pan="4111111111114417").pan == Card(pan="5500000000004417").pan


def test_two_ibans_sharing_last_four_render_identically() -> None:
    """Same deliberate collision as above, for IBANs. Both values below are
    real mod-97-valid ES IBANs that happen to share their last four digits."""
    assert (
        Account(iban="ES9121000418450200051332").iban
        == Account(iban="ES8921000418450200091332").iban
    )


@pytest.mark.parametrize(
    "iban",
    [
        "ES9121000418450200051332",  # ends in digits
        "GB29NWBK60161331926819",  # ends in digits
        "MT84MALT011000012345MTLCAST001S",  # ends in letters
        "SC18SSCB11010000000000001497USD",  # ends in letters
        "BR9700360305000010009795493P1",  # ends in letters
    ],
)
def test_iban_masking_round_trips_through_re_validation(iban: str) -> None:
    """A masked IBAN must itself validate as an already-masked value for
    every country shape, not just ones whose national check digits happen
    to be numeric. ES and GB round-trip trivially and would miss a
    regression here; MT, SC and BR end in letters and are the ones that
    actually exercise the already-masked pattern's last-four character
    class."""
    masked = Account(iban=iban).iban
    remasked = Account(iban=masked).iban
    assert remasked == masked


# Hostile PAN-shaped inputs: bare, spaced, hyphenated, embedded in prose,
# before/after the mask marker, separated by whitespace variants (some now
# recognized separators, some deliberately not -- zero-width space stays
# rejected), and Unicode (Arabic-Indic) digits, which must never be treated
# as equivalent to ASCII digits regardless of where they appear.
_PAN_HOSTILE_INPUTS = [
    "4111111111114417",
    "4111 1111 1111 4417",
    "4111-1111-1111-4417",
    "my card number is 4111111111114417 thanks",
    "•••• 0000 4111111111114417",
    "4111111111114417 •••• 0000",
    "4111\n1111\n1111\n4417",
    "4111\t1111\t1111\t4417",
    "4111​1111​1111​4417",
    "4111\xa01111\xa01111\xa04417",
    "4111 1111 1111 ٤٤١٧",
]

# Same shapes, for a full IBAN.
_IBAN_HOSTILE_INPUTS = [
    "ES9121000418450200051332",
    "ES91 2100 0418 4502 0005 1332",
    "es9121000418450200051332",
    "IBAN: ES9121000418450200051332 please",
    "ES•• •••• 1332 ES9121000418450200051332",
    "ES9121000418450200051332 ES•• •••• 1332",
    "ES91\n2100\n0418\n4502\n0005\n1332",
    "ES91\t2100\t0418\t4502\t0005\t1332",
    "ES91​21000418450200051332",
    "ES91\xa021000418450200051332",
]


@pytest.mark.parametrize("value", _PAN_HOSTILE_INPUTS)
def test_pan_hostile_inputs_never_leak(value: str) -> None:
    """Whichever branch a hostile PAN-shaped input takes, the invariant
    holds exactly, not heuristically: an accepted value is exactly the
    canonical masked shape (a loose digit-run/bullet-count check would
    still pass a regression that put a space-grouped PAN behind the
    marker); a rejected value never echoes the raw input back through any
    representation of the error, including the structured ones
    hide_input_in_errors does not touch. This is the invariant stated once
    so it survives a rewrite of the branching logic above."""
    try:
        out = Card(pan=value).pan
    except ValidationError as exc:
        assert value not in str(exc)
        assert value not in repr(exc.errors(include_input=False))
        assert value not in exc.json(include_input=False)
        return
    assert _PAN_MASKED_RE.fullmatch(out)


@pytest.mark.parametrize("value", _IBAN_HOSTILE_INPUTS)
def test_iban_hostile_inputs_never_leak(value: str) -> None:
    """Same invariant as above, for IBAN-shaped hostile input."""
    try:
        out = Account(iban=value).iban
    except ValidationError as exc:
        assert value not in str(exc)
        assert value not in repr(exc.errors(include_input=False))
        assert value not in exc.json(include_input=False)
        return
    assert _IBAN_MASKED_RE.fullmatch(out)


def test_free_text_redacts_an_embedded_iban_and_pan() -> None:
    """Unstructured remittance information is exactly where a counterparty
    IBAN or a card reference appears in ISO 20022 traffic (security review,
    Task 3, second round)."""
    memo = Memo(text="SEPA CT ES9121000418450200051332 CARD 4111111111114417")
    assert memo.text == "SEPA CT ES•• •••• 1332 CARD •••• 4417"
    assert "ES9121000418450200051332" not in memo.text
    assert "4111111111114417" not in memo.text


def test_free_text_leaves_ordinary_merchant_text_unchanged() -> None:
    memo = Memo(text="Coffee at Blue Bottle, Barcelona")
    assert memo.text == "Coffee at Blue Bottle, Barcelona"


def test_free_text_leaves_an_iban_shaped_but_invalid_checksum_string_unchanged() -> None:
    """IBAN-shaped (two letters, two digits, alnum) but failing the mod-97
    checksum: not a real IBAN, so a merchant reference that happens to look
    like one is not corrupted on a false positive. Its digits are broken up
    by letters ("XY99ABCD123456"), so the separate PAN scan does not catch
    it either -- a pure 12+ digit run embedded in an IBAN-shaped-but-invalid
    string (no letters breaking it up) would still get masked as PAN-shaped
    on its own merits, which is over-redaction by design, not a bug; this
    test is about the string genuinely surviving both passes untouched."""
    memo = Memo(text="Reference XY99ABCD123456 for invoice")
    assert memo.text == "Reference XY99ABCD123456 for invoice"


# --- Free-text digit runs longer than a PAN (leak found by security review) ---

_DIGIT_RUN_RE = re.compile(r"[0-9]+")

# Two sources for contiguous digit runs, sliced to each length under test.
# "ascending" is structure-only filler. "amex-repeated" repeats a complete,
# Luhn-valid 15-digit American Express number, so that a redaction which
# emits a last-four and leaves an unconsumed remainder of the same run
# concatenates the two back into a real card number -- which is exactly the
# reported leak at length 30.
_DIGIT_RUN_SOURCES = {
    "ascending": "1234567890" * 5,
    "amex-repeated": "378282246310005" * 4,
}


def _luhn_ok(digits: str) -> bool:
    """Luhn check (ISO/IEC 7812-1 Annex B), the card-number check digit."""
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _long_digit_runs(text: str) -> list[str]:
    """Digit runs of 13 or more, i.e. long enough to be most real PANs."""
    return [run for run in _DIGIT_RUN_RE.findall(text) if len(run) >= 13]


def _luhn_valid_pan_substrings(text: str) -> list[str]:
    """Every 13-to-19-digit substring of `text` that passes Luhn.

    This is the assertion that actually encodes "a real card number
    survived the redaction". A length check alone would pass a 15-digit run
    of arbitrary digits; this one only fires on something a payment network
    would accept as a PAN.
    """
    found: list[str] = []
    for run in _DIGIT_RUN_RE.findall(text):
        for length in range(13, 20):
            for start in range(len(run) - length + 1):
                candidate = run[start : start + length]
                if _luhn_ok(candidate):
                    found.append(candidate)
    return found


def test_luhn_helper_agrees_with_known_card_numbers() -> None:
    """The leak assertions below are only as good as this helper."""
    assert _luhn_ok("378282246310005")  # AmEx, the number in the reported leak
    assert _luhn_ok("4111111111111111")  # the canonical Visa test number
    assert not _luhn_ok("378282246310006")
    assert not _luhn_ok("1234567890123")


def test_free_text_bare_thirty_digit_run_does_not_reconstitute_a_pan() -> None:
    """Measured leak: a 30-digit run was matched as 19 digits, replaced by
    the mask plus THAT RUN's last four, and the unconsumed 11-digit
    remainder left immediately after it -- so the mask's own last four
    concatenated with the residue into 378282246310005, a complete valid
    AmEx number. The redaction was helping reconstitute the card."""
    out = Memo(text="378282246310005378282246310005").text
    assert "378282246310005" not in out
    assert _long_digit_runs(out) == []
    assert _luhn_valid_pan_substrings(out) == []


def test_free_text_embedded_thirty_digit_run_does_not_reconstitute_a_pan() -> None:
    out = Memo(text="paid 378282246310005378282246310005 today").text
    assert "378282246310005" not in out
    assert _long_digit_runs(out) == []
    assert _luhn_valid_pan_substrings(out) == []


@pytest.mark.parametrize("source", sorted(_DIGIT_RUN_SOURCES))
@pytest.mark.parametrize("length", range(12, 41))
def test_free_text_digit_run_of_any_length_never_leaves_a_pan(length: int, source: str) -> None:
    """Property over every contiguous digit-run length from 12 (shortest
    PAN) to 40 (well past the longest), bare and embedded in prose.

    The invariant is stated on the OUTPUT, not on the matching strategy, so
    it survives any rewrite of the regex: whatever the redaction emits, no
    accepted output may contain a 13+ digit run, and none may contain a
    Luhn-valid 13-to-19-digit run. A run of 12 or more must also actually
    be redacted -- an output that simply left it alone would satisfy a
    "no long run" check at length 12 while leaking."""
    run = _DIGIT_RUN_SOURCES[source][:length]
    assert len(run) == length
    for text in (run, f"paid {run} today"):
        out = Memo(text=text).text
        assert _MASK in out, f"{text!r} -> {out!r} was not redacted at all"
        assert run not in out, f"{text!r} -> {out!r} carries the run verbatim"
        assert _long_digit_runs(out) == [], f"{text!r} -> {out!r}"
        assert _luhn_valid_pan_substrings(out) == [], f"{text!r} -> {out!r}"


_WORD_CHAR_RE = re.compile(r"\w")


def _assert_iban_mask_is_token_aligned(text: str, out: str) -> None:
    """No IBAN mask in `out` may have a word character against either side.

    That adjacency is the precondition the PAN leak needed: a mask emitting
    its own last four directly against unconsumed characters of the same
    token. Checked wherever an IBAN redaction is produced.
    """
    for match in _IBAN_MASKED_RE.finditer(out):
        before = out[match.start() - 1 : match.start()]
        after = out[match.end() : match.end() + 1]
        assert not _WORD_CHAR_RE.fullmatch(before or " "), f"{text!r} -> {out!r}"
        assert not _WORD_CHAR_RE.fullmatch(after or " "), f"{text!r} -> {out!r}"


@pytest.mark.parametrize(
    "text",
    [
        "ES9121000418450200051332",
        "SEPA CT ES9121000418450200051332 thanks",
        "ref-ES9121000418450200051332-ok",
        "ES9121000418450200051332XXXXXXXXXX",  # 34 chars, the pattern's ceiling
        "ES9121000418450200051332XXXXXXXXXXX",  # 35, one past it
        "MT84MALT011000012345MTLCAST001S",
        "MT84MALT011000012345MTLCAST001SREF9",
        "ES9121000418450200051332_tail",
        "xES9121000418450200051332",
    ],
)
def test_iban_redaction_is_never_adjacent_to_a_word_character(text: str) -> None:
    """The PAN leak's mechanism has no IBAN analogue, and this is why.

    The PAN scan could match a PAN-length WINDOW of a longer digit run and
    leave the rest of that run touching the mask, so the mask's own last
    four concatenated with the residue. `_IBAN_IN_TEXT_RE` cannot do that:
    it is `\\b`-anchored at both ends and every character it can match is a
    word character, so a match is always a whole word-character token, never
    a proper substring of a longer one. The IBAN pass then replaces that
    whole token, tail included, so there is never an unconsumed remainder
    of it left against the emitted mask.

    Asserted on the output: no redaction the IBAN pass emits may have a
    word character against either side of it, which is the precondition the
    reconstitution needs and cannot get. This is the guard to re-run if
    anyone re-bounds the candidate pattern or drops a `\\b`, and it is the
    reason the tail of a token cannot be preserved beside the mask.
    """
    _assert_iban_mask_is_token_aligned(text, Memo(text=text).text)


def test_free_text_still_scans_iban_before_pan() -> None:
    """The IBAN pass must keep running first: the PAN scan consuming an
    IBAN's numeric run would leave nothing IBAN-shaped for the IBAN pass to
    recognize, costing the country code the IBAN mask is supposed to keep.
    An input carrying both an IBAN and an over-long digit run must redact
    both, each in its own shape."""
    text = "SEPA ES9121000418450200051332 ref 378282246310005378282246310005"
    out = Memo(text=text).text
    assert out == "SEPA ES•• •••• 1332 ref ••••"
    assert "ES9121000418450200051332" not in out
    assert "378282246310005" not in out
    assert _long_digit_runs(out) == []
    assert _luhn_valid_pan_substrings(out) == []


# --- An IBAN with a tail glued to it (second hole, same lesson) --------------
#
# Every value below is mod-97 valid. These are the country shapes whose BBAN
# carries letters, so their digit runs are short and the PAN pass does not
# incidentally destroy what the IBAN pass missed. "MT-synth" is the worst
# case and the one that leaked completely: a real-format MT IBAN
# (MT 2!n 4!a 5!n 18!c) whose longest digit run is 5, so once a tail
# defeated the IBAN scan, NOTHING in either pass touched it.
_TAILED_IBANS = {
    "MT-synth": ("MT92MALT01100ABCDEFGH1234IJKL56", "MT•• •••• KL56"),
    "MT-real": ("MT84MALT011000012345MTLCAST001S", "MT•• •••• 001S"),
    "SC": ("SC18SSCB11010000000000001497USD", "SC•• •••• 7USD"),
    "BR": ("BR9700360305000010009795493P1", "BR•• •••• 93P1"),
}


@pytest.mark.parametrize(
    "text",
    [
        "MT92MALT01100ABCDEFGH1234IJKL56",
        "MT92MALT01100ABCDEFGH1234IJKL56REF9",
        "MT92MALT01100ABCDEFGH1234IJKL56REF99",
    ],
)
def test_free_text_redacts_an_iban_whatever_is_glued_after_it(text: str) -> None:
    """Measured leak: appending word characters to a valid IBAN made the
    whole-token checksum fail, and the IBAN pass then gave up on the token
    entirely instead of looking at the IBAN inside it -- so a complete,
    mod-97-valid Maltese IBAN reached the output verbatim. The redaction
    must not be defeatable by concatenation."""
    assert Memo(text=text).text == "MT•• •••• KL56"


def test_free_text_redacts_an_iban_with_one_character_glued_after_it() -> None:
    """The sharpest form of the same leak, and the reason it is not just a
    ceiling problem: ONE appended letter takes the token to 32 characters,
    comfortably inside the old pattern's 34-character range, so the pattern
    matched the whole token, the checksum failed on it, and the IBAN was
    returned untouched. No length bound was involved at all."""
    assert Memo(text="MT92MALT01100ABCDEFGH1234IJKL56R").text == "MT•• •••• KL56"


@pytest.mark.parametrize("name", sorted(_TAILED_IBANS))
def test_free_text_drops_an_iban_tail_rather_than_leaving_it_beside_the_mask(
    name: str,
) -> None:
    """The emit decision, locked in: a token that contains a valid IBAN is
    replaced whole, so the output is the same with or without a tail.

    Preserving the tail is the one option that must not be taken. It would
    put the mask's own last four directly against unconsumed,
    attacker-influenced characters of the same token ("KL56" + "REF9"),
    which is precisely the shape of the PAN leak this branch already fixed,
    and it would break the token-alignment invariant above."""
    iban, expected = _TAILED_IBANS[name]
    assert Memo(text=iban).text == expected
    assert Memo(text=iban + "R").text == expected


@pytest.mark.parametrize("name", sorted(_TAILED_IBANS))
@pytest.mark.parametrize("tail_len", range(0, 11))
def test_free_text_iban_never_survives_a_tail_of_any_length(name: str, tail_len: int) -> None:
    """Property over appended-tail lengths 0 to 10, bare and in prose,
    across the country shapes whose BBAN contains letters.

    Stated on the output rather than on the matching strategy: whatever the
    IBAN pass emits, neither the IBAN nor the token it sits in may reach
    the output, something must have been redacted in IBAN shape, and the
    mask must stay token-aligned."""
    iban, _ = _TAILED_IBANS[name]
    tail = "REF9A7X2QZ"[:tail_len]
    token = iban + tail
    for text in (token, f"SEPA CT {token} ok"):
        out = Memo(text=text).text
        assert iban not in out, f"{text!r} -> {out!r} carries the IBAN verbatim"
        assert token not in out, f"{text!r} -> {out!r} carries the token verbatim"
        assert _IBAN_MASKED_RE.search(out), f"{text!r} -> {out!r} was not redacted"
        _assert_iban_mask_is_token_aligned(text, out)

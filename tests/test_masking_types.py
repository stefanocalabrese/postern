import asyncio
import re
import unicodedata

import pytest
from postern_core.domain.masking import (
    _DEFAULT_IGNORABLE_UNASSIGNED_RANGES,
    _IBAN_MASKED_RE,
    _IBAN_SCAN_BUDGET,
    _IBAN_SCAN_MAX_TOKEN,
    _MASK,
    _PAN_MASKED_RE,
    FreeText,
    MaskedIban,
    MaskedPan,
    RedactionScope,
    _current_budget,
    _has_qualifying_start,
    redaction_budget,
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


_ALNUM_CHAR_RE = re.compile(r"[A-Za-z0-9]")


def _assert_iban_mask_is_token_aligned(text: str, out: str) -> None:
    """No IBAN mask in `out` may have an alphanumeric character against
    either side, and something must actually have been redacted.

    That adjacency is the precondition the PAN leak needed: a mask emitting
    its own last four directly against unconsumed characters of the same
    token. Checked wherever an IBAN redaction is produced.

    The first assertion exists because this check is otherwise vacuous: on
    unfixed code, `_IBAN_MASKED_RE.finditer(out)` finds zero matches for an
    input the boundary bug defeats entirely (e.g. an IBAN with an
    underscore glued to it), the loop body never runs, and a helper with no
    failing assertion "passes" -- proving nothing about the input it was
    called with. `out != text` is deliberately the broad "some redaction
    ran" check, not "a structured IBAN mask specifically": a token that
    turns out to be ambiguous (`_find_iban_in_token`'s `_AMBIGUOUS`) is
    correctly redacted to the bare `_MASK` marker, which does not match
    `_IBAN_MASKED_RE`, and this helper must not treat that safe outcome as
    a failure to redact.

    Uses `[A-Za-z0-9]`, not `\\w`, for the character class being checked
    against: `\\w` includes `_`, but this module's tokenization now treats
    `_` as a token separator exactly like a space or a hyphen (the
    underscore-boundary fix), so a mask legitimately sitting next to a
    literal underscore from the ORIGINAL text (as opposed to unconsumed
    alphanumeric remainder of the same token) is not the reconstitution
    shape this check exists to catch, and must not be flagged as one.
    """
    assert out != text, f"{text!r} -> {out!r} was not redacted at all"
    for match in _IBAN_MASKED_RE.finditer(out):
        before = out[match.start() - 1 : match.start()]
        after = out[match.end() : match.end() + 1]
        assert not _ALNUM_CHAR_RE.fullmatch(before or " "), f"{text!r} -> {out!r}"
        assert not _ALNUM_CHAR_RE.fullmatch(after or " "), f"{text!r} -> {out!r}"


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
    the output, something must have been redacted, and any STRUCTURED mask
    that does appear must stay token-aligned.

    Not "a structured IBAN mask must appear", which is what this asserted
    before the ambiguity rule existed. It no longer holds universally:
    "MT84MALT011000012345MTLCAST001S" plus a tail of 6 to 10 characters
    from "REF9A7X2QZ" is a genuine, found-not-invented case where the real
    IBAN at position 0 and a SECOND, coincidentally mod-97-valid substring
    starting at position 6 ("LT011000012345MTLCAST001SREF9A7...") both
    checksum inside the same token -- checked directly against
    `_find_iban_in_token`. Two valid interpretations means neither is
    disclosed (`_AMBIGUOUS` -> bare `_MASK`), which is correct and exactly
    what the ambiguity rule (see `_find_iban_in_token`) exists to do: the
    real IBAN still never reaches the output either way, which is the
    property this test is actually named for and still asserts below."""
    iban, _ = _TAILED_IBANS[name]
    tail = "REF9A7X2QZ"[:tail_len]
    token = iban + tail
    for text in (token, f"SEPA CT {token} ok"):
        out = Memo(text=text).text
        assert iban not in out, f"{text!r} -> {out!r} carries the IBAN verbatim"
        assert token not in out, f"{text!r} -> {out!r} carries the token verbatim"
        assert _MASK in out, f"{text!r} -> {out!r} was not redacted"
        _assert_iban_mask_is_token_aligned(text, out)


# --- An IBAN with junk glued to its FRONT (the third hole, same lesson) -----
#
# `_IBAN_IN_TEXT_RE`'s own opener, `[A-Za-z]{2}[0-9]{2}`, had to land at the
# very start of the `\b`-bounded token. One alphanumeric character glued to
# the front of a genuine IBAN moves that opening shape one position into
# the token, where the anchored pattern never looks -- not "checksums and
# fails", not attempted at all. Reusing the tail country shapes: their BBAN
# carries letters, so the digit run stays short and the PAN pass does not
# incidentally catch what the IBAN pass missed.
_FRONT_GLUED_IBANS = {
    "MT-synth": ("XMT92MALT01100ABCDEFGH1234IJKL56", "MT•• •••• KL56"),
    "MT-real": ("XMT84MALT011000012345MTLCAST001S", "MT•• •••• 001S"),
    "SC": ("XSC18SSCB11010000000000001497USD", "SC•• •••• 7USD"),
    "BR": ("XBR9700360305000010009795493P1", "BR•• •••• 93P1"),
}


@pytest.mark.parametrize("name", sorted(_FRONT_GLUED_IBANS))
def test_free_text_redacts_an_iban_with_one_character_glued_in_front(name: str) -> None:
    """Measured leak: this is the sharpest form, one character defeating
    redaction completely, across every alphanumeric country shape."""
    token, expected = _FRONT_GLUED_IBANS[name]
    assert Memo(text=token).text == expected


def test_free_text_redacts_an_iban_with_a_multi_character_prefix_glued_in_front() -> None:
    """A whole reference code glued in front, not just one stray character."""
    assert Memo(text="REF9MT92MALT01100ABCDEFGH1234IJKL56").text == "MT•• •••• KL56"


def test_free_text_redacts_an_iban_with_junk_glued_at_both_ends() -> None:
    """Front and tail junk together: neither end may defeat the other's fix."""
    assert Memo(text="REF9MT92MALT01100ABCDEFGH1234IJKL56XYZ").text == "MT•• •••• KL56"


def test_free_text_redacts_an_iban_mid_sentence_with_a_glued_prefix() -> None:
    out = Memo(text="please send to XMT92MALT01100ABCDEFGH1234IJKL56 today").text
    assert out == "please send to MT•• •••• KL56 today"
    assert "MT92MALT01100ABCDEFGH1234IJKL56" not in out


def test_free_text_still_masks_the_existing_separator_prefixed_case() -> None:
    """A non-word separator immediately before the IBAN already split the
    text into two tokens, so this case never depended on the front-glue
    fix. Locked in as a regression guard against the fix disturbing it."""
    assert Memo(text="ref:MT92MALT01100ABCDEFGH1234IJKL56").text == "ref:MT•• •••• KL56"


def test_free_text_front_glue_does_not_break_the_longest_match_choice() -> None:
    """The registry example with a coincidental mod-97-valid 18-character
    prefix (see `_find_iban_in_token`'s docstring), now with a character
    glued to the front too: the longest, genuine match must still win over
    the shorter coincidence, at whatever start position it is found."""
    assert Memo(text="XSC18SSCB11010000000000001497USD").text == "SC•• •••• 7USD"


@pytest.mark.parametrize("name", sorted(_FRONT_GLUED_IBANS))
def test_free_text_front_glued_iban_mask_is_token_aligned(name: str) -> None:
    token, _ = _FRONT_GLUED_IBANS[name]
    for text in (token, f"SEPA CT {token} ok"):
        _assert_iban_mask_is_token_aligned(text, Memo(text=text).text)


_REALISTIC_MERCHANT_DESCRIPTORS = [
    "AMZN MKTP ES*2X4B91",
    "CARREFOUR 3421 BARCELONA",
    "N26 TRANSFER REF 88213X",
    "MERCADONA S.A. TERRASSA",
    "GLOVO*ORDER9931 BCN",
    "RENFE VENTA ONLINE MADRID",
    "SPOTIFY P1234567890",
    "DECATHLON ESPANA SL",
    "OBRAS Y SERVICIOS SL FRA 2026-0912",
    "TRANSFERENCIA NOMINA SEPTIEMBRE",
]


@pytest.mark.parametrize("descriptor", _REALISTIC_MERCHANT_DESCRIPTORS)
def test_free_text_leaves_realistic_merchant_descriptors_unchanged(descriptor: str) -> None:
    """None of these are PAN- or IBAN-shaped; the front-glue fix must not
    turn an ordinary merchant descriptor into a false positive."""
    assert Memo(text=descriptor).text == descriptor


# --- The scan-cost bound: `_IBAN_SCAN_MAX_TOKEN` ----------------------------
#
# `_find_iban_in_token` scanning every qualifying start closes the
# front-glue leak, but the cost of a token that never checksums grows with
# the token's own length -- and `services/api/middleware/audit.py` runs
# `FreeText` over agent-supplied tool arguments of whatever length the
# agent sends. A token longer than `_IBAN_SCAN_MAX_TOKEN` is not scanned at
# all: it cannot be a real IBAN regardless of what it checksums to (ISO
# 13616 caps one at 34 characters), so it is replaced wholesale with the
# bare marker instead.


def test_free_text_replaces_an_over_long_token_with_a_bare_mask() -> None:
    """One character past the bound: no scan, no country code, no last
    four -- just the bare marker, the same emit-nothing shape as the PAN
    path's over-19-digit branch."""
    token = "A1" * 65  # 130 characters, 2 past the 128 bound
    assert len(token) > _IBAN_SCAN_MAX_TOKEN
    assert Memo(text=token).text == _MASK


def test_free_text_token_under_the_bound_still_gets_the_normal_scan() -> None:
    """One character under the bound: behaviour is unchanged from before
    this bound existed. A real IBAN padded out to 127 characters must
    still be found and given its proper country code and last four, not
    the bare marker."""
    iban = "MT84MALT011000012345MTLCAST001S"  # 32 chars
    padded = iban + "X" * (127 - len(iban))
    assert len(padded) == 127
    assert Memo(text=padded).text == "MT•• •••• 001S"


def test_free_text_an_iban_inside_an_over_long_token_does_not_survive() -> None:
    """The bound must not reopen the leak it sits next to: a genuine IBAN
    embedded in a token past the bound is masked wholesale along with the
    rest of the token, never left readable because the scan that would
    have found it never ran."""
    iban = "MT84MALT011000012345MTLCAST001S"  # 32 chars
    token = iban + "X" * (_IBAN_SCAN_MAX_TOKEN + 50 - len(iban))
    assert len(token) > _IBAN_SCAN_MAX_TOKEN
    out = Memo(text=token).text
    assert iban not in out
    assert out == _MASK


# --- The call-wide checksum budget: `_IBAN_SCAN_BUDGET` --------------------
#
# `_IBAN_SCAN_MAX_TOKEN` alone bounds one token's cost, not a payload made
# of many token-sized pieces -- an attacker who tokenizes their own input
# controls token count as much as token length. `_ScanBudget` makes the
# allowance a property of the whole `_redact_free_text` call: once spent,
# no further token is scanned at all, and must still be masked, never left
# readable, because an un-scanned token might contain a real IBAN.

# One 128-character junk token that never checksums spends 559 checksum
# operations (measured directly against `_find_iban_in_token`); comfortably
# more than enough of them exhausts `_IBAN_SCAN_BUDGET` well before the
# trailing real IBAN below is reached, however the exact per-token cost
# might shift with a future change to the scan itself.
_JUNK_TOKENS_TO_EXHAUST_BUDGET = _IBAN_SCAN_BUDGET // 100 + 50


def test_free_text_budget_exhaustion_still_masks_a_later_iban() -> None:
    """Once the call-wide checksum budget is spent by earlier tokens, a
    later token is not scanned at all -- `_redact_iban_match` checks
    `budget.exhausted` before ever calling `_find_iban_in_token` -- but it
    must still be masked (bare `_MASK`, fail closed), never left readable
    just because scanning it was skipped."""
    junk = " ".join(["AB12" * 32] * _JUNK_TOKENS_TO_EXHAUST_BUDGET)  # 128-char tokens
    real_iban = "MT84MALT011000012345MTLCAST001S"
    text = f"{junk} {real_iban}"
    out = Memo(text=text).text
    assert real_iban not in out, f"budget exhaustion let a real IBAN through: {out!r}"
    # The trailing IBAN specifically must have been bare-masked (no country
    # code, no last four), which is the observable signature of "was not
    # scanned" rather than "was scanned and happened to be ambiguous".
    assert out.endswith(_MASK), f"trailing token was not bare-masked: {out!r}"


def test_free_text_budget_exhaustion_does_not_affect_a_value_within_budget() -> None:
    """Sanity check on the fixture above: comfortably fewer junk tokens
    than needed to exhaust the budget must still let the trailing real IBAN
    resolve normally, proving the previous test's failure mode (if it were
    to fail) is genuinely about budget exhaustion and not some unrelated
    breakage."""
    junk = " ".join(["AB12" * 32] * 3)  # far fewer than needed to exhaust
    real_iban = "MT84MALT011000012345MTLCAST001S"
    text = f"{junk} {real_iban}"
    out = Memo(text=text).text
    assert out.endswith("MT•• •••• 001S")


# --- The ambiguity rule: exactly one checksum-valid start wins, two or
# more get the bare mask, never a guess ------------------------------------
#
# `_find_iban_in_token` used to return on the FIRST start position that
# checksummed. That is wrong across starts (only right within one, for
# "SC18SSCB..."-style coincidental short prefixes of a longer real IBAN):
# a coincidental hit at an early start can end in the middle of a real IBAN
# sitting further right in the same token. The three tokens below are
# exactly this, found by review, not invented for the test.
_AMBIGUOUS_TOKENS = [
    "NB91ODZDOC9IMT92MALT01100ABCDEFGH1234IJKL56",
    "BV18UVW53EMT92MALT01100ABCDEFGH1234IJKL56",
    "ZZ99MU17BOMM0101101030300200000MUR",
]


@pytest.mark.parametrize("token", _AMBIGUOUS_TOKENS)
def test_free_text_ambiguous_token_gets_the_bare_mask_not_a_guess(token: str) -> None:
    """More than one start position checksums in each of these. The safe
    output is the bare marker, matching the over-length and
    budget-exhausted branches: no country code and no last four, because
    neither can be disclosed without picking one interpretation over
    another with nothing but luck to justify the pick."""
    out = Memo(text=token).text
    assert out == _MASK
    assert "MT92MALT01100ABCDEFGH1234IJKL56" not in out


def test_free_text_unambiguous_token_still_gets_the_full_mask() -> None:
    """The other half of the same rule: exactly one checksum-valid start
    must still resolve to the ordinary structured mask, not the bare one --
    the ambiguity rule must not turn into "always bare-mask a multi-start
    scan". Every front-glue and tail test elsewhere in this file already
    exercises this; this is the rule stated as its own, explicit test."""
    assert Memo(text="MT84MALT011000012345MTLCAST001S").text == "MT•• •••• 001S"


# --- Underscore family: `_` must not defeat tokenization -------------------
#
# `\b` is defined against `\w`, which includes `_`, so the old boundary let
# an underscore glued to an IBAN suppress the whole scan the same way one
# glued alphanumeric character used to (the front-glue hole this module
# already closed once). `(?<![A-Za-z0-9])`/`(?![A-Za-z0-9])` treats `_`
# as a separator instead, the same as a space or a hyphen.
@pytest.mark.parametrize(
    "text",
    [
        "_MT92MALT01100ABCDEFGH1234IJKL56",
        "MT92MALT01100ABCDEFGH1234IJKL56_",
        "REF_MT92MALT01100ABCDEFGH1234IJKL56",
    ],
)
def test_free_text_underscore_does_not_defeat_redaction(text: str) -> None:
    out = Memo(text=text).text
    assert "MT92MALT01100ABCDEFGH1234IJKL56" not in out
    assert "•• •••• KL56" in out


def test_pan_pass_is_not_affected_by_underscore() -> None:
    """Verified, not assumed: `_PAN_IN_TEXT_RE` (`\\d{12,}`) has no `\\b`
    at all, so it is unanchored and cannot be defeated by an underscore the
    way the old IBAN pattern was."""
    for text in (
        "_4111111111114417",
        "4111111111114417_",
        "REF_4111111111114417",
    ):
        out = Memo(text=text).text
        assert "4111111111114417" not in out
        assert _MASK in out


# --- Zero-width and combining-mark family: invisible/format characters must
# not defeat tokenization either --------------------------------------------
#
# Unlike a space or a hyphen, these render as nothing (Cf) or as an accent
# on the previous character (Mn) -- a human or a model reading the
# RENDERED text sees one continuous IBAN either way, while the unstripped
# codepoint stream splits it into fragments below `_IBAN_MIN_LEN`.
_ZERO_WIDTH_SPACE = "​"
_SOFT_HYPHEN = "­"
_ZERO_WIDTH_JOINER = "‍"
_COMBINING_ACUTE_ACCENT = "́"


@pytest.mark.parametrize(
    "invisible",
    [_ZERO_WIDTH_SPACE, _SOFT_HYPHEN, _ZERO_WIDTH_JOINER, _COMBINING_ACUTE_ACCENT],
)
def test_free_text_invisible_characters_inside_an_iban_do_not_survive(invisible: str) -> None:
    iban = "MT92MALT01100ABCDEFGH1234IJKL56"
    # Scatter the character at three different positions, including inside
    # the country-code opener itself, which is the part most sensitive to
    # being split.
    planted = invisible.join([iban[:2], iban[2:15], iban[15:]])
    out = Memo(text=planted).text
    assert iban not in out
    assert planted not in out
    assert out == "MT•• •••• KL56"


def test_free_text_invisible_characters_are_removed_from_ordinary_text_too() -> None:
    """Documented, deliberate side effect: a `Cf`/`Mn` character in text
    that never touches an IBAN or PAN is still stripped."""
    out = Memo(text=f"Coffee{_ZERO_WIDTH_SPACE} at Blue Bottle").text
    assert _ZERO_WIDTH_SPACE not in out
    assert out == "Coffee at Blue Bottle"


# --- Cc control characters: render as nothing, get stripped -- except the
# visible-whitespace exceptions (tab, newline, carriage return) ------------
#
# Found live, same bug class and same day as the invisible-character family
# above: "MT92MALT01100AB\x01CDEFGH1234IJKL56" reached the output unchanged
# on the code that only stripped `Cf`/`Mn`, and "41111111\x0111114417"
# leaked a complete, Luhn-valid PAN split by the same character.
_ALL_CC_CHARACTERS = [chr(cp) for cp in (*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0))]
_VISIBLE_WHITESPACE_CC = {"\t", "\n", "\r"}
_STRIPPED_CC_CHARACTERS = [ch for ch in _ALL_CC_CHARACTERS if ch not in _VISIBLE_WHITESPACE_CC]


def test_all_enumerated_cc_characters_are_actually_category_cc() -> None:
    """Characterization test locking the enumeration above to Unicode's own
    category data, so a future Unicode version silently reclassifying one
    of these does not go unnoticed by the tests below that rely on it."""
    for ch in _ALL_CC_CHARACTERS:
        assert unicodedata.category(ch) == "Cc", f"{ch!r} (U+{ord(ch):04X}) is not Cc"


def test_the_two_reported_examples_exactly() -> None:
    """The two leaks as reported, verbatim, before the parametrized sweep
    below generalizes them."""
    assert Memo(text="MT92MALT01100AB\x01CDEFGH1234IJKL56").text == "MT•• •••• KL56"
    assert Memo(text="41111111\x0111114417").text == "•••• 4417"


@pytest.mark.parametrize("ch", _STRIPPED_CC_CHARACTERS, ids=lambda ch: f"U+{ord(ch):04X}")
def test_free_text_strips_cc_control_characters_inside_an_iban(ch: str) -> None:
    iban = "MT92MALT01100ABCDEFGH1234IJKL56"
    planted = ch.join([iban[:2], iban[2:15], iban[15:]])
    out = Memo(text=planted).text
    assert iban not in out
    assert out == "MT•• •••• KL56"


@pytest.mark.parametrize("ch", _STRIPPED_CC_CHARACTERS, ids=lambda ch: f"U+{ord(ch):04X}")
def test_free_text_strips_cc_control_characters_inside_a_pan(ch: str) -> None:
    pan = "4111111111114417"
    planted = ch.join([pan[:8], pan[8:]])
    out = Memo(text=planted).text
    assert pan not in out
    assert out == "•••• 4417"


@pytest.mark.parametrize("ch", sorted(_VISIBLE_WHITESPACE_CC), ids=lambda ch: f"U+{ord(ch):04X}")
def test_free_text_does_not_strip_visible_whitespace_controls(ch: str) -> None:
    """Tab, newline and carriage return render as a visible break, so they
    are not stripped. Planting one mid-IBAN splits the token into pieces
    too short (or, for the trailing piece, not IBAN-shaped) to redact --
    the module's own already-documented grouped-IBAN limitation, not a new
    leak: the full IBAN never appears as a contiguous run either way, and
    the character is preserved rather than silently dropped."""
    iban = "MT92MALT01100ABCDEFGH1234IJKL56"
    planted = ch.join([iban[:2], iban[2:15], iban[15:]])
    out = Memo(text=planted).text
    assert out == planted


# --- Blank-rendering characters outside Cc/Cf/Mn: enumerated individually,
# not by category (their categories are mostly ordinary visible text) -----
_HANGUL_FILLERS = ["ᅟ", "ᅠ", "ㅤ", "ﾠ"]
_BRAILLE_BLANK = "⠀"


@pytest.mark.parametrize("ch", _HANGUL_FILLERS, ids=lambda ch: f"U+{ord(ch):04X}")
def test_free_text_strips_hangul_filler_characters_inside_an_iban(ch: str) -> None:
    iban = "MT92MALT01100ABCDEFGH1234IJKL56"
    planted = ch.join([iban[:2], iban[2:15], iban[15:]])
    out = Memo(text=planted).text
    assert iban not in out
    assert out == "MT•• •••• KL56"


def test_free_text_strips_braille_pattern_blank_inside_an_iban() -> None:
    iban = "MT92MALT01100ABCDEFGH1234IJKL56"
    planted = _BRAILLE_BLANK.join([iban[:2], iban[2:15], iban[15:]])
    out = Memo(text=planted).text
    assert iban not in out
    assert out == "MT•• •••• KL56"


# --- The ambient budget: `redaction_budget` -------------------------------


def test_redaction_budget_defaults_to_no_ambient_budget() -> None:
    assert _current_budget.get() is None


def test_redaction_budget_resets_on_exception() -> None:
    """An exception raised anywhere inside the block must not leave a
    spent, stale budget ambient for whatever unrelated work runs next in
    the same context."""
    assert _current_budget.get() is None
    with pytest.raises(ValueError, match="boom"), redaction_budget(10):
        assert _current_budget.get() is not None
        raise ValueError("boom")
    assert _current_budget.get() is None


def test_redaction_budget_restores_a_nested_callers_own_budget() -> None:
    """`reset`, not a blind `set(None)`: a caller already inside its own
    `redaction_budget` block must get its own budget back, not `None`, if
    something nests another one inside it."""
    with redaction_budget(500):
        outer = _current_budget.get()
        with redaction_budget(10):
            assert _current_budget.get() is not outer
        assert _current_budget.get() is outer


async def test_redaction_budget_is_isolated_between_concurrent_tasks() -> None:
    """Two tasks each open their own `redaction_budget`, interleaved via
    `await asyncio.sleep(0)` so both context managers are active at once
    from the event loop's perspective. Neither may observe or spend from
    the other's allowance -- the property that makes this safe for
    concurrently-served requests on the same instance, proven by actually
    interleaving them rather than by running them one after the other."""
    results: dict[str, int] = {}

    async def worker(name: str, total: int) -> None:
        with redaction_budget(total):
            await asyncio.sleep(0)
            budget = _current_budget.get()
            assert budget is not None
            budget.spend()
            await asyncio.sleep(0)
            results[name] = budget.remaining

    await asyncio.gather(worker("a", 10), worker("b", 20))
    assert results == {"a": 9, "b": 19}


def test_redaction_budget_is_shared_across_separate_free_text_validations() -> None:
    """The property `redaction_budget` exists for: the allowance is spent
    down across SEPARATE `FreeText` validations inside the same block, not
    given a fresh budget for each one. A junk token that would each cost
    ~559 checksums on its own (measured against `_find_iban_in_token`)
    exhausts a small ambient budget after the first, so a genuine IBAN
    validated afterward -- in its OWN `Memo`, a separate `FreeText`
    validation -- is never scanned and comes back bare-masked rather than
    with its correct country code and last four."""
    junk = "AB12" * 32  # 128 chars, never checksums
    real_iban = "MT84MALT011000012345MTLCAST001S"
    with redaction_budget(600):  # enough for one junk token's scan, not two
        Memo(text=junk)
        out = Memo(text=f"{junk} {real_iban}").text
    assert real_iban not in out
    assert out.endswith(_MASK)


# --- The scope object `redaction_budget` yields: `exhausted`, and nothing
# else public ----------------------------------------------------------------
#
# `services/api/middleware/audit.py` needs to know, from OUTSIDE this module,
# whether a call's checksum allowance ran out -- a narrower question than
# whether its redaction degraded, see `RedactionScope.exhausted`'s own
# docstring for how the two diverge -- without gaining a route to
# `_ScanBudget` itself: `spend()` and `remaining` stay private on purpose --
# `remaining`'s meaning has already changed shape three times (per-token
# bound, call-wide budget, qualifying-start narrowing), and anything built
# against it would pin every caller to today's scan strategy.
# `redaction_budget` yields a scope object instead, exposing exactly one
# public property.


def test_redaction_scope_exhausted_is_false_on_a_fresh_budget() -> None:
    with redaction_budget(10) as scope:
        assert scope.exhausted is False


def test_redaction_scope_exhausted_is_true_once_the_budget_is_spent() -> None:
    """A small, explicit budget, not a megabyte of junk: one 128-character
    junk token spends 559 checksum operations (measured elsewhere in this
    file against `_find_iban_in_token`), comfortably more than a budget of
    1."""
    with redaction_budget(1) as scope:
        Memo(text="AB12" * 32)  # a single junk token; spends the one checksum
        assert scope.exhausted is True


def test_redaction_scope_exhausted_is_readable_after_the_block_exits() -> None:
    """Live delegation, not a snapshot taken at `yield` time: reading
    `scope.exhausted` after the block has exited must still report what
    happened DURING the block, because the scope holds a reference to the
    same `_ScanBudget` the block spent from rather than copying a bool at
    yield time."""
    with redaction_budget(1) as scope:
        assert scope.exhausted is False
        Memo(text="AB12" * 32)
    assert scope.exhausted is True


def test_redaction_scope_exhausted_is_true_after_an_exception_inside_the_block() -> None:
    """The audit middleware's `raised` path writes its row AFTER an
    exception has propagated out of the block, so the flag must still be
    readable, and correct, from the `except` handler. The `ContextVar` is
    reset in `redaction_budget`'s `finally` on the way out, so this only
    holds if `scope.exhausted` reads its own stored `_ScanBudget` reference
    rather than looking the current budget up from the (by then reset)
    `ContextVar`."""
    scope_from_block: RedactionScope | None = None
    try:
        with redaction_budget(1) as scope:
            scope_from_block = scope
            Memo(text="AB12" * 32)
            raise ValueError("boom")
    except ValueError:
        pass
    assert scope_from_block is not None
    assert scope_from_block.exhausted is True
    assert _current_budget.get() is None


def test_redaction_scope_exhausted_is_false_after_an_exception_with_the_budget_untouched() -> None:
    """Same exception path, but nothing inside the block ever spent the
    budget: `exhausted` must read False, not True, and not raise."""
    scope_from_block: RedactionScope | None = None
    try:
        with redaction_budget(500) as scope:
            scope_from_block = scope
            raise ValueError("boom")
    except ValueError:
        pass
    assert scope_from_block is not None
    assert scope_from_block.exhausted is False
    assert _current_budget.get() is None


def test_bare_redaction_budget_without_as_still_works() -> None:
    """Every existing call site uses `with redaction_budget():`, with no
    `as` clause -- the changed return type must not break any of them."""
    with redaction_budget(10):
        assert _current_budget.get() is not None


def test_redaction_scope_nesting_reports_its_own_budgets_exhaustion() -> None:
    """An inner scope reports its OWN budget's exhaustion, not the outer
    one's -- and exiting the inner block restores the outer budget exactly
    as `test_redaction_budget_restores_a_nested_callers_own_budget` above
    already proves at the `ContextVar` level."""
    with redaction_budget(500) as outer:
        with redaction_budget(1) as inner:
            Memo(text="AB12" * 32)
            assert inner.exhausted is True
            assert outer.exhausted is False
        assert outer.exhausted is False


def test_redaction_scope_does_not_expose_spend_or_remaining() -> None:
    """The scope's only public member is `exhausted`. Asserted with
    `hasattr` rather than by inspecting the scope class's own source, so a
    future passthrough (a `__getattr__`, say) would be caught the same way
    a caller reaching through it would be."""
    with redaction_budget(10) as scope:
        assert not hasattr(scope, "spend")
        assert not hasattr(scope, "remaining")


def test_redaction_scope_exhausted_at_exactly_the_cost_of_one_full_scan() -> None:
    """Pins the semantics `exhausted`'s docstring documents, so they cannot
    silently drift back to "True means degraded": measure the exact
    checksum cost of one full, uncontested scan (never hardcoded, so this
    stays correct if the scan strategy's own cost ever changes), then set
    the budget to exactly that cost. The token must still resolve to its
    full, structured mask -- nothing was degraded -- AND `exhausted` must
    still read True, because the budget's last unit was spent getting
    there."""
    iban = "MT92MALT01100ABCDEFGH1234IJKL56"
    with redaction_budget(10_000):
        Memo(text=iban)
        budget = _current_budget.get()
        assert budget is not None
        cost = 10_000 - budget.remaining

    with redaction_budget(cost) as scope:
        out = Memo(text=iban).text
    assert out == "MT•• •••• KL56"  # full match: nothing degraded
    assert scope.exhausted is True  # yet exhausted reads True regardless


# --- Default_Ignorable_Code_Point: unassigned codepoints that still render
# as nothing, missed by category-only stripping -----------------------------
#
# `Cf`/`Mn`/`Cc` cover ASSIGNED codepoints that render as nothing (or as an
# accent). Unicode's `Default_Ignorable_Code_Point` property is the
# property that actually MEANS "renders as nothing", and 3,769 of its
# 4,174 members are UNASSIGNED (`Cn`) -- a category this module does not
# otherwise touch, on purpose (stripping all of `Cn` would strip every
# codepoint Unicode has not assigned a meaning to yet). Verified live, not
# assumed from the property's name: any one of the ranges below, planted
# mid-value on unpatched code, defeats both the IBAN and the PAN scan, and
# deleting the single codepoint recovers the complete original value.


def _all_default_ignorable_unassigned() -> list[str]:
    return [
        chr(cp)
        for start, end in _DEFAULT_IGNORABLE_UNASSIGNED_RANGES
        for cp in range(start, end + 1)
    ]


def test_default_ignorable_unassigned_ranges_total_3769_codepoints() -> None:
    """Locks the range list to the count review verified against Unicode
    15.0's DerivedCoreProperties.txt, so a future edit that trims or
    extends a range notices immediately rather than silently narrowing
    coverage."""
    assert len(_all_default_ignorable_unassigned()) == 3769


def test_all_enumerated_default_ignorable_codepoints_are_actually_unassigned() -> None:
    """Characterization test tying the enumeration to THIS interpreter's
    bundled Unicode data (`unicodedata.unidata_version`), not just to the
    Unicode 15.0 spec text: if the bundled version ever reassigns one of
    these, this fails loudly rather than the coverage silently degrading
    to "still works, for a reason nobody wrote down"."""
    for ch in _all_default_ignorable_unassigned():
        assert unicodedata.category(ch) == "Cn", f"U+{ord(ch):04X} is no longer Cn"


# Unicode version the ranges above were derived against. The count lock and
# the `Cn` characterization test above both check the SIX enumerated ranges
# against the running interpreter, but neither one notices a codepoint
# OUTSIDE those ranges: if a Python upgrade bundles a newer Unicode version
# that assigns Default_Ignorable_Code_Point to some new codepoint elsewhere,
# both of those tests stay green while coverage silently degrades. This is
# the version pin the test below fails against.
_RANGES_DERIVED_AGAINST_UNICODE_VERSION = "15.0.0"


def test_bundled_unicode_version_matches_the_version_the_ranges_were_derived_against() -> None:
    """Neither the count lock nor the `Cn` characterization test above
    detects a newer bundled Unicode version assigning Default_Ignorable to a
    codepoint OUTSIDE the six ranges enumerated in
    `_DEFAULT_IGNORABLE_UNASSIGNED_RANGES` -- both would stay green while
    redaction coverage silently degrades. This test is the gate for that
    case: it pins the exact Unicode version the ranges were derived
    against, so a Python upgrade that moves `unicodedata.unidata_version`
    fails the build immediately instead of leaving a residual bypass
    nobody notices."""
    assert unicodedata.unidata_version == _RANGES_DERIVED_AGAINST_UNICODE_VERSION, (
        f"Bundled Unicode version is {unicodedata.unidata_version!r}, but "
        f"_DEFAULT_IGNORABLE_UNASSIGNED_RANGES was derived against Unicode "
        f"{_RANGES_DERIVED_AGAINST_UNICODE_VERSION!r}. A newer Unicode version "
        "can assign Default_Ignorable_Code_Point to codepoints outside the six "
        "ranges already enumerated, and neither the count-lock test nor the "
        "Cn characterization test above would catch that -- they only check "
        "the codepoints already listed. To fix, in order: (1) re-derive the "
        "Default_Ignorable_Code_Point list from the new Unicode version's "
        "DerivedCoreProperties.txt "
        "(https://www.unicode.org/Public/<version>/ucd/DerivedCoreProperties.txt), "
        "keeping only the codepoints unassigned (category Cn) in that "
        "version; (2) update _DEFAULT_IGNORABLE_UNASSIGNED_RANGES in "
        "packages/postern-core/src/postern_core/domain/masking.py to match; "
        "(3) update the expected count in "
        "test_default_ignorable_unassigned_ranges_total_3769_codepoints "
        "(tests/test_masking_types.py) to the new total, renaming the test "
        "itself too since its name embeds the old count (3769); (4) update "
        "_RANGES_DERIVED_AGAINST_UNICODE_VERSION (tests/test_masking_types.py, "
        "this test) to the new unicodedata.unidata_version string."
    )


def test_free_text_strips_every_default_ignorable_unassigned_codepoint_inside_an_iban() -> None:
    """The whole property list, not a sample, against the IBAN path."""
    iban = "MT92MALT01100ABCDEFGH1234IJKL56"
    for ch in _all_default_ignorable_unassigned():
        planted = ch.join([iban[:2], iban[2:15], iban[15:]])
        out = Memo(text=planted).text
        assert iban not in out, f"U+{ord(ch):04X} was not stripped from an IBAN"
        assert out == "MT•• •••• KL56", f"U+{ord(ch):04X}: got {out!r}"


def test_free_text_strips_every_default_ignorable_unassigned_codepoint_inside_a_pan() -> None:
    """The whole property list, not a sample, against the PAN path."""
    pan = "4111111111114417"
    for ch in _all_default_ignorable_unassigned():
        planted = ch.join([pan[:8], pan[8:]])
        out = Memo(text=planted).text
        assert pan not in out, f"U+{ord(ch):04X} was not stripped from a PAN"
        assert out == "•••• 4417", f"U+{ord(ch):04X}: got {out!r}"


# --- Narrowing what budget exhaustion destroys ------------------------------
#
# Denial-of-audit primitive, found by review: unconditionally bare-masking
# every token after the budget runs out blanks every OTHER legitimate
# value in the same request too -- a payee reference, a challenge ID, a
# device ID, none of them junk. `_has_qualifying_start` narrows this to
# "could this token EVER have matched, with any amount of budget" -- a
# token with no letter-letter-digit-digit start anywhere in it can never
# reach a checksum regardless of budget, so leaving it untouched loses
# nothing on the leak axis.


def test_has_qualifying_start_is_false_for_a_value_that_can_never_checksum() -> None:
    """No letter-letter-digit-digit run anywhere in this token -- not
    within the last-`_IBAN_MIN_LEN` characters where `_find_iban_in_token`
    would even look -- so it could never have bought a single checksum."""
    assert not _has_qualifying_start("ACMECORP20260912X")


def test_has_qualifying_start_is_true_for_a_real_iban() -> None:
    """A real IBAN's own opening shape is exactly this test's condition by
    construction (country code, two check digits)."""
    assert _has_qualifying_start("MT84MALT011000012345MTLCAST001S")


def test_free_text_budget_exhaustion_preserves_a_value_that_could_never_match() -> None:
    """The fix, end to end: a value with no possible IBAN-shaped start
    survives budget exhaustion untouched, closing the denial-of-audit
    primitive without reopening the leak axis (nothing here could ever
    have checksummed, budget or no budget)."""
    junk = " ".join(["AB12" * 32] * _JUNK_TOKENS_TO_EXHAUST_BUDGET)
    safe_value = "ACMECORP20260912X"
    out = Memo(text=f"{junk} {safe_value}").text
    assert out.endswith(safe_value)


def test_free_text_budget_exhaustion_still_masks_a_token_that_could_have_matched() -> None:
    """The other half of the same rule: a token that DOES have a
    qualifying start is still bare-masked after exhaustion. The narrowing
    only ever removes masking from tokens that could never have been
    found regardless of budget -- it must not weaken the fail-closed
    behaviour for anything that could plausibly have been a real IBAN."""
    junk = " ".join(["AB12" * 32] * _JUNK_TOKENS_TO_EXHAUST_BUDGET)
    plausible_but_unverified = "AB99XYZQWERTYUIOPAS"
    assert _has_qualifying_start(plausible_but_unverified.upper())
    out = Memo(text=f"{junk} {plausible_but_unverified}").text
    assert plausible_but_unverified not in out
    assert out.endswith(_MASK)


def test_free_text_budget_exhaustion_survivor_count_on_a_seven_value_payload() -> None:
    """Illustrative reconstruction of review's payload shape (179 tokens of
    padding, one past the exhaustion point, then several legitimate
    values) -- not review's own literal strings, which were not part of
    this report, but the same shape: some values immune regardless (too
    short, or split by a separator already) and some that were blanked
    outright before this fix. Locks in the count this change actually
    produces for a representative mix rather than only for the two
    single-value cases above."""
    junk = " ".join(["AB12" * 32] * _JUNK_TOKENS_TO_EXHAUST_BUDGET)
    immune_regardless = ["DEV42AB", "TXN-2026-0912"]
    previously_destroyed = [
        "PAYEEREF88213XBCN",
        "a1b2c3d4e5f67890fedcba9876543210",
        "DEVICE7A9B3C1D2E4F5061728394A5B6",
        "REF20260912ABCDEFGH",
        "ES9121000418450200051332",
    ]
    all_values = immune_regardless + previously_destroyed
    out = Memo(text=f"{junk} {' '.join(all_values)}").text
    survivors = [v for v in all_values if v in out]
    for v in immune_regardless:
        assert v in survivors, f"{v!r} should have been immune regardless"
    # A real IBAN and an IBAN-opener-shaped reference both have a
    # qualifying start, so both stay conservatively masked; the other
    # three previously-destroyed values have no qualifying start and now
    # survive. Asserted as a count, not a hardcoded set, so this documents
    # the actual number rather than silently tolerating a different split.
    assert len(survivors) == 5, f"expected 5 of 7 to survive, got {survivors!r}"

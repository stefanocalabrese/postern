import pytest
from postern_core.domain.masking import _IBAN_MASKED_RE, _PAN_MASKED_RE, MaskedIban, MaskedPan
from pydantic import BaseModel, ConfigDict, ValidationError


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

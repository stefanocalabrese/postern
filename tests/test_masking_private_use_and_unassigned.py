"""The `Co`/`Cn` splitter gap, closed (residual 9 on `_mask_bridged_runs`).

`masking.py` sorts a non-ASCII character interrupting an alphanumeric run
into one of two treatments: STRIPPED (`_STRIPPED_CATEGORIES`, for characters
that render as nothing) or BRIDGED (`_is_script_intrusion`, for characters
that split a token without being a break a reader can see). Everything
between those two sets was neither, and `Co` (private use, 137,468
codepoints) and `Cn` (unassigned, 825,345) fell in the gap, which made it by
two orders of magnitude the largest hole the module has had.

The rule stated above `_STRIPPED_CATEGORIES` -- "a character that renders as
NOTHING is stripped; a character that renders as a visible break is not" --
cannot decide either category, and that is why they were missed rather than
declined. A private-use codepoint renders as whatever a private agreement
says, which is nothing at all outside that agreement; an unassigned one
renders as a `.notdef` box or as nothing, at the renderer's discretion.
Neither is a break the writer of the text can rely on a reader seeing.

And the consumer here is not a reader. It is an LLM consuming a codepoint
stream, which reads straight through a tofu box as though it were absent --
which is what makes this a leak rather than a display quirk, and why the
doctrine's rendering-calibrated question is the wrong one to ask of these
two categories.

This file is separate from `tests/test_masking_confusables.py` on purpose:
that file's corpora and this module's other false-positive corpora had to
pass BYTE-IDENTICALLY and UNEDITED across this change, so nothing here
touches them. `test_the_false_positive_corpora_are_untouched` below reads
them and asserts exactly that.
"""

import unicodedata

import pytest
from postern_core.domain.masking import (
    _DEFAULT_IGNORABLE_UNASSIGNED,
    _MASK,
    FreeText,
    _is_script_intrusion,
    _is_stripped,
)
from pydantic import BaseModel, ConfigDict

from tests.test_masking_confusables import LEGITIMATE_MIXED_SCRIPT_CORPUS
from tests.test_masking_homoglyph_measurement import (
    FALSE_POSITIVE_CORPUS,
    FALSE_POSITIVE_CORPUS_BY_SCRIPT,
)

MT_IBAN = "MT92MALT01100ABCDEFGH1234IJKL56"  # 31, mod-97 valid
ES_IBAN = "ES9121000418450200051332"  # 24
NL_IBAN = "NL91ABNA0417164300"  # 18
NO_IBAN = "NO9386011117947"  # 15, the registry's shortest
PAN = "4111111111111111"  # 16 digits, Luhn-valid

# The three codepoints the defect was reported and re-derived against, each
# INSERTED at offset 15 of `MT_IBAN`. Before the fix all three returned the
# complete IBAN verbatim; the exact recorded outputs are in the commit
# message and in residual 9 on `_mask_bridged_runs`.
REPORTED_LEAKS = [
    ("U+E000 (Co, first BMP private-use)", ""),
    ("U+F8FF (Co, last BMP private-use)", ""),
    ("U+0378 (Cn, unassigned, NOT Default_Ignorable)", "͸"),
]


class Memo(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    text: FreeText


@pytest.mark.parametrize(("label", "splitter"), REPORTED_LEAKS)
def test_the_three_reported_leaks_are_closed(label: str, splitter: str) -> None:
    """The defect exactly as reported: splitter INSERTED at offset 15 of the
    Maltese format, through the public `FreeText` entry point.

    INSERTION rather than substitution, and that is the sharper of the two
    rather than the gentler: every character of the real IBAN is still
    present in the input, so an output that keeps them is not "the IBAN
    minus a character", it is the IBAN, recoverable by a `str.replace` that
    costs the reader nothing.
    """
    assert unicodedata.category(splitter) in {"Co", "Cn"}, label
    planted = MT_IBAN[:15] + splitter + MT_IBAN[15:]
    assert MT_IBAN in planted.replace(splitter, ""), "fixture does not keep the IBAN intact"

    out = Memo(text=f"pay {planted} now").text

    assert MT_IBAN not in out.replace(splitter, ""), f"{label} still leaks the IBAN: {out!r}"
    assert "MT92MALT01100" not in out, f"{label} left an IBAN fragment: {out!r}"
    assert "ABCDEFGH1234IJKL56" not in out, f"{label} left an IBAN fragment: {out!r}"
    assert out == f"pay {_MASK} now", out


# A spread over both categories rather than the three reported members: all
# three private-use blocks at both ends, unassigned codepoints from several
# planes, both noncharacter shapes, and one Default_Ignorable unassigned
# codepoint (which takes the OTHER safe path -- `_strip_invisible` removes
# it before this predicate is consulted at all, and the reassembled value is
# then masked by the ordinary IBAN scan). The full 4,172-codepoint sweep
# these are drawn from is recorded in residual 9 on `_mask_bridged_runs`;
# what runs here is sized to stay a gate rather than a benchmark.
SAMPLED_SPLITTERS = [
    "",  # Co, first of the BMP private use area
    "",  # Co, last of it
    "\U000f0000",  # Co, first of plane 15
    "\U000ffffd",  # Co, last of plane 15
    "\U00100000",  # Co, first of plane 16
    "\U0010fffd",  # Co, last of plane 16
    "͸",  # Cn, the Greek block's unassigned hole
    "΀",  # Cn, another
    "׮",  # Cn, Hebrew block
    "⿠",  # Cn, between the Kangxi radicals and CJK
    "﷐",  # Cn, first noncharacter of the Arabic Presentation Forms range
    "﷯",  # Cn, last of it
    "￾",  # Cn, BMP noncharacter
    "￿",  # Cn, BMP noncharacter
    "\U0001fffe",  # Cn, plane 1 noncharacter
    "\U0010ffff",  # Cn, the very last codepoint
    "⁥",  # Cn AND Default_Ignorable: stripped, not bridged
]

VALUES = [
    ("PAN-16 Luhn-valid", PAN),
    ("IBAN NO, 15", NO_IBAN),
    ("IBAN NL, 18", NL_IBAN),
    ("IBAN ES, 24", ES_IBAN),
    ("IBAN MT, 31", MT_IBAN),
]


@pytest.mark.parametrize("splitter", SAMPLED_SPLITTERS)
@pytest.mark.parametrize(("label", "value"), VALUES)
def test_no_interior_offset_survives_in_any_value_shape(
    label: str, value: str, splitter: str
) -> None:
    """Every INTERIOR insertion offset of a Luhn-valid PAN and of four IBAN
    formats spanning the registry's shortest (NO, 15) to its longest common
    one (MT, 31).

    Length is swept rather than fixed because both floors this module
    defends are length floors: `_could_be_an_identifier` needs
    `_PAN_MIN_DIGITS` digits or `_IBAN_MIN_LEN` alphanumerics, so a format
    that clears them by one character behaves differently from one that
    clears them by seventeen. Residual 4 is exactly the shape that gets
    under them, and it takes TWO splitters to do it -- one never does, which
    is what this asserts.
    """
    assert unicodedata.category(splitter) in {"Co", "Cn"}, splitter
    for offset in range(1, len(value)):
        planted = value[:offset] + splitter + value[offset:]
        out = Memo(text=f"ref {planted} end").text
        assert value not in out.replace(splitter, ""), (
            f"{label} recoverable with U+{ord(splitter):04X} at offset {offset}: {out!r}"
        )


def test_every_private_use_and_unassigned_codepoint_is_covered() -> None:
    """Exhaustive over the two categories, not sampled, because the per-
    codepoint claim is the one that can be made exhaustively: once
    `_is_script_intrusion` says True, `_bridged_runs` treats the codepoint
    identically to every other splitter, so sampling is only ever needed for
    the POSITIONAL half of the question (the test above, and the wider sweep
    on `_mask_bridged_runs`).

    Either treatment is safe and both are asserted as a single disjunction:
    a stripped codepoint is deleted and the reassembled value goes to the
    ordinary checksum scan, a bridged one is masked. What must not happen,
    and what did happen for all 962,813 of these before the fix, is
    neither.

    The counts are pinned rather than recomputed-and-trusted so that the
    numbers written into residual 9 are numbers this test defends. They are
    Unicode 15.0.0 figures; `tests/test_masking_types.py` already fails the
    build the day the bundled version moves.
    """
    assert unicodedata.unidata_version == "15.0.0"

    private_use = unassigned = 0
    stripped_first = 0
    uncovered: list[int] = []
    for codepoint in range(0x110000):
        char = chr(codepoint)
        category = unicodedata.category(char)
        if category == "Co":
            private_use += 1
        elif category == "Cn":
            unassigned += 1
        else:
            continue
        if _is_stripped(char):
            stripped_first += 1
        elif not _is_script_intrusion(char):
            uncovered.append(codepoint)

    assert uncovered == [], (
        f"{len(uncovered)} Co/Cn codepoints are neither stripped nor bridged, "
        f"first few: {[hex(cp) for cp in uncovered[:8]]}"
    )
    assert private_use == 137_468, private_use
    assert unassigned == 825_345, unassigned
    assert private_use + unassigned == 962_813
    # The Default_Ignorable unassigned codepoints, which `_strip_invisible`
    # already removed before this change and still does.
    assert stripped_first == 3_769, stripped_first
    assert stripped_first == len(_DEFAULT_IGNORABLE_UNASSIGNED)


def test_they_are_bridged_and_not_stripped() -> None:
    """Which of the two treatments this change chose, pinned by its
    observable consequence rather than by reading the predicate.

    Stripping `Cn` whole is the alternative, and it is the one
    `_STRIPPED_CATEGORIES`'s own comment refuses: a strip list covering
    every codepoint Unicode has not assigned a meaning to YET grows with
    every future Unicode version without this file changing, silently
    deleting characters from customer text as the standard moves. Bridging
    deletes nothing -- the codepoint is still in the output wherever the run
    around it did not qualify for masking.
    """
    for splitter in ("", "͸"):
        assert not _is_stripped(splitter), f"U+{ord(splitter):04X} must not be stripped"
        assert _is_script_intrusion(splitter), f"U+{ord(splitter):04X} must be bridged"
        # Too short to clear either floor in `_could_be_an_identifier`, so
        # nothing is masked and the character survives verbatim.
        short = f"ab{splitter}cd"
        assert Memo(text=short).text == short, "a bridged codepoint was deleted from short text"


def test_the_false_positive_corpora_are_untouched() -> None:
    """The cost side of the trade, measured on the corpora this module
    already defends rather than argued from the categories' definitions.

    Zero is the expected false-positive count and it is expected for a
    structural reason, not a lucky one: `Co` has no meaning outside a
    private agreement between the parties that made it up, and `Cn` is by
    definition what no encoder emits for any standard text, so neither can
    appear in a merchant descriptor produced by any system in the payment
    chain. The census below asserts that directly -- if a corpus entry ever
    does acquire one, this fails and the trade has to be re-argued rather
    than assumed.
    """
    corpora: list[str] = [
        *FALSE_POSITIVE_CORPUS,
        *LEGITIMATE_MIXED_SCRIPT_CORPUS,
        *(text for texts in FALSE_POSITIVE_CORPUS_BY_SCRIPT.values() for text in texts),
    ]
    assert len(corpora) >= 200, len(corpora)

    offenders = [
        (text, char)
        for text in corpora
        for char in text
        if unicodedata.category(char) in {"Co", "Cn"}
    ]
    assert offenders == [], f"a corpus entry acquired a Co/Cn character: {offenders[:3]}"

    altered = [text for text in corpora if Memo(text=text).text != text]
    assert altered == [], f"legitimate text is now being masked: {altered[:3]}"


def test_new_residual_ten_a_lone_surrogate_still_leaks() -> None:
    """Residual 10, OPEN, and demonstrated rather than asserted from the
    category table -- the same discipline every other open shape on
    `_mask_bridged_runs`'s list gets, and the reason none of them can be
    lost to a later edit of that comment.

    `Cs` is now in precisely the position `Co` and `Cn` were in before this
    change: not alphanumeric so part 1 declines it, not in part 2's set, not
    stripped. It is reachable -- `json.loads('"\\ud800"')` returns one -- and
    it defeats the scan at the same offset, in the same way, for the same
    reason.

    Left open deliberately. The fix is a different decision rather than a
    wider version of this one: a lone surrogate cannot be UTF-8 encoded, so
    the `audit_log` INSERT and every other consumer downstream raises on it,
    which makes the live question where such a value should be REJECTED, not
    what this predicate should return for it. Adding `Cs` to part 2 would
    mask the leak and leave the encoding failure exactly where it is.
    """
    surrogate = "\ud800"
    assert unicodedata.category(surrogate) == "Cs"
    assert not _is_script_intrusion(surrogate)
    assert not _is_stripped(surrogate)

    planted = MT_IBAN[:15] + surrogate + MT_IBAN[15:]
    out = Memo(text=f"pay {planted} now").text

    assert MT_IBAN in out.replace(surrogate, ""), (
        f"residual 10 has been closed -- update `_mask_bridged_runs`'s list: {out!r}"
    )
    with pytest.raises(UnicodeEncodeError):
        out.encode("utf-8")

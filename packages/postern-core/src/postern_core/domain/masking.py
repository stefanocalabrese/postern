"""Masked identifier types (handoff §6.5).

These types exist so that a handler which forgets to mask fails validation
rather than leaking. Never replace them with a `str` plus a helper function.

Validation-failure boundary, not closable by the type alone: a
`ValidationError` raised by these types carries the raw PAN or IBAN
regardless of the validator's own message, so any code that serializes one
toward a client MUST call `errors(include_input=False)` or
`json(include_input=False)`; `hide_input_in_errors` covers only `str()` and
`repr()` of the exception, not its structured `errors()` output or
`.json()`.
"""

import re
from typing import Annotated

from pydantic import AfterValidator

_MASK = "••••"
_PAN_MASKED_RE = re.compile(r"•••• [0-9]{4}")
_IBAN_MASKED_RE = re.compile(r"[A-Z]{2}•• •••• [A-Z0-9]{4}")
_PAN_RE = re.compile(r"[0-9]{12,19}")
_IBAN_RE = re.compile(r"[A-Z]{2}[0-9]{2}[A-Z0-9]{10,30}")

# Separators a real PAN or IBAN may legitimately carry when copy-pasted from
# a rendered statement or typed with grouping: plain and non-breaking
# whitespace variants, hyphen variants, and dot grouping. Normalized once,
# identically, for both types -- they previously diverged (str.split() for
# IBAN absorbed more whitespace than PAN's literal " "/"-" strip), which
# rejected real PAN formats the IBAN path already accepted.
_SEPARATORS = str.maketrans(
    "",
    "",
    " \t\n\r\v\f\xa0 -‐‑‒–—.",
)


def _mod97_ok(compact: str) -> bool:
    """ISO 7064 mod-97 check (the IBAN checksum algorithm).

    Move the first four characters to the end, map each character to its
    base-36 value written out as a decimal string, and require the
    resulting integer mod 97 to equal 1.
    """
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1


def _mask_pan(value: str) -> str:
    if _PAN_MASKED_RE.fullmatch(value):
        return value
    compact = value.translate(_SEPARATORS)
    if not _PAN_RE.fullmatch(compact):
        raise ValueError("not a PAN: expected 12 to 19 digits")
    return f"{_MASK} {compact[-4:]}"


def _mask_iban(value: str) -> str:
    if _IBAN_MASKED_RE.fullmatch(value):
        return value
    compact = value.translate(_SEPARATORS).upper()
    if not _IBAN_RE.fullmatch(compact) or not _mod97_ok(compact):
        raise ValueError("not an IBAN: expected ISO 13616 form")
    return f"{compact[:2]}•• {_MASK} {compact[-4:]}"


MaskedPan = Annotated[str, AfterValidator(_mask_pan)]
"""Card PAN, last four digits only. Cannot represent a full PAN."""

MaskedIban = Annotated[str, AfterValidator(_mask_iban)]
"""Own IBAN, country code plus last four. Counterparty IBANs are omitted entirely."""

# Substring scan, not the fullmatch `_PAN_RE`/`_IBAN_RE` above: free text is a
# sentence with a PAN or IBAN embedded in it (unstructured remittance
# information is exactly where a counterparty IBAN or a card reference
# appears in ISO 20022 traffic), not a value that is entirely a PAN or IBAN.
# No separator handling here (no grouped "4111 1111 1111 4417" detection):
# `MaskedPan`/`MaskedIban` own that job for a value that IS a PAN/IBAN; this
# only has to stop a contiguous run reaching a client, which is what a
# memo/description field actually carries in practice.
#
# The run pattern is deliberately UNBOUNDED above (`{12,}`, not `{12,19}`).
# An upper bound here is not a harmless approximation, it reconstitutes
# cards: against the 30-digit run "378282246310005378282246310005" the
# bounded form matched only the first 19 digits, emitted THAT window's last
# four ("3782"), and left the unconsumed 11-digit remainder
# ("82246310005") immediately after the mask -- so the output read
# "•••• 378282246310005", a complete valid 15-digit AmEx number that the
# redaction itself had helped assemble out of its own mask. Consuming the
# whole run first and deciding what to emit afterwards is the only shape
# that cannot leave a residue for the mask to concatenate with.
_PAN_IN_TEXT_RE = re.compile(r"\d{12,}")

# Same lesson, IBAN side: the candidate pattern is unbounded above too, and
# for a sharper reason than the ceiling. `[A-Za-z0-9]{10,30}` matched a whole
# token only up to 34 characters, and `_redact_iban_match` then checksummed
# THAT WHOLE TOKEN and gave up when it failed -- so one word character glued
# to a valid IBAN was enough to defeat the scan entirely:
# "MT92MALT01100ABCDEFGH1234IJKL56R" is 32 characters, well inside the old
# range, and the complete mod-97-valid IBAN reached the output verbatim. Past
# 34 the same input failed differently and just as badly: the trailing `\b`
# rejected the greedy 30-character attempt and every backtrack with it, so
# the pattern matched nothing at all. Neither failure is a length problem.
# Match the maximal token, then look for an IBAN inside it.
_IBAN_IN_TEXT_RE = re.compile(r"\b[A-Za-z]{2}[0-9]{2}[A-Za-z0-9]{10,}\b")

# ISO/IEC 7812-1 caps a PAN at 19 digits; no scheme issues a longer one.
_PAN_MAX_DIGITS = 19

# ISO 13616 caps an IBAN at 34 characters. 14 is this module's own historical
# lower bound (the old `2 + 2 + {10,30}`), kept rather than tightened to the
# registry's true 15-character minimum so that this change only ever adds
# redaction and never removes any.
_IBAN_MIN_LEN = 14
_IBAN_MAX_LEN = 34


def _longest_iban_prefix(token: str) -> str | None:
    """The longest leading slice of `token` that checksums as an IBAN.

    Longest first, not shortest: a genuine IBAN's own length is the answer
    wanted, and shorter slices of it can checksum by coincidence -- the
    registry example "SC18SSCB11010000000000001497USD" has a mod-97-valid
    18-character prefix, and returning that would emit a last-four taken
    from the middle of the real account number instead of its end.

    At most 21 checks per token however long the token is, because nothing
    longer than 34 characters can be an IBAN. Scanning every WINDOW of the
    token rather than its prefixes would cost O(len(token)) checks and hand
    an attacker a CPU-burn primitive through a field they write; the price
    of the cheap version is that an IBAN with junk glued to its FRONT is
    not found (documented limitation, see `_redact_free_text`).
    """
    for end in range(min(len(token), _IBAN_MAX_LEN), _IBAN_MIN_LEN - 1, -1):
        prefix = token[:end]
        if _mod97_ok(prefix):
            return prefix
    return None


def _redact_iban_match(match: re.Match[str]) -> str:
    candidate = match.group(0)
    compact = _longest_iban_prefix(candidate.upper())
    if compact is None:
        # IBAN-shaped but nothing in it checksums: not a real IBAN (e.g. a
        # merchant reference that happens to look like one). Leave it as
        # written rather than mangling ordinary text on a false positive.
        return candidate
    # The WHOLE token is replaced, tail included, not just the IBAN prefix.
    # Keeping the tail would set the mask's own last four directly against
    # unconsumed, attacker-influenced characters of the same token
    # ("KL56" + "REF9"), which is exactly the shape that let the PAN scan
    # reassemble a card out of its own mask. Country code plus last four is
    # kept, and only that: the checksum has positively identified a genuine
    # IBAN here, and that is precisely the disclosure `MaskedIban` is
    # approved to make about one -- unlike an over-long digit run, which is
    # definitionally not a card and so has no approved last-four at all.
    return f"{compact[:2]}•• {_MASK} {compact[-4:]}"


def _redact_pan_match(match: re.Match[str]) -> str:
    candidate = match.group(0)
    if len(candidate) > _PAN_MAX_DIGITS:
        # Longer than any PAN, so this run is not a card and its last four
        # digits are not a card's last four. `MaskedPan`'s last-four IS the
        # deliberate, policy-approved disclosure for a genuine card, and
        # that approval does not transfer to arbitrary digits: copying the
        # shape here would publish four attacker-chosen digits into a
        # vendor's chat history and the audit table for no benefit, while
        # asserting a confident, wrong "card ending NNNN" to whatever reads
        # the text next -- the same failure `MaskedPan` refuses when it
        # rejects well-formed-looking garbage instead of guessing a
        # last-four for it. Emit the marker and nothing else.
        return _MASK
    return f"{_MASK} {candidate[-4:]}"


def _redact_free_text(value: str) -> str:
    # IBAN pass first: an IBAN's digits (e.g. "9121000418450200051332", 22
    # digits) would otherwise be greedily chewed by the PAN scan first,
    # consuming the IBAN's whole numeric run without leaving anything for
    # `_redact_iban_match` to recognize as IBAN-shaped afterwards -- which
    # costs the country code that `MaskedIban` exists to keep. The
    # unbounded PAN run pattern makes this ordering matter more, not less.
    # The IBAN replacement cannot feed the PAN pass either: it is
    # `\b`-anchored at both ends, so no digit can sit against the "1332" it
    # emits, and the bullets in it are not digits.
    #
    # Known limitation, deliberate: `_longest_iban_prefix` checks prefixes,
    # so an IBAN with junk glued to its FRONT ("REF9MT92MALT...") is not
    # found -- that token does not even match the candidate pattern, whose
    # `[A-Za-z]{2}[0-9]{2}` opener has to land at the token start. Closing
    # it means scanning every window of every token, which is O(len(token))
    # checksum checks on attacker-written text. Worth doing behind an input
    # length cap; not worth doing unbounded.
    text = _IBAN_IN_TEXT_RE.sub(_redact_iban_match, value)
    return _PAN_IN_TEXT_RE.sub(_redact_pan_match, text)


FreeText = Annotated[str, AfterValidator(_redact_free_text)]
"""Free text (transaction memos, payee names, labels): redacts any IBAN- or
PAN-shaped substring on validation, rather than requiring every caller to
remember to scrub it (handoff §3.4's leak scenario, security review of
Task 3). Ordinary text passes through unchanged."""

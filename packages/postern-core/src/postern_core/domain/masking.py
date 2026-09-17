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

import contextvars
import re
import unicodedata
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Annotated

from pydantic import AfterValidator

# Byte width and character width diverge here, and the divergence runs the
# opposite way most people guess: masking a value can GROW its byte length
# even while it shrinks or holds its character length. The bullet is
# U+2022, 3 bytes in UTF-8 against 1 byte for the ASCII digit or letter it
# typically stands in for, so a string made entirely of masked output can
# reach up to 3x its character count in bytes -- `len(("•" *
# 64).encode())` is 192, not 64. Measured on a realistic value too, not
# just the theoretical extreme: `'.'.join(['NO9386011117947'] * 4)` is 63
# characters (and 63 bytes -- pure ASCII) going in, and comes back 59
# characters but 107 UTF-8 bytes after masking -- narrower by every
# character-based measure, wider by every byte-based one.
#
# This is safe for `audit_log.tool_name` specifically because Postgres
# `VARCHAR(n)` counts characters, not bytes (see the tool-name clamp in
# `services/api/middleware/audit.py`, which documents that column's own
# reasoning). It is NOT safe in general: any consumer that counts bytes
# rather than characters -- a byte-limited index key, a fixed-width export,
# a buffer sized off a `VARCHAR(n)`'s `n`, or any downstream system that
# receives a masked value over a wire format that counts bytes -- can
# receive something noticeably wider than the schema it was measured
# against advertises.
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
#
# `\d`, not `[0-9]` -- deliberately different from `_PAN_RE` above, and not
# a bug to reconcile. Python's `\d` is Unicode-aware, so this pattern
# already matches a PAN written in Arabic-Indic (`٠١٢٣٤٥٦٧٨٩`) or Eastern
# Arabic-Indic (`۰۱۲۳۴۵۶۷۸۹`) digits -- verified directly, not assumed:
# `_redact_free_text("pay ٤٤١٧٤٤١٧٤٤١٧")` masks it, last four preserved IN
# THE ORIGINAL SCRIPT ("pay •••• ٤٤١٧"). `_PAN_RE` (`_mask_pan`'s own
# fullmatch check, for `MaskedPan`) stays `[0-9]{12,19}`, ASCII-only, and
# would REJECT that same digit run outright ("not a PAN: expected 12 to 19
# digits") rather than mask it. This divergence is intentional and safe in
# the direction it goes: `FreeText` (this pattern) fails closed by matching
# MORE digit scripts than it strictly needs to, `MaskedPan` fails closed by
# accepting FEWER; neither can be talked into leaking a PAN by the other's
# choice. It is also unreachable in practice, which is why it has never
# needed resolving: ISO/IEC 7812 specifies ASCII digits for a PAN (ISO
# 13616 likewise for an IBAN), so no real backend sends either in
# Arabic-Indic numerals. Do not "fix" this by making the two patterns
# agree -- that is exactly the kind of asymmetry a later reader tidies into
# a bug without knowing why it existed.
_PAN_IN_TEXT_RE = re.compile(r"\d{12,}")

# ISO/IEC 7812-1 caps a PAN at 19 digits; no scheme issues a longer one.
_PAN_MAX_DIGITS = 19

# ISO 13616 caps an IBAN at 34 characters. 14 is this module's own historical
# lower bound (the old `2 + 2 + {10,30}`), kept rather than tightened to the
# registry's true 15-character minimum so that this change only ever adds
# redaction and never removes any. Unchanged by the front-glue fix below:
# widening or narrowing it is a separate decision this change does not make.
_IBAN_MIN_LEN = 14
_IBAN_MAX_LEN = 34

# A per-token scan-cost bound, not an ISO invariant -- do not confuse this
# with `_IBAN_MAX_LEN` above. `_find_iban_in_token` scanning every
# qualifying start in a token is what closes the front-glue leak, but it
# also means the work for a token that never checksums grows with the
# token's own length: `services/api/middleware/audit.py` runs `FreeText`
# over agent-supplied tool arguments of whatever length the agent sends, so
# that growth is an agent-controllable cost sitting directly in the request
# path, not a theoretical one. 128 is nearly four times `_IBAN_MAX_LEN`, so
# no token this long can possibly be a real IBAN regardless of what it
# checksums to, and no legitimate descriptor token comes anywhere close --
# every merchant descriptor this module has been tested against tops out
# well under 40 characters. `_redact_iban_match` checks this BEFORE calling
# `_find_iban_in_token` at all, which is what makes an over-long token an
# O(1) decision instead of an O(len(token)) one.
#
# This bound alone is NOT sufficient, and asserting otherwise was a mistake
# corrected in this revision: it caps the cost of one LONG token, but an
# attacker who tokenizes their own input controls token count as much as
# token length, and every token up to and including 128 characters still
# gets the full per-token scan. Splitting a payload into many token-sized
# pieces (e.g. space-separated 128-character junk) multiplies the token's
# own worst-case cost by however many of them fit in the payload, which
# scales with total input size exactly the way a single unbounded token
# used to. `_IBAN_SCAN_BUDGET` below is the bound that actually closes that:
# a budget shared across every token in one `_redact_free_text` call, not
# reset per token.
_IBAN_SCAN_MAX_TOKEN = 128


class _ScanBudget:
    """A checksum-operation allowance shared across one `_redact_free_text`
    call, not reset between tokens.

    `_IBAN_SCAN_MAX_TOKEN` bounds the cost of any ONE token but not the
    total across a payload made of many of them, and an attacker chooses
    the tokenization of their own input: space-separated tokens sized just
    at the per-token bound each buy the full scan, and the number of such
    tokens that fit scales with total payload size the same way a single
    unbounded token used to. Every checksum attempt across the whole call
    -- not per token -- draws from this one allowance; once it is spent, no
    further token is scanned at all (`_redact_iban_match` checks
    `exhausted` before calling `_find_iban_in_token`), so the bound is a
    property of the call, not of any token in it. See `_IBAN_SCAN_BUDGET`
    for the chosen size and how it was derived.
    """

    __slots__ = ("remaining",)

    def __init__(self, total: int) -> None:
        self.remaining = total

    def spend(self) -> bool:
        """Spend one checksum operation. Fails closed: once `remaining`
        hits zero this stops decrementing and returns False forever, so a
        caller that keeps calling it after exhaustion cannot go negative or
        wrap around."""
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True

    @property
    def exhausted(self) -> bool:
        return self.remaining <= 0


# Chosen so that the worst-case cost of scanning ONE `FreeText` STRING at
# 1 MiB -- `settings.max_body_bytes`'s default, the largest single value
# that can reach this code today -- does not exceed the UNFIXED code's own
# cost on the same input, with margin. Derived empirically, not by
# intuition: swept against the adversarial shape review identified
# (space-separated tokens sized exactly at `_IBAN_SCAN_MAX_TOKEN`,
# maximum-density letter-letter-digit-digit filler) at 1 MiB, picking the
# largest value whose measured worst case stays comfortably under the
# unfixed code's own measured cost on the identical input. 100,000 measured
# ~223-242ms across five runs against an unfixed-code baseline of
# ~302-315ms on the same machine, the same five runs -- roughly 25%
# margin, not a photo finish. 1 MiB of ORDINARY transaction text
# (realistic merchant descriptors and sentences, repeated to size,
# including genuine embedded IBANs and PANs) consumed 2,101 checksum
# operations end to end -- about 2% of this budget -- so legitimate use is
# nowhere near it. See `_redact_free_text` for the full measurement
# tables, including the shapes invented specifically to try to beat the
# chosen shape and why none of them did.
#
# This is a PER-STRING amount, used verbatim only when no ambient budget
# is active (see `redaction_budget` immediately below). On its own it does
# NOT bound a request that validates many strings -- `services/api/
# middleware/audit.py:_scrub` walks a whole argument tree and validates
# every string in it, so without an ambient budget each one gets a fresh
# 100,000, and an attacker who spreads junk across many short strings
# (a list of 128-character elements, say) pays this cost once per element,
# not once per call. That gap, found and closed after this constant was
# first chosen, is exactly what `redaction_budget` exists to close: see
# its own docstring, and the request-level numbers on `_redact_free_text`.
_IBAN_SCAN_BUDGET = 100_000

# The context-local budget for the CURRENT call, when one has been made
# ambient by `redaction_budget`. `contextvars.ContextVar`, not a plain
# module global: `AuditMiddleware.on_call_tool` is async, and a module
# global would be shared mutable state across every concurrently-served
# request on the same instance -- one request's spend would count against
# another's allowance, or a slow request could starve a fast one that
# started later. A `ContextVar` is local to the current context, and
# `asyncio` gives every `Task` its own copy of the context it was created
# in, so two concurrently-running requests never observe each other's
# budget. `default=None` is "no ambient budget active": `_redact_free_text`
# falls back to a fresh per-string `_ScanBudget(_IBAN_SCAN_BUDGET)`
# exactly as before `redaction_budget` existed, so every caller that does
# not opt in keeps its current behaviour unchanged -- see
# `redaction_budget` for which callers that is, and why it is acceptable.
_current_budget: contextvars.ContextVar[_ScanBudget | None] = contextvars.ContextVar(
    "_current_budget", default=None
)


class RedactionScope:
    """Read-only view onto the `_ScanBudget` active for one `redaction_budget`
    block, yielded by that context manager so a caller outside this module
    can learn whether the block's checksum allowance ran out, without ever
    gaining a route to `_ScanBudget` itself. That is a narrower question
    than "did the block's redaction degrade" -- see `exhausted`'s own
    docstring for exactly how the two can diverge in both directions; do
    not repeat "ran out" as "degraded" elsewhere in this codebase without
    that caveat attached.

    `spend()` and `remaining` stay unreachable through this on purpose: this
    class holds a `_ScanBudget` but does not subclass it, forward attribute
    access to it, or expose it, so `exhausted` is the only thing a caller can
    read. `remaining` is a checksum count whose meaning has already changed
    three times (a per-token bound, then a call-wide budget, then a
    qualifying-start narrowing of what exhaustion masks) -- anything built
    against it, from outside this module, would pin every future revision of
    the scan strategy to today's one.

    `exhausted` delegates LIVE to the underlying `_ScanBudget` on every read,
    rather than copying a bool at construction time: `services/api/
    middleware/audit.py` reads it once the whole `_scrub` walk has finished
    (or, on the exception path, once it has propagated past the `with`
    block), by which point `redaction_budget` has already reset the
    `ContextVar` back to whatever it held before -- so a `RedactionScope`
    keeps its own direct reference to the one `_ScanBudget` it was built
    with, rather than reading `_current_budget` at property-access time. The
    two are the same object as long as the block's own budget was never
    superseded by a nested `redaction_budget`, which is exactly the
    condition nesting keeps true: see `redaction_budget`'s docstring for how
    a nested block restores the outer `ContextVar` value on exit, and this
    class's own tests in `tests/test_masking_types.py` for the nested and
    exception-inside-the-block cases checked directly.
    """

    __slots__ = ("_budget",)

    def __init__(self, budget: _ScanBudget) -> None:
        self._budget = budget

    @property
    def exhausted(self) -> bool:
        """Whether this scope's checksum allowance was fully spent at some
        point during the block -- not "was any value in this scope
        degraded because of it". The two are different questions, and
        conflating them is wrong in both directions (verified against
        `_find_iban_in_token`/`_redact_iban_match`, not asserted from
        reading the code):

        True does not imply anything was degraded. `_ScanBudget.exhausted`
        is `remaining <= 0`, and `remaining` reaches zero on the
        SUCCESSFUL spend of the last unit, not only when a caller is
        refused one -- so the very token whose scan spends that last unit
        can still resolve to a complete, structured mask. Measured: a full,
        uncontested scan of "MT92MALT01100ABCDEFGH1234IJKL56" costs exactly
        13 checksums; a budget of 13 masks it correctly (full country code
        and last four) AND leaves `exhausted` True, the same reading a
        budget of 11 or 12 gives for a bare, degraded mask.

        False does not imply nothing was degraded, or even that nothing
        was bare-masked. `_redact_iban_match`'s over-`_IBAN_SCAN_MAX_TOKEN`
        branch and its ambiguous-match branch (`isinstance(compact,
        _Ambiguous)`) both emit the bare marker WITHOUT spending any
        budget at all -- an over-long or ambiguous token can be bare-masked
        in a scope where `exhausted` reads False throughout.

        What this DOES reliably report: whether the qualifying-start-
        narrowed budget-exhaustion branch on `_redact_iban_match` (the
        `if budget.exhausted:` check, taken before scanning) could have
        fired for some token in this scope. `_ScanBudget.remaining` only
        ever decreases, so once this reads True it stays True for the rest
        of the scope's life -- True is therefore NECESSARY for that branch
        to have fired for any token after the one that spent the last
        unit, but not sufficient (as the 13-checksum example above shows),
        and it says nothing about which token, or how many."""
        return self._budget.exhausted


@contextmanager
def redaction_budget(checksums: int = _IBAN_SCAN_BUDGET) -> Iterator[RedactionScope]:
    """Make one checksum-operation allowance ambient for every `FreeText`
    validation performed inside this `with` block, across as many separate
    strings as it validates.

    Built for `services/api/middleware/audit.py:_scrub`'s tree walk: one
    tool call can carry its arguments as one long string, a list of short
    ones, a nested structure of dicts and lists, or any mix, and the
    attacker chooses which. Without this, each string validated through
    `FreeText` creates its OWN fresh `_ScanBudget(_IBAN_SCAN_BUDGET)` (see
    `_redact_free_text`), so splitting a payload into many short strings
    multiplies the total allowance by however many strings it is split
    into -- measured through the real `_scrub`, a 1 MiB LIST of
    128-character junk strings cost 7.60 SECONDS against a per-string
    budget (independently re-measured; a prior review pass measured 7.45s
    for the same shape), because the split bought a fresh
    100,000-checksum allowance for every element instead of spending down
    one shared one -- a 1 MiB DICT of them, which validates a key AND a
    value per entry, cost 14.66 seconds the same way. Wrapping the whole
    walk in `with redaction_budget():` makes every `FreeText` validation
    inside it spend from the SAME `_ScanBudget`, so the total cost is
    bounded by `checksums` regardless of how the value is shaped -- both
    of those shapes cost ~173-181ms with this wrapped around them, see
    `_redact_free_text`'s module-level comment for the full request-level
    table.

    Sets the `ContextVar` on entry and resets it (not just clears it, so a
    NESTED caller's own earlier budget -- if this is ever called
    reentrantly -- is restored rather than wiped to `None`) in a `finally`
    on exit, so an exception raised anywhere inside the block -- a
    `ValidationError` from a non-`FreeText` field partway through the tree,
    for instance -- cannot leave a spent, stale budget ambient for
    whatever unrelated work runs next in the same context. Callers that
    validate `FreeText` OUTSIDE of this context manager are unaffected and
    keep today's per-string behaviour; see `_current_budget` for why that
    is a deliberate, stated choice and not an oversight, and
    `services/api/middleware/audit.py` for the one caller that opts in
    today.

    Entirely synchronous, on purpose: set and reset happen in the same
    synchronous call with no `await` between them, so no `asyncio` task
    boundary is ever crossed while the budget is ambient, and there is
    nothing for a concurrently-scheduled coroutine on the same task to
    observe even if `ContextVar` did not already isolate it by task.

    Yields a `RedactionScope`, not the `_ScanBudget` itself: a caller
    outside this module -- `services/api/middleware/audit.py`'s audit-log
    write, specifically -- needs to know whether this block's checksum
    allowance ran out, but must never gain a route to `_ScanBudget.spend()`
    or `.remaining`. That is a narrower question than "did this block's
    redaction degrade" -- see `RedactionScope.exhausted`'s own docstring for
    exactly how the two diverge. See `RedactionScope` for why that view is
    read-only, one property wide, and safe to read after this block has
    already exited and reset the `ContextVar` above.
    """
    budget = _ScanBudget(checksums)
    token = _current_budget.set(budget)
    try:
        yield RedactionScope(budget)
    finally:
        _current_budget.reset(token)


class _Ambiguous:
    """Sentinel type returned by `_find_iban_in_token` when a token's
    correct interpretation cannot be established -- either because more
    than one start position inside it checksums, or because `_ScanBudget`
    ran out before the token could be fully ruled unambiguous. Deliberately
    a distinct type, not `None`: `None` means "scanned to completion, zero
    matches, confirmed not an IBAN, leave the text as written"; this means
    "do not know, and guessing is not safe" -- and both cases get the same
    treatment (`_MASK`, no country code, no last four) precisely because
    the caller must not be able to tell "ambiguous" from "ran out of
    budget" and quietly treat the budget-exhaustion case as safer than it
    is."""


_AMBIGUOUS = _Ambiguous()

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
#
# The candidate pattern no longer requires the IBAN's own opening shape
# (`[A-Za-z]{2}[0-9]{2}`) at the token's start -- that requirement was a
# third, sharper instance of the same lesson: one alphanumeric character
# glued to the FRONT of a valid IBAN ("XMT92MALT...") moves the opening
# shape one position to the right, where an anchored pattern can never look
# -- not "checksums the token and fails", not attempted at all, because the
# token does not even match the candidate regex. `_IBAN_MIN_LEN` is the only
# length constraint left at this boundary; `_find_iban_in_token` below does
# the work of locating the opener inside the token, wherever it sits.
#
# Boundaries are `(?<![A-Za-z0-9])` / `(?![A-Za-z0-9])`, not `\b`, for a
# fourth instance of the SAME lesson, found live on main: `\b` is defined
# against `\w`, which includes `_`. "_MT92MALT01100ABCDEFGH1234IJKL56" has
# no `\b` between the underscore and the "M" that follows it -- both are
# word characters -- so the pattern's own leading `\b` can only land before
# the underscore, where `[A-Za-z0-9]` immediately fails to match it, and the
# whole run is never scanned at all: a complete, valid IBAN reaching the
# output verbatim, one underscore away from being found by the very same
# front-glue fix above. An explicit "not alphanumeric" test on each side
# does not have this gap, because it does not go through `\w` at all: `_`
# fails `[A-Za-z0-9]` exactly like a space or a hyphen does, so it splits a
# token the same way they always did, and the front-glue and ambiguity
# logic below operate on the correctly split "MT92MALT..." token as if the
# underscore were a space. This also fixes the mirror case (an underscore
# glued to the END or in the MIDDLE of a reference like "REF_MT92MALT...")
# for the same reason, in the same change: the assertion is checked on both
# sides of every candidate span, not just the leading one.
_IBAN_IN_TEXT_RE = re.compile(rf"(?<![A-Za-z0-9])[A-Za-z0-9]{{{_IBAN_MIN_LEN},}}(?![A-Za-z0-9])")


def _find_iban_in_token(token: str, budget: _ScanBudget) -> str | None | _Ambiguous:
    """The checksum-valid IBAN substring inside `token`, wherever it starts
    -- or `_AMBIGUOUS` if that is not a well-defined question for this
    token, or `None` if the token was fully scanned and nothing checksums.

    Structural prefilter before any checksum, not a window scan: ISO
    13616's own opening shape is letter, letter, digit, digit, which is an
    O(1) character-class test per start position. A position only buys
    checksums -- at most `_IBAN_MAX_LEN - _IBAN_MIN_LEN + 1 == 21` of them,
    the same budget `_redact_iban_match` always spent on the token's own
    start before front-glue was ever considered -- if it clears that gate
    first. On real text almost every position is pruned for free: a digit,
    or a letter pair that isn't followed by two digits, never reaches a
    checksum. This is what makes an IBAN with junk glued to its FRONT
    findable without turning the scan into a window scan of every
    substring at every length.

    EVERY qualifying start is checked, not just the first that succeeds.
    Stopping at the first success was this function's original front-glue
    behaviour, and it is wrong: longest-match-wins is only meaningful
    WITHIN one start position (a coincidentally valid short prefix of a
    longer real IBAN, the "SC18SSCB..." registry case below), not ACROSS
    different starts, and a coincidental hit at an early start can end in
    the middle of a real IBAN sitting further right in the same token --
    measured, with a random letter-letter-digit-digit prefix glued in
    front of a real IBAN, at roughly 18-27% of tokens, essentially all of
    them with a wrong country code and a last-four sliced out of the real
    account number's interior, e.g.
    "NB91ODZDOC9IMT92MALT01100ABCDEFGH1234IJKL56" -> country code "NB",
    which was never in the input, and last-four "00AB", which is not the
    end of anything. The real IBAN never survived in either case measured
    (this is not a leak), but a WRONG, CONFIDENT last-four is exactly the
    failure `_redact_pan_match`'s over-19-digit branch and
    `_redact_iban_match`'s over-128 branch both already refuse to commit:
    an unverified disclosure reads as authoritative to whatever sees it
    next. So: collect every start's own longest match (if it has one), and
    only emit a country code and last four when EXACTLY ONE start
    produced one. Two or more is `_AMBIGUOUS` -- correct precisely because
    it is not knowable from the checksum alone which start (if any) is the
    "real" IBAN, so no start's answer is disclosed. Zero is `None`: the
    token was fully IBAN-shaped-checked and nothing in it is a real IBAN.

    Longest-at-a-start is unchanged from before: the registry example
    "SC18SSCB11010000000000001497USD" has a mod-97-valid 18-character
    prefix, and returning that would emit a last-four taken from the
    middle of the real account number instead of its end.

    Checking every start costs strictly more checksums than stopping at
    the first success, which is exactly why `budget` exists: this function
    spends nothing of its own accord and instead calls `budget.spend()`
    immediately before every checksum, anywhere in the double loop. The
    first call that returns False aborts the scan for this token
    immediately and returns `_AMBIGUOUS` -- not `None` -- because the scan
    did not run to completion and a real IBAN might be sitting in the part
    that was never reached; treating an aborted scan as "confirmed clean"
    would be exactly the guess this function exists to refuse. See
    `_IBAN_SCAN_BUDGET` for why the budget is total across a call rather
    than per token, and what a token this long already cost before any
    budget existed.
    """
    found: str | None = None
    limit = len(token) - _IBAN_MIN_LEN
    for start in range(limit + 1):
        if not (
            token[start].isalpha()
            and token[start + 1].isalpha()
            and token[start + 2].isdigit()
            and token[start + 3].isdigit()
        ):
            continue
        max_end = min(len(token), start + _IBAN_MAX_LEN)
        start_match: str | None = None
        for end in range(max_end, start + _IBAN_MIN_LEN - 1, -1):
            if not budget.spend():
                return _AMBIGUOUS
            candidate = token[start:end]
            if _mod97_ok(candidate):
                start_match = candidate
                break
        if start_match is not None:
            if found is not None:
                return _AMBIGUOUS
            found = start_match
    return found


def _has_qualifying_start(token: str) -> bool:
    """True if any position in `token` has ISO 13616's own opening shape
    (letter, letter, digit, digit) -- the identical O(1)-per-position
    structural test `_find_iban_in_token` runs before spending a single
    checksum, with the checksum loop itself removed. Spends no budget, and
    is exactly what a caller needs after the budget IS exhausted: a token
    with no qualifying start could never have reached `_mod97_ok` even
    with an unlimited budget, so it could never have been found to be a
    real IBAN regardless of how much allowance was left. Leaving such a
    token untouched loses nothing on the leak axis.

    O(len(token)), one pass, exact rather than approximate: every position
    is the SAME `str.isalpha`/`str.isdigit` test `_find_iban_in_token`
    itself uses to decide whether a position is even worth a checksum, not
    a cheaper, looser stand-in for it -- so "conservative if unsure" has no
    case to cover here: this function is never unsure, it runs the real
    test and only omits the part that costs a checksum.
    """
    limit = len(token) - _IBAN_MIN_LEN
    for start in range(limit + 1):
        if (
            token[start].isalpha()
            and token[start + 1].isalpha()
            and token[start + 2].isdigit()
            and token[start + 3].isdigit()
        ):
            return True
    return False


def _redact_iban_match(match: re.Match[str], budget: _ScanBudget) -> str:
    candidate = match.group(0)
    if len(candidate) > _IBAN_SCAN_MAX_TOKEN:
        # Not scanned at all, checksum or no checksum: a token this long
        # cannot be a real IBAN regardless of what any slice of it computes
        # to, because ISO 13616 caps a real one at `_IBAN_MAX_LEN`
        # characters. Emitting the bare marker -- no country code, no
        # last four -- mirrors the PAN path's over-19-digit branch exactly
        # (`_redact_pan_match` below): nothing here has been positively
        # checksummed, so there is no identified IBAN and therefore no
        # approved last-four disclosure to make. Emitting one anyway would
        # assert a confident, wrong "account ending NNNN" to whatever
        # reads the text next. This masks strictly MORE than a full scan
        # would -- a real IBAN embedded in an over-long token is covered
        # by the same bare marker, never left readable -- so the bound
        # cannot reopen the leak it sits next to; it can only over-redact.
        # Free: no call to `_find_iban_in_token`, so no budget is spent
        # deciding this, which is what keeps this branch effective even
        # after `budget` itself runs out (see below).
        return _MASK
    if budget.exhausted:
        # The call-wide budget was spent by earlier tokens in this same
        # value, not by this one. Fail closed on anything that could
        # POSSIBLY have matched -- bare-mask, never scan for free, because
        # scanning "for free" is precisely the per-token exemption that
        # made the budget necessary in the first place -- but narrow that
        # to tokens that could possibly have matched, using
        # `_has_qualifying_start`, which spends no budget of its own.
        #
        # Without this narrowing, budget exhaustion is a denial-of-audit
        # primitive, found by review: pad a request with ~23 KB of junk
        # tokens (179 of them, one past the budget) and EVERY later
        # alphanumeric token 14 characters or longer in the SAME request
        # -- a payee reference, a challenge ID, a device ID, an IBAN, none
        # of them junk -- comes back as a bare `••••`, indistinguishable
        # from an actual redaction, in the attacker's OWN audit row. Fail
        # SAFE on the leak axis throughout (verified: no post-exhaustion
        # branch ever leaks), but forensic erasure of the very call being
        # audited is its own cost, and one this module can remove for
        # free: a token with no letter-letter-digit-digit start anywhere
        # in it (e.g. "ACMECORP20260912X") can never reach `_mod97_ok`
        # regardless of budget, so it was never a candidate this budget
        # exhaustion could have cost -- masking it anyway is pure
        # collateral damage, not a safety margin.
        #
        # Cost, precisely: this branch used to be O(1) per remaining
        # token; it is now O(length) per remaining token, because
        # `_has_qualifying_start` is one full pass over the token (the
        # same pass `_find_iban_in_token` runs before spending its first
        # checksum, minus the checksum loop). That does not reopen the
        # bound `_IBAN_SCAN_BUDGET` exists to hold: the quantity it caps is
        # CHECKSUM operations, and this branch spends zero of those --
        # `candidate.upper()` and `_find_iban_in_token` itself are still
        # never called here. Re-measured against the same adversarial
        # shapes as before to confirm the wall-clock bound still holds
        # with this extra linear pass added; see `_redact_free_text`.
        if _has_qualifying_start(candidate):
            return _MASK
        return candidate
    compact = _find_iban_in_token(candidate.upper(), budget)
    if compact is None:
        # IBAN-shaped but nothing in it checksums: not a real IBAN (e.g. a
        # merchant reference that happens to look like one). Leave it as
        # written rather than mangling ordinary text on a false positive.
        return candidate
    if isinstance(compact, _Ambiguous):
        # Either more than one start position in this token checksummed
        # (see `_find_iban_in_token`'s docstring for why picking one would
        # be a guess dressed as a disclosure), or the budget ran out before
        # that could be ruled out. Both get the bare marker: masking more
        # than a confirmed single match is the safe direction, the same
        # "cannot reopen the leak, can only over-redact" property the
        # over-length and budget-exhausted branches above already rely on.
        return _MASK
    # The WHOLE token is replaced, tail included, not just the IBAN prefix.
    # Keeping the tail would set the mask's own last four directly against
    # unconsumed, attacker-influenced characters of the same token
    # ("KL56" + "REF9"), which is exactly the shape that let the PAN scan
    # reassemble a card out of its own mask. Country code plus last four is
    # kept, and only that: the checksum has positively, UNAMBIGUOUSLY
    # identified a genuine IBAN here, and that is precisely the disclosure
    # `MaskedIban` is approved to make about one -- unlike an over-long
    # digit run, which is definitionally not a card and so has no approved
    # last-four at all, or an ambiguous token, which has one but does not
    # say which.
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


# Unicode characters stripped from `FreeText` before either pass runs,
# found live on main the same day as the underscore hole above and by the
# same reasoning: a human or a model reading the RENDERED text sees a
# complete IBAN, while a pattern matching on codepoints sees it split into
# fragments below `_IBAN_MIN_LEN`, because the inserted character is a
# non-alphanumeric codepoint the same way a space or an underscore is.
#
# The rule, stated once so it survives a rewrite of the set below: a
# character that renders as NOTHING is stripped; a character that renders
# as visible whitespace is not, because a reader sees a break there and
# that break is this module's own already-documented grouped-IBAN
# limitation (the "no separator handling" comment on `_PAN_IN_TEXT_RE`
# above), not an evasion. Applied category by category:
#
# `Cf` ("format") is every zero-width/invisible format character -- U+200B
# ZERO WIDTH SPACE, U+00AD SOFT HYPHEN, U+200D ZERO WIDTH JOINER among them
# -- planted mid-token specifically because it renders as nothing. Stripped
# in full: no exceptions in this category render as anything.
#
# `Mn` ("nonspacing mark", combining diacritics) is included too, on
# purpose, not swept in as part of `Cf`: a combining mark attaches visually
# to the character before it rather than being invisible, so the rendered
# text still looks like one continuous token to a reader, but the
# codepoint itself is just as non-alphanumeric as a `Cf` character and
# breaks a token the same way. No real IBAN or PAN ever legitimately
# contains one -- both are plain ASCII by their respective standards
# (ISO 13616, ISO/IEC 7812) -- so, unlike the `Cf` case, this one does have
# a cost, and it is accepted deliberately rather than by omission:
# legitimate prose using a DECOMPOSED accented character (a combining mark
# following a bare letter, rather than the single precomposed codepoint --
# "cafe" + U+0301 rather than the single "é") loses the accent on output.
# Precomposed (NFC) form is what every system this module has been tested
# against actually sends; a decomposed merchant descriptor was not among
# the realistic ones checked, and if one is ever found reaching this code,
# stripping `Mn` should be revisited rather than assumed still correct.
#
# `Cc` ("control") closes a hole this revision found on main, in the same
# bug class and the same day: U+0001, for instance, renders as nothing and
# splits a token exactly like a `Cf` character does --
# "MT92MALT01100AB\x01CDEFGH1234IJKL56" reached the output unchanged, and
# "41111111\x0111114417" leaked a complete, Luhn-valid PAN. `_scrub`
# (`services/api/middleware/audit.py`) already strips NUL specifically,
# before this function ever runs, for a REASSEMBLY reason of its own (see
# its docstring); this is a different, broader fix, for `FreeText` callers
# other than `_scrub` and for NUL's 30-odd siblings in the same category,
# which share NUL's "renders as nothing" property and were never covered
# by a NUL-only strip. Not all of `Cc` renders as nothing, though: TAB,
# LF and CR are the visible-whitespace exception the rule above carves
# out, listed explicitly in `_VISIBLE_WHITESPACE_CONTROLS` because there
# is no Unicode category that means exactly "control character that
# happens to render as a break" -- every OTHER `Cc` character (the rest of
# the C0 block, DEL, and the C1 block U+0080-U+009F) renders as nothing
# and is stripped.
_STRIPPED_CATEGORIES = frozenset({"Cf", "Mn", "Cc"})

_VISIBLE_WHITESPACE_CONTROLS = frozenset("\t\n\r")

# A handful of individual characters that render as blank but do not share
# a category that means only that: `Lo` ("letter, other") is most of CJK,
# and `So` ("symbol, other") is a large swath of ordinary symbols, so
# stripping either category whole would destroy legitimate text far
# outside this module's remit. Enumerated one by one instead, each found
# live and each doing the identical trick as the categories above --
# rendering as a blank cell so a reader sees one continuous IBAN while the
# codepoint stream is split below `_IBAN_MIN_LEN`:
#   U+115F  HANGUL CHOSEONG FILLER
#   U+1160  HANGUL JUNGSEONG FILLER
#   U+3164  HANGUL FILLER
#   U+FFA0  HALFWIDTH HANGUL FILLER
#   U+2800  BRAILLE PATTERN BLANK (the all-dots-lowered, i.e. blank, cell)
_BLANK_RENDERING_CHARACTERS = frozenset("ᅟᅠㅤﾠ⠀")

# Unicode 15.0's `Default_Ignorable_Code_Point` property -- the property
# that MEANS "render as nothing in a conforming renderer" -- covers 4,174
# codepoints; `Cf`/`Mn`/`Cc` above catch the ASSIGNED ones (a Default
# Ignorable codepoint that has been given a purpose is typically `Cf`), but
# 3,769 of the 4,174 are unassigned (`Cn`) and none of those are stripped
# by any category check above, because this module deliberately does not
# treat all of `Cn` as strippable -- doing that would silently strip every
# codepoint Unicode has not assigned a meaning to YET, an unbounded,
# unreviewable set that grows with every future Unicode version without
# this file changing at all. Default_Ignorable is a specific, named,
# version-pinned list, not "any Cn", which is why it is enumerated by
# range instead. Demonstrated live, not inferred from the property's name:
# planting any one of these mid-value defeats BOTH the IBAN and the PAN
# scan, and deleting the single codepoint recovers the complete original
# value -- a full-PAN bypass.
#
# `unicodedata` (the stdlib module this file already uses) does not expose
# Default_Ignorable_Code_Point directly, so the ranges below are transcribed
# from Unicode 15.0's DerivedCoreProperties.txt by hand and must be
# RE-CHECKED whenever the Python interpreter's bundled Unicode version
# changes (`unicodedata.unidata_version`; 15.0.0 as of this writing). That
# recheck is gated, not just requested: see
# `test_bundled_unicode_version_matches_the_version_the_ranges_were_derived_against`
# in `tests/test_masking_types.py`, which fails the build the day the
# bundled version moves, rather than relying on a reader noticing this
# comment.
# `U+E0002-U+E001F` is why this needed checking against the property and
# not just patched from examples: it sits INSIDE the Tags block whose
# ASSIGNED members -- U+E0001 LANGUAGE TAG and U+E0020-U+E007F (tag
# characters) -- are `Cf` and already stripped by the category check above.
# A codepoint in this list can be reassigned a category (typically `Cf`)
# in a future Unicode version without ever stopping being Default
# Ignorable, exactly as already happened to that block's other members;
# the category check would then cover it too, redundantly but harmlessly,
# so there is no need to remove a range from here when that happens.
#
# Weaker evidence than the assigned strips above, and worth saying
# plainly: Default_Ignorable is a SHOULD for a renderer encountering an
# unassigned codepoint, not a MUST, and real renderers vary -- some show
# nothing per the property, some show a ".notdef" replacement box instead.
# This module strips them anyway, because the alternative, weighed
# against a demonstrated full-PAN/full-IBAN bypass, is worse: a renderer
# that shows a visible box for one of these still shows the reader
# something between the fragments, which is closer to today's grouped-
# IBAN limitation (a visible break) than to a silent, complete bypass.
_DEFAULT_IGNORABLE_UNASSIGNED_RANGES: tuple[tuple[int, int], ...] = (
    (0x2065, 0x2065),
    (0xFFF0, 0xFFF8),
    (0xE0000, 0xE0000),
    (0xE0002, 0xE001F),
    (0xE0080, 0xE00FF),
    (0xE01F0, 0xE0FFF),
)

_DEFAULT_IGNORABLE_UNASSIGNED = frozenset(
    chr(cp) for start, end in _DEFAULT_IGNORABLE_UNASSIGNED_RANGES for cp in range(start, end + 1)
)

# Known, not overlooked: `_SEPARATORS` (above) already treats U+00A0
# (NO-BREAK SPACE) as legitimate IBAN grouping punctuation for
# `MaskedIban`/`MaskedPan` -- "ES91 2100 0418..." compacts and
# validates. `FreeText` cannot do the equivalent: `_IBAN_IN_TEXT_RE` has no
# grouped-IBAN detection at all (the "no separator handling" limitation
# documented on `_PAN_IN_TEXT_RE` above applies to every separator,
# including U+00A0, not just ones this revision touches), so a
# free-text IBAN grouped with non-breaking spaces is not found by either
# path. U+00A0 is category `Zs`, not `Cf`/`Mn`/`Cc`, so `_strip_invisible`
# does not remove it either -- correctly, since it renders as a visible
# gap and stripping it would not close the grouped-IBAN gap anyway (the
# groups would still be individually under `_IBAN_MIN_LEN`). Left as is;
# flagged here so the asymmetry between the two types is a known limit,
# not a surprise found again later.


def _is_stripped(ch: str) -> bool:
    if ch in _BLANK_RENDERING_CHARACTERS or ch in _DEFAULT_IGNORABLE_UNASSIGNED:
        return True
    category = unicodedata.category(ch)
    return category in _STRIPPED_CATEGORIES and ch not in _VISIBLE_WHITESPACE_CONTROLS


# Fast path for `_strip_invisible`: every character `_is_stripped` can ever
# say yes to for a plain-ASCII string is a C0 control below U+0020 or DEL
# (U+007F) -- `Cf`, `Mn`, every character in `_BLANK_RENDERING_CHARACTERS`,
# and every codepoint in `_DEFAULT_IGNORABLE_UNASSIGNED` (lowest member
# U+2065) are non-ASCII by construction, so a string that IS ASCII can only
# ever need this table. `str.translate` runs the
# removal in C rather than a Python-level loop calling
# `unicodedata.category` once per character; measured on 1 MiB of plain
# ASCII text, the difference is documented on `_strip_invisible` below.
_ASCII_STRIP_TABLE = str.maketrans(
    "",
    "",
    "".join(chr(cp) for cp in range(0x20) if chr(cp) not in _VISIBLE_WHITESPACE_CONTROLS) + "\x7f",
)


def _strip_invisible(value: str) -> str:
    """Remove every character `_is_stripped` matches, before any IBAN or
    PAN scanning runs.

    Same ordering principle as the NUL strip in
    `services/api/middleware/audit.py._scrub`, applied here to a broader
    character set for the same reason: strip the evasion character before
    either pattern ever runs, never after. Stripping afterwards would let,
    say, a zero-width character split a token below `_IBAN_MIN_LEN` (or
    split a PAN's digit run the same way a NUL byte does) so that neither
    pass matches anything, and then removing the character re-assembles
    the very thing that should have been caught -- the identical
    reassembly failure the NUL fix documents, for a character an attacker
    chooses specifically because it renders as nothing, or as an accent on
    the previous character, rather than because it survived an ordinary
    copy-paste.

    This changes output text for legitimate input too, not just
    adversarial input: any stripped character present in otherwise-
    ordinary free text is silently removed, including the accent-loss case
    described where `Mn` is added to `_STRIPPED_CATEGORIES`. That is a
    deliberate decision for text heading to a model, not an accident of
    implementation.

    The `value.isascii()` branch is a pure performance fast path, not a
    behaviour difference -- see `_ASCII_STRIP_TABLE`; confirmed identical
    output on both plain-ASCII and non-ASCII input before this was landed.
    Measured on 1 MiB of plain ASCII transaction text, repeated runs on an
    ordinary development machine (not an isolated benchmarking host, and
    the ratio is noisy at this scale): the general per-character path
    (calling `unicodedata.category` once per character, now also checking
    membership in `_DEFAULT_IGNORABLE_UNASSIGNED`) consistently costs
    65-75ms; `str.translate` on the ASCII fast path consistently costs
    under 1ms (0.46-0.9ms observed). That is a speedup somewhere in the
    90-155x range depending on the run -- a prior pass on this same code
    reported 123x, and an independent review measured 86x -- rather than
    one precise multiplier; the two stable, load-bearing facts are "tens of
    milliseconds" versus "a fraction of a millisecond" per MiB, and that
    the fast path is consistently and by far the cheaper of the two, not
    the exact ratio between them. Non-ASCII text always takes the general
    path, unchanged -- `_BLANK_RENDERING_CHARACTERS`,
    `_DEFAULT_IGNORABLE_UNASSIGNED`, and `Cf`/`Mn` are all non-ASCII by
    construction, so the fast path never needs to consider them.
    """
    if value.isascii():
        return value.translate(_ASCII_STRIP_TABLE)
    return "".join(ch for ch in value if not _is_stripped(ch))


_LOOKALIKE_DIGIT_WORDS = {
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
_MATH_ALPHANUMERIC_LETTER_RE = re.compile(r"^MATHEMATICAL [A-Z][A-Z -]* (CAPITAL|SMALL) ([A-Z])$")
_MATH_ALPHANUMERIC_DIGIT_RE = re.compile(
    r"^MATHEMATICAL [A-Z][A-Z -]* DIGIT (" + "|".join(_LOOKALIKE_DIGIT_WORDS) + ")$"
)
_ENCLOSED_ALPHANUMERIC_LETTER_RE = re.compile(
    r"^CIRCLED (LATIN CAPITAL|LATIN SMALL) LETTER ([A-Z])$"
)
_ENCLOSED_ALPHANUMERIC_DIGIT_RE = re.compile(
    r"^CIRCLED DIGIT (" + "|".join(_LOOKALIKE_DIGIT_WORDS) + ")$"
)


def _build_fullwidth_lookalikes() -> dict[str, str]:
    """Fullwidth Latin letters and digits (U+FF01-U+FF5E block): a fixed
    +0xFEE0 offset from ASCII ('Ａ' - 'A' == '１' - '1' == 0xFEE0),
    verified directly against the running interpreter, not assumed from the
    block's name. A formula, not a lookup table: nothing here can drift
    across a Unicode version bump, because the block's own definition is the
    offset -- there is no name-parsing step for this source to get out of
    sync with anything."""
    table: dict[str, str] = {}
    for cp in range(0xFF21, 0xFF3B):  # fullwidth A-Z
        table[chr(cp)] = chr(cp - 0xFEE0)
    for cp in range(0xFF41, 0xFF5B):  # fullwidth a-z
        table[chr(cp)] = chr(cp - 0xFEE0)
    for cp in range(0xFF10, 0xFF1A):  # fullwidth 0-9
        table[chr(cp)] = chr(cp - 0xFEE0)
    return table


def _build_math_alphanumeric_lookalikes() -> dict[str, str]:
    """Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF), derived by
    parsing `unicodedata.name()` rather than hand-listing ~700 codepoints.
    Deliberately restricted to names ending in '(CAPITAL|SMALL) <letter>' or
    'DIGIT <word>': the math-styled GREEK letters sharing this same block
    (e.g. MATHEMATICAL BOLD CAPITAL ALPHA) are excluded by the same regex,
    on purpose -- a math-styled Greek alpha is not a Latin look-alike the
    way a math-styled Latin A is, and this table's job is Latin/digit
    look-alikes only. This block is complete and closed in Unicode (every
    math-alphabet style ISO 13616/7812 could plausibly encounter was
    assigned when the block was created); a future Unicode version is not
    expected to add new members here the way it can to Cyrillic or Greek."""
    table: dict[str, str] = {}
    for cp in range(0x1D400, 0x1D800):
        try:
            name = unicodedata.name(chr(cp))
        except ValueError:
            continue
        m = _MATH_ALPHANUMERIC_LETTER_RE.match(name)
        if m:
            case, letter = m.groups()
            table[chr(cp)] = letter.lower() if case == "SMALL" else letter
            continue
        m = _MATH_ALPHANUMERIC_DIGIT_RE.match(name)
        if m:
            table[chr(cp)] = _LOOKALIKE_DIGIT_WORDS[m.group(1)]
    return table


def _build_enclosed_alphanumeric_lookalikes() -> dict[str, str]:
    """Enclosed Alphanumerics (U+2460-U+24FF) only -- not the Enclosed
    Alphanumeric Supplement (U+1F100-U+1F1FF, "negative circled"/"squared"
    forms), a different, much larger, and visually distinct block. Two-digit
    forms ("CIRCLED NUMBER TEN".."TWENTY") are skipped on purpose: mapping
    one codepoint to a two-character string would break the 1:1 codepoint
    correspondence every other entry in this table keeps, which
    `_delookalike` (below) relies on to stay a single `str.translate` pass."""
    table: dict[str, str] = {}
    for cp in range(0x2460, 0x2500):
        try:
            name = unicodedata.name(chr(cp))
        except ValueError:
            continue
        m = _ENCLOSED_ALPHANUMERIC_LETTER_RE.match(name)
        if m:
            case, letter = m.groups()
            table[chr(cp)] = letter.lower() if "SMALL" in case else letter
            continue
        m = _ENCLOSED_ALPHANUMERIC_DIGIT_RE.match(name)
        if m:
            table[chr(cp)] = _LOOKALIKE_DIGIT_WORDS[m.group(1)]
    return table


# Hand-enumerated: Cyrillic and Greek letters visually identical -- not
# merely similar -- to a Latin letter, both cases, plus dotless i. This is
# the ONLY source in `_LOOKALIKE_TABLE` with no mechanical derivation and no
# formal Unicode property backing it ("confusable with a specific other
# letter" is not itself an enumerable Unicode property the way
# Default_Ignorable_Code_Point is on `_DEFAULT_IGNORABLE_UNASSIGNED` above);
# it is a closed, manually curated list, and
# `test_bundled_unicode_version_matches_the_version_the_lookalike_table_was_derived_against`
# (tests/test_masking_types.py) exists specifically because nothing else in
# this file can detect a future Unicode version assigning a new
# Cyrillic/Greek character with a Latin look-alike -- see that test's own
# failure message for what a human must do about it, and do not treat
# passing it as evidence this list is complete.
#
# Both cases were added in the same change that discovered the gap:
# uppercase-only was this table's first shape, on the reasoning that ISO
# 13616 IBANs are conventionally rendered uppercase -- true, but irrelevant,
# because `_delookalike` runs on the WHOLE free-text value, not on an
# isolated IBAN candidate, and an attacker is not obliged to render the rest
# of their homoglyph in the same case as the real IBAN. Measured directly: a
# single lowercase Cyrillic а (U+0430) substituted into an otherwise-
# uppercase IBAN reached `_redact_free_text`'s output completely unchanged
# under the uppercase-only table -- not merely "degraded", but byte-for-byte
# identical to the input -- because the uppercase-only table left it
# non-ASCII and `_IBAN_IN_TEXT_RE` split the token on it exactly as it would
# on any other non-ASCII codepoint. See
# `test_lowercase_cyrillic_homoglyph_is_now_properly_masked` (tests/
# test_masking_confusables.py) for that case, now closed.
#
# Every precomposed accented Latin letter (a-with-acute, n-with-tilde,
# c-with-cedilla, ...) is excluded BY CONSTRUCTION: none of the four sources
# in `_LOOKALIKE_TABLE` touches the Latin-1 Supplement or Latin Extended-A
# blocks at all, so there is no code path through which "ñ", "ç", "à" could
# ever enter this table by accident. Verified against 53 realistic Spanish
# and Catalan merchant descriptors and payee names with zero alterations
# (`test_false_positive_corpus_is_untouched_through_the_public_api`, same
# test file, and `test_false_positives_on_legitimate_text` in tests/
# test_masking_homoglyph_measurement.py).
_HAND_CYRILLIC_LOOKALIKES = {
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
    "а": "a",
    "в": "b",
    "е": "e",
    "к": "k",
    "м": "m",
    "н": "h",
    "о": "o",
    "р": "p",
    "с": "c",
    "т": "t",
    "у": "y",
    "х": "x",
    "ѕ": "s",
    "ј": "j",
}
_HAND_GREEK_LOOKALIKES = {
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
_HAND_MISC_LOOKALIKES = {
    "ı": "i",  # LATIN SMALL LETTER DOTLESS I
}

_LOOKALIKE_TABLE: dict[str, str] = {
    **_build_fullwidth_lookalikes(),
    **_build_math_alphanumeric_lookalikes(),
    **_build_enclosed_alphanumeric_lookalikes(),
    **_HAND_CYRILLIC_LOOKALIKES,
    **_HAND_GREEK_LOOKALIKES,
    **_HAND_MISC_LOOKALIKES,
}

# `_redact_free_text`'s position-preserving splice (`_sub_preserving_original`
# below) depends on `_delookalike` never changing a value's LENGTH: it finds
# match spans in a transliterated skeleton and slices the ORIGINAL string at
# those same offsets, which is only correct if the skeleton and the original
# stay index-aligned, character for character. That alignment holds only if
# every entry in this table maps to EXACTLY one character -- true today by
# construction (see `_build_enclosed_alphanumeric_lookalikes`'s own
# docstring for the one source that had to be deliberately narrowed to keep
# it true), but "true today" is a fact about data, not about code, and nothing
# else in this file would notice if a future edit added a multi-character
# target. A `str.maketrans` mapping ALLOWS multi-character replacement
# values -- `_delookalike` itself would keep working, silently producing a
# LONGER string with no error -- so this cannot be left as a remembered
# invariant: checked here, unconditionally, at import time, raising rather
# than asserting, because `assert` is stripped under `python -O` and this is
# exactly the kind of check `_STRIPPED_CATEGORIES`'s own module docstring
# warns a stripped assert would silently fail to protect. A future edit that
# violates this must fail the moment the module is imported, not
# desynchronise a splice offset and cut a mask into the wrong place months
# later. See `test_lookalike_table_values_are_single_characters`
# (tests/test_masking_confusables.py) for the same property checked as a
# test too, and `test_delookalike_preserves_string_length` for the
# consequence this guards, exercised directly.
_MULTI_CHARACTER_LOOKALIKE_TARGETS = {k: v for k, v in _LOOKALIKE_TABLE.items() if len(v) != 1}
if _MULTI_CHARACTER_LOOKALIKE_TARGETS:
    raise ValueError(
        "_LOOKALIKE_TABLE must map every codepoint to exactly one ASCII "
        "character -- _redact_free_text's position-preserving splice relies "
        "on the skeleton and the original string staying the same length "
        "and index-aligned. Found multi-character (or empty) targets: "
        f"{_MULTI_CHARACTER_LOOKALIKE_TARGETS!r}"
    )

_LOOKALIKE_TRANS = str.maketrans(_LOOKALIKE_TABLE)


def _delookalike(value: str) -> str:
    """Map every codepoint in `_LOOKALIKE_TABLE` to the ASCII letter or digit
    it visually renders as, before either `_IBAN_IN_TEXT_RE` or
    `_PAN_IN_TEXT_RE` ever runs. Same ordering principle as
    `_strip_invisible` immediately above it, for the mirror-image reason:
    that function strips a codepoint that renders as NOTHING so a reader
    sees one continuous token while the codepoint stream is split below the
    scan's length floor; this one neutralizes a codepoint that renders as an
    ASCII LOOK-ALIKE for the identical structural reason --
    `_IBAN_IN_TEXT_RE`/`_PAN_IN_TEXT_RE` are `[A-Za-z0-9]`-only, so a single
    Cyrillic А inside an otherwise-ASCII IBAN splits the token exactly the
    way a zero-width space does, and the checksum pass never runs. Found
    live on main: `'MT92MАLT01100ABCDEFGH1234IJKL56'` (one Cyrillic А,
    U+0410) reached `_redact_free_text`'s output completely unchanged.

    This function itself only builds the SKELETON -- the ASCII-mapped copy
    used to find matches. It does not decide what reaches the output; see
    `_sub_preserving_original` and `_redact_free_text` below for the splice
    that applies a match found here back onto the UNTRANSLITERATED original,
    leaving every character outside a matched span exactly as written.

    That position-preserving design was not the first one shipped, and the
    reversal is worth recording rather than quietly overwriting: the first
    version of this function transliterated the whole value and let
    `_redact_free_text` scan and mask that transliterated copy directly, on
    the reasoning that this deployment's realistic `FreeText` input
    distribution is Spanish/Catalan and would not contain genuine Cyrillic
    or Greek script. That premise was wrong -- `FreeText` covers SEPA
    remittance information and counterparty names, and SEPA includes
    Greece, Cyprus and Bulgaria, so a Greek payee or a Bulgarian
    counterparty name is ordinary traffic, not an exotic case. Measured on
    the whole-value version before it was replaced: `'ΜΑΡΙΑ ΠΑΠΑΔΟΠΟΥΛΟΥ'`
    (a Greek name, no IBAN or PAN anywhere in it) came out
    `'MAPIA ΠAΠAΔOΠOYΛOY'`, and `'payment to МОСКВА office'` came out
    `'payment to MOCKBA office'` -- half-transliterated gibberish in a field
    a customer and a model both read, which is corruption, not the
    over-redaction this module's other trade-offs accept. Over-redaction
    means masking MORE than necessary; it does not mean silently rewriting
    unrelated, unmasked characters into a different script. Every mapping
    in `_LOOKALIKE_TABLE` being 1:1 (see `_build_enclosed_alphanumeric_
    lookalikes`'s own docstring for the one source deliberately narrowed to
    keep this true, and the module-level check immediately above
    `_LOOKALIKE_TRANS` that fails the import if it ever stops being true) is
    exactly what makes the position-preserving splice tractable: the
    skeleton this function returns is always the same length, and
    index-aligned, with whatever string was passed in.

    Cost, stated plainly rather than left for a reader to discover under
    load: this runs unconditionally, before `_ScanBudget` is even
    constructed, so it is spent whether or not the value contains anything
    resembling an IBAN or PAN -- `_IBAN_SCAN_BUDGET` bounds CHECKSUM
    operations only, and a `str.translate` call is not one. On its own this
    is a single O(length) pass, and the `value.isascii()` fast path below
    (identical in shape to `_strip_invisible`'s own) means an ordinary ASCII
    memo -- the overwhelming majority of real traffic -- pays only the cost
    of that one C-level check, not a translation pass at all.
    Two numbers, for two different strings, because they are not the same
    claim: a genuinely ALL-ASCII 67-character memo
    ("TRANSFER SALARY PAYMENT REF 2024-09-15 SABADELL BRANCH ACCOUNT 4471")
    measured 2.0-2.1 microseconds end to end (`_redact_free_text` as a
    whole, this function called twice, once per pass -- see
    `_redact_free_text` itself), min of 5 trials of 20,000 reps each, five
    repeated runs, all landing in that band -- independently corroborated
    at 2.51 microseconds on a different 73-character all-ASCII memo, same
    method, by a reviewer of this change; the two numbers are close enough
    (both "a few microseconds") to support the same conclusion without
    either being asserted as the one true figure. A 61-character memo WITH
    accented Latin characters ("Transferència nòmina mensual Josep Martí
    ref 2024-09 Sabadell", the realistic Catalan memo this module's own
    test suite uses for false-positive testing) measured 7.6-7.8
    microseconds instead, same method -- NOT the isascii() fast path this
    paragraph is about, because that string genuinely is not ASCII; it is
    the general per-character path taken by both this function and
    `_strip_invisible` finding nothing to change, still cheap, just not the
    same claim as the all-ASCII number above. Earlier revisions of this
    docstring conflated the two and cited "7-9 microseconds" as the
    ASCII-fast-path figure; that was the accented-memo number mislabelled,
    corrected here after a reviewer measured the true ASCII case and found
    the citation roughly 3x too high. Both numbers are, either way,
    indistinguishable in practice from this function not existing.
    The cost that matters is what this does to the module's OWN documented
    worst case, and it makes it worse, not neutral: `masking.py`'s adversarial
    shape is space-separated 128-character tokens built to maximize
    qualifying-start checksum attempts (see `_IBAN_SCAN_BUDGET`'s own
    derivation above). Measured on a 1 MiB payload of that shape with every
    'A' opener replaced by a Cyrillic А (U+0410) -- a payload an attacker
    controls as freely as the plain-ASCII version -- this function
    RE-ASSEMBLES the exact expensive shape the unfixed scan could not even
    see: under the unfixed ASCII-only scan (no `_delookalike` at all) the
    substitution splits each 128-character token into 3-character fragments
    (below `_IBAN_MIN_LEN`), so the checksum pass finds nothing to do
    (measured: 81ms, cheaper than the plain-ASCII adversarial case, because
    the unfixed scan is doing structurally less work). With `_delookalike`
    in place, the SAME payload measures 265-272ms across repeated runs --
    noticeably above the 165-175ms the plain-ASCII adversarial shape itself
    costs on identical, unmodified `_redact_free_text` -- because the full
    128-character token is reassembled before the scan runs and pays the
    scan's own known worst case in full, on top of this function's own
    translate pass over non-ASCII input (which does not get the isascii()
    fast path), paid roughly TWICE for this shape specifically: once to
    build the IBAN pass's skeleton, and again to build the PAN pass's,
    because this payload's own budget-exhaustion bare-masking (see
    `_redact_iban_match`'s `budget.exhausted` branch) touches nearly the
    whole string, which defeats the one optimization `_redact_free_text`
    has for skipping that second call (see its own comment, immediately
    below the two calls to this function, for exactly when that skip does
    and does not help -- this adversarial shape is the "does not" case,
    by design: it is built to spend the budget, and spending the budget is
    what makes the skip unable to fire). `_ScanBudget` does not see any of
    this: every microsecond here is spent before `budget` is read for the
    first time, so this is, by construction, an UNBOUNDED cost with respect
    to that budget -- bounded only by this being at most two O(length)
    passes over one value, the same KIND of bound `_strip_invisible`
    already carries and this module already accepts elsewhere, just paid
    twice instead of once in the worst case. This module has a documented
    history of a per-token bound being defeated by attacker-controlled
    tokenization (`_IBAN_SCAN_MAX_TOKEN`), then a per-string bound being
    defeated by attacker-controlled string-splitting (`_IBAN_SCAN_BUDGET`
    vs `redaction_budget`); an unbudgeted preprocessing pass whose cost
    SCALES WITH how much of the adversarial shape it manages to reassemble,
    and can be paid MORE THAN ONCE per call, is the obvious next place to
    look for the same pattern, and it has not been closed here -- only
    measured and stated.

    This is a real cost increase from the position-preserving splice
    (`_sub_preserving_original`) this function's skeleton feeds, not from
    this function itself changing -- the whole-value version that shipped
    first measured 193-197ms on the identical payload, because it needed
    only one transliteration pass, scanned and masked that single
    transliterated copy directly, and never needed a second, freshly
    rebuilt skeleton for a second pass. That version was replaced because it
    corrupted legitimate non-Latin text outside any match (see this
    function's own "position-preserving, not whole-value" section above);
    the ~70-100ms difference on this specific adversarial shape is the
    measured price of that correctness fix, not an oversight in it.

    Residual gap, stated for an auditor rather than left implicit: this
    function closes the leak for exactly the codepoints in
    `_LOOKALIKE_TABLE` -- fullwidth Latin, Mathematical Alphanumeric Latin,
    Enclosed Alphanumeric Latin, and the hand-enumerated Cyrillic/Greek
    look-alikes (both cases) plus dotless i. Any OTHER non-ASCII codepoint
    that splits a token the same way -- a Cyrillic letter with no Latin
    look-alike (Ж, none attempted), an Armenian, Georgian or CJK character,
    or a future Unicode-assigned Cyrillic/Greek look-alike not yet added to
    the hand-enumerated slice -- is NOT covered and still reaches
    `_redact_free_text`'s output as a full, unmasked leak, identically to
    main before this change. See
    `test_residual_gap_an_uncatalogued_cyrillic_letter_still_leaks` (tests/
    test_masking_confusables.py) for that gap demonstrated directly, not
    asserted from reading this comment. Heuristic look-alike redaction
    cannot, by its nature, enumerate every codepoint that could ever render
    like an ASCII character; closing this class of leak completely belongs
    upstream, in a backend that returns pre-masked projections rather than
    free text a homoglyph can hide inside at all (handoff §10.17).
    """
    if value.isascii():
        return value
    return value.translate(_LOOKALIKE_TRANS)


def _sub_preserving_original(
    pattern: re.Pattern[str],
    replace: Callable[[re.Match[str]], str],
    skeleton: str,
    original: str,
) -> str:
    """`pattern.sub(replace, skeleton)`, except every character OUTSIDE a
    matched span is taken from `original`, not from `skeleton` -- the
    position-preserving splice `_redact_free_text` uses instead of masking
    the transliterated copy directly.

    Matching happens against `skeleton` (built by `_delookalike`, so a
    Cyrillic А reads as "A" and a fullwidth "１" reads as "1" for the
    purpose of finding a span at all): `_IBAN_IN_TEXT_RE`/`_PAN_IN_TEXT_RE`
    are `[A-Za-z0-9]`-only and would not see the match otherwise. What
    happens to that span in the OUTPUT is decided by `replace`, exactly as
    it already was before this function existed (`_redact_iban_match` /
    `_redact_pan_match`, unchanged) -- this function only decides where
    each piece of the result comes from:

    - A span `replace` decided NOT to mask (`_redact_iban_match`'s two
      "nothing checksums" branches, which return `match.group(0)`
      unmodified) is spliced back in FROM `original`, not from `skeleton`
      -- so a coincidentally IBAN-shaped span that never checksums comes out
      exactly as the caller wrote it, look-alikes and all, rather than
      silently rewritten to its ASCII skeleton form. Detected generically,
      by comparing `replace(match)` against `match.group(0)`, not by
      special-casing which branch of `_redact_iban_match`/
      `_redact_pan_match` produced it: every masking branch in both of
      those functions returns something containing a `_MASK` bullet, which
      can never equal an alphanumeric `match.group(0)`, so this comparison
      cannot mistake a real mask for a no-op in either direction.
    - A span `replace` DID mask is inserted as `replace` returned it
      (`_MASK`, or the `XX•• •••• YYYY` form) -- these are synthetic,
      ASCII-and-bullets strings built from the checksum-verified compact
      form, not copied from either `original` or `skeleton`, so there is no
      "which copy" question for a masked span.
    - Everything BETWEEN matches is copied from `original` verbatim,
      including any look-alike codepoint nowhere near a match -- a Greek
      word elsewhere in the same value is untouched, character for
      character, because this function never looks at `skeleton` for
      anything except locating spans.

    Relies on `skeleton` and `original` being the same length and
    index-aligned, which holds because `_delookalike` only ever produces
    `skeleton` from `original` via a 1:1 translation table (enforced at
    import time immediately above `_LOOKALIKE_TRANS`) -- every offset
    `pattern.finditer(skeleton)` reports is therefore valid, and means the
    same thing, in `original` too.
    """
    pieces: list[str] = []
    last_end = 0
    for match in pattern.finditer(skeleton):
        pieces.append(original[last_end : match.start()])
        replacement = replace(match)
        if replacement == match.group(0):
            # `replace` decided this span is not sensitive after all --
            # preserve exactly what the caller wrote, look-alikes included,
            # rather than the ASCII skeleton form `match.group(0)` itself
            # holds.
            pieces.append(original[match.start() : match.end()])
        else:
            pieces.append(replacement)
        last_end = match.end()
    pieces.append(original[last_end:])
    return "".join(pieces)


def _redact_free_text(value: str) -> str:
    # Strip invisible/format and combining-mark characters FIRST, from the
    # untransliterated value. See `_strip_invisible` for why this has to
    # happen before either scan runs, and `_STRIPPED_CATEGORIES` for exactly
    # which characters and why. `value` from this point on is this
    # function's SPLICE TARGET -- the string every non-matched character in
    # the final output is copied from, look-alikes included -- so it must
    # never be built from a transliterated copy.
    #
    # An earlier version of this function ran `_delookalike` BEFORE this
    # strip, on `value` directly, for a real, measured ~30% cost saving:
    # `_strip_invisible` has its own `value.isascii()` fast path, and
    # feeding it an already-ASCII (post-`_delookalike`) string let it take
    # that fast path instead of its general per-character one. That
    # optimization does NOT carry over to this shape, and reintroducing it
    # would reopen the bug this rewrite exists to close: `_strip_invisible`
    # ran on the transliterated copy would strip the SAME positions either
    # way (Cf/Mn/Cc and `_LOOKALIKE_TABLE`'s Lu/Ll/Nd/No keys are disjoint
    # categories, confirmed by `test_preprocessing_order_does_not_affect_
    # output`, tests/test_masking_confusables.py), but its OUTPUT would then
    # be the transliterated text, not the original -- and that output is
    # exactly what this variable would carry forward as the splice target,
    # silently reintroducing whole-value transliteration through the back
    # door. See `_delookalike`'s own docstring for why whole-value
    # transliteration was replaced, and this function's own cost comment
    # below for the number this costs now that the trick is gone.
    value = _strip_invisible(value)

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
    # Front-glue closed, at a measured cost: `_find_iban_in_token` now finds
    # an IBAN with junk glued to its FRONT ("REF9MT92MALT...", "XMT92MALT
    # ..."), which used to reach the output verbatim -- the candidate
    # pattern's old `[A-Za-z]{2}[0-9]{2}` opener had to land at the token's
    # own start, and one glued character moved it out of the pattern's
    # reach entirely. The structural prefilter (letter, letter, digit,
    # digit -- an O(1) test) that makes this possible without a window scan
    # is documented on `_find_iban_in_token`, along with the ambiguity rule
    # that decides what to do when more than one start position checksums
    # (bare-mask rather than guess, not "first one wins" -- that was this
    # module's own first attempt, and it guessed a wrong country code and
    # an interior last-four on 18-27% of tokens; see `_find_iban_in_token`
    # for the measured numbers and why "leftmost" was never a safe rule).
    # Underscore- and invisible-character evasion of the token boundary
    # itself are separate holes with their own fixes and their own comments
    # (on `_IBAN_IN_TEXT_RE` and `_strip_invisible` respectively); this
    # comment is about the cost of the scan once a token is correctly
    # delimited, not about delimiting it.
    #
    # That prefilter is not free, and the honest numbers, measured on random
    # alphanumeric non-IBAN tokens forced to open with the same four-
    # character shape (letter, letter, digit, digit) so they reach a
    # checksum in both the old and new code -- the shape that actually
    # costs checksum-collision false positives, not inert text the old code
    # never looked at:
    #
    #   length   old (single start)   new (every qualifying start)
    #     14           1.08%                  1.08%   (only one start fits)
    #     24          10.67%                 11.65%
    #     34          19.86%                 24.62%
    #     60          19.62%                 38.58%
    #
    # On fully unstructured random alphanumeric text (no forced opener --
    # the more realistic shape of an arbitrary reference string), the
    # absolute numbers are far lower but the same growth shows up: 0.04% /
    # 0.43% / 0.80% / 0.80% (old) versus 0.04% / 2.67% / 8.84% / 26.14%
    # (new) at the same four lengths. Ten realistic merchant descriptors
    # ("AMZN MKTP ES*2X4B91", "CARREFOUR 3421 BARCELONA", ...) showed zero
    # regressions either way; the cost lands on long, unbroken, punctuation-
    # free alphanumeric runs (reference codes, hashes, tracking numbers),
    # not on ordinary prose, because a space or separator still ends a
    # token the way it always did. Both tables are for tokens under
    # `_IBAN_SCAN_MAX_TOKEN`; none of these lengths (14/24/34/60) are
    # affected by the bound described next, and the numbers do not move
    # from the values above once it exists.
    #
    # The ambiguity rule (above, and on `_find_iban_in_token`) does not
    # change these "masked at all" numbers either -- scanning every start
    # instead of stopping at the first hit still masks a token exactly when
    # at least one start checksums, the same condition as before -- but it
    # does change WHAT gets emitted for some of them. Reclassifying the
    # same forced-opener corpus by match count rather than by "masked or
    # not": at length 14, every masked token has exactly one match (0.00%
    # ambiguous, because only one start position can even fit). At 24, 34,
    # 60: 0.11% / 1.25% / 6.66% of ALL tokens (not just the masked ones)
    # have two or more checksum-valid starts, and now get the bare `_MASK`
    # instead of the wrong, confident guess the old leftmost-wins code
    # would have emitted for every one of them. That is the no-guess rule's
    # measured cost: up to roughly 1 in 6 tokens at length 60, all of them
    # cases that were already being altered (never a case that used to
    # pass through untouched and now doesn't), trading a wrong structured
    # answer for an honest "do not know".
    #
    # CPU, worst case -- and why a PER-TOKEN bound was not enough on its
    # own, corrected in this revision after review found the gap and
    # measured it independently: `_IBAN_SCAN_MAX_TOKEN` caps the cost of
    # any ONE token, but an attacker who controls the whole value also
    # controls how it is split into tokens, and every token up to and
    # including the 128-character bound still gets the full scan.
    # Space-separated tokens sized just at the bound each buy the maximum
    # the prefilter allows, and the number of them that fit in a payload
    # scales with the payload's own size -- so the earlier claim that this
    # module's cost was "bounded regardless of attacker input size" was
    # true per token and false for the call as a whole. Measured: a 1 MiB
    # payload of 128-character space-separated junk tokens cost 7.5
    # SECONDS on the per-token-only version of this fix (`services/
    # api/middleware/audit.py` calls this synchronously before `call_next`,
    # so that is 7.5 seconds of blocked event loop, stalling every
    # concurrent request on the instance, contained only by
    # `settings.max_body_bytes`), against 278ms for the unfixed code on the
    # identical input -- 26x slower than doing nothing at all.
    #
    # `_ScanBudget` closes this by making the allowance a property of ONE
    # `_redact_free_text` CALL -- one STRING's validation -- rather than of
    # any token inside it, and `_IBAN_SCAN_BUDGET = 100_000` was chosen
    # empirically, not by intuition: swept against this exact adversarial
    # shape at 1 MiB, picking the largest value whose measured worst case
    # still stays comfortably under the UNFIXED code's own measured cost on
    # the identical input, five runs each, same machine, interleaved to
    # cancel drift:
    #
    #   unfixed code, 1 MiB, space-separated 128-char tokens: 278-282ms
    #   this fix, budget=100,000, same input, five runs:      197-202ms
    #
    # Re-measured against every shape in the table below, 1 MiB each,
    # unfixed code vs this fix, including two shapes invented specifically
    # to try to beat the budget:
    #
    #   shape                                        unfixed      budget=100,000
    #   single "AB12"-repeated token (no separators)    6.6ms          35.4ms
    #   space-separated 128-char tokens (review's)    278.5ms         197.1ms
    #   127-char tokens + space (invented)            281.9ms         197.2ms
    #   34-char tokens + space (invented)            1012.8ms         191.4ms
    #   128-char tokens + "_" separator (invented)      9.0ms         202.3ms
    #
    # No invented shape beat the review's own space-separated-at-the-bound
    # shape under this fix; every budgeted run landed in a narrow 191-202ms
    # band regardless of token size or separator, which is the point of a
    # budget that spans a whole STRING -- the total cost of validating ONE
    # string is a function of the budget, not of how the attacker chops up
    # that string into tokens. (This does NOT yet cover an attacker who
    # chops up the REQUEST into many separate strings instead of one long
    # one -- that gap, and its own fix, `redaction_budget`, is covered in
    # the "Request-scoped budget" paragraph below.) Two rows are worth
    # reading carefully rather than as a regression: the single-token and
    # underscore-separated shapes are SLOWER under this fix than under the
    # unfixed code (35ms and 202ms vs 6.6ms and 9.0ms), because the unfixed
    # code's `\b`-based tokenizer never correctly recognizes either shape
    # as many separate tokens in the first place -- it treats the whole
    # value as one giant word-run and only ever checksums its first 34
    # characters, which is fast because it is wrong (this IS the
    # underscore hole and a variant of the front-glue hole, both closed
    # elsewhere in this function). A cheap answer to a question the old
    # code never actually answered is not a baseline worth preserving; the
    # 34-char-token row shows the same tokenizer costing over a SECOND once
    # it does correctly split the input, which is the realistic comparison.
    # The realistic sub-200-character memo costs low single-digit
    # microseconds either way (2.99us unfixed, 7.31us with every fix in
    # this revision applied, `_strip_invisible`'s per-character pass
    # included) -- not a concern at the sizes `FreeText` actually carries
    # in practice.
    #
    # Legitimate use, for comparison: 1 MiB of ordinary transaction text
    # (the ten realistic merchant descriptors and typical memo sentences,
    # repeated to size, including genuine embedded IBANs and PANs) consumed
    # 2,101 checksum operations end to end against the 100,000 budget --
    # about 2% of it. Legitimate `FreeText` values are nowhere near this
    # bound; if that ever stops being true, the budget is the wrong number
    # to move first -- see `_IBAN_SCAN_BUDGET`.
    #
    # Request-scoped budget: `_ScanBudget` bounding one STRING is not the
    # same as bounding one REQUEST, and asserting the latter was a mistake
    # corrected in this revision, found by review: `services/api/
    # middleware/audit.py:_scrub` walks a whole argument TREE and validates
    # every string in it, and without more, each one creates its own fresh
    # `_ScanBudget(_IBAN_SCAN_BUDGET)` -- so an attacker who spreads junk
    # across many short strings (a LIST of them, rather than one long one)
    # buys a fresh 100,000-checksum allowance per element instead of
    # spending down one shared one, and the total cost again scales with
    # how much of the request is junk, exactly the shape of gap this
    # revision's own per-token bound had. Measured through the real
    # `_scrub`, 1 MiB, unfixed code / per-string budget only / this
    # revision's `redaction_budget` wrapped around the whole walk:
    #
    #   shape                                  unfixed   per-string budget   redaction_budget
    #   one string, space-separated tokens     288.6ms          206.4ms            171.6ms
    #   a LIST of 128-char strings              288.6ms         7602.1ms           172.6ms
    #   a DICT of 128-char keys and values      302.2ms        14664.1ms           181.3ms
    #   nested lists of 128-char strings        302.8ms         7841.7ms           183.8ms
    #
    # The dict row costs roughly double the list row under a per-string
    # budget because `_scrub` validates a key AND a value per entry, each
    # buying its own fresh allowance. `redaction_budget` (see its own
    # docstring, and `services/api/middleware/audit.py`'s
    # `on_call_tool`, the one caller that wraps `_scrub`'s whole walk in
    # it) closes this by making the checksum allowance ambient for the
    # whole walk via a `contextvars.ContextVar`, so every string validated
    # inside it spends from the SAME `_ScanBudget` -- all four shapes above
    # land in a narrow ~172-184ms band, under the unfixed code's ~289-303ms
    # on the identical input, regardless of whether the request is one
    # string, a list, a dict, or nested. Tried, and did not beat the
    # budgeted result: 500 levels of single-element list nesting around
    # one ordinary junk token (near-zero cost either way, since it is
    # still only one `FreeText` validation) and short-but-genuinely-
    # IBAN-shaped strings sized at 20/34/60/128 characters, tens of
    # thousands of them per MiB -- all four land in the same ~163-187ms
    # band. One shape DOES cost more under this fix than under the unfixed
    # code: tens of thousands of short strings whose incidental
    # letter-letter-digit-digit opener sits a few characters INSIDE the
    # string rather than at its start (unremarkable-looking text, not
    # crafted to look IBAN-shaped) costs 184ms here against 20ms unfixed --
    # for the same reason the single-token and underscore-separated rows
    # above do: the unfixed code's own opener-must-be-at-position-zero
    # pattern never recognizes such a string as a candidate at all, which
    # is the front-glue hole itself, not a baseline this fix should be
    # measured against. Callers that validate `FreeText` OUTSIDE of
    # `redaction_budget` -- today, that is every tool RESPONSE validated
    # through a pydantic model on data returned from the operator's own
    # backend, as opposed to agent-supplied tool ARGUMENTS -- keep a fresh
    # per-string budget each, unchanged from before this section existed.
    # That is a stated decision, not an oversight: response data is not
    # agent-controlled the way arguments are, so splitting it into many
    # strings is not a lever an attacker holds there. See `_current_budget`
    # and `redaction_budget` for the mechanism, and
    # `services/api/middleware/audit.py` for the one caller that opts in.
    #
    # Narrowing what exhaustion destroys: unconditionally bare-masking
    # every token once the budget runs out is fail-safe on the leak axis
    # (verified: nothing post-exhaustion ever leaks) but it is also a
    # denial-of-audit primitive review demonstrated -- pad a request with
    # ~23 KB of junk (179 tokens, one past the budget) and every OTHER
    # alphanumeric token 14+ characters long in the SAME request, junk or
    # not, comes back as an indistinguishable bare `••••` in the
    # attacker's own audit row. `_has_qualifying_start` (see its own
    # docstring, and the `budget.exhausted` branch on
    # `_redact_iban_match`) narrows this to "could this token EVER have
    # matched, with any amount of budget": a token with no
    # letter-letter-digit-digit start anywhere in it can never reach a
    # checksum regardless of allowance, so leaving it untouched costs
    # nothing on the leak axis. On an illustrative 7-value reconstruction
    # of review's payload shape (179 tokens of padding, then a payee
    # reference, a challenge ID, a device ID, a transaction reference, and
    # an IBAN, plus two values already immune for unrelated reasons -- one
    # short, one hyphen-split), 5 of 7 survive after this change, versus 2
    # of 7 before it: the two that stay masked are the real IBAN (whose
    # own format guarantees a qualifying start) and the one reference that
    # happens to be IBAN-opener-shaped, both correctly treated as "could
    # plausibly have been a real IBAN, was never checked, so mask".
    #
    # Cost of the narrowing: `_has_qualifying_start` spends no checksums --
    # it is the same structural pass `_find_iban_in_token` already runs
    # before spending its first one, with the checksum loop removed -- so
    # `_IBAN_SCAN_BUDGET` (a budget over checksum operations) is untouched
    # by it. It does cost one O(length) pass per post-exhaustion token,
    # where the branch used to be O(1); re-measured against the same
    # shapes as the request-scoped table above to confirm this did not
    # move the wall-clock bound:
    #
    #   shape                                   before narrowing   after narrowing
    #   one string, space-separated tokens            171.3ms            174.3ms
    #   a LIST of 128-char strings                     172.2ms            174.6ms
    #   list of 69,905 tokens, 14 chars each           136.5ms            137.1ms
    #   list of 29,959 tokens, 34 chars each           172.5ms            177.2ms
    #   list of 17,189 tokens, 60 chars each           175.4ms            179.7ms
    #   list of 8,128 tokens, 128 chars each           174.1ms            176.5ms
    #
    # A few milliseconds across the board, comfortably inside run-to-run
    # noise, because scanning up to 128 characters with plain
    # `str.isalpha`/`str.isdigit` calls is cheap next to the checksum work
    # that already dominates the pre-exhaustion cost.
    #
    # Accepted trade-off, not a free fix: this module holds firm on two
    # decisions that would cut the false-positive and CPU cost further --
    # no country-code-to-length registry, no `max_length` added to any
    # `FreeText`-typed field -- because both are decisions about an operator's
    # own tool contracts and backend field limits, not about this masking
    # function, and adding either here would be making that call by
    # accident. `_IBAN_SCAN_MAX_TOKEN` and `_IBAN_SCAN_BUDGET` are a
    # different kind of decision and not an exception to that: both bound
    # what THIS function will spend, the same way the PAN path's
    # over-19-digit branch already declines to scan an arbitrarily long
    # digit run, and both only ever mask MORE than an unbounded scan would,
    # never less, so neither can reopen the leak. The severity asymmetry is
    # what justifies the remaining cost: the failure mode being closed is a
    # complete, verbatim IBAN reaching a vendor's chat history and the
    # audit table with no redaction at all and no way to recall it, against
    # an over-redaction rate that stays at zero on every realistic
    # descriptor tested and only grows on a token shape -- 34-plus unbroken
    # alphanumeric characters -- that ordinary payee names and merchant
    # strings do not take, at a CPU cost that is now bounded for one
    # string's own validation regardless of any one token in it, AND -- for
    # the one caller that wraps its whole argument tree in
    # `redaction_budget` -- for the request as a whole, regardless of how
    # many strings the request is split into.
    ambient_budget = _current_budget.get()
    # Explicit `is None`, not `ambient_budget or _ScanBudget(...)`: `or`
    # falls back to a fresh budget for anything falsy, not just `None`, and
    # `_ScanBudget` defines no `__bool__`/`__len__` today, so an ambient
    # budget is always truthy regardless of how much it has spent -- but
    # that is an absence of a bug, not a guarantee, and a later change
    # adding either dunder to `_ScanBudget` (a natural thing to add, e.g.
    # "is this budget still useful") would silently make an EXHAUSTED
    # ambient budget (falsy, if `__bool__` reflected `not exhausted`) get
    # replaced by a fresh, full one here -- reopening the request-wide hole
    # `redaction_budget` exists to close, for every request from then on,
    # with no test failing to say so. `is None` only ever means "no ambient
    # budget was set", which is the one condition this fallback exists for.
    budget = ambient_budget if ambient_budget is not None else _ScanBudget(_IBAN_SCAN_BUDGET)

    def _redact_iban(m: re.Match[str]) -> str:
        return _redact_iban_match(m, budget)

    # Build a fresh ASCII-mapped SKELETON of the current `value` for each
    # pass, rather than transliterating once up front: `_sub_preserving_
    # original` only ever reads `skeleton` to locate spans, never to supply
    # output characters (see its own docstring), so `value` itself never
    # holds transliterated text at any point in this function. In principle
    # a second skeleton is needed for the PAN pass, built from the IBAN
    # pass's OWN output rather than reusing the first one: whatever the IBAN
    # pass left untouched may still contain look-alike codepoints the PAN
    # scan needs to see as digits (a card number written with fullwidth or
    # circled digits, unrelated to any IBAN match), and the first skeleton
    # no longer corresponds -- character for character -- to `value` once
    # the IBAN pass has spliced any mask into it.
    #
    # But if the IBAN pass spliced NOTHING -- every match it found was a
    # "leave as written" no-op, or it found no match at all -- `value` is
    # byte-identical to what it was before that pass ran, and `iban_skeleton`
    # is therefore still exactly correct for the PAN pass too; recomputing
    # it would be a second full `_delookalike` translate pass over the same
    # non-ASCII content for no benefit.
    #
    # Measured honestly rather than assumed, on two different shapes, because
    # the first shape tried (this module's own 1 MiB adversarial payload,
    # injected with look-alikes throughout -- see `_delookalike`'s own
    # docstring) showed NO measurable benefit: 265-272ms either way, with or
    # without this skip. That payload is built to maximise checksum
    # attempts, which exhausts `_IBAN_SCAN_BUDGET` well before the scan
    # finishes (see that budget's own derivation above) -- and once
    # exhausted, `_redact_iban_match`'s budget-exhausted branch bare-masks
    # every remaining qualifying-start token, which touches nearly the whole
    # payload and defeats the "nothing changed" condition this skip checks
    # for almost immediately. This skip is NOT a fix for that cost; the
    # honest number for that shape is the one on `_redact_free_text`'s own
    # cost comment (265-272ms), unchanged by this skip existing.
    #
    # Where this skip DOES measurably help is the realistic case this
    # change was made FOR: legitimate non-Latin text with no IBAN or PAN
    # anywhere in it (a Greek, Bulgarian, Serbian or Turkish name or
    # sentence -- see the false-positive corpus in tests/test_masking_
    # homoglyph_measurement.py). There, `_IBAN_IN_TEXT_RE` may still match a
    # 14+-character word as a CANDIDATE (its skeleton is 14+ ASCII
    # characters), but with no digit anywhere in it `_has_qualifying_start`
    # is false at every position, so `_redact_iban_match` returns the
    # candidate unchanged, `_sub_preserving_original` splices back the
    # original, and `value` ends up byte-identical to what it was --
    # exactly the condition this skip checks for. Measured on a realistic
    # ~90-character Greek memo ("Πληρωμή προς Ιωάννη Παπαδόπουλο για
    # υπηρεσίες συμβουλευτικής Σεπτέμβριος 2026 Θεσσαλονίκη"), min of
    # several trials: with this skip, ~11-12 microseconds per call;
    # recomputing unconditionally, ~13-14 microseconds -- a real, repeatable
    # ~15-20% reduction, though at an absolute scale ordinary traffic
    # was already nowhere near noticing. Byte-identical output confirmed
    # both ways, on both shapes, not assumed.
    #
    # Net honest statement: this skip is a correctness-neutral, modest win
    # for realistic non-Latin legitimate text, and no win at all -- not a
    # regression, just inert -- for the module's own documented adversarial
    # worst case, where the budget-exhaustion behaviour it depends on
    # (nothing changing) essentially never holds.
    iban_skeleton = _delookalike(value)
    after_iban = _sub_preserving_original(_IBAN_IN_TEXT_RE, _redact_iban, iban_skeleton, value)
    pan_skeleton = iban_skeleton if after_iban == value else _delookalike(after_iban)
    return _sub_preserving_original(_PAN_IN_TEXT_RE, _redact_pan_match, pan_skeleton, after_iban)


FreeText = Annotated[str, AfterValidator(_redact_free_text)]
"""Free text (transaction memos, payee names, labels): redacts any IBAN- or
PAN-shaped substring on validation, rather than requiring every caller to
remember to scrub it (handoff §3.4's leak scenario, security review of
Task 3). Ordinary text passes through unchanged."""

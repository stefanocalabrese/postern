# 0008: Masking residuals — accepted risks and upstream closure path

**Date:** 2026-09-20

## Question

`packages/postern-core/src/postern_core/domain/masking.py::_mask_bridged_runs`
documents five open shapes that reach `_redact_free_text`'s output as a
complete, unmasked PAN or IBAN. None is closable by this module's own means.
The question is whether to accept them as irreducible risks (with an explicit
upstream closure path) or to keep them listed as "open" without a decision.

## The five residuals

All five are exercised by tests in
`tests/test_masking_confusables.py`. A number stated here is a number some
test will defend. Counts are against Unicode 15.0.0, the version
`unicodedata.unidata_version` reports in this interpreter.

### Residual 1 — Latin-named splitters

A splitter whose Unicode NAME contains "LATIN" sits between two ASCII
alphanumerics and is NOT bridged, because `_is_script_intrusion` exempts it
via `_LATIN_SCRIPT_EXEMPTIONS`. The exemption exists to keep ordinary Spanish,
Catalan, Portuguese and Italian reference codes from being bare-masked:

- `FACTURANº20240912` (U+00BA MASCULINE ORDINAL INDICATOR)
- `1ªPLANTAEDIFICI2026` (U+00AA FEMININE ORDINAL INDICATOR)
- `superficie120m²parcela4455` (U+00B2 SUPERSCRIPT TWO)

But the same exemption covers pixel-level homoglyphs that an attacker picks
from: U+0261 LATIN SMALL LETTER SCRIPT G, U+026A LATIN LETTER SMALL CAPITAL I,
U+1D04 LATIN LETTER SMALL CAPITAL C.

`"MT92MALT01100ÀBCDEFGH1234IJKL56"` reaches the output verbatim.

**Why not close here:** closing it requires bridging across Latin-named
codepoints, which masks every ordinary reference code that uses them. The only
safe closure is upstream: the backend never puts a full PAN or IBAN into free
text in the first place.

### Residual 2 — Edge splitters

A splitter at a token EDGE (start or end) rather than between two ASCII
alphanumerics. `"MT92MALT01100ABCDEFGH1234IJKL5Ж"` leaves a thirty-character
ASCII run that the ordinary IBAN pass scans, finds does not checksum, and
leaves as written — thirty of the IBAN's thirty-one characters.

**Why not close here:** `_bridged_runs` requires ASCII alphanumeric on BOTH
sides for a block to bridge. A rule that bridges edge blocks fires on ordinary
text like `"SAMSUNGGALAXYS24手机壳"` (16 ASCII alphanumerics, 2 digits, CJK
at the trailing edge). The test corpus includes this shape precisely so that
dropping the requirement fails a test.

### Residual 4 — Two splitters in a short national format

Two splitters substituted into a short national IBAN format. Norway's is 15
characters: `NO9386011117947`. Of the 78 interior position pairs, 66 evade:
hiding two of its 13 ASCII digits leaves 11, under `_PAN_MIN_DIGITS` of 12,
and 13 ASCII alphanumerics, under `_IBAN_MIN_LEN` of 14. The other 12 pairs
are exactly those touching position 1, its only interior letter, which keeps
the digit count at 12 and masks.

Recovery from an evading pair is not hypothetical: mod-97 restores the hidden
pair with min 1, max 5, mean 1.70 candidates once the analyst uses the NO
format's own shape (`NO` then 13 digits), or min 5, max 22, mean 13.77
without it.

**Why not close here:** raising either floor to catch this would mask short
legitimate references. The floors have about one character of slack against the
registry's shortest format, and two intrusions clear them.

### Residual 5 — One splitter in a 12-digit card

One splitter substituted into a 12-digit PAN. Twelve digits is the floor
exactly (`_PAN_MIN_DIGITS`), so hiding one digit leaves 11 (under
`_PAN_MIN_DIGITS`) and 11 alphanumerics (under `_IBAN_MIN_LEN`), and both
routes fail: it leaks at all ten interior positions of `869926608025`, with
Luhn restoring the hidden digit at exactly one candidate per position.

Note the mutation KIND matters here and nowhere else in this list: INSERTING
a splitter into the same card preserves all twelve digits and masks normally,
so a test written with insertion passes while substitution leaks.

**Why not close here:** this sits at the exact floor boundary. Lowering
`_PAN_MIN_DIGITS` to 11 would catch it but also mask shorter digit runs that
are not cards.

### Residual 6 — `_LOOKALIKE_TABLE` completeness

The catalogued look-alike path depends on `_LOOKALIKE_TABLE` being complete.
This is a hand-curated list (Cyrillic, Greek, fullwidth, mathematical
alphanumeric, enclosed alphanumeric) with no mechanical derivation for future
Unicode-assigned look-alikes. The module checks at import time that every entry
maps to exactly one character (position-preserving splice invariant), and a
test (`test_bundled_unicode_version_matches_the_version_the_lookalike_table_was_derived_against`)
fails the build when the bundled Unicode version changes, but no automated
check detects a new Cyrillic/Greek look-alike added in a future Unicode version.

**Why not close here:** heuristic look-alike redaction cannot, by its nature,
enumerate every codepoint that could ever render like an ASCII character. The
table is closed and reviewed; the residual is about future Unicode versions,
which no module can anticipate mechanically.

## What would close them

None of these is closable by this module's own means. The earlier version of
this docstring said "handoff §10.17 will close them" — that was wrong.

§10.17 asks whether the domain teams will expose agent-facing projections
returning pre-masked values (§6.5). §6.5 is about typed PAN and IBAN fields
(`MaskedPan`, `MaskedIban`). Answer §10.17 yes tomorrow and account and card
objects stop carrying full PANs while this entire class is untouched, because a
memo is not a masked field.

The handoff never contemplates scrubbing identifiers out of free text at all:
it has zero occurrences of "remittance", zero of "free text", and its only
"memo" substrings are inside "memory".

**Closing this class upstream needs a WIDER commitment than §10.17:** the
domain services must pre-scrub remittance information and any other free-text
fields before they reach the MCP server. This means:

1. **No full PAN or IBAN in any free-text field** that the MCP server can
   observe. The backend's own internal storage may carry them (PCI DSS scope is
   a separate question), but the agent-facing projection must scrub them.

2. **This is not a masking-layer question.** The MCP server's `FreeText`
   redaction (`_redact_free_text`) is a safety net, not the primary control.
   The primary control is that the data never arrives raw.

3. **This requires a domain-service change, not an MCP-server change.** The
   scrubbing happens in the backend's projection layer (or the domain service
   itself), before data crosses the MCP wire. The MCP server's masking types
   (`MaskedPan`, `MaskedIban`) remain as a defense-in-depth fallback for any
   path the upstream team missed.

## Decision

**Accept these five residuals as irreducible risks of free-text masking, with
an explicit upstream closure path.**

The residuals are:

- Documented in `masking.py::_mask_bridged_runs` (lines 1772-1853).
- Each has a corresponding test in `tests/test_masking_confusables.py`.
- None is closable by this module alone.
- The closure path is upstream: pre-scrubbed remittance information from the
  domain services, which is a wider commitment than handoff §10.17 (pre-masked
  typed fields) and is not currently an open question in the handoff.

This decision does NOT change the masking module's behaviour. The five
residuals remain open in the code; this decision records that they are known,
bounded (each has a test), and not closable here. It also records the upstream
path that would close them, so a future reviewer does not mistake "open" for
"forgotten."

**The residuals are formally accepted as part of the irreducible risk set.**
They belong in the same category as §5.1 (client runtime integrity cannot be
attested) and §5.2 (third-party retention is unrecallable): they are risks
that cannot be eliminated by this deployment's controls, only bounded.

## What this costs

Nothing at the code level. The residuals exist today regardless of this record;
the record only makes them explicit and gives them a closure path.

The cost of NOT closing them upstream is that every free-text field carrying a
PAN or IBAN (transaction memos, payee names, counterparty references) carries
these five residual leak shapes. The probability of exploitation depends on the
attacker's knowledge: a random adversarial model will not hit these shapes, but
a targeted attacker who knows the masking implementation (the residuals are
documented in the source) can construct inputs that trigger them.

The mitigation is the upstream commitment: if domain services pre-scrub free
text, these residuals never fire because the data never arrives raw.

## Related decisions

- **ADR-0006** (audit write failure): the audit row itself may carry a
  residual-masked PAN/IBAN if an attacker triggers one of these shapes. The
  audit log's `FreeText` fields are subject to the same five residuals.

- **Handoff §6.5**: masking is a type property, never a function someone
  remembers to call. The `MaskedPan`/`MaskedIban` types are the primary
  control for typed fields; `FreeText` redaction is the fallback for free text.

- **Handoff §10.17**: will domain teams return pre-masked values? This ADR
  extends that question: not just "pre-masked typed fields" but "pre-scrubbed
  free text."

- **Zero-trust plan §5**: irreducible risks. These residuals belong in the
  same category as client runtime integrity and third-party retention — known,
  bounded, not closable by this deployment's controls.


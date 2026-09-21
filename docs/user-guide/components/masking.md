# Masking (PAN/IBAN Redaction)

Multi-layer redaction pipeline for card PANs and IBANs, type-level enforcement.

## Overview

Masking is a **type property**, not a function call. `MaskedPan` and `MaskedIban` mask
on construction via Pydantic validators. A handler that forgets to use the type fails
validation instead of leaking raw values.

```
packages/postern-core/src/postern_core/domain/masking.py    5-layer redaction pipeline
packages/postern-core/src/postern_core/facade/projection.py  build_model wrapper (catches validation errors)
packages/postern-core/src/postern_core/domain/masking.py    FreeText type (automatic redaction on validation)
```

## Type-Level Enforcement

```python
from postern_core.domain.masking import MaskedPan, MaskedIban

# MaskedPan, card PAN, last four digits only. Cannot represent a full PAN.
pan: MaskedPan = "4111 1111 1111 4417"
# → "•••• 4417"

# MaskedIban, own IBAN, country code plus last four. Counterparty IBANs are omitted entirely.
iban: MaskedIban = "NO93 8601 1117 947"
# → "NO•• •••• 7947"

# A handler that forgets to use the type:
bad_pan: str = "4111 1111 1111 4417"  # ← raw value, no masking
# This compiles fine but is a security risk, the type system cannot prevent this.
# The convention "Never replace them with a str plus a helper function" is enforced
# by code review and the [ADR-0008](../dev-docs/decisions/0008-masking-residuals.md) residual gaps documentation.
```

> **Warning:** Validation-failure boundary, not closable by the type alone: a
> `ValidationError` raised by these types carries the raw PAN or IBAN regardless of
> the validator's own message, so any code that serializes one toward a client MUST call
> `errors(include_input=False)` or `json(include_input=False)`.

## Five-Layer Redaction Pipeline

### Layer 1: Invisible Character Stripping (`_strip_invisible()`)

Removes zero-width characters (U+200B ZERO WIDTH SPACE, U+200C ZERO WIDTH NON-JOINER,
U+FEFF BYTE ORDER MARK, etc.) that could be used to split a PAN or IBAN across visual
boundaries while remaining contiguous in the byte stream.

### Layer 2: Lookalike Codepoint Mapping (`_delookalike()`)

Maps Unicode lookalikes to their ASCII equivalents before scanning:
- Cyrillic `а` (U+0430) → Latin `a`
- Greek `α` (U+03B1) → Latin `a`
- Full-width digits → ASCII digits

This prevents script injection attacks where a PAN is written with Cyrillic characters
that look identical to Latin ones.

### Layer 3: Bridged Run Masking (`_mask_bridged_runs()`)

Handles digit runs that span across separators (spaces, hyphens) in free text.
For example: `"pay 4111 1111 1111 4417 now"`, the PAN is split by spaces but forms
a contiguous 16-digit run when separators are removed.

The pattern is deliberately **unbounded above** (`\d{12,}`, not `\d{12,19}`) because
a bounded form would reconstitute cards: against a 30-digit run, the bounded form
matched only the first 19 digits and left an 11-digit residue that concatenated with
the mask to form a complete card number.

### Layer 4: IBAN Checksum Validation (`_mod97_ok()`)

Validates ISO 7064 mod-97 checksum before masking. An IBAN is only masked if it
passes the checksum, this prevents false positives on random digit sequences that
happen to look like IBANs.

```python
def _mod97_ok(compact: str) -> bool:
    """ISO 7064 mod-97 check (the IBAN checksum algorithm).
    Move the first four characters to the end, map each character to its
    base-36 value written out as a decimal string, and require the
    resulting integer mod 97 to equal 1.
    """
    rearranged = compact[4:] + compact[:4]
    digits = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(digits) % 97 == 1
```

### Layer 5: PAN Unbounded Digit Scanning (`_PAN_IN_TEXT_RE`)

Scans free text for contiguous digit runs of 12+ digits and masks them, preserving
the last four. Uses `\d` (Unicode-aware) rather than `[0-9]`, so it also matches
Arabic-Indic and Eastern Arabic-Indic digits.

```python
# This matches PANs in ANY digit script:
_redact_free_text("pay ٤٤١٧٤٤١٧٤٤١٧")  # Arabic-Indic digits
# → "pay •••• ٤٤١٧"  (last four preserved in ORIGINAL SCRIPT)
```

## FreeText Type (`packages/postern-core/src/postern_core/domain/masking.py`)

The `FreeText` type is a Pydantic Annotated string that automatically redacts PANs
and IBANs on validation:

```python
from typing import Annotated
from postern_core.domain.masking import _redact_free_text

FreeText = Annotated[str, AfterValidator(_redact_free_text)]

class TransactionResponse(BaseModel):
    remittance_info: FreeText  # Automatically redacted on validation
```

## Scan Budget (`_ScanBudget`)

The IBAN scan uses a bounded checksum budget to prevent denial-of-service via
adversarial input. The budget is **per-call**, not per-string:

```python
_IBAN_SCAN_BUDGET = 100_000   # checksum operations per call
```

### Why a budget?

`services/api/middleware/audit.py:_scrub()` walks a whole argument tree and validates
every string in it. Without an ambient budget, each string gets a fresh 100,000
checksum operations. An attacker who spreads junk across many short strings pays this
cost once per element, not once per call.

### ContextVar-based ambient budget

```python
_current_budget: contextvars.ContextVar[_ScanBudget | None] = ContextVar(
    "_current_budget", default=None
)

@contextmanager
def redaction_budget(total: int = _IBAN_SCAN_BUDGET) -> Iterator[RedactionScope]:
    """Set an ambient checksum budget for the duration of a block."""
    ...
```

The `ContextVar` is local to the current async task, two concurrently-running requests
never observe each other's budget.

### Measured performance

| Input type | Checksum operations consumed |
|------------|----------------------------|
| 1 MiB of ordinary transaction text (realistic merchant descriptors) | ~2,101 (~2% of budget) |
| 1 MiB of adversarial space-separated tokens (worst case) | ~223-242ms (~75% of unfixed baseline) |

The budget was chosen so that the worst-case cost of scanning one 1 MiB string does not
exceed the unfixed code's own cost on the same input, with ~25% margin.

## Masking Residual Gaps (ADR-0008)

See [ADR-0008](../dev-docs/decisions/0008-masking-residuals.md) for documented residual gaps
in the masking pipeline that are accepted as trade-offs:

- Invisible character stripping may miss some edge cases in Unicode normalization
- Lookalike mapping covers common scripts but not every possible lookalike
- The scan budget means extremely long inputs may exhaust the checksum allowance before
  all IBANs are found (fail-closed: unscanned text is returned as-is)

## Counterparty Account Numbers

Counterparty account numbers are **omitted entirely** from responses, only the name is
returned. This prevents any counterparty IBAN or PAN from reaching the client through
the response model, regardless of masking layer behavior.

## Source References

| Component | File |
|-----------|------|
| Masking types + 5-layer pipeline | [`packages/postern-core/src/postern_core/domain/masking.py`](../../../packages/postern-core/src/postern_core/domain/masking.py) |
| FreeText type | [`packages/postern-core/src/postern_core/domain/masking.py`](../../../packages/postern-core/src/postern_core/domain/masking.py) |
| Projection wrapper (catches validation errors) | [`packages/postern-core/src/postern_core/facade/projection.py`](../../../packages/postern-core/src/postern_core/facade/projection.py) |
| Audit scrub (redacts in tool arguments) | [`services/api/middleware/audit.py`](../../../services/api/middleware/audit.py) (see `_scrub()`) |
| ADR-0008: Masking residual gaps | [`docs/decisions/0008-masking-residuals.md`](../dev-docs/decisions/0008-masking-residuals.md) |

# Audit System

Two-row pattern, fail-closed writes, and database CHECK constraints.

## Overview

Every tool call produces **two audit rows** (when it reaches the backend): an entry row
committed before the first backend request, and a completion row after the call finishes.
A consent-denied or pre-backend-failure call produces exactly one row.

```
packages/postern-core/src/postern_core/store/audit.py     audit.append (all parameters)
packages/postern-core/src/postern_core/store/models.py    AuditEntry ORM model + CHECK constraints
services/api/middleware/audit.py                          Two-row audit middleware (1263 lines)
[ADR-0006](../../decisions/0006-audit-write-failure.md)   Fail-closed design
```

## Two-Row Pattern

### Entry Row (`outcome='reaching'`)

Written **before** the operator's backend is reached. Committed in its own transaction
via `_PendingEntry` with an at-most-once guard (`asyncio.Lock`).

```python
# Written from the façade, immediately before the first HTTP request:
await audit.append(
    db=session,
    call_id=call_id,
    tool_name="accounts.list",
    outcome=OUTCOME_REACHING,       # "reaching", about to touch backend
    reaching_at=datetime.now(UTC),  # timestamp of the entry row
    customer_ref="cust_7f3a",       # from validated access token
    ...
)
```

### Completion Row (`outcome='returned'` or `outcome='raised'`)

Written **after** the tool call finishes, either successfully (`returned`) or with an
exception (`raised`).

```python
# Successful call:
await audit.append(
    db=session,
    call_id=call_id,
    tool_name="accounts.list",
    outcome=OUTCOME_RETURNED,       # "returned", completed successfully
    returned_at=datetime.now(UTC),  # timestamp of completion
    duration_ms=42,                 # time from entry to completion
    customer_ref="cust_7f3a",
    ...
)

# Failed call:
await audit.append(
    db=session,
    call_id=call_id,
    tool_name="accounts.list",
    outcome=OUTCOME_RAISED,         # "raised", exception occurred
    raised_at=datetime.now(UTC),
    detail="NotFoundError",         # exception TYPE only (never message)
    customer_ref="cust_7f3a",
    ...
)
```

### Paired by `call_id`

Both rows share the same `call_id` (a UUID), allowing an investigator to pair them:

```sql
SELECT * FROM audit_log
WHERE call_id = 'abc-123-def'
ORDER BY reaching_at NULLS FIRST, raised_at NULLS FIRST;
```

### Consent-denied calls (one row)

A call refused by consent enforcement produces exactly one row:
`outcome='raised'`, `detail='NotFoundError'`, with the refusal reason. The entry row
is never written because the backend is never reached.

## Fail-Closed Writes (ADR-0006)

See [ADR-0006](../../decisions/0006-audit-write-failure.md) for the full design rationale.

**Before 2026-09-18:** A single row was written AFTER `call_next`, meaning the backend
was reached first and the record attempted afterwards. If the audit store was down,
customer data was touched with nothing recorded.

**After 2026-09-18:** The entry row is committed in its own transaction **before** the
first backend request. This inverts the failure mode: an audit outage now means the
backend is never reached at all, rather than data being touched with nothing recorded.

### Failure modes under fail-closed

| Scenario | Entry row | Completion row | Result |
|----------|-----------|----------------|--------|
| Audit store down | fails | N/A | Call blocked (never reaches backend) |
| Audit store slow (within timeout) | committed | fails | Backend reached, no outcome recorded |
| Cancellation (deadline fires) | committed | never written | True statement: "touched, no outcome" |
| Normal success | committed | committed | Full audit trail |

### `_PendingEntry`, At-most-once guard

The entry row uses an `asyncio.Lock` to prevent duplicate writes under concurrent
cancellation:

```python
class _PendingEntry:
    """Guard against duplicate entry writes under cancellation.

    When a request is cancelled, the lock may be released before the
    write completes, allowing a second write attempt. The lock ensures
    only one write proceeds.
    """
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
```

## Database CHECK Constraints (`packages/postern-core/src/postern_core/store/models.py`)

Closed vocabularies for key columns are enforced at the database level, not just in
application code:

| Constraint | Column | Allowed values |
|------------|--------|----------------|
| `ck_audit_log_refusal_reason` | `refusal_reason` | `consent_denied`, `tool_not_found`, or NULL |
| `ck_audit_log_outcome` | `outcome` | `reaching`, `returned`, `raised` |
| `ck_audit_log_call_id_present` | `call_id` | NOT NULL (every row must have a call_id) |
| `ck_audit_log_reaching_at_matches_outcome` | `reaching_at` | Present when outcome='reaching', absent otherwise |
| `ck_audit_log_customer_ref_absence_reason` | `absence_reason` | `no_access_token`, `no_string_subject`, `subject_not_customer_ref` |
| `ck_audit_log_customer_ref_xor_absence` | - | XOR: every row has EITHER customer_ref OR absence_reason, never both or neither |

### XOR Invariant

```sql
-- Every audit row has either a customer_ref OR an absence_reason, never both or neither.
ALTER TABLE audit_log ADD CONSTRAINT ck_audit_log_customer_ref_xor_absence
    CHECK (
        (customer_ref IS NOT NULL AND absence_reason IS NULL) OR
        (customer_ref IS NULL AND absence_reason IS NOT NULL)
    );
```

This ensures that every row explains why there is (or isn't) a customer reference.

## Field-Level Details

### `detail`, Exception type only, never message

A `pydantic.ValidationError` message embeds the raw offending value, which is the
leak path. The audit table is a long-lived store, so only the exception TYPE is recorded:

```python
detail="NotFoundError"    type name only, type name only
# NOT:
detail="NotFoundError: account 'acc_123' not found"  raw value
```

### `refusal_reason`, Transcribed, never inferred

A consent denial and a mistyped tool name both arrive as one `NotFoundError`, so this
module cannot tell them apart from what it can see. The refusal reason is transcribed
from `services/api/consent.py`, which is the only place that knows it refused and which
of its refusals it made.

### `customer_ref_absence_reason`, Derived here

This is the only place that sees the access token at all. It records which of three
things left `customer_ref` NULL:

| Value | Meaning |
|-------|---------|
| `no_access_token` | Request carried no validated access token |
| `no_string_subject` | Token had a `sub` claim but it was not a string |
| `subject_not_customer_ref` | `sub` failed `CustomerRef` validation (pattern mismatch) |

### Tool name clamping (`_MAX_TOOL_NAME = 64`)

The `tool_name` column is `VARCHAR(64)`. Agent-controlled tool names are clamped before
writing, with a truncation marker (`…`, U+2026 HORIZONTAL ELLIPSIS) appended when
something was cut:

```python
# 64-char limit, marker takes 1 character:
clamped = value[:63] + "…" if len(value) > 64 else value
```

### Request ID clamping (`_MAX_REQUEST_ID = 128`)

Same pattern for the `request_id` column (`VARCHAR(128)`). A truncated ID still
correlates with a client-side log whose ID shares the first 127 characters.

### `_scrub()`, PAN/IBAN redaction in arguments

Redacts PAN- and IBAN-shaped substrings anywhere in the argument tree, including dict
keys:

```python
# Keys matter as much as values, arguments are captured before call_next validates them:
_scrub({"4111111111114417": "x"})  # → {"•••• 4417": "x"}
_scrub("pay to NO9386011117947")   # → "pay to NO•• •••• 7947"
```

NUL bytes are also stripped. The scrub runs under the ambient `redaction_budget`
context manager (see [Masking](masking.md) for budget details).

## Audit Append Function (`packages/postern-core/src/postern_core/store/audit.py`)

```python
async def append(
    db: Database,
    call_id: str,
    tool_name: str,
    outcome: str,
    reaching_at: datetime | None = None,
    returned_at: datetime | None = None,
    raised_at: datetime | None = None,
    duration_ms: int | None = None,
    customer_ref: str | None = None,
    absence_reason: str | None = None,
    refusal_reason: str | None = None,
    detail: str | None = None,
    client_id: str | None = None,
    risk_signals: list[dict] | None = None,
) -> None:
```

All parameters are required because only the caller knows which absence type occurred.
The function is called from two places:

1. **Entry row**: from `record_data_touch` in the façade, before backend request
2. **Completion row**: from `AuditMiddleware.on_call_tool`, after tool call completes

## Source References

| Component | File |
|-----------|------|
| Audit append function | [`packages/postern-core/src/postern_core/store/audit.py`](../../../packages/postern-core/src/postern_core/store/audit.py) |
| AuditEntry ORM model + CHECK constraints | [`packages/postern-core/src/postern_core/store/models.py`](../../../packages/postern-core/src/postern_core/store/models.py) |
| Two-row audit middleware | [`services/api/middleware/audit.py`](../../../services/api/middleware/audit.py) |
| ADR-0006: Fail-closed audit writes | [`docs/decisions/0006-audit-write-failure.md`](../../decisions/0006-audit-write-failure.md) |
| Masking in audit scrub | [`packages/postern-core/src/postern_core/domain/masking.py`](../../../packages/postern-core/src/postern_core/domain/masking.py) |

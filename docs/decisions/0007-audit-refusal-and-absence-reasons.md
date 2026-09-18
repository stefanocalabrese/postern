# 0007: What the audit row says about a refusal, and about a missing customer

**Date:** 2026-09-17

## Question

Two commits on 2026-09-17 add one column each to `audit_log`:
`refusal_reason` (`2571446`, migration `0eb813c87298`) and
`customer_ref_absence_reason` (`dae1c3d`, migration `3186c04c018c`). Both
answer the same complaint from opposite ends: a field in this table was
carrying several unrelated facts under one value, and the investigator
reading the row could not tell which fact it held.

**A consent denial and a typo were the same row.** FastMCP's `_get_tool`
returns None both for a name it does not know and for a tool whose `auth=`
check denied the caller (fastmcp 4.0.3, `fastmcp/server/server.py:886-915`,
where the comment on that branch calls returning None "consistent with list
filtering"), and the dispatch turns both into one `NotFoundError`.
`AuditMiddleware` therefore wrote `outcome='raised'`,
`detail='NotFoundError'` for each. Measured against the running server,
2026-09-17: a denied `cards.list` and a nonexistent `no_such_tool` differed
in `tool_name` and in nothing else. One of those rows is a consent record a
regulator can act on, the other is an agent spelling a name wrong.

**A NULL `customer_ref` meant three things.**
`services/api/middleware/audit.py`'s `_customer_ref` returned `None` for all
three: no access token at all; a token whose `sub` claim was absent or not a
string; and a token whose `sub` was a string that `CustomerRef` rejects. The
third is what `token_customer_resolver` (`services/api/server.py:42-66`)
refuses on the tool path with a `PermissionError`. `_OPAQUE`
(`packages/postern-core/src/postern_core/identity.py:30`,
`^cust[:_][A-Za-z0-9]{1,60}$`) requires a `cust:` or `cust_` namespace
prefix, so a bare PAN, IBAN or DNI arriving as `sub` fails it. identity.py
lines 20-29 say what stands behind that pattern and what does not: it is a
provenance convention, not proof of opacity, and the only guarantee is that
`sub` was minted by the token issuer. A subject the issuer minted that this
pattern rejects is evidence about that issuer, and it was landing in the
table as the same blank an unauthenticated call produces. That blank is
common: the in-process `fastmcp.Client` carries no credentials at all, so
every call this repo's own tests make through it produces one.

Neither column can be derived from the other.
`refusal_reason = 'no_customer_ref'` is written for all three absences
alike, and only on calls a consent check actually refused
(`packages/postern-core/src/postern_core/store/models.py:314-317`).

## Decision

Record the CLASS, in a closed vocabulary the database enforces, on the audit
row and nowhere else.

- `audit_log.refusal_reason`, `VARCHAR(32)`, nullable, no server default,
  held to `no_customer_ref` and `domain_not_consented` by
  `ck_audit_log_refusal_reason`. NULL means the call was not refused by
  consent, or the row predates migration `0eb813c87298`.
- `audit_log.customer_ref_absence_reason`, `VARCHAR(64)`, nullable, no
  server default, held to `no_access_token`, `no_string_subject` and
  `subject_not_a_customer_ref` by
  `ck_audit_log_customer_ref_absence_reason`, and tied to `customer_ref` by
  `ck_audit_log_customer_ref_xor_absence`:
  `(customer_ref IS NULL) = (customer_ref_absence_reason IS NOT NULL)`.
  Every row carries a reference or a reason it has none, never both, never
  neither. `tests/test_audit_middleware.py:373` runs the search that
  motivated the column against Postgres: three calls, three rows with a NULL
  `customer_ref`, and one
  `WHERE customer_ref_absence_reason = 'subject_not_a_customer_ref'`
  returning the issuer row alone.

Both are `VARCHAR` plus a CHECK rather than a Postgres `ENUM`: widening a
CHECK is one statement, while `ALTER TYPE ... ADD VALUE` cannot run in the
same transaction that then uses the new value. The vocabularies live at
`store/models.py:47` and `:88` (`REFUSAL_REASONS`,
`CUSTOMER_REF_ABSENCE_REASONS`), and both migrations hardcode their own copy
rather than importing those tuples, so a later widening cannot change what
an already-applied revision claims to have created.

## Which module is allowed to know

`refusal_reason` is TRANSCRIBED, `customer_ref_absence_reason` is DERIVED,
and the split follows what each module can see.

`services/api/consent.py`'s `check` is the only code that knows it refused
and which of its two refusals it made; `auth=` answers a bare bool, and the
exception the middleware sees is `NotFoundError` either way. So `_refuse`
(`consent.py:110`) files the decision on `request.state` under
`postern_consent_refusals`, and `services/api/middleware/audit.py:725` reads
it back with `consent.refusal_for` after `call_next` raises. The rejected
alternative was inferring the reason in the middleware from the exception
type or its message: the type is identical for a denial and a typo, a
message match couples an audit column to wording nobody promised to keep,
and either inference breaks the first time a third refusal reason exists.

Both directions fail toward NULL on purpose. `_refuse` never raises: when
`get_http_request()` raises, it returns and `check` still answers False
(`consent.py:135-138`), so the worst outcome is a denial under-reported as
NULL, never a tool call that went through because its bookkeeping failed.
`refusal_for` returns None on a lookup miss, and `audit.py:725` keys the
lookup on the RAW requested name rather than the scrubbed, clamped `name`
about to be written, since neither a masked nor a truncated name can be a
registered tool: the lookup can only miss, and a miss under-reports a
refusal instead of inventing one.

`customer_ref_absence_reason` goes the other way because `AuditMiddleware`
is the only place that sees the access token at all. `_customer_ref`
(`audit.py:226`) takes the whole token rather than the `sub` it holds:
`token.claims.get("sub")` answers None both for a token without the claim
and for no token at all, so a caller that reads the claim first has already
collapsed two of the three classes.

## The keying is per tool name, and it is load-bearing

One `tools/call` evaluates several tools' consent checks, most of them for
tools nobody called. A `tools/call` carrying non-empty arguments makes the
MCP SDK dispatch an internal `tools/list` first, to validate `Mcp-Param-*`
headers (`mcp/server/_streamable_http_modern.py:285-359`), gated on a real
`MCP-Protocol-Version` header naming a non-handshake version (ADR 0005).
Measured 2026-09-17 for `accounts.get_balance` on a customer consented to
`accounts` only: `accounts.list`=True, `accounts.get_balance`=True,
`transactions.list`=False, `cards.list`=False, then
`accounts.get_balance`=True again for the real dispatch. Five evaluations,
two denials, during one call that was allowed.

So `_refuse` keys by `ctx.component.name` (`consent.py:143`), the registered
name, which is the name the client asked for. A single last-refusal-wins
slot would have stamped `domain_not_consented` onto a call consent allowed,
writing a consent refusal into a regulator-facing table where none happened.

The row it would corrupt is the raised-path row, and the successful row is
guarded by different code. The returned path writes NULL as a literal
constant (`audit.py:778`), so `outcome='returned'` implies no refusal by
construction, whatever the consent module left on the request;
`tests/test_audit_refusal_reason.py:328` covers that. The raised path is the
one that looks a refusal up, and only the keying keeps it honest:
`tests/test_audit_refusal_reason.py:354` calls consented
`accounts.get_balance` for an account the stub backend has no balance for,
so the tool fails inside itself while two other tools are denied in the same
HTTP request, and asserts `detail != 'NotFoundError'` with `refusal_reason
is None`. That test is the only one a one-slot design fails.

## The wire answer did not change

Telling an agent that `cards.list` was refused confirms both that the tool
exists and that this customer holds cards. The audit row gained the
distinction; the response did not.
`tests/test_audit_refusal_reason.py:241` asserts that on raw response text
rather than a parsed body: both calls return 200 with
`Unknown tool: '<name>'`, and the two texts are compared byte for byte after
substituting the tool name for one placeholder, with `content-type` and
`content-length` asserted equal. `cards.lost` is the typo, chosen the same
LENGTH as `cards.list` so `Content-Length` matches with no allowance made
for it (`tests/test_audit_refusal_reason.py:68-75`). A name the server
echoes back is already known to whoever sent it; any other differing byte
fails the test.

## The rejected subject's value is never stored

The obvious column would record what the issuer minted. That is the one
thing this column must not do. The rejected string is the PAN-, IBAN- or
DNI-shaped value `_customer_ref` refuses to put in `customer_ref`, so
writing it into a neighbouring column would be the one write that survives
the refusal it documents, in the longest-lived table this system has.

The exception is not a safe carrier for it either. `CustomerRef` sets
`hide_input_in_errors` (`identity.py:36`), which scrubs `str()` and `repr()`
of the `ValidationError` and leaves the raw value in its structured
`.errors()`; `audit.py:272-273` discards that exception without logging or
re-raising it.

`tests/test_audit_middleware.py:308` proves the property against the stored
row rather than against the code path: it drives a call whose `sub` is
`4111111111111111`, then reads `SELECT audit_log::text` (`row_texts`,
`tests/test_audit_middleware.py:247`), a whole-row record literal covering
every column including ones added after the test was written, and asserts
the PAN appears nowhere in it, nor a masked `•••• 1111` form, while
`subject_not_a_customer_ref` does.

The cost is stated rather than left to be found: the table says a
non-conforming subject was minted, when, how often, from which tool and
under which `request_id`, never what the string was. Recovering the value
means asking the identity issuer for its own logs, which is where a claim
about what an issuer minted belongs. A table that could answer "what did it
mint" would be a table holding attacker-supplied PANs.

## `ck_audit_log_customer_ref_xor_absence` is `NOT VALID`, deliberately

Every row written before revision `3186c04c018c` holds NULL for both columns
whenever its call had no customer, which is exactly what this constraint
rejects. Adding it validated fails the migration outright with
`CheckViolation` on any database that has recorded such a call, and no test
would have caught that: every test database is built by
`alembic upgrade head` against an empty table (`tests/conftest.py:49-51`).
Measured end to end on a container seeded with one such row at the previous
revision (`dae1c3d`): validated, the migration fails; `NOT VALID`, it
applies, the legacy row is left exactly as it was, and every violating
INSERT is still rejected. On an append-only table, "every INSERT from here
on" is every row that will ever be written.

It is raw SQL because `op.create_check_constraint` has no `NOT VALID`, and
the parentheses around the two null tests are load-bearing: in PostgreSQL
`IS` binds looser than `=`, so the unparenthesised form parses as something
other than this comparison. SQLAlchemy's `CheckConstraint` cannot express
`NOT VALID` either, so a database built from `store/models.py:544-547`
instead of from the migrations gets a validated constraint. No such path
exists in this repo, and on an empty table the two are the same thing.

**Backfilling the legacy rows was rejected.** It would be the only UPDATE
this append-only, regulator-facing table has ever taken, and it would assert
a class of absence for calls where nobody recorded one. Those rows keep the
meaning the column's own comment gives them: NULL, because they predate it.

**The trailing cost:** `pg_constraint.convalidated` stays false for this
constraint. Running
`ALTER TABLE audit_log VALIDATE CONSTRAINT ck_audit_log_customer_ref_xor_absence`
later scans the whole table and fails on exactly those pre-migration rows.
That is a known landmine needing a decision about those rows first, not a
tidy-up for someone to run blind.

## Every parameter that feeds these columns is required, with no default

`append` (`packages/postern-core/src/postern_core/store/audit.py:14`) takes
both new values as keyword-only parameters with no default, and
`AuditMiddleware._write` (`services/api/middleware/audit.py:827`) does the
same. `_write` is reached from both branches of `on_call_tool`
(`audit.py:742` and `:778`), each of which already holds a real answer.

`_write` was the only call site of `append` outside tests when this record
was written, and stopped being so on 18 September 2026:
`_PendingEntry._write_entry_row` (`audit.py:436`) is the second, writing the
`outcome='reaching'` row before the operator's backend is reached. It is
held to the same rule. Nothing else in that change weakens this section --
the new `call_id` parameter is required on `append` too -- but "the only
call site" is no longer a thing a reader can rely on when reasoning about
what reaches this table.

This record states it once as a rule, because the repo has now refused the
same optional-parameter seam six times, once per column added to this table
since the original schema: `redaction_budget_exhausted`, `duration_ms`,
`request_id`, `refusal_reason`, `customer_ref_absence_reason`, and (18
September 2026) `call_id`. On
`audit_log`, a parameter whose NULL already carries a meaning gets no
default. NULL on `duration_ms` means "this row predates the column"; NULL on
`refusal_reason` means "this call was not refused"; NULL on
`customer_ref_absence_reason` beside a NULL `customer_ref` is rejected by
the equivalence constraint outright. A default lets a future branch make one
of those statements without having established it, in the table this system
exists to keep complete.

`_customer_ref` returns both fields as one `_Subject` (`audit.py:208`) with
exactly one populated, so the pair is decided once per call instead of being
a rule two branches have to remember.

## What this costs

All three constraints are enforcement, and under the fail-closed policy of
`docs/decisions/0006-audit-write-failure.md` a violation costs the audit row
AND fails the tool call, including a call that otherwise succeeded. For the
vocabulary constraints that lands on exactly the rows these columns exist to
record: a refusal, or a call with no customer.

Nothing an agent sends can reach either column -- every value comes from
`services/api/consent.py` or from `_customer_ref` -- so the failure mode is
a code change that adds a value without the migration widening the
constraint. Adding a refusal reason or a class of absence is now two edits
and a migration, and skipping the migration fails the first call that
produces the new value. Both halves are pinned against the real database
rather than against the SQLAlchemy metadata:
`tests/test_audit_middleware.py:417` and `:451` for the absence vocabulary,
`:1338` and `:1378` for the refusal vocabulary, `:481` and `:512` for the
two halves of the equivalence constraint.

`refusal_reason` under-reports rather than over-reports, by construction:
every failure to file or to find a decision reads as NULL, so a query
counting consent denials on this column is a lower bound.

## What was not built, and why

- **No "not refused" or "customer present" sentinel value.** NULL on either
  column cannot separate "it did not happen" from "the row predates the
  column" on its own; `at`, read against the migration's deploy time, is
  what separates them. A sentinel would make a claim about pre-migration
  rows that nothing in this table can support. On the absence column a
  fourth value meaning "a reference was found" would also be the same fact
  stored twice, free to disagree with `customer_ref`.
- **`no_string_subject` is not split** into "claim absent" and "claim
  present, not a string". Neither is the compromised-issuer case, and both
  leave the same hole. `VARCHAR(64)` is sized for that split: the longest
  current value, `subject_not_a_customer_ref`, is 26 characters, and 32
  would be the column sized at its own maximum. Migration `1c64b7ed3f4b`
  exists because both `customer_ref` columns were sized that way at 64 and
  `_OPAQUE`'s 65-character maximum did not fit.
- **No index on either column.** The searches these columns exist for
  (`WHERE customer_ref_absence_reason = 'subject_not_a_customer_ref'`,
  `WHERE refusal_reason IS NOT NULL`) run against a table carrying one
  index today, `ix_audit_log_customer_at` (`store/models.py:418`). Nobody
  has measured a query that needs a second one.

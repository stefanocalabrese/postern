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
third is what `token_customer_resolver` (`services/api/server.py::token_customer_resolver`)
refuses on the tool path with a `PermissionError`. `_OPAQUE`
(`packages/postern-core/src/postern_core/identity.py::_OPAQUE`,
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
(`packages/postern-core/src/postern_core/store/models.py::AuditEntry.refusal_reason`).

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
  neither. `tests/test_audit_middleware.py::test_the_three_absences_are_one_predicate_apart_in_the_stored_rows` runs the search that
  motivated the column against Postgres: three calls, three rows with a NULL
  `customer_ref`, and one
  `WHERE customer_ref_absence_reason = 'subject_not_a_customer_ref'`
  returning the issuer row alone.

Both are `VARCHAR` plus a CHECK rather than a Postgres `ENUM`: widening a
CHECK is one statement, while `ALTER TYPE ... ADD VALUE` cannot run in the
same transaction that then uses the new value. The vocabularies live at
`packages/postern-core/src/postern_core/store/models.py::REFUSAL_REASONS` and `:88` (`REFUSAL_REASONS`,
`CUSTOMER_REF_ABSENCE_REASONS`), and both migrations hardcode their own copy
rather than importing those tuples, so a later widening cannot change what
an already-applied revision claims to have created.

## Which module is allowed to know

`refusal_reason` is TRANSCRIBED, `customer_ref_absence_reason` is DERIVED,
and the split follows what each module can see.

`services/api/consent.py`'s `check` is the only code that knows it refused
and which of its two refusals it made; `auth=` answers a bare bool, and the
exception the middleware sees is `NotFoundError` either way. So `_refuse`
(`services/api/consent.py::_refuse`) files the decision on `request.state` under
`postern_consent_refusals`, and `services/api/middleware/audit.py::on_call_tool` reads
it back with `consent.refusal_for` after `call_next` raises. The rejected
alternative was inferring the reason in the middleware from the exception
type or its message: the type is identical for a denial and a typo, a
message match couples an audit column to wording nobody promised to keep,
and either inference breaks the first time a third refusal reason exists.

Both directions fail toward NULL on purpose. `_refuse` never raises: when
`get_http_request()` raises, it returns and `check` still answers False
(`services/api/consent.py::_refuse`), so the worst outcome is a denial under-reported as
NULL, never a tool call that went through because its bookkeeping failed.
`refusal_for` returns None on a lookup miss, and `services/api/middleware/audit.py::on_call_tool` keys the
lookup on the RAW requested name rather than the scrubbed, clamped `name`
about to be written, since neither a masked nor a truncated name can be a
registered tool: the lookup can only miss, and a miss under-reports a
refusal instead of inventing one.

`customer_ref_absence_reason` goes the other way because `AuditMiddleware`
is the only place that sees the access token at all. `_customer_ref`
(`services/api/middleware/audit.py::_customer_ref`) takes the whole token rather than the `sub` it holds:
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

So `_refuse` keys by `ctx.component.name` (`services/api/consent.py::_refuse`), the registered
name, which is the name the client asked for. A single last-refusal-wins
slot would have stamped `domain_not_consented` onto a call consent allowed,
writing a consent refusal into a regulator-facing table where none happened.

The row it would corrupt is the raised-path row, and the successful row is
guarded by different code. The returned path writes NULL as a literal
constant (`services/api/middleware/audit.py::on_call_tool`), so `outcome='returned'` implies no refusal by
construction, whatever the consent module left on the request;
`tests/test_audit_refusal_reason.py::test_a_permitted_call_that_succeeds_records_no_refusal_reason` covers that. The raised path is the
one that looks a refusal up, and only the keying keeps it honest:
`tests/test_audit_refusal_reason.py::test_a_permitted_call_that_fails_is_not_stamped_with_another_tools_denial` calls consented
`accounts.get_balance` for an account the stub backend has no balance for,
so the tool fails inside itself while two other tools are denied in the same
HTTP request, and asserts `detail != 'NotFoundError'` with `refusal_reason
is None`. That test is the only one a one-slot design fails.

## The wire answer did not change

Telling an agent that `cards.list` was refused confirms both that the tool
exists and that this customer holds cards. The audit row gained the
distinction; the response did not.
`tests/test_audit_refusal_reason.py::test_the_caller_still_cannot_tell_a_denial_from_a_typo` asserts that on raw response text
rather than a parsed body: both calls return 200 with
`Unknown tool: '<name>'`, and the two texts are compared byte for byte after
substituting the tool name for one placeholder, with `content-type` and
`content-length` asserted equal. `cards.lost` is the typo, chosen the same
LENGTH as `cards.list` so `Content-Length` matches with no allowance made
for it (`tests/test_audit_refusal_reason.py::DENIED_TOOL`). A name the server
echoes back is already known to whoever sent it; any other differing byte
fails the test.

## The rejected subject's value is never stored

The obvious column would record what the issuer minted. That is the one
thing this column must not do. The rejected string is the PAN-, IBAN- or
DNI-shaped value `_customer_ref` refuses to put in `customer_ref`, so
writing it into a neighbouring column would be the one write that survives
the refusal it documents, in the longest-lived table this system has.

The exception is not a safe carrier for it either. `CustomerRef` sets
`hide_input_in_errors` (`packages/postern-core/src/postern_core/identity.py::CustomerRef`), which scrubs `str()` and `repr()`
of the `ValidationError` and leaves the raw value in its structured
`.errors()`; `services/api/middleware/audit.py::_customer_ref` discards that exception without logging or
re-raising it.

`tests/test_audit_middleware.py::test_a_pan_shaped_token_subject_records_the_compromised_issuer_class` proves the property against the stored
row rather than against the code path: it drives a call whose `sub` is
`4111111111111111`, then reads `SELECT audit_log::text` (`row_texts`,
`tests/test_audit_middleware.py::row_texts`), a whole-row record literal covering
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
`alembic upgrade head` against an empty table (`tests/conftest.py::pg_url`).
Measured end to end on a container seeded with one such row at the previous
revision (`dae1c3d`): validated, the migration fails; `NOT VALID`, it
applies, the legacy row is left exactly as it was, and every violating
INSERT is still rejected. On an append-only table, "every INSERT from here
on" is every row that will ever be written.

It is raw SQL because `op.create_check_constraint` has no `NOT VALID`, and
the parentheses around the two null tests are load-bearing: in PostgreSQL
`IS` binds looser than `=`, so the unparenthesised form parses as something
other than this comparison. SQLAlchemy's `CheckConstraint` cannot express
`NOT VALID` either, so a database built from `packages/postern-core/src/postern_core/store/models.py::AuditEntry`
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

`append` (`packages/postern-core/src/postern_core/store/audit.py::append`) takes
both new values as keyword-only parameters with no default, and
`AuditMiddleware._write` (`services/api/middleware/audit.py::_write`) does the
same. `_write` is reached from both branches of `on_call_tool`
(`services/api/middleware/audit.py::on_call_tool` and `:1083`), each of which already holds a real answer.

`_write` was the only call site of `append` outside tests when this record
was written, and stopped being so on 18 September 2026:
`_PendingEntry._write_entry_row` (`services/api/middleware/audit.py::_PendingEntry._write_entry_row`) is the second, writing the
`outcome='reaching'` row before the operator's backend is reached. It is
held to the same rule. Nothing else in that change weakens this section --
`call_id`, the parameter it added, is required on `append` too -- but "the
only call site" is no longer a thing a reader can rely on when reasoning
about what reaches this table.

This record states it once as a rule, because the repo has now refused the
same optional-parameter seam eight times, once per column added to this
table since the original schema: `redaction_budget_exhausted`
(`f45183f7ff50`), `duration_ms` and `request_id` (`561b48768c00`, the one
revision that added two), `refusal_reason` (`0eb813c87298`),
`customer_ref_absence_reason` (`3186c04c018c`), and, all three on 18
September 2026, `call_id` (`71a4c0d9e3b2`), `reaching_at` (`9a7d4e51c6f8`)
and `client_id` (`c91f79e6d34a`). `1c64b7ed3f4b` is the one revision in the
chain that added no parameter: it widened two existing columns. Beside the
six `f69be5a09d99` created that this function takes, that is 14 keyword-only
parameters on `append` today, not one of them with a default. On
`audit_log`, a parameter whose NULL already carries a meaning gets no
default. NULL on `duration_ms` means "this row predates the column"; NULL on
`refusal_reason` means "this call was not refused"; NULL on
`customer_ref_absence_reason` beside a NULL `customer_ref` is rejected by
the equivalence constraint outright. A default lets a future branch make one
of those statements without having established it, in the table this system
exists to keep complete.

`_customer_ref` returns both fields as one `_Subject` (`services/api/middleware/audit.py::_Subject`) with
exactly one populated, so the pair is decided once per call instead of being
a rule two branches have to remember.

## What this costs

All three constraints are enforcement, and under the fail-closed policy of
`dev-docs/decisions/0006-audit-write-failure.md` a violation costs the audit row
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
`tests/test_audit_middleware.py::test_the_database_refuses_an_absence_reason_outside_the_documented_set` and `:470` for the absence vocabulary,
`:1940` and `:1983` for the refusal vocabulary, `:727` and `:761` for the
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
  index today, `ix_audit_log_customer_at` (`packages/postern-core/src/postern_core/store/models.py::AuditEntry`). Nobody
  has measured a query that needs a second one.

**Amendment, 2026-09-18: `audit_log` gained a `client_id` column -- scrubbed,
clamped, and with no CHECK constraint.** `65d0652` ("feat(audit): record which
OAuth client made the call"), migration `c91f79e6d34a`, adds
`client_id VARCHAR(512)`, nullable, read once per call from
`get_access_token()` in `on_call_tool` (`services/api/middleware/audit.py::on_call_tool`)
and carried on `_PendingEntry` (`:989`) so the entry row and the completion row
for one `call_id` cannot name two different callers. capo ruled the same day
that `audit_log` records the customer data the operator TOUCHED rather than the
calls it served; the row shapes built for that said whose data
(`customer_ref`), what was asked for (`tool_name`, `arguments`), when the
operator reached (`reaching_at`) and how the call ended, and none of them said
who asked. The design handoff's answer to Client ID Metadata Documents, where
anyone holding a metadata document can present themselves, is per-client
controls -- a known set, each with its own client id, rate limits and kill
switch -- and until this column the table a regulator reads carried no client
id to act on.

**It is SCRUBBED, and the reason is one fallback in the verifier rather than
distrust of the issuer in general.** fastmcp 4.0.3's
`JWTVerifier.load_access_token` fills the field with `claims.get("client_id")
or claims.get("azp") or claims.get("sub") or "unknown"` -- read directly in the
installed source at `fastmcp/server/auth/providers/jwt.py:531-536`, with
`client_id=str(client_id)` reaching the `AccessToken` at `:617`. A verified
token carrying neither `client_id` nor `azp` therefore puts its RAW `sub` in
this column: the exact string `_customer_ref` refuses for `customer_ref` and
files as `subject_not_a_customer_ref`, the PAN-, IBAN- or DNI-shaped value
`packages/postern-core/src/postern_core/identity.py::_OPAQUE` warns a compromised issuer can mint. Unscrubbed, the column
is a bypass around that control rather than a second opinion on it, and
`tests/test_audit_middleware.py::test_a_pan_shaped_client_id_does_not_reach_the_audit_row` pins the difference against the stored
row: a token whose `client_id` is `4111111111114417` records `•••• 4417` here
and `no_string_subject` beside it.

**It carries NO CHECK constraint, deliberately, unlike the two vocabulary
columns this record is about.** The biconditional worth expressing --
`client_id IS NULL` exactly when `customer_ref_absence_reason` is
`no_access_token` -- is true of every row this application writes, because
both values come from one `get_access_token()` return. It is a fact about ONE
code path and not about the data: the other two absence values and a non-NULL
`customer_ref` all require a token to exist, so the equivalence holds only
while `_customer_ref` and `_client_id` are fed the same token object. A second
writer with its own token source, a provider yielding a token that carries no
client id, would be filing an honest row this constraint would reject, and
under `dev-docs/decisions/0006-audit-write-failure.md` the rejection costs the row
and the call. `packages/postern-core/src/postern_core/store/models.py::AuditEntry.client_id` states that in the column's own
comment.

**The hazard that decision sidesteps has an asymmetric failure direction.**
Alembic autogenerate does not compare CHECK constraints at all:
`migrations/versions/9a7d4e51c6f8_add_reaching_at_to_audit_log.py::upgrade`
records the measurement taken on 2026-09-18 -- invert the expression in
`models.py` to the opposite of what the migration creates, run
`make migrations` (`alembic check`), and it still answers "No new upgrade
operations detected". So a CHECK the migration never created is caught by
nothing, while a CHECK created inverted is caught loudly, by every honest row
it rejects and every call that row takes down with it. Declining to add one
removes both halves. For the record above: `audit_log` carries six CHECK
constraints today -- `ck_audit_log_refusal_reason`,
`ck_audit_log_customer_ref_absence_reason`,
`ck_audit_log_customer_ref_xor_absence`, `ck_audit_log_outcome`,
`ck_audit_log_call_id_present` and
`ck_audit_log_reaching_at_matches_outcome` -- so "All three constraints" under
"What this costs" counts the three this record introduced, which were the
whole set when it was written.

---

## Amendment, 26 September 2026: `refusal_reason` widened to three values

Migration `2d2aa72c0cb3`. A consent check that could not reach the consents
table was recorded as a call nobody refused. `_refuse` sits on the two
branches around the database read, so when that read raised, the row came out
`outcome='raised'`, `detail='NotFoundError'`, `refusal_reason` NULL --
byte-identical to a mistyped tool name.

The masking was not in this repository's code. FastMCP's `_evaluate_check`
catches `Exception` around every auth check, logs a WARNING and returns
`False`, so the exception never reached a branch that could file anything.
That is worth recording because it is where the fix had to go, and because
catching it ourselves means this repository now owns that log line.

Surfaced while sizing the connection pool: at the ceiling the next concurrent
operation waits `pool_timeout` and the lookup raises, so a saturated pool and
a revoked consent produced one row.

`consent_store_unavailable` is the third admissible value, 25 characters in a
`VARCHAR(32)`. It is the first value in this column that describes the
OPERATOR'S OWN INFRASTRUCTURE rather than the caller, and it is deliberately
not a security signal. `services/confirm/customer_rate_limit.py` chose 503
over 429 so that a dashboard would not attribute an outage to customer
behaviour; the same reasoning applies to a literal an alerting rule fires on.
A query counting consent denials must exclude it or it counts an outage as
customer state.

The denial itself is unchanged and stays. `AuthorizationError` is re-raised
ahead of the broad catch so a deliberate denial is never refiled as
infrastructure, and `CancelledError` is a `BaseException`, so a cancelled
request is not filed at all.

`_clear_refusal` is new, and is the price of the value not being cached. A
filing describes the evaluation the dispatch used, which is the last one; one
`tools/call` evaluates a tool's check several times, and a store that
recovers mid-request answers some and raises on others. Per-tool keying
cannot catch that, because the stale filing and the live call share a name.
Without the withdrawal, a call consent ALLOWED would carry a refusal reason
on an append-only table.

TWO LIMITS, STATED RATHER THAN LEFT TO BE FOUND. Production hands consent and
audit one `Database`, so a saturation deep enough to fail the audit write
costs the row entirely under record 0006, and this reason reaches the table
only for calls whose write got a connection. And `tools/list` writes no audit
row in any state, so a catalogue silently shrinking during an outage still
looks exactly like a customer with no consent.

`downgrade` fails by design against any database holding one of these rows.
`audit_log` is append-only, so there is no `UPDATE` that could rewrite them,
and inventing an admissible value would restate an outage as a customer's
consent state.

---

## Second amendment, 27 September 2026: the failure is remembered per request

The paragraph above describing `_clear_refusal` held for one day. The function
is gone and the value it cleaned up is now cached.

`_CACHE_ATTR` was written on the success path only, so an unreachable store
was re-probed by every evaluation. Measured: one `tools/call` carrying
arguments cost five connection attempts and five `pool_timeout` waits,
serially, during the event that exhausted the pool. Against a blackholed
listener with the connect timeout at 1.0s that call took 5.11 seconds to be
denied. It now takes 1.18.

THE LATENCY WAS THE SMALLER HALF. `tools/list` evaluates one check per gated
tool, so a single contended moment produced a catalogue reflecting no
authorization state at all: measured with consent granted to all four domains
and exactly one attempt failing, the old code listed three of the four and
split the two `accounts` tools, hiding `accounts.list` while listing
`accounts.get_balance`. An agent cannot act on that, and `tools/list` writes
no audit row in any state, so the only party who saw the incoherence was the
one that could not diagnose it. One probe per request means the gated surface
is present or absent together.

`_FAILED_ATTR` holds the customer references whose lookup already raised in
this request -- a set of strings, not of exceptions, so nothing keeps a
traceback and the frames and connections it references alive for the rest of
the request. A private `_ConsentStoreUnavailable` is raised instead of probing
on later evaluations, carrying the one bit the driver's exception cannot:
whether `check` is seeing this for the first time. The first failure
propagates unchanged, is logged with its traceback and remembered; the rest
file the same reason and log nothing. ERROR lines per outaged call went from
five to one.

ROWS DID NOT CHANGE. `AuditMiddleware` writes per call, never per evaluation,
so an outage still produces one completion row carrying
`consent_store_unavailable` -- and the sentinel branch files against its own
tool name precisely because the called tool's evaluation is usually not the
one that paid for the probe.

`_clear_refusal` was deleted rather than kept as defence, and an invariant
replaced it. Within one request the verdict for a (customer, tool) pair cannot
change: `no_customer_ref` is pinned by `ctx.token`, the request's own
validated token; `domain_not_consented` by the domain set the success cache
holds; `consent_store_unavailable` by the failure memory. No evaluation can
contradict an earlier one, so no filing can go stale. Keeping the withdrawal
would have kept the one function the suite can no longer reach, since caching
makes its scenario unreachable. `services/api/consent.py`'s module docstring
carries this under "WHY NOTHING NEEDS WITHDRAWING", and
`tests/test_consent_check_failure_mode.py::test_a_recovery_mid_request_no_longer_recovers_the_call`
fails when someone restores a per-evaluation probe without a withdrawal.

THE COST, STATED BECAUSE IT IS REAL. A store that raised on an early
evaluation and answered a later one used to let the call through, and that
exact call is now denied. Nobody chose five attempts: five is what the MCP
SDK's internal `tools/list` pass costs, and the retry it amounts to has no
policy, no backoff and no bound. A client re-issues a dropped call anyway --
MCP `2026-07-28` has no SSE resumability and every handler must be safe to
re-run -- so the retry survives one layer out, where it holds no connection.

TWO THINGS THIS IS NOT. It is not a circuit breaker: one attempt per request
still scales with request rate under a sustained outage. And `except
Exception` still labels any lookup failure as unavailability, so a schema
error against a reachable store files `consent_store_unavailable` and is now
remembered for the rest of the request as well as filed.

---

## Third amendment, 27 September 2026: four values, and a catalogue fetch still writes none

Migration `e08757299819`. `consent_store_unavailable` was being written for two
unrelated causes, because `services/api/consent.py` caught `Exception` and
filed that one value whatever had been raised. A connection pool at its
ceiling and a migration nobody applied produced the same row, so an operator
alerting on the value that names the operator's infrastructure was being woken
for this repository's SQL. The second amendment made it worse before this
fixed it: the cause is remembered for the request now, so one misclassified
exception labels every refusal in that request rather than one.

`consent_check_faulted`, 21 characters in the `VARCHAR(32)`, so no width
change and 7 characters of headroom left. The column now separates three
populations, and a query that does not separate them is wrong about at least
one: the CUSTOMER (`no_customer_ref`, `domain_not_consented`), the OPERATOR'S
INFRASTRUCTURE (`consent_store_unavailable`) and THIS SOFTWARE
(`consent_check_faulted`).

THE CLASS LISTS ARE READ OFF THE INSTALLED PACKAGES, not recalled, and they
live beside the code that catches because they are a property of SQLAlchemy
2.0.52 and asyncpg 0.31.0 rather than of the schema. Two findings from that
reading drive them. `sqlalchemy.exc.TimeoutError` -- the pool at its ceiling,
which is the condition this whole line of work started from -- descends from
`SQLAlchemyError` and **not** from `DBAPIError`, so a list built out of the
DBAPI tree misses saturation entirely. And `_asyncpg_error_translate` in the
dialect keys on seven asyncpg classes and sends everything else under
`PostgresError` to the bare DBAPI `Error`, so `TooManyConnectionsError`,
`CannotConnectNowError` and `AdminShutdownError` arrive as a generic
`DBAPIError`: naming only `OperationalError` and `InterfaceError` would file a
database that is shutting down as a defect in our code.

The fault families are consulted FIRST, because every one of them is a
`DBAPIError` subclass and reversing the two checks would silently file a
schema error as an outage. The DEFAULT is the fault reason, because an
exception out of one `SELECT` with three bound predicates that is neither a
database nor a socket error is ours -- and the most common such exception is an
`AttributeError`. A design that enumerated reachability and defaulted the rest
to unavailability would file the most obvious bug class there is as
infrastructure.

THE DENIAL DID NOT MOVE. A faulted check refuses exactly as an unreachable one
does; a bug in the consent lookup must never become a reason to allow a call.
The invariant that retired `_clear_refusal` survives, because the failure
memory now holds the classified reason and not merely the fact -- which is also
why a fault is remembered even though it fails fast and the latency argument
does not apply to it.

A `tools/list` WRITES NO ROW, IN ANY STATE, AND THAT IS A RULING. `PairingAudit`'s
rule is satisfied by an authenticated catalogue fetch during an outage, so a
row is owed -- and `audit_log` is not where it goes. `tool_name` is a per-tool
column and a catalogue is not one tool; `outcome` is closed at `reaching`,
`returned` and `raised`, none of which describes a tool filtered out of a list
nobody called. The volume is measured: `on_list_tools` fires for the MCP SDK's
internal param-validation dispatch as well as for a real fetch, so a row per
withheld tool would turn one `tools/call` carrying arguments into five audit
INSERTs during an outage instead of one, each fail-closed under record 0006,
against the pool whose exhaustion caused the outage. A row per fetch was
rejected on the reasoning that already refuses one per
`POST /device_authorization`, and "a row when the catalogue was reduced" was
rejected because partial consent is the normal state -- for a customer
consented to one domain, every fetch is reduced.

THE RECORD THEREFORE LIVES IN THE ERROR LINE, WHICH HAD TO BE FIXED TO CARRY
IT. It read `denying accounts.list` while all four gated tools were denied,
because only the evaluation that probes reaches the log and the rest are
answered from the memory: an outage under-reported by three quarters.
Remembering the failure is what makes the request-wide claim true, so the line
now states it.

THE RESIDUE, STATED. A data defect reaching PostgreSQL as a `PostgresError`
outside `SyntaxOrAccessError` lands in the generic `DBAPIError` bucket and
reads as an outage. Both reasons log at ERROR with distinct literals, so
either mislabel costs a wrong first hypothesis and never silence -- which is
what allowed the lists to be chosen on accuracy rather than on which
misclassification would be safer.

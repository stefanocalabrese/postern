# 2026-09-16: audit-log redaction of a POPULATED arguments payload, against the real database

## What this closes, and what it does not

`docs/verification/2026-09-16-consent-and-audit.md` (Plan 2 Task 7) proved
the audit table itself against real Postgres, but every `tools/call` it made
took no arguments, so all four rows it wrote carried `arguments = {}`. Its
own "what was not, and could not be, verified this way" section named the
gap explicitly: `AuditMiddleware._scrub`'s masking of PAN- and IBAN-shaped
values, and of dict KEYS, inside a non-empty `arguments` JSONB payload had
only ever been proven in-process (`tests/test_audit_middleware.py`,
`tests/test_asgi_app.py`), never through HTTP against the real database.
This record closes exactly that gap and nothing else: no other claim from
the earlier record is re-checked here.

**No browser UI was driven.** Same method as the two prior records in this
directory: `curl` against the running containers, `docker compose exec ...
psql` for ground truth.

## Setup

The stack was already up when this session resumed (another Claude session
had brought it up and applied migrations earlier in the day; verified
rather than assumed):

```bash
docker compose ps
```

```
NAME                               ...  SERVICE        ...  STATUS                 PORTS
masking-followups-api-1            ...  api            ...  Up 2 hours             0.0.0.0:8080->8080/tcp
masking-followups-backend-stub-1   ...  backend-stub   ...  Up 2 hours             0.0.0.0:8081->8081/tcp
masking-followups-db-1             ...  db             ...  Up 2 hours (healthy)   0.0.0.0:5432->5432/tcp
```

```bash
docker compose exec -T db psql -U postern -d postern -c "SELECT count(*) FROM consents;" -c "SELECT count(*) FROM audit_log;"
```

```
 count
-------
     0
(1 row)

 count
-------
     0
(1 row)
```

Migrations were already applied (`alembic_version`, `audit_log`, `consents`
tables present; confirmed by the same `\dt`/`SELECT` method the 2026-09-16
consent record used, not re-run here since nothing had changed). Zero
consents and zero audit rows, matching a clean slate.

## Which domain gates `transactions.list`

Read from the code, not assumed:

```bash
grep -n "consent_for|register(" services/api/server.py
```

```
transactions_check = (
    consent_for("transactions", db) if db is not None else _no_consent_required
)
transactions_tools.register(server, resolver, backend, transactions_check)
```

`services/api/tools/transactions.py:31` confirms `transactions.list` takes
`account_ref: Ref` and `days: int = 30` (`Field(ge=1, le=365)`), and no
other parameters -- which is what makes every extra key below an
`unexpected_keyword_argument`, not a schema-valid field.

## Seed: consent for `transactions`

```bash
docker compose exec -T db psql -U postern -d postern -c \
  "INSERT INTO consents (customer_ref, domain, granted, granted_at, expires_at) VALUES ('cust_7f3a','transactions',true,now(),null);"
```

`INSERT 0 1`.

## Token

```bash
TOKEN=$(curl -sS "http://localhost:8081/mint-token?sub=cust_7f3a")
```

Every request below carries `MCP-Protocol-Version: 2026-07-28`,
`Mcp-Method: tools/call`, `Mcp-Name: transactions.list`, the bearer token,
and the `_meta` envelope FastMCP's request validation requires -- the same
set the two prior records in this directory established as load-bearing.

## Call A: IBAN-shaped value in a string VALUE

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: transactions.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":101,"method":"tools/call","params":{"name":"transactions.list","arguments":{"account_ref":"ES9121000418450200051332","days":30},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

```json
{"jsonrpc":"2.0","id":101,"result":{"content":[{"text":"1 validation error for call[transactions_list]\naccount_ref\n  String should match pattern '^[a-z]{3}_[A-Za-z0-9]{1,32}$' [type=string_pattern_mismatch, input_value='ES9121000418450200051332', input_type=str]\n...","type":"text"}],"isError":true,"resultType":"complete", ...}}
```

`isError` is `true`: the raw IBAN fails `Ref`'s pattern (it does not start
with `[a-z]{3}_`), so this call fails validation. `_scrub` runs on the raw
argument tree BEFORE that validation, per `AuditMiddleware.on_call_tool`
(`services/api/middleware/audit.py:135-136`), so this is a real test of
redaction on the write path, not a call that never reached the middleware.

## Call B: PAN-shaped value in a string VALUE

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: transactions.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":102,"method":"tools/call","params":{"name":"transactions.list","arguments":{"account_ref":"acc_7f3a","days":30,"memo":"refund for card 4111111111114417 purchase"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

```json
{"jsonrpc":"2.0","id":102,"result":{"content":[{"text":"1 validation error for call[transactions_list]\nmemo\n  Unexpected keyword argument [type=unexpected_keyword_argument, input_value='refund for card 4111111111114417 purchase', input_type=str]\n...","type":"text"}],"isError":true,"resultType":"complete", ...}}
```

`memo` is not a parameter `transactions_list` declares, so this also fails
validation -- again, after `_scrub` already ran on the full raw tree.

## Call C: PAN-shaped value as a dict KEY

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: transactions.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":103,"method":"tools/call","params":{"name":"transactions.list","arguments":{"account_ref":"acc_7f3a","days":30,"4111111111114417":"note"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

```json
{"jsonrpc":"2.0","id":103,"result":{"content":[{"text":"1 validation error for call[transactions_list]\n4111111111114417\n  Unexpected keyword argument [type=unexpected_keyword_argument, input_value='note', input_type=str]\n...","type":"text"}],"isError":true,"resultType":"complete", ...}}
```

The raw PAN is the argument *key* here, not a value. This is the path the
2026-09-16 consent/audit record's own gap list flagged as unexercised
against real JSONB: `_scrub`'s dict-comprehension branch
(`services/api/middleware/audit.py:80-81`) applies `_scrub` to keys as well
as values, and the docstring's own worked example
(`{"4111111111114417": "x"}`) is this exact shape.

## Call D: valid, populated arguments that pass validation

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: transactions.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":104,"method":"tools/call","params":{"name":"transactions.list","arguments":{"account_ref":"acc_7f3a","days":30},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

`isError` is `false`; the call returns one transaction row (masked
`description`, matching the 2026-09-14 record's Proof 4). Included so the
audit table shows a `returned` row alongside the three `raised` ones, not
because this call's own arguments contain a PAN or IBAN (`transactions.list`
has no field that both accepts one and passes validation: `Ref`'s pattern
requires a `[a-z]{3}_` prefix no PAN or IBAN has).

Reasoning for why none of the three redaction-proving calls above is also
the one that succeeds, corrected after review: it is not because a
`Ref`-valid value can never carry a maskable substring. It can --
`Ref`'s pattern is `^[a-z]{3}_[A-Za-z0-9]{1,32}$`, and
`account_ref: "acc_4111111111114417"` satisfies it while `_scrub`'s
substring scan (`FreeText`, not `Ref`'s own fullmatch pattern) still masks
it to `acc_•••• 4417` -- this is exactly the `_PAN_RE`-versus-
`_PAN_IN_TEXT_RE` distinction `docs(audit): correct a stale PAN-pattern
reference` (this branch) exists to clarify, and it applies to `Ref` the
same way.

Verified directly, in-process, against this repo's own mock-backend test
harness (`tests/test_tools_transactions.py`'s fixture pattern), because it
changes the conclusion below: a `transactions.list` call with
`account_ref="acc_4111111111114417"` returns `is_error=False`. Both
`stub/backend.py`'s `/transactions` route and the pytest mock handler that
stands in for it ignore the `account_id` query parameter entirely and
always return the same fixture rows -- there is no per-account lookup or
ownership check anywhere in this codebase yet (ZT-2 enforcement is a
backend-side control this stub does not implement). So a `Ref`-valid,
PAN-bearing `account_ref` would have succeeded here exactly like Call D's
`acc_7f3a` did, and would have been scrubbed the same way in the audit row.

The gap this record actually leaves, then, is narrower than the original
wording claimed: no call was made whose arguments both pass every field's
validation and carry a PAN- or IBAN-shaped substring. That is one fixture
value away from closable -- swap Call D's `account_ref` for a Ref-valid,
PAN-bearing one -- not a structural property of `Ref` or of this tool's
validation. See "What was not, and could not be, verified this way" below.

## Reading the rows straight out of Postgres

```bash
docker compose exec -T db psql -U postern -d postern -c \
  "SELECT id, tool_name, outcome, detail, customer_ref, arguments FROM audit_log ORDER BY id;"
```

```
 id |     tool_name     | outcome  |     detail      | customer_ref |                                       arguments
----+-------------------+----------+-----------------+--------------+---------------------------------------------------------------------------------------
  1 | transactions.list | raised   | ValidationError | cust_7f3a    | {"days": 30, "account_ref": "ES•• •••• 1332"}
  2 | transactions.list | raised   | ValidationError | cust_7f3a    | {"days": 30, "memo": "refund for card •••• 4417 purchase", "account_ref": "acc_7f3a"}
  3 | transactions.list | raised   | ValidationError | cust_7f3a    | {"days": 30, "account_ref": "acc_7f3a", "•••• 4417": "note"}
  4 | transactions.list | returned |                  | cust_7f3a    | {"days": 30, "account_ref": "acc_7f3a"}
(4 rows)
```

Same result re-read with `-x` for the unabbreviated column values (identical
content, shown once here for the record):

```
-[ RECORD 1 ]+--------------------------------------------------------------------------------------
id           | 1
tool_name    | transactions.list
outcome      | raised
detail       | ValidationError
customer_ref | cust_7f3a
arguments    | {"days": 30, "account_ref": "ES•• •••• 1332"}
-[ RECORD 2 ]+--------------------------------------------------------------------------------------
id           | 2
tool_name    | transactions.list
outcome      | raised
detail       | ValidationError
customer_ref | cust_7f3a
arguments    | {"days": 30, "memo": "refund for card •••• 4417 purchase", "account_ref": "acc_7f3a"}
-[ RECORD 3 ]+--------------------------------------------------------------------------------------
id           | 3
tool_name    | transactions.list
outcome      | raised
detail       | ValidationError
customer_ref | cust_7f3a
arguments    | {"days": 30, "account_ref": "acc_7f3a", "•••• 4417": "note"}
-[ RECORD 4 ]+--------------------------------------------------------------------------------------
id           | 4
tool_name    | transactions.list
outcome      | returned
detail       |
customer_ref | cust_7f3a
arguments    | {"days": 30, "account_ref": "acc_7f3a"}
```

## Explicit assertion: no raw PAN or IBAN anywhere in `arguments`

```bash
docker compose exec -T db psql -U postern -d postern -c \
  "SELECT id, arguments FROM audit_log WHERE arguments::text LIKE '%4111111111114417%' OR arguments::text LIKE '%ES9121000418450200051332%';"
```

```
 id | arguments
----+-----------
(0 rows)
```

Zero rows. The raw PAN (`4111111111114417`, `stub/backend.py`'s `FULL_PAN`)
and the raw IBAN (`ES9121000418450200051332`, `stub/backend.py`'s
`FULL_IBAN`) that were typed into the three populated `tools/call` requests
above do not occur anywhere in the `audit_log.arguments` column, checked
directly against the JSONB text form in the database, not inferred from the
HTTP responses.

## What is now proven that was not before

- **A PAN- or IBAN-shaped value inside an argument STRING is masked before
  it reaches `audit_log.arguments`**, against real Postgres JSONB, not only
  in-process. (Row 1: `ES9121000418450200051332` → `ES•• •••• 1332`. Row 2:
  `4111111111114417` embedded inside a longer free-text string →
  `•••• 4417`.)
- **A PAN-shaped value used as a dict KEY is masked the same way a value
  is**, against real Postgres JSONB. (Row 3: the key `4111111111114417`
  itself, not a value, is stored as `•••• 4417`.) This is the specific gap
  the 2026-09-16 consent/audit record named as unexercised against the real
  database, and it is the one no in-process test path had been run through
  the actual JSONB column before this record.
- **`_scrub` runs before validation, and a rejected call still writes a
  scrubbed row**, confirmed against the database rather than assumed from
  the middleware's own code ordering: all three redaction-proving calls
  above have `outcome = raised`, `detail = ValidationError`, and still carry
  fully-masked `arguments`.
- **A successful call's `arguments` round-trip through the same scrub path
  without incident** (row 4, `outcome = returned`), confirming the scrub
  step is not a special case reached only on the failure path -- see "What
  was not, and could not be, verified this way" below for what this bullet
  does NOT cover.

Nothing here contradicts or reopens Plan 2 Task 7's other findings; this
record only closes the one gap that record itself listed as open.

## No defect found

Every masked value matched the mask forms already established in this
codebase's other verification records (`ES•• •••• 1332` for the IBAN,
`•••• 4417` for the PAN). No raw value, in any position (string value or
dict key), survived into the stored row.

## What was not, and could not be, verified this way

- [ ] **Not exercised.** A `tools/call` whose arguments BOTH pass every
  field's own validation AND carry a PAN- or IBAN-shaped substring,
  redacted on the SUCCESS path (`outcome = returned`) rather than the
  `raised` path all three redaction-proving calls above take. Call D's
  arguments (`{"account_ref": "acc_7f3a", "days": 30}`) pass validation but
  contain nothing maskable, so row 4 proves the scrub step runs on the
  success path, not that it masks anything there. This is not a structural
  gap -- see the corrected reasoning above: a `Ref`-valid, PAN-bearing
  `account_ref` (`"acc_4111111111114417"`, say) would have satisfied `Ref`'s
  pattern, been scrubbed to `acc_•••• 4417` in the audit row, and still
  succeeded against `stub/backend.py`, which does not check account
  ownership at all -- one additional call, not attempted in this session,
  closes it.
- [ ] **Not exercised**, for the same reason: a successful call whose
  arguments contain a PAN- or IBAN-shaped dict KEY (Call C's shape, but
  reaching `outcome = returned` instead of `raised`).
- [ ] **Authorization is not exercised by this record, at all.** Every
  route `stub/backend.py` serves -- `accounts`, `balance`, `transactions`,
  `cards` -- takes a `_request: Request` parameter and never reads it,
  returning the same fixed fixture regardless of who is asking or which
  account, card or customer is named in the path, query, or token. This
  record covers argument redaction only, and the same limitation applies
  to every other verification run against this compose stack until the
  stub gains a subject check: whatever a call here proves about masking,
  it proves nothing about whether a handler scopes its query to the
  caller (CLAUDE.md's ZT-2). This is a statement about the stub in this
  repository, not about the bank's real backend services, which are
  another team's and outside this repo.

## Teardown

```bash
docker compose down -v
```

Result: all three containers, the compose network, and the named volumes
removed. `docker compose ps` returned an empty table afterward, freeing port
5432 for the other session waiting on it.

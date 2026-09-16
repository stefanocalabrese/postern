# 2026-09-16: `audit_log.redaction_budget_exhausted` over real HTTP, read out of Postgres

Run performed at commit `c8b1fa2bd663ecb6a87a11151147ce57a4959e6b`
(`wire redaction_budget_exhausted from middleware to audit.append`), in the
worktree `.claude/worktrees/postern-4b-verification` on branch
`worktree-postern-4b-verification`. No production code was changed for this
run; this document is the only file the session created.

`$SCRATCH` below stands for the session scratchpad directory, outside the
repository. It is the only substitution made in any command shown here.

## What this closes, and what it does not

`c8b1fa2` made `AuditMiddleware.on_call_tool` wrap the argument walk in
`redaction_budget()` and pass `scope.exhausted` through to `audit.append`
(`services/api/middleware/audit.py:135-136` and `:149`). Four tests in
`tests/test_audit_middleware.py` (assertions at lines 311, 324, 334, 344)
already prove both values on both audit paths against real Postgres,
in-process. What had never been run is the same behaviour through the HTTP
surface of the full compose stack, with the resulting rows read by a psql
client that is not the application. This record closes exactly that and
nothing else.

`docs/verification/2026-09-16-audit-arguments-redaction.md` supplied the
procedure reused below: which domain gates `transactions.list`, how consent
is seeded, how a token is minted, and the header set FastMCP's request
validation requires. That record's own gap list named one call it did not
make, a call whose arguments both pass validation and carry a maskable
substring. Call 4 here makes it.

**No browser UI was driven.** `curl` against the containers,
`docker compose exec -T db psql` for ground truth.

## Setup

Nothing was listening on 5432, 8080 or 8081 before the run
(`lsof -iTCP:<port> -sTCP:LISTEN` produced no output for all three, and
`docker ps -a` listed no containers).

```bash
docker compose up -d
docker compose ps
```

```
NAME                                     IMAGE                                                                                                                   COMMAND                  SERVICE        CREATED         STATUS                   PORTS
postern-4b-verification-api-1            postern-4b-verification-api                                                                                             "uvicorn services.ap…"   api            7 seconds ago   Up 4 seconds             0.0.0.0:8080->8080/tcp, [::]:8080->8080/tcp
postern-4b-verification-backend-stub-1   ghcr.io/astral-sh/uv:python3.12-bookworm-slim@sha256:e5b65587bce7de595f299855d7385fe7fca39b8a74baa261ba1b7147afa78e58   "uv run uvicorn stub…"   backend-stub   7 seconds ago   Up 6 seconds             0.0.0.0:8081->8081/tcp, [::]:8081->8081/tcp
postern-4b-verification-db-1             postgres:17-alpine                                                                                                      "docker-entrypoint.s…"   db             7 seconds ago   Up 6 seconds (healthy)   0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp
```

```bash
POSTERN_DATABASE_URL=postgresql+asyncpg://postern:postern@localhost:5432/postern uv run alembic upgrade head
```

```
Using CPython 3.12.13
Creating virtual environment at: .venv
   Building postern-core @ file:///Users/stefano/Projects/postern/.claude/worktrees/postern-4b-verification/packages/postern-core
      Built postern-core @ file:///Users/stefano/Projects/postern/.claude/worktrees/postern-4b-verification/packages/postern-core
Installed 97 packages in 94ms
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> f69be5a09d99, consents and audit log
INFO  [alembic.runtime.migration] Running upgrade f69be5a09d99 -> f45183f7ff50, add redaction_budget_exhausted to audit_log
```

Both migrations ran on an empty database, `f45183f7ff50` being the one
`c8b1fa2` depends on. The column it adds, read back from the live schema,
alongside the two row counts:

```bash
docker compose exec -T db psql -U postern -d postern -c "\d audit_log" -c "SELECT count(*) FROM consents;" -c "SELECT count(*) FROM audit_log;"
```

```
                                               Table "public.audit_log"
           Column           |           Type           | Collation | Nullable |                Default
----------------------------+--------------------------+-----------+----------+---------------------------------------
 id                         | integer                  |           | not null | nextval('audit_log_id_seq'::regclass)
 at                         | timestamp with time zone |           | not null |
 customer_ref               | character varying(64)    |           |          |
 tool_name                  | character varying(64)    |           | not null |
 arguments                  | jsonb                    |           | not null |
 outcome                    | character varying(16)    |           | not null |
 detail                     | text                     |           |          |
 redaction_budget_exhausted | boolean                  |           | not null | false
Indexes:
    "audit_log_pkey" PRIMARY KEY, btree (id)
    "ix_audit_log_customer_at" btree (customer_ref, at)

 count
-------
     0
(1 row)

 count
-------
     0
(1 row)
```

Zero consents, zero audit rows: a clean slate, so every row below was
written by one of the four calls in this document and by nothing else.

## Seed: consent for `transactions`

`services/api/server.py` gates `transactions.list` behind
`consent_for("transactions", db)`, per the earlier record's section "Which
domain gates `transactions.list`".
`services/api/tools/transactions.py:29-31` declares `account_ref: Ref` and
`days: Annotated[int, Field(ge=1, le=facade.MAX_DAYS)] = 30`, and no other
parameter; `MAX_DAYS = 365`
(`packages/postern-core/src/postern_core/facade/transactions.py:82`). That
is what makes an extra key an `unexpected_keyword_argument` and `days=9999`
a `less_than_equal` failure below.

```bash
docker compose exec -T db psql -U postern -d postern -c "INSERT INTO consents (customer_ref, domain, granted, granted_at, expires_at) VALUES ('cust_7f3a','transactions',true,now(),null);"
```

```
INSERT 0 1
```

## Token

```bash
curl -sS "http://localhost:8081/mint-token?sub=cust_7f3a" -o $SCRATCH/token.txt -w "%{http_code}\n"
wc -c < $SCRATCH/token.txt
```

```
200
     552
```

552 bytes of JWT. Every request below carries `MCP-Protocol-Version:
2026-07-28`, `Mcp-Method: tools/call`, `Mcp-Name: transactions.list`, that
bearer token, and the `_meta` envelope FastMCP's request validation
requires. In each command `$TOKEN` is the contents of that file.

## Call 1: ordinary small call that succeeds

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: transactions.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":201,"method":"tools/call","params":{"name":"transactions.list","arguments":{"account_ref":"acc_7f3a","days":30},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

```json
{"jsonrpc":"2.0","id":201,"result":{"content":[{"text":"{\"items\":[{\"ref\":\"txn_1\",\"account_ref\":\"acc_7f3a\",\"booked_at\":\"2026-09-11T08:30:00Z\",\"amount\":{\"amount\":\"34.20\",\"currency\":\"EUR\"},\"direction\":\"debit\",\"counterparty_name\":\"Acme Ltd\",\"description\":\"Card •••• 4417 purchase, ref DE•• •••• 3000\"}],\"truncated\":false}","type":"text"}],"isError":false,"resultType":"complete","structuredContent":{"items":[{"ref":"txn_1","account_ref":"acc_7f3a","booked_at":"2026-09-11T08:30:00Z","amount":{"amount":"34.20","currency":"EUR"},"direction":"debit","counterparty_name":"Acme Ltd","description":"Card •••• 4417 purchase, ref DE•• •••• 3000"}],"truncated":false},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"postern","version":"4.0.3"}}}}
```

`isError` is `false`. Expected row: `outcome = returned`,
`redaction_budget_exhausted = false`.

## Call 2: ordinary small call that fails validation

`days=9999` violates `Field(ge=1, le=facade.MAX_DAYS)`, so the tool raises
past the middleware after `_scrub` has already run on the raw argument tree
(`services/api/middleware/audit.py:135-136`, before `call_next` at `:143`).

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: transactions.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":202,"method":"tools/call","params":{"name":"transactions.list","arguments":{"account_ref":"acc_7f3a","days":9999},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

```json
{"jsonrpc":"2.0","id":202,"result":{"content":[{"text":"1 validation error for call[transactions_list]\ndays\n  Input should be less than or equal to 365 [type=less_than_equal, input_value=9999, input_type=int]\n    For further information visit https://errors.pydantic.dev/2.13/v/less_than_equal","type":"text"}],"isError":true,"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"postern","version":"4.0.3"}}}}
```

Expected row: `outcome = raised`, `detail = ValidationError`,
`redaction_budget_exhausted = false`.

## Call 3: arguments that exhaust the 100,000-checksum allowance

The payload uses the technique `tests/test_masking_types.py:711-725`
derives, reimplemented rather than imported: 128-character junk tokens
(`"AB12" * 32`), `_IBAN_SCAN_BUDGET // 100 + 50 = 1050` of them,
space-joined. One such token costs 559 checksum operations by that file's
own measurement, so 1050 of them overrun `_IBAN_SCAN_BUDGET = 100_000`
(`packages/postern-core/src/postern_core/domain/masking.py:206`) well before
the end of the string. 128 is exactly `_IBAN_SCAN_MAX_TOKEN`
(masking.py:137) and not above it, so these tokens get scanned rather than
masked unread for over-length. The junk went in a `memo` key, leaving
`account_ref` valid, so the only validation failure is the extra key.

Body generated by a throwaway script in the session scratchpad, outside the
repository. Its substantive lines:

```python
BUDGET = 100_000
n = BUDGET // 100 + 50              # 1050
junk = " ".join(["AB12" * 32] * n)  # 128-character tokens, space-joined
body = {"jsonrpc": "2.0", "id": 203, "method": "tools/call",
        "params": {"name": "transactions.list",
                   "arguments": {"account_ref": "acc_7f3a", "days": 30, "memo": junk},
                   "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28",
                             "io.modelcontextprotocol/clientCapabilities": {}}}}
```

```bash
python3 $SCRATCH/mkbody.py $SCRATCH/call3.json
```

```
tokens=1050 junk_bytes=135449
body_bytes=135727
```

135,727 bytes, 12.9% of `settings.max_body_bytes` (1,048,576, the default in
`services/api/settings.py:40`), so `HeaderBodyValidation` does not reject it
with a 413.

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: transactions.list' \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @$SCRATCH/call3.json | head -c 1200
```

```json
{"jsonrpc":"2.0","id":203,"result":{"content":[{"text":"1 validation error for call[transactions_list]\nmemo\n  Unexpected keyword argument [type=unexpected_keyword_argument, input_value='AB12AB12AB12AB12AB12AB12...B12AB12AB12AB12AB12AB12', input_type=str]\n    For further information visit https://errors.pydantic.dev/2.13/v/unexpected_keyword_argument","type":"text"}],"isError":true,"resultType":"complete","_meta":{"io.modelcontextprotocol/serverInfo":{"name":"postern","version":"4.0.3"}}}}
```

The `...` inside `input_value` is pydantic's own elision of the 135,449-byte
value, not an edit to this transcript. Expected row: `outcome = raised`,
`redaction_budget_exhausted = true`.

## Call 4: successful call carrying a maskable argument

`account_ref = "acc_4111111111114417"` satisfies `Ref`'s pattern
`^[a-z]{3}_[A-Za-z0-9]{1,32}$`
(`packages/postern-core/src/postern_core/domain/models.py:16`) while
containing `stub/backend.py:24`'s `FULL_PAN`.

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: transactions.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":204,"method":"tools/call","params":{"name":"transactions.list","arguments":{"account_ref":"acc_4111111111114417","days":30},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

```json
{"jsonrpc":"2.0","id":204,"result":{"content":[{"text":"{\"items\":[{\"ref\":\"txn_1\",\"account_ref\":\"acc_7f3a\",\"booked_at\":\"2026-09-11T08:30:00Z\",\"amount\":{\"amount\":\"34.20\",\"currency\":\"EUR\"},\"direction\":\"debit\",\"counterparty_name\":\"Acme Ltd\",\"description\":\"Card •••• 4417 purchase, ref DE•• •••• 3000\"}],\"truncated\":false}","type":"text"}],"isError":false,"resultType":"complete","structuredContent":{"items":[{"ref":"txn_1","account_ref":"acc_7f3a","booked_at":"2026-09-11T08:30:00Z","amount":{"amount":"34.20","currency":"EUR"},"direction":"debit","counterparty_name":"Acme Ltd","description":"Card •••• 4417 purchase, ref DE•• •••• 3000"}],"truncated":false},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"postern","version":"4.0.3"}}}}
```

`isError` is `false`: the call succeeded, as the earlier record predicted it
would. Note what came back. The request named `acc_4111111111114417`; the
response carries `"account_ref":"acc_7f3a"`, the fixture's own account, with
no error. That is the ZT-2 limitation below, observed from outside rather
than inferred from reading `stub/backend.py`.

## Reading the rows straight out of Postgres

```bash
docker compose exec -T db psql -U postern -d postern -c "SELECT id, tool_name, outcome, detail, customer_ref, redaction_budget_exhausted, length(arguments::text) AS args_len FROM audit_log ORDER BY id;"
```

```
 id |     tool_name     | outcome  |     detail      | customer_ref | redaction_budget_exhausted | args_len
----+-------------------+----------+-----------------+--------------+----------------------------+----------
  1 | transactions.list | returned |                 | cust_7f3a    | f                          |       39
  2 | transactions.list | raised   | ValidationError | cust_7f3a    | f                          |       41
  3 | transactions.list | raised   | ValidationError | cust_7f3a    | t                          |    27372
  4 | transactions.list | returned |                 | cust_7f3a    | f                          |       44
(4 rows)
```

All four rows match the expectation stated with each call. Nothing in this
run surprised the prediction. The same read in expanded form, with the write
timestamps:

```bash
docker compose exec -T db psql -U postern -d postern -x -c "SELECT id, at, tool_name, outcome, detail, customer_ref, redaction_budget_exhausted FROM audit_log ORDER BY id;"
```

```
-[ RECORD 1 ]--------------+------------------------------
id                         | 1
at                         | 2026-09-16 13:28:37.581411+00
tool_name                  | transactions.list
outcome                    | returned
detail                     |
customer_ref               | cust_7f3a
redaction_budget_exhausted | f
-[ RECORD 2 ]--------------+------------------------------
id                         | 2
at                         | 2026-09-16 13:28:42.277251+00
tool_name                  | transactions.list
outcome                    | raised
detail                     | ValidationError
customer_ref               | cust_7f3a
redaction_budget_exhausted | f
-[ RECORD 3 ]--------------+------------------------------
id                         | 3
at                         | 2026-09-16 13:29:03.065223+00
tool_name                  | transactions.list
outcome                    | raised
detail                     | ValidationError
customer_ref               | cust_7f3a
redaction_budget_exhausted | t
-[ RECORD 4 ]--------------+------------------------------
id                         | 4
at                         | 2026-09-16 13:29:08.183531+00
tool_name                  | transactions.list
outcome                    | returned
detail                     |
customer_ref               | cust_7f3a
redaction_budget_exhausted | f
```

The four calls span 31 seconds, 13:28:37 to 13:29:08 UTC, in the order
issued.

The stored `arguments` for the three small rows:

```bash
docker compose exec -T db psql -U postern -d postern -c "SELECT id, arguments FROM audit_log WHERE id IN (1,2,4) ORDER BY id;"
```

```
 id |                  arguments
----+----------------------------------------------
  1 | {"days": 30, "account_ref": "acc_7f3a"}
  2 | {"days": 9999, "account_ref": "acc_7f3a"}
  4 | {"days": 30, "account_ref": "acc_•••• 4417"}
(3 rows)
```

Row 4 is the case the earlier record left open: a validation-passing,
`outcome = returned` call whose argument was masked in the audit row,
`acc_4111111111114417` stored as `acc_•••• 4417`.

## What row 3 actually holds

```bash
docker compose exec -T db psql -U postern -d postern -c "SELECT id, arguments->>'account_ref' AS account_ref, arguments->>'days' AS days, length(arguments->>'memo') AS memo_len, left(arguments->>'memo', 80) AS memo_head, right(arguments->>'memo', 80) AS memo_tail FROM audit_log WHERE id = 3;"
```

```
 id | account_ref | days | memo_len |                                    memo_head                                     |                                    memo_tail
----+-------------+------+----------+----------------------------------------------------------------------------------+----------------------------------------------------------------------------------
  3 | acc_7f3a    | 30   |    27321 | AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12AB12 |  •••• •••• •••• •••• •••• •••• •••• •••• •••• •••• •••• •••• •••• •••• •••• ••••
(1 row)
```

The head is intact junk, the tail is bare `••••`. Counted:

```bash
docker compose exec -T db psql -U postern -d postern -c "SELECT id, array_length(string_to_array(arguments->>'memo', ' '), 1) AS total_tokens, (SELECT count(*) FROM unnest(string_to_array((SELECT arguments->>'memo' FROM audit_log WHERE id=3), ' ')) t WHERE t = repeat('AB12', 32)) AS intact_junk_tokens, (SELECT count(*) FROM unnest(string_to_array((SELECT arguments->>'memo' FROM audit_log WHERE id=3), ' ')) t WHERE t = repeat(chr(8226), 4)) AS bare_masked_tokens FROM audit_log WHERE id = 3;"
```

```
 id | total_tokens | intact_junk_tokens | bare_masked_tokens
----+--------------+--------------------+--------------------
  3 |         1050 |                178 |                872
(1 row)
```

178 of the 1050 tokens survived the scan intact; 872 are bare `_MASK`. Two
independent checks that this is budget exhaustion and not some other
truncation:

- 178 x 559 = 99,502 checksums, leaving 498 of the 100,000 allowance, fewer
  than the 559 a full token costs. The 179th token could not complete, which
  is exactly where the intact run stops.
- 178 x 128 + 872 x 4 + 1049 separators = 22,784 + 3,488 + 1,049 = 27,321,
  the exact `memo_len` Postgres reports.

## Explicit assertion: no raw PAN or IBAN anywhere in `arguments`

```bash
docker compose exec -T db psql -U postern -d postern -c "SELECT id, arguments FROM audit_log WHERE arguments::text LIKE '%4111111111114417%' OR arguments::text LIKE '%ES9121000418450200051332%';"
```

```
 id | arguments
----+-----------
(0 rows)
```

Zero rows. `4111111111114417` (`stub/backend.py:24`, `FULL_PAN`) was typed
verbatim into Call 4's `account_ref` and does not occur in any stored
`arguments` value. `ES9121000418450200051332` (`stub/backend.py:25`,
`FULL_IBAN`) was not sent in this run's arguments at all and equally does
not occur. Checked against the JSONB text form in the database, not inferred
from the HTTP responses.

## What is now proven that was not before

- **`redaction_budget_exhausted` records `false` on the success path over
  real HTTP**, against real Postgres, for calls whose arguments are small
  (rows 1 and 4, `outcome = returned`).
- **It records `false` on the `raised` path too** (row 2, `days = 9999`,
  `detail = ValidationError`), so a failed call is not flagged merely for
  having failed.
- **It records `true` for a call whose arguments genuinely overrun the
  allowance** (row 3), written through the HTTP surface with no in-process
  fixture anywhere in the path. `true` cannot come from the column's
  `server_default`, which the `\d` output above shows is `false`, so the
  value on row 3 demonstrably travelled from `RedactionScope.exhausted`
  through `services/api/middleware/audit.py:146` into the column.
- **A validation-passing call carrying a PAN-shaped substring is masked in
  the audit row and still succeeds** (row 4: `acc_4111111111114417` sent,
  `acc_•••• 4417` stored, `isError: false`). This is the gap
  `docs/verification/2026-09-16-audit-arguments-redaction.md` listed first
  under "What was not, and could not be, verified this way".

## What the exhaustion row does and does not show

`RedactionScope.exhausted` is `_ScanBudget.remaining <= 0`
(masking.py:173, masking.py:302). Zero is reachable by the checksum that
COMPLETES a successful scan, so `true` in this column does not by itself
mean any value on that row was bare-masked. It means the allowance for that
call reached zero.

This run happens to demonstrate real bare-masking as well, and the token
count is the evidence: 872 of row 3's 1050 tokens are bare `••••` rather
than their original text, which `tests/test_masking_types.py:730-733` names
as the observable signature of "was not scanned" rather than "was scanned
and came out ambiguous". Stated precisely, what degraded on row 3 is audit
fidelity, not confidentiality: none of the 872 masked tokens was a real
IBAN, and the 178 that were scanned establish that this shape carries none,
so the cost was readability of junk the agent supplied itself.

This run does NOT demonstrate the serious variant, a readable non-sensitive
argument lost because an attacker padded the same call with junk, nor a real
IBAN bare-masked after the exhaustion point over the wire.

The column also cannot separate the two cases after the fact. A reader who
sees `true` and needs to know whether anything was bare-masked has to
inspect `arguments` itself, exactly as this section did.

## No defect found

Every value landed where `c8b1fa2`'s tests say it should. The two mask forms
match those this codebase's other verification records established,
`•••• 4417` for the PAN and bare `••••` for an unscanned token.

One observation, recorded and not acted on, because this session changed no
code. The column's `server_default` is `false`
(`migrations/versions/f45183f7ff50_add_redaction_budget_exhausted_to_audit_.py:26-30`).
`audit.append`'s parameter is required and never defaulted
(`packages/postern-core/src/postern_core/store/audit.py:29`), so every row
this application writes supplies the value explicitly and the default is
reached only by an INSERT that bypasses `audit.append`. Read from the
database alone, such a row is indistinguishable from one where the scan ran
and did not exhaust. Rows 1, 2 and 4 above are `false`, and psql alone
cannot say which of the two produced them; row 3's `true` is what proves the
application writes the column at all.

## What was not, and could not be, verified this way

- [ ] **Authorization is not exercised by this record, at all.**
  `stub/backend.py` serves four domain routes: `/accounts` (handler at line
  60), `/accounts/{account_id}/balance` (line 64), `/transactions` (line
  68), `/cards` (line 72). Every one takes a `_request: Request` parameter
  and never reads it, returning the same fixed `ACCOUNTS`, `BALANCE`,
  `TRANSACTIONS` or `CARDS` fixture regardless of who is asking or which
  account is named. Call 4 shows it from the outside: the request named
  `acc_4111111111114417`, the response carried `acc_7f3a`, no error. So
  this record proves nothing about whether a handler scopes its query to
  the token subject, and the same limit applies to every run against this
  compose stack until the stub gains a subject check. That control is ZT-2,
  which `docs/bank-mcp-zero-trust-plan.md:301` calls the critical path on
  which everything else depends ("if the domain services do not enforce on
  the token subject, nothing else in this plan matters"), and CLAUDE.md:128
  repeats. This is a statement about the stub in this repository, not about
  the bank's real backend services, which belong to another team and sit
  outside this repo.
- [ ] **Not exercised.** A budget-exhausting call that reaches
  `outcome = returned`. Row 3 is `raised`, and with this tool it has to be:
  exhausting 100,000 checksums needs roughly 135 KB of argument text, and
  `transactions.list` declares only `account_ref: Ref` (33 characters
  maximum) and `days: int`, so any payload large enough to spend the
  allowance must arrive as an extra key and fail validation. Proving `true`
  on the success path over HTTP needs a tool with a long free-text
  parameter, which this server does not expose yet. The assertion at
  `tests/test_audit_middleware.py:311` covers that combination in-process.
- [ ] **Not exercised.** Exhaustion caused by many short argument strings
  rather than one long one, the spread-across-a-list shape that
  `services/api/middleware/audit.py:119-134` says `redaction_budget` exists
  to defeat. Call 3 puts all 135,449 bytes in a single `memo` string, which
  would have exhausted a per-string budget too, so this run does not
  distinguish the call-wide allowance from the old per-string one.
- [ ] **Not exercised.** A real IBAN placed after the exhaustion point in a
  live HTTP payload, to confirm over the wire that it is bare-masked rather
  than left readable. `tests/test_masking_types.py:719-733` proves that
  in-process; row 3's trailing tokens here were junk, not an IBAN.
- [ ] **Not re-checked.** Every claim in
  `docs/verification/2026-09-16-audit-arguments-redaction.md` and
  `docs/verification/2026-09-16-consent-and-audit.md` other than the one
  Call 4 closes. The dict-KEY masking path, the NUL-stripping order, and
  consent expiry were not re-run in this session.

## Teardown

```bash
docker compose down -v
```

```
 Container postern-4b-verification-api-1 Stopping
 Container postern-4b-verification-api-1 Stopped
 Container postern-4b-verification-api-1 Removing
 Container postern-4b-verification-api-1 Removed
 Container postern-4b-verification-backend-stub-1 Stopping
 Container postern-4b-verification-db-1 Stopping
 Container postern-4b-verification-db-1 Stopped
 Container postern-4b-verification-db-1 Removing
 Container postern-4b-verification-db-1 Removed
 Container postern-4b-verification-backend-stub-1 Stopped
 Container postern-4b-verification-backend-stub-1 Removing
 Container postern-4b-verification-backend-stub-1 Removed
 Network postern-4b-verification_default Removing
 Network postern-4b-verification_default Removed
```

```bash
docker compose ps
lsof -iTCP:5432 -sTCP:LISTEN; echo "lsof exit: $?"
docker ps -a --format '{{.Names}}'
docker volume ls --filter name=postern-4b
```

```
NAME      IMAGE     COMMAND   SERVICE   CREATED   STATUS    PORTS
lsof exit: 1
DRIVER    VOLUME NAME
```

`docker compose ps` lists a header and no rows. `lsof` printed nothing and
exited 1, meaning no process is listening on 5432. `docker ps -a` printed
nothing, so no container from this run survives, stopped or otherwise.
`docker volume ls` matched no volume. The machine is free for the next
session.

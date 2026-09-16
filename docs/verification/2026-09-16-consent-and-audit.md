# 2026-09-16: Plan 2 Task 7 verification against the running stack

## What this is, and what it is not

The plan's Task 7 lists eight steps, none of which mention MCP Inspector.
**No browser UI was driven for this record either way** -- every check below
was run with `curl` and `docker compose exec ... psql` directly against the
containers, the same method `docs/verification/2026-09-14-stack-run.md` used
for Plan 1's Task 14. Anything not checked this way is listed at the end as
an explicit unchecked item, not implied to have passed.

## Setup

```bash
docker compose up -d --build
```

Result: `db`, `backend-stub` and `api` all started; `docker compose ps`
showed `db` as `Up ... (healthy)` and the other two as `Up`.

Every request below carries the three mandatory headers this codebase's own
notes call out as load-bearing (`Mcp-Method`, `Mcp-Name`,
`MCP-Protocol-Version: 2026-07-28`) plus the `_meta` envelope
(`io.modelcontextprotocol/protocolVersion`, `io.modelcontextprotocol/
clientCapabilities`) FastMCP's request validation requires. A token is
minted per section from the stub's own throwaway IdP:

```bash
TOKEN=$(curl -sS "http://localhost:8081/mint-token?sub=cust_7f3a")
```

## Proof 1: migrations apply cleanly against the compose database

```bash
POSTERN_DATABASE_URL=postgresql+asyncpg://postern:postern@localhost:5432/postern uv run alembic upgrade head
```

Output:

```
INFO  [alembic.runtime.migration] Context impl PostgresqlImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> f69be5a09d99, consents and audit log
```

Exit code `0`. Confirmed against the database itself:

```sql
-- \dt
 public | alembic_version | table | postern
 public | audit_log       | table | postern
 public | consents        | table | postern

-- SELECT * FROM alembic_version;
 version_num
--------------
 f69be5a09d99
```

**Method: real `alembic upgrade head` against the compose Postgres, exit
code plus a direct `\dt`/`SELECT`, not pytest.**

## Seed: consent for `accounts` only

```bash
docker compose exec -T db psql -U postern -d postern -c \
  "INSERT INTO consents (customer_ref, domain, granted, granted_at, expires_at) VALUES ('cust_7f3a','accounts',true,now(),null);"
```

`INSERT 0 1`. Verified with a `SELECT * FROM consents;`: one row,
`cust_7f3a` / `accounts` / `granted=t`.

## Proof 2: the catalogue is filtered by consent -- verified over HTTP

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/list' -H 'Mcp-Name: tools/list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

`result.tools[].name`, extracted with `jq`:

```
accounts.get_balance
accounts.list
banking_start_session
```

`cards.list` and `transactions.list` are absent. `result.cacheScope` is
`"private"`, `result.ttlMs` is `60000`. **Confirmed.**

## Proof 3: the hidden tool is uncallable, and discloses nothing about its existence

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: cards.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cards.list","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

Result:

```json
{"jsonrpc":"2.0","id":2,"result":{"content":[{"text":"Unknown tool: 'cards.list'","type":"text"}],"isError":true,"resultType":"complete", ...}}
```

`isError` is `true`. Non-disclosure was checked two ways, not asserted:

1. Stripping the literal echoed string `"Unknown tool: 'cards.list'"` from
   the response leaves no remaining occurrence of `cards` anywhere in
   `result`.
2. The same request against a name that was never registered at all,
   `nonexistent.tool`, produces the byte-identical shape:
   `{"...","text":"Unknown tool: 'nonexistent.tool'","isError":true,...}`.
   A denied-by-consent tool and a typo are indistinguishable to the caller
   -- which the plan's own "what this plan deliberately does not establish"
   table already flags for the *audit log* (see Proof 5); this confirms the
   same indistinguishability holds for the *HTTP response* too, live, not
   just in the log.

**Confirmed.**

## Proof 4: the consented tool succeeds and returns the masked IBAN; the stub serves the raw one

Stub backend, called directly, no auth:

```bash
curl -sS http://localhost:8081/accounts
```

```json
{"accounts":[{"id":"acc_7f3a","label":"Joint expenses","iban":"ES9121000418450200051332"}, ...]}
```

Through the server:

```bash
curl -sS http://localhost:8080/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: accounts.list' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"accounts.list","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

Decoded `structuredContent.result[0].iban` equals exactly `ES•• •••• 1332`
(compared with Python `==`, not eyeballed against the JSON-escaped
`•` form). `isError` is `false`. The raw value
`ES9121000418450200051332` (`stub/backend.py`'s `FULL_IBAN`) does not occur
anywhere in the response body (`raw in json.dumps(response)` is `False`).
**Confirmed.**

## Proof 5: the audit table -- verified by querying the database directly

At this point three `tools/call` requests had been made (`cards.list`
denied, `nonexistent.tool` denied, `accounts.list` returned -- plus one
throwaway `cards.list` retry whose HTTP response file got corrupted by a
`curl -i`/`-o` flag conflict and was re-run cleanly; the request itself
still reached the server and is in the log as row 1):

```sql
SELECT id, tool_name, outcome, detail, customer_ref, arguments FROM audit_log ORDER BY id;
```

```
 id |    tool_name     | outcome  |    detail     | customer_ref | arguments
----+------------------+----------+---------------+--------------+-----------
  1 | cards.list       | raised   | NotFoundError | cust_7f3a    | {}
  2 | nonexistent.tool | raised   | NotFoundError | cust_7f3a    | {}
  3 | cards.list       | raised   | NotFoundError | cust_7f3a    | {}
  4 | accounts.list    | returned |               | cust_7f3a    | {}
```

One `returned` row for the successful call, three `raised` rows for the
denied/unknown calls, all with `customer_ref = cust_7f3a`. A separate query
for a raw PAN or IBAN anywhere in `arguments` or `detail`
(`arguments::text LIKE '%4111111111114417%'`, same for the IBAN, `OR`ed
across both columns) returned zero rows. `arguments` is `{}` on every row
here regardless (`cards.list`/`accounts.list` take no arguments), so this is
a real but limited proof: it did not exercise redaction of a populated
`arguments` payload, which `tests/test_asgi_app.py` and the audit
middleware's own docstring already cover in-process. **Confirmed against
the database, not inferred from the HTTP responses above.**

Also confirmed, and worth naming plainly: `cards.list` (denied by consent)
and `nonexistent.tool` (denied because it never existed) both landed as
`outcome="raised", detail="NotFoundError"`. The plan's own table already
names this as a known gap ("decision needed at Task 6"); Task 6 (already
merged) did not resolve it. This record confirms the gap is live in the
real database, not only a theoretical reading of the code -- it remains
open, not fixed here (out of this task's scope: no application code was
touched).

## Proof 6: granting `cards` consent works without restarting the container

```bash
docker compose exec -T db psql -U postern -d postern -c \
  "INSERT INTO consents (customer_ref, domain, granted, granted_at, expires_at) VALUES ('cust_7f3a','cards',true,now(),null);"
```

`INSERT 0 1`. Container restart was never issued; confirmed by
`docker inspect p2-task7-verification-api-1 --format '{{.State.StartedAt}}'`
being identical (`2026-09-16T07:28:53.268344256Z`) before this insert and
after Proof 7 below.

`tools/list`, re-run with the same token, no new headers or session:

```
accounts.get_balance
accounts.list
banking_start_session
cards.list
```

`tools/call` for `cards.list`:

```json
{"jsonrpc":"2.0","id":6,"result":{"content":[{"text":"[{\"ref\":\"crd_1\",\"label\":\"Debit\",\"pan\":\"•••• 4417\",\"status\":\"active\"}]","type":"text"}],"isError":false, ...}}
```

`isError` is `false`, `pan` is masked. **Confirmed: consent is read per
request, not cached at process startup.**

## Proof 7: revoking `cards` consent works without restarting the container

```bash
docker compose exec -T db psql -U postern -d postern -c \
  "UPDATE consents SET granted=false WHERE customer_ref='cust_7f3a' AND domain='cards';"
```

`UPDATE 1`. `tools/list`, same token, same running container:

```
accounts.get_balance
accounts.list
banking_start_session
```

`cards.list` is gone again. `tools/call` for `cards.list`:

```json
{"jsonrpc":"2.0","id":8,"result":{"content":[{"text":"Unknown tool: 'cards.list'","type":"text"}],"isError":true, ...}}
```

`docker inspect ... StartedAt` re-checked immediately after: still
`2026-09-16T07:28:53.268344256Z`, identical to the value captured before
Proof 6. **Confirmed: revocation takes effect on the next request, no
restart.**

**Open item this project has not built and this record does not close:**
a real MCP client honouring `cacheScope`/`ttlMs` (Proof 2: `"private"` /
`60000`) may legitimately keep showing `cards.list` in its own cached
catalogue for up to 60 seconds after this revocation, even though the
server itself already denies the call. This plan's own "what this plan
deliberately does not establish" table already names this
(`stateless_http=True` means no `notifications/tools/list_changed` path
exists in FastMCP 4.0.3); this record adds nothing new here beyond
confirming the server side is correct, live.

## The `MCP-Protocol-Version` header: not just a validation nicety

Checked directly rather than assumed, because CLAUDE.md's "Version traps"
names it as load-bearing. The installed `mcp` package
(`mcp/server/streamable_http_manager.py:192-198`) routes on it:

```python
pv = next((v.decode("latin-1") for k, v in scope["headers"] if k == header), None)
if pv is not None and pv not in HANDSHAKE_PROTOCOL_VERSIONS:
    await handle_modern_request(...)
    return
```

Sending the identical `tools/list` request with the header omitted still
returns `200` with the same three tool names, but the envelope is
`{"jsonrpc":"2.0","id":9,"result":{"tools":[...]}}` -- no `cacheScope`, no
`ttlMs`, no `resultType`. The request silently falls through to the
package's legacy stateless dispatcher instead of being rejected. Consent
enforcement itself (filtering and rejection) was unaffected by the header's
absence in both directions tested (an omitted-header `accounts.list` still
succeeded with the masked IBAN; not shown as a numbered proof above because
it duplicates Proof 4/6 except for the header, but it is in the audit log as
row 7 -- see the count below). Written up as `docs/decisions/
0005-protocol-version-header-gates-modern-dispatch.md` because it is a
dependency-version fact, not a claim about this repo's own code, and the
existing decision-record set already carries facts of that shape (e.g.
`0001-facade-http-client.md`).

## Audit row count versus tool calls made

Total `tools/call` requests made across this session: **7** (cards.list
denied x1 retried after a local `curl` flag mistake corrupted the saved
response but the request itself reached the server and is counted;
nonexistent.tool x1; accounts.list x1; cards.list denied clean x1;
cards.list allowed after grant x1; cards.list denied after revoke x1;
accounts.list without the `MCP-Protocol-Version` header x1).

```sql
SELECT count(*) FROM audit_log;
```

```
 7
```

**7 audit rows for 7 tool calls. No discrepancy found; nothing to chase.**
`tools/list` calls (four, across Proofs 2, 6, 7 and the header check) do not
produce audit rows, matching `AuditMiddleware`'s own scope (`on_call_tool`
only).

## What was not, and could not be, verified this way

- [ ] **Human step, not done.** Running `npx @modelcontextprotocol/inspector`
  against a browser UI was explicitly out of scope for this session (an
  agent cannot drive a browser UI); everything above was checked with
  `curl` and `psql` instead, the same substitution `docs/verification/
  2026-09-14-stack-run.md` used for Plan 1. If a human runs Inspector
  against this same consent/audit setup, record the outcome as a dated
  addendum here or a new file -- do not edit the "Confirmed" verdicts above
  to claim it happened.
- [ ] **Not measured.** Whether a real MCP client actually honours
  `cacheScope: "private"` / `ttlMs: 60000` and therefore shows a stale
  catalogue for up to 60 seconds after Proof 7's revocation. The plan
  records honouring `cacheScope` as a client opt-in to be treated as
  unhonoured until measured per vendor; this record does not change that.
- [ ] **Not exercised.** Audit redaction of a non-empty `arguments` payload
  against the real database (Proof 5's rows are all `{}` because none of
  the tools called here take arguments). `tests/test_asgi_app.py` covers
  this in-process; it was not re-proven against the compose Postgres here.

## Teardown

```bash
docker compose down
```

Result: all three containers and the compose network removed.
`docker compose ps -a` and `docker ps -a --filter name=p2-task7-verification`
both returned zero rows afterward. Confirmed no containers remain.

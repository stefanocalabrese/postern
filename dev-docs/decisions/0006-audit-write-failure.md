# 0006: What happens when the audit store is unavailable

**Date:** 2026-09-16

## Question

`services/api/middleware/audit.py`'s `AuditMiddleware.on_call_tool` writes one
audit row per tool call, on both the success path and the failure path, via
`_write`. Neither path had ever asked what should happen if `_write` itself
raises -- the audit store being unreachable, a connection pool exhausted, a
constraint violation. The behaviour that existed was an accident of control
flow, not a decision:

- **Success path.** The tool ran and returned. `_write` ran after it, unguarded.
  If it raised, the exception propagated out of `on_call_tool` unchanged. That
  is not a `FastMCPError`, so the wire handler above the middleware chain
  (`fastmcp`'s `mcp_operations._on_call_tool`) does not convert it into a
  `CallToolResult(is_error=True)`; it reaches the caller as a raw JSON-RPC
  `-32603` protocol error ("Internal server error"), even though the tool
  itself completed successfully. Confirmed directly against the real
  in-process `Client`, before any fix: `mcp.shared.exceptions.MCPError:
  Internal server error`.
- **Failure path.** The tool raised. The `except` branch called `_write` to
  record that failure. If `_write` itself then raised, the new exception
  propagated in its place -- Python's implicit `__context__` chaining meant
  the audit store's exception, not the tool's, was what left `on_call_tool`.
  Confirmed directly: `boom_tool`'s `ValueError` and a simulated audit-store
  failure both surfaced identically as `MCPError: Internal server error`. The
  caller could not tell "the tool failed" from "we couldn't even record that
  the tool failed" -- and in the second case, was never told what the tool
  itself did.

Neither shape was chosen. Both were what happens when nobody puts a `try`
around a database call.

## Two policies considered

**Audit-or-refuse (fail closed on both paths).** A tool call that cannot be
audited does not succeed, regardless of what the tool itself did. An audit
outage becomes a full outage of tool calls.

**Write-through-and-log.** The call succeeds or fails on its own merits; a
failed audit write is logged as an operational event, never fed back into the
result the caller sees. An audit outage degrades observability, not
availability.

## Decision

**Fail closed on both paths**, chosen over write-through-and-log.

The audit table is the artefact a regulator asks for after the fact, not a
convenience log. CLAUDE.md's own operating assumption for this project is
that the caller is under adversarial influence at all times, even when
correctly authenticated -- which is exactly the situation a missing audit row
creates: a call that moved through the system with no record a reviewer can
later stand behind. Write-through-and-log would mean this project's answer to
"can you show me every call this token made" is sometimes "no, and we cannot
tell you how often the answer was no" -- a silent gap in the one artefact this
system exists to keep complete. Fail closed makes that gap loud and bounded
(an outage window, visible in monitoring) instead of quiet and unbounded (an
unknown number of missing rows scattered through history).

This was already the accidental behaviour on the success path (see the
"Question" section above), which is worth stating plainly: this decision
keeps that outcome, but for a stated reason with a log line attached, not
because nobody wrote an except clause.

## What was actually broken, independent of which policy is chosen

The failure path's exception swap was a bug under *either* policy. Losing the
tool's own exception when the audit write also fails tells the caller
something false about why their call failed, regardless of whether the
overall call should ultimately succeed or fail. Fixed by catching the
audit-write exception explicitly and re-raising the ORIGINAL exception object
with the audit failure attached as its `__cause__`:

```python
try:
    await self._write(at, customer, name, arguments, "raised", type(exc).__name__, scope.exhausted)
except Exception as audit_exc:
    logger.error("audit write failed for tool %r after it raised %s: %s",
                 name, type(exc).__name__, audit_exc, exc_info=audit_exc)
    raise exc from audit_exc
raise
```

`raise exc from audit_exc` re-raises `exc` -- same type, same message, so
whatever `FastMCPError` handling applies above this middleware still applies
to it exactly as before -- and sets `audit_exc` as its explicit `__cause__`
rather than letting it become the primary exception through implicit
`__context__` chaining. A traceback now shows both, in the order they
happened, and neither hides the other. Verified directly: `boom_tool`'s own
`ToolError` ("Error calling tool 'boom_tool': internal detail") now reaches
the caller in a `CallToolResult(is_error=True, ...)` exactly as it would if
the audit write had succeeded; the simulated audit-store exception's message
does not appear anywhere in that result.

**Where each path's message containment actually lives.** On the failure
path, this middleware itself is what keeps the store exception's text off
the wire: `raise exc from audit_exc` substitutes the tool's own exception
before anything leaves `on_call_tool`, so containment there is this code's
property. The success path has no such substitution -- the raw store
exception genuinely escapes `on_call_tool` unchanged -- and what keeps its
text (a hostname, a DSN fragment, whatever the driver puts in the message)
off the wire is the MCP SDK runner one layer up, which turns an unhandled
exception that is not a `FastMCPError` into the generic `-32603 Internal
server error` rather than echoing `str(exc)`, and does so regardless of
`mask_error_details` (that setting only governs the `ToolError` wrapping
used for genuine tool failures, not this path). That holds for realistic
store exceptions today, but it is a property of the SDK's dispatcher, not
of this module, and it would stop holding the moment an audit-store failure
is ever wrapped in a `ToolError` instead of left as a plain exception, since
the SDK does echo a `ToolError`'s own message.

## What an operator sees when the audit store is down

Both paths log through `logging.getLogger("services.api.middleware.audit")`
at `ERROR`, with `exc_info` set to the audit-store exception, before
re-raising:

- Success path: `"audit write failed for tool %r after it returned
  successfully; failing the call because the audit row could not be
  written"`, followed by the audit-store exception's own traceback.
- Failure path: `"audit write failed for tool %r after it raised %s: %s"`
  (tool name, the tool's own exception type, and the audit-store exception),
  same traceback attachment.

Neither message is fed back to the MCP client; both are visible only in the
server's own logs, which is where an operator -- not the model, not the
end user -- is expected to be looking. This is a plain `logging` call, not a
metrics counter or an alert; whether that is enough to page someone depends
on how this deployment ships logs, which is outside this record's scope.

That claim rests on this module's logger being enabled in the hosting
process, and until `c1a1275` that assumption was fragile: `migrations/env.py`'s
`fileConfig` call ran with `disable_existing_loggers` at Alembic's template
default of `True`, which sets `.disabled` on every logger already created in
the process, for the rest of that process's life. Harmless when migrations
run in their own process; not harmless if `alembic upgrade head` ever ran
in-process at application startup, where it would have silenced every logger
the application created before that call -- including this one, and
specifically the ERROR line this section describes, which is the only signal
an operator gets that the audit store is down. The reasoning is worth keeping
even though the instance is fixed: a silenced logger does not overturn this
record's fail-closed decision, it removes the only signal that the decision
fired, which turns fail-closed into fail-silent. That is a property of
`disable_existing_loggers`, not of Alembic specifically, so anyone
configuring logging in a hosting process -- a second `fileConfig` call, a
`dictConfig` with the same default, a library that touches `logging.config.*`
on import -- can reproduce it against this logger or any other, regardless of
what this fix changed.

`c1a1275` fixed the instance: it passes `disable_existing_loggers=False` to
that call, so pre-existing loggers survive it. The guarantee now rests on a
test, not a fixed line. `tests/test_migrations_env_logging.py` runs the exact
guard-and-call block from `migrations/env.py` in a subprocess, because
`fileConfig` mutates process-wide logging state and an in-process test would
have to prove a total restore rather than risk a partial one leaking into
later tests; it extracts that block via `ast.get_source_segment` rather than
retyping it, so a future edit that drops the keyword breaks the test by
changing what it executes instead of leaving a hand-copied duplicate that
keeps passing regardless of what `env.py` actually does; and it asserts both
that a pre-existing logger survives the call and that
`logging.getLogger("alembic").level == 20`, which proves the ini actually
parsed rather than the `os.path.exists` guard silently taking its false
branch and skipping `fileConfig` altogether.

## What this costs

Fail-closed means a database outage takes down every tool call, including
read calls that touch no money and would otherwise have succeeded. That is
the explicit cost of this decision, not a side effect discovered later: while
the audit store is unreachable, `accounts.list` fails exactly as hard as
`payments.create_payment` does, even though only one of them moves money.
There is no tiering in this fix between reads and writes, and this record
does not invent one.

**Amendment, 2026-09-18: the outage above is no longer the only way to pay
this cost.** `61934d1` ("feat(store): bound every wait on the way to
Postgres") gave `Database.__init__` a `command_timeout_seconds`, defaulting
to `3.0`
(`packages/postern-core/src/postern_core/store/engine.py`). Before that
commit, "the audit store is unreachable" was the condition that triggered
this section. After it, unreachable is no longer required: a store that is
merely slow -- up, answering, reachable -- now fails the call too, at the
command timeout, because the consent lookup and the audit write both still
fail closed on whatever exception that timeout raises. A store that would
have answered in 4 seconds now fails the call at 3. A slow dependency is a
condition every deployment meets far more often than a full outage, so this
is a lower and much more reachable threshold than the one this section
originally described, and a reader who watches a call fail against a
database that is merely slow will reach for "bug" before "policy" unless
this section says otherwise.

Measured in `docs/verification/2026-09-17-query-stall-deadline.md`: a query
stalled behind a table lock -- a live, reachable store, not a down one --
now fails at 3.09s against production defaults. Read alone that number
looks like a regression; the same record measured why it is not. Before
`61934d1`, sixteen concurrent calls against a stalled store left fifteen of
them hanging with no deadline at all, and only the sixteenth ever produced
an answer, at 30 seconds, for the unrelated reason of a connection pool it
could not get a slot from. After `61934d1`, the same sixteen calls all
answer, in 3.45s. Turning fifteen indefinite hangs into fifteen bounded
failures, at the price of failing a call a slightly slower store would have
served, is this record's own fail-closed bargain carried through from the
down case to the slow case, not a new trade-off.

**The residual, with the bound corrected.** A path silent in both
directions -- a blackholing firewall rule, a security group closed under an
incident, a failed-over primary whose old address still accepts -- is not
bounded by any of the above. `command_timeout` fires on schedule, but
SQLAlchemy then invalidates the connection through asyncpg's graceful
close, which awaits asyncpg's own out-of-band cancel with no deadline of
its own -- and that includes the `pool_pre_ping` health check every pooled
checkout runs, which the fix's own reasoning treated as already covered and
is not. `docs/verification/2026-09-17-query-stall-deadline.md`'s
end-to-end reproduction, a real HTTP request against a socket silent in
both directions with `command_timeout=1.0`, had not returned on either path
at its 60-second cap. This record's original bargain -- a bounded outage
window instead of an unbounded one -- does not hold for this shape: the
call neither succeeds nor fails, it holds a pool connection open
indefinitely, and enough concurrent instances of it exhaust the pool the
same way the pre-`61934d1` case did.

## What was not built, and why

- **No retry.** A retry turns a hard outage into a slower hard outage unless
  it is bounded, and a bounded retry needs a chosen backoff, a chosen ceiling,
  and a decision about whether the tool itself re-runs or only the write does
  -- none of which anyone has specified. Nothing in this task asked for one.
- **No queue.** A queue changes the audit table's guarantee from "this row
  exists before the caller is told the call happened" to "this row will
  probably exist eventually," which is a materially weaker property for a
  regulator-facing log, and introduces its own failure mode (a full queue, a
  crashed consumer, a row that never drains) that would need its own design.
- **No fallback store.** Writing audit rows somewhere else during an outage
  splits the audit trail across two stores with two consistency models, and
  answers "show me every call this token made" with "check both places and
  reconcile," which is worse than the bounded outage this decision accepts.

**Recommendation, not built:** if an audit-store outage turning into a full
read-path outage proves unacceptable in practice, the right follow-up is
almost certainly a tiered policy -- fail closed for `payments.*` (or anything
that reaches a backend write endpoint) and write-through-and-log for
read-only domains -- rather than a retry or a queue. That is a genuine design
with its own trade-offs (a domain-by-domain policy table, a decision about
which domain a given tool belongs to, and a second code path to keep in sync
with the first), and nobody has asked for it yet.

## Amendment, 18 September 2026: two rows, and three ways this record went stale

This record is cited as the authority for an audit write that did not exist
when it was written. Three of its statements are now wrong or incomplete, and
the decision it records is unchanged and in fact stronger. The original
reasoning above is left exactly as it was.

### capo's ruling, which is the premise

**`audit_log` is a record of customer data the operator TOUCHED, not a record
of calls it served.** Ruled 18 September 2026. Everything below follows from
that and not from a new reading of this record.

### 1. "One audit row per tool call" is no longer the shape

The Question section above describes one row per call, written after the tool
returned or raised. That was accurate then. A tool call now writes up to two
rows, and `services/api/middleware/audit.py`'s module docstring is the
current description:

- `outcome='reaching'`, committed in its own transaction immediately before
  the first backend request of the call, from a callable the middleware
  pre-binds and `postern_core.facade.client.BackendClient` invokes.
- `outcome='returned'` or `'raised'`, after the call finishes. Unchanged.

They share a `call_id`. A call that reaches no backend -- one consent
refused, one that failed earlier, one whose tool touches nothing -- still
writes exactly one row, as before.

**Why the write moved.** `services/api/asgi/request_deadline.py` created a
request deadline, and `tests/test_request_deadline.py` measured what the
single-row shape cost under it: with the audit store on a path silent in both
directions, consent answered, the tool ran, the operator's backend served the
customer's accounts, the deadline cancelled the request, and `audit_log` held
zero rows. Under the ruling above that is a missing row, not a documented
limitation.

**What it buys, in this record's own terms.** Fail-closed used to mean an
audit outage could still leave data touched with nothing recorded, because
the touch happened before the write was attempted. It now means the backend
is never reached at all. The residual is an unpaired `reaching` row -- "we
touched this, no outcome was recorded" -- which is a true statement about a
call that happened rather than silence about one.

### 2. The operator now sees three failure paths, not two

"What an operator sees when the audit store is down" enumerates two ERROR
lines. There is a third, and it is the one that needed the most care because
the middleware never sees it: the entry write raises inside the tool body, so
if that call's completion write then SUCCEEDS, the operator would have been
left with an ordinary-looking `raised` row and no ERROR line anywhere.
`_PendingEntry.record` logs it through the same logger at ERROR with
`exc_info` set, before re-raising:

- Entry path: `"audit entry write failed for tool %r; the backend request it
  precedes will not be made"`.

The same caveat this section already records applies to it: the line is only
a signal if this module's logger is enabled in the hosting process.

### 3. The `-32603` containment claim is contradicted by measurement

"Where each path's message containment actually lives" says the MCP SDK
runner turns an unhandled non-`FastMCPError` into a generic `-32603 Internal
server error` rather than echoing `str(exc)`, and treats that as what keeps a
store exception's text off the wire on the success path.

Measured against the composed app in
`tests/test_asgi_app.py::test_a_tool_call_fails_closed_when_the_audit_
database_is_unreachable`, on this repository's pinned versions, that is not
what happens. With the audit store pointed at a refused address, the
JSON-RPC error carried `code: 0` and a message containing the raw connection
target `127.0.0.1`. It did NOT carry the DSN's credentials, since asyncpg's
`ConnectionRefusedError` names only the address it tried. So the disclosure
this record treats as prevented has been reaching the client all along, at
the level of an internal address rather than a secret.

The entry write changes the ENVELOPE of that same disclosure and not its
content. Because the exception is raised inside the tool body, FastMCP
returns it as `CallToolResult(is_error=True)` inside an HTTP 200, so the same
text arrives as a tool error rather than as a top-level JSON-RPC error. Both
shapes are pinned by that test.

**Not wrapped, and the first reason given for that was false.** An earlier
version of this paragraph argued that substituting a quiet exception of our
own would make `audit_log.detail` read `AuditWriteFailed` instead of naming
the actual failure. That benefit does not exist. `detail` records
`type(exc).__name__`, and FastMCP wraps anything a tool body raises in
`ToolError` before the middleware sees it
(`fastmcp/server/server.py:1555`), so an entry-write failure ALREADY records
`detail='ToolError'`, the same value an ordinary tool failure records, and a
wrapper of our own would be wrapped into `ToolError` in its turn. This table
cannot distinguish an entry-write outage from any other tool error through
that column, and no wrapping decision changes it. The ERROR line in the
section above is the compensation, and the only thing in the record that
separates the two.

What survives is the disclosure argument, narrower than it first looks.
Wrapping WOULD keep the address off the wire on the entry-write path, since
the quiet message is what FastMCP would embed instead. It would do nothing
on the completion write's SUCCESS path, where the raw store exception
escapes `on_call_tool` unchanged and reaches the client as a JSON-RPC error
carrying the same address.

The completion write's RAISED path leaks nothing to begin with, and an
earlier draft of this paragraph blurred that by writing "the completion-write
path" as though it were one thing: `raise exc from audit_exc` substitutes
the tool's own exception before anything leaves `on_call_tool`, which is the
distinction the "Where each path's message containment actually lives"
section above already draws. So the open surface is two of the three write
paths, not three, and wrapping the entry write would close one of those two.
The one left open is the completion write's success path, holding a
disclosure that predates this change entirely. Whoever decides an internal
address must not reach the client should fix it at the level of that
disclosure, for both open paths at once.

### What is NOT changed by any of this

The decision itself. Audit-or-refuse, on every path, for the reasons the
Decision section gives. The cost section's amendment of the same date still
holds and now has a wider reach: a store that is merely slow fails calls, and
with the entry write it fails them *before* the backend is reached rather
than after. That is this record's own bargain moved earlier in the call, not
a new trade-off.

---

## Amendment, 27 September 2026: the reserve is not the retry this record refused

`postern_core.store.audit`'s `append_with_reserve` makes a second attempt at an
audit write, and that is not the retry refused above. This record refused a
second attempt against the same unavailable store, on the ground that it
"turns a hard outage into a slower hard outage".

The reserve fires on `sqlalchemy.exc.TimeoutError` ONLY -- the pool saying its
connections are all checked out and none came back, which says nothing about
the database. A refused connect, a `command_timeout`, a schema error and a
plain bug all propagate untouched, precisely so that no failure already lost
pays a second `connect_timeout`.

Nothing about the rows changed: not their columns, not when they are written,
not that a failure to write one still fails the call. Only whether the write
can get a connection.

One new operator-visible signal: a WARNING from `postern_core.store.audit` when
a row is written on the reserve, which means this replica hit its pool ceiling
on a path that no longer fails because of it. That is the line to alert on to
learn a deployment is one connection short.

---

## Second amendment, 27 September 2026: the write path, and the question this record never asked

`services/confirm` has the reserve now. It is not the retry this record
refused, for the reason the first amendment gives: it fires on
`sqlalchemy.exc.TimeoutError` alone.

`ApprovalAudit._write_entry_row` is deliberately excluded from it, and that
exclusion is THIS RECORD'S OWN POLICY WORKING rather than an exception to it.
A row that cannot be written still stops the money: the entry row's refusal
reaches `BackendRequestHook`'s contract, the backend is never touched, and the
challenge stays `pending`. Record 0013's second amendment carries why routing
it to the reserve would be worse -- it would carry a request across the money
boundary on a connection that cannot carry it to the end.

AND THE NEIGHBOURING QUESTION, which this record accepts by implication and
never states: whether the RECORD survives when Postgres is unreachable, as
against whether the request fails. It does not, and record 0016 is where that
is argued and accepted rather than left for someone to discover and try to fix
with a spool.

---

## Amendment, 7 October 2026: the re-raise stays, and the log it produces is sanitised

Nothing in this record's decision changes. The approval callback still writes
its `raised` audit row and then re-raises the approval's own exception, and
`tests/test_audit_reserve.py` still pins the escaping class (`TimeoutError`,
`ConnectionRefusedError`). The request still fails with 500.

What changed is the line that escape produces. Measured through a real uvicorn
server, an uncaught SQL driver error was logged as `Exception in ASGI
application` with SQLAlchemy's `[SQL: ...]` and `[parameters: (...)]`, and with
the asyncpg message under it, which names the offending value (for a unique
violation, the `Key (a, b)=(x, y)` detail). `hide_parameters=True` on both
`Database` engines removes the `[parameters: ...]` line and does not touch the
driver's own message, which `tests/test_sql_safe_logging.py` measures: a value
cast to an integer is named in asyncpg's message with parameters hidden.

So `postern_core.log_safety.SqlSafeExceptionFilter` rewrites the rendering of
any record on `uvicorn.error` or `uvicorn` whose exception chain holds a
SQLAlchemy `StatementError` or an asyncpg exception: traceback frames, one line
per exception with its type and SQLSTATE, and a literal saying the message, SQL
and parameters were withheld. `tests/test_sql_safe_logging_uvicorn.py` drives it
through a real uvicorn server, the confirm approval callback and an api route,
with the filter off (the sentinel is in the log) and on (it is nowhere).

WHERE IT IS INSTALLED, stated for the shipped image. `create_confirm_app` and
`create_app` both call `install_sql_safe_logging()`. The Dockerfile's `CMD` for
the `api` and `confirm` targets is `uvicorn services.<name>.main:app` with no
`--log-config`. uvicorn applies its logging config in `Config.__init__` and
imports the application afterwards, in `Config.load()`, so on the shipped
command the filter is installed after uvicorn's config and is not removed by it.
An operator who replaces uvicorn's logging after the app exists (a `dictConfig`
run from their own wrapper module, after importing the app) can drop it and must
call `install_sql_safe_logging()` again after that. An operator who serves the
app under a different server (a gunicorn worker class with its own loggers) is
not covered, because the filter attaches to uvicorn's two loggers only.

What an operator loses: the driver's message text in the application log. The
SQLSTATE and the time identify the statement in Postgres' own log.

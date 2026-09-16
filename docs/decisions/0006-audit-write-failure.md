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

That claim assumes this module's logger is still enabled in the hosting
process, and that assumption is not free: `migrations/env.py:33` calls
`fileConfig(config.config_file_name)` with `disable_existing_loggers` at
Alembic's template default of `True`, which silences any logger created
before that call and not listed in `alembic.ini` -- including this one --
for the rest of that process. It is harmless today because migrations run
as their own process, but if migrations are ever run in-process at startup
of whatever hosts this middleware, the log line this section describes goes
silent with nothing else changing. That is `migrations/env.py`'s hazard to
fix, not this module's; it has been reported to the session that owns it
and is not addressed here.

## What this costs

Fail-closed means a database outage takes down every tool call, including
read calls that touch no money and would otherwise have succeeded. That is
the explicit cost of this decision, not a side effect discovered later: while
the audit store is unreachable, `accounts.list` fails exactly as hard as
`payments.create_payment` does, even though only one of them moves money.
There is no tiering in this fix between reads and writes, and this record
does not invent one.

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

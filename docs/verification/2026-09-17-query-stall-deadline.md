# 2026-09-17: how long a request hangs when a query stalls, before and after `61934d1`

## The question

`tests/test_consent_check_failure_mode.py` (commit `c7b884f`) measured what a
consent check does when the store is UNREACHABLE: a refused connection raises
`ConnectionRefusedError` in ~0.0s, a blackholed connect raises `TimeoutError`
after 60 seconds (asyncpg's own `connect(timeout=60)` default), and both fail
closed. It named 60s "the ONLY deadline anywhere on this path" and said, in so
many words, that it had **not** measured the other shape: a store that
completes the handshake and then stalls during query execution. It reasoned
that with `command_timeout` unset there might be no deadline at all there, and
marked that as reasoned rather than measured.

This record measures it. It ended up measuring it twice, because
`61934d1 feat(store): bound every wait on the way to Postgres` landed on
`main` while the reproduction was being built. Both halves are here, which is
worth more than either: the "before" says the gap was real, and the "after"
says what the fix does and does not close.

**Short answer.** Before: no deadline existed at all, and a stalled query
hung a request until something outside the process gave up. After: a store
that is still REACHABLE is bounded at `command_timeout` (measured 3.09s at
the 3.0s default). A path that is SILENT IN BOTH DIRECTIONS is still
unbounded end to end: measured **not returned at a 60-second cap**, on two
separate paths, with `command_timeout` set to 1.0s.

## Method, and how faithful it is

Everything below runs the real ASGI stack: `_app` from
`tests/test_consent_check_failure_mode.py` (which is `create_app`'s assembly),
a real `JWTVerifier` with a real signed token, the three mandatory MCP headers
including `MCP-Protocol-Version`, a production-shaped `Database`, and a real
Postgres 17 container from `tests/conftest.py::pg_url`. The backend is an
`httpx2.MockTransport` that records every path it is asked for -- a denial and
a success are both HTTP 200, so "did the backend get called" is the only
signal that says whether customer data moved.

Two reproductions, because neither covers the shape alone, and after
`61934d1` they no longer give the same answer -- which is the whole finding.

**(A) A locked table: a REACHABLE stall, real Postgres, no interposer.** A
second session holds `LOCK TABLE consents IN ACCESS EXCLUSIVE MODE`; the
consent check's own SELECT crosses a healthy connection, reaches the server,
and waits. The most faithful thing available short of breaking a database on
purpose: the connection is genuine, the query is genuine, the wait is
server-side. Its one infidelity is that this server *would* answer if the lock
were released -- and that turns out to be the property that matters, because a
server that can answer also answers asyncpg's cancel request.

**(B) A silent path: a TCP interposer between the pool and Postgres.** A plain
byte pump in both directions, so startup, authentication, parameter status,
type introspection and the pre-ping all cross it normally; then it forwards a
chosen client packet upstream and holds the answer. This is the path that
never delivers: a blackholing firewall, a dropped route, a primary that failed
over mid-query. A lock cannot express it.

A fake that stalls before the handshake was deliberately not built: that is
the blackhole case `c7b884f` already answered with 60 seconds.

Environment: Python 3.12.13, sqlalchemy 2.0.52, asyncpg 0.31.0, fastmcp 4.0.3,
`postgres:17-alpine` (the image `docker-compose.yml` uses), macOS arm64.
`docker-compose.yml` was read, not edited.

## BEFORE (`c7b884f`): no deadline existed

**A locked table, capped at 120 seconds.**

```
[M1 lock-stall] elapsed=120.00s payload=None backend=[]
```

Cap hit. No response, no status code, nothing on the wire, backend never
called. The same call answers in 0.10s when the query is answered.

**A silent path, capped at 120 seconds.** The interposer forwarded the consent
SELECT upstream and held the reply.

```
[M2 proxy mid-query] elapsed=120.00s payload=None backend=[] triggered=True dropped=59B conns=2
```

Cap hit. The 59 bytes are Postgres's actual answer, executed and never
delivered.

**`pool_pre_ping` was not a rescue.** One warm call, then the path goes silent,
then a second call on the same pooled connection:

```
[M3 warm call]     elapsed=0.10s isError=False backend=['/accounts'] conns=1 pool_checkedin=1
[M3 after silence] returned=False elapsed=45.00s backend=['/accounts'] dropped=17B conns=1
```

45-second cap hit. The 17 bytes are the reply to the ping itself (SQLAlchemy's
asyncpg dialect pings with `;`). `conns=1`: the pool never reached the point of
opening a replacement. A liveness check with no timeout cannot report a
liveness failure.

**The stall could also land AFTER the backend was called.** Consent healthy,
`audit_log` locked instead -- the shape a migration taking `ACCESS EXCLUSIVE`
during a deploy produces:

```
[M5 audit-locked] elapsed=60.00s payload=None backend=['/accounts']
```

The tool ran, the operator's backend served the customer's accounts, the
response was computed, and the request then hung in `AuditMiddleware`'s write
holding an answer it never delivered.

**Nothing bounded any of it**, read from the running system rather than from
the source:

```
asyncpg ConnectionConfiguration(command_timeout=None, statement_cache_size=100, ...)
client socket SO_KEEPALIVE = 0
statement_timeout = '0'   lock_timeout = '0'   idle_in_transaction_session_timeout = '0'
[M7 pool] class=AsyncAdaptedQueuePool size=5 max_overflow=10 timeout=30.0 pre_ping=True recycle=-1
```

`uvicorn.Config` defaults (`timeout_keep_alive=5`, `timeout_notify=30`,
`timeout_graceful_shutdown=None`) are not request deadlines, the `Dockerfile`
CMDs pass no timeout flags, and `docker-compose.yml`'s `timeout: 3s` belongs to
the `db` healthcheck. The only bounded wait in the system was SQLAlchemy's
default `QueuePool` checkout timeout of 30 seconds, which bounds the wait for a
CONNECTION and never the wait for an ANSWER.

**Concurrency: 16 calls against a stalled store.**

```
[M4 req 00..14] STILL HANGING at 45.0s
[M4 req 15]     elapsed=30.07s -> {"isError": true, "content": [{"text": "Unknown tool: 'accounts.list'"}]}
```

Fifteen -- `pool_size` 5 plus `max_overflow` 10 -- hung with no deadline. The
sixteenth waited 30.07s for a slot it was never going to get. In production's
shape, where `create_app` gives consent and audit ONE `Database` and therefore
one pool, the same run answered at **60.06s** (30s for a consent connection,
then 30s for an audit connection) and lost the audit row:

```
ERROR services.api.middleware.audit: audit write failed for tool 'accounts.list' after it
  raised NotFoundError: QueuePool limit of size 5 overflow 10 reached, connection timed out,
  timeout 30.00
```

## AFTER (`61934d1`): the reachable case is bounded

`Database.__init__` now takes `connect_timeout_seconds=2.0`,
`command_timeout_seconds=3.0` and `pool_timeout_seconds=1.0`, passed as
asyncpg `connect_args` plus SQLAlchemy's `pool_timeout`, wired through
`Settings` and `create_app`.

**A locked table, production defaults, cap 30s:**

```
[A1 lock, prod defaults] elapsed=3.09s isError=True text=Unknown tool: 'accounts.list' backend=[]
```

**The same with `command_timeout_seconds=1.0`:**

```
[A2 lock, command=1.0]   elapsed=1.06s isError=True text=Unknown tool: 'accounts.list' backend=[]
```

3.09s and 1.06s against 120 seconds and counting. The deadline is real,
reachable through the constructor, and lands where it says it does.

**Sixteen concurrent calls, production defaults, cap 60s:**

```
[D] 16/16 answered in 3.45s
[D req 00..15] isError=True text=Unknown tool: 'accounts.list'
[D] backend=[]
```

Every one of them answered, in three and a half seconds. Before the fix,
fifteen of those sixteen never answered at all. That is the difference between
a slow dependency and a service-wide outage, and it is the fix's main
achievement.

## AFTER: what is still unbounded, and exactly where

`61934d1`'s constructor docstring names this case and measures it at 20
seconds through `AsyncSession.execute`. Measured here END TO END through a
real HTTP request, with `command_timeout=1.0` and a 60-second cap:

```
[B silent mid-query, command=1.0]  elapsed=60.00s None backend=[] held=53B conns=2
[C warm]                           returned=True backend=['/accounts']
[C pre-ping, command=1.0]          elapsed=60.00s None backend=['/accounts'] conns=2
```

**Neither returned.** Not at 60 times the command timeout. Two findings in
that block, and the second is the one worth flagging:

1. **The query path.** `command_timeout` fires at 1.0s as advertised, then
   SQLAlchemy invalidates the connection through asyncpg's graceful `close()`,
   whose first act is `await self.cancel_sent_waiter` with no deadline on that
   await (`asyncpg/protocol/protocol.pyx:602-613`). That waiter resolves only
   when a second connection, opened to the same silent address to carry
   Postgres's out-of-band cancel, finishes
   (`asyncpg/connect_utils.py:1255-1281`, `loop.create_connection` with no
   timeout). `conns=2` at the interposer is that second connection arriving.
2. **The `pool_pre_ping` path, which the fix's own reasoning treats as
   covered.** That docstring works out a 13.0s worst case for a recycled
   connection on the basis that BEGIN, the ping and ROLLBACK each inherit
   `command_timeout`. Each statement does; the invalidation that follows the
   first one to expire does not, so on a silent path the health check hangs
   exactly like the query. A fix that closed the query path and left this one
   would look complete from the outside, and this is the measurement that says
   it is not.

The committed test proves the mechanism rather than just the wait: after the
probe it lifts the silence, and the request comes back **denied** rather than
served. Before `61934d1` that same step returned `isError: false` with a real
backend call, because the query was merely late. Now the deadline has already
fired, so what is delivered is the refusal it produced -- which means the
request was not waiting on the query during the probe. It was waiting on the
close that follows the timeout.

## What the caller gets

Bounded cases: HTTP 200, `isError: true`, `Unknown tool: 'accounts.list'`,
after `command_timeout` (3.0s by default) or `pool_timeout` (1.0s). Unbounded
case: nothing, indefinitely, with the connection held open.

The text is a false statement in every one of them. The tool exists and the
customer consented to it; the `TimeoutError` reaches FastMCP's
`_evaluate_check`, which catches every `Exception` and denies, and the answer
is byte-identical to a mistyped tool name. `tests/test_audit_refusal_reason.py`
already treats that collision as worth solving for consent denials.
`61934d1` bounded the wait and did not touch this, which is the correct scope
for it; it is noted here because a bounded wrong answer is still a wrong
answer handed to a model that will act on it.

## Severity: an assessment, not a decision

**Before `61934d1`: HIGH** on availability. Fifteen in-flight requests were
enough to turn any store hiccup into an outage that could not self-heal, with
no error and no log line for the first 30 seconds.

**After `61934d1`: MEDIUM, and narrowed to one shape.** CWE-1088 (synchronous
access of a remote resource without a timeout), residual.

- **Scope.** Only a path silent in both directions that also swallows a fresh
  connection. A store that answers, resets, refuses or drops the connection is
  bounded by the new numbers. Reachable-but-slow -- the common outage -- is
  fixed.
- **But that shape is not exotic.** A blackholing firewall rule, a security
  group closed under an incident, a failed-over primary whose old address
  still accepts, and a partitioned link all produce it. It is the same shape
  `tests/test_consent_check_failure_mode.py` already built a blackhole
  listener for, on the connect path, where it IS bounded.
- **Blast radius, reasoned and not measured.** A wedged request holds its pool
  connection, so 15 of them exhaust the pool; after that, new requests fail at
  `pool_timeout=1.0s` rather than hanging. Fail-fast for the many, hung
  forever for the fifteen, and no recovery without a restart. **This specific
  combination was not measured** -- see below.
- **It is invisible.** No error, no 5xx, no log line, for as long as it lasts.

## What this record does NOT establish

- **A genuinely wedged Postgres was not used.** Both reproductions imitate one
  from the client's side, which is the side that decides how long a request
  hangs. A server wedged for an internal reason (disk, OOM, a stuck
  checkpoint) was not measured.
- **Concurrency against a SILENT path was not measured**, only against a
  reachable stall. The 15-connections-then-fail-fast sentence above is
  reasoned from the pool arithmetic and the single-request measurement, not
  observed.
- **Whether the silent-path request EVER returns** was not determined, only
  that it had not at 60 seconds. Nor was the kernel-level backstop measured:
  the client socket has `SO_KEEPALIVE=0`, so there is no client-side probe at
  all, and the OS retransmission behaviour for a connection that is waiting
  rather than sending was not exercised.
- **uvicorn was not exercised.** Every measurement went through
  `httpx2.ASGITransport`, not a real socket. uvicorn's timeout defaults were
  read from `uvicorn.Config`, not observed under a stall.
- **Nothing outside the process was measured.** Istio, an ingress gateway, or
  an AI client's own HTTP timeout may cut a hanging request long before 60
  seconds; none is configured in this repository. What POSTERN does is what is
  measured here.
- **`migrations/env.py` was not measured.** `61934d1`'s message notes it builds
  its own engine with `async_engine_from_config` and constructs no `Database`,
  so it inherits none of these deadlines. Read, not tested.

## If anyone wants the residual case closed

Not a recommendation to act on today, and not this record's decision. The
mechanism is asyncpg's graceful close awaiting an undeadlined waiter, so the
candidates are: wrap the session call in `asyncio.timeout` (bounds the caller,
and per the cancellation measurement may leave the connection checked out);
terminate rather than close on invalidation, if SQLAlchemy exposes the choice;
or accept it and put the deadline at the ASGI edge, which is the only place
that bounds a request regardless of which dependency stalled, and which owes
an HTTP status and therefore belongs in ASGI middleware for the reason
`docs/decisions/0002-header-validation.md` records.

## The committed test

`tests/test_store_query_stall_deadline.py` carries this harness with probes of
three times the configured command timeout rather than two-minute caps. Each
bounded case asserts a LOWER as well as an upper bound, because "it raised"
also passes against a sixty-second wait; each unbounded case lifts the stall
afterwards and asserts the same request completes, so a short probe is not a
statement about a slow machine.

Cost, measured back to back on this tree by moving the file out of `tests/`
and running the gate again: `make ci` 29.6s without it (831 passed), 34.8s
with it (836 passed); the `test` step 28.4s -> 33.6s. **+5.2 seconds, +17%,
zero skips.** Run on its own the file takes 6.8s, but most of that is the
Postgres container and fixtures the rest of the suite already pays for, which
is why the delta is the honest number and the standalone figure is not.

Nearly all of that cost is the two unbounded cases: each waits 3x the
configured `command_timeout` (0.4s) before it is entitled to call the request
hung, and that ratio is what makes the probe evidence rather than a stopwatch.
Shortening it weakens the claim; it can be shortened if the gate's total
matters more than the margin, and it is one constant (`COMMAND`) to change.

# 0013: How many database connections a replica may hold

**Date:** 2026-09-26

## Question

`Database.__init__` passed `pool_timeout` and neither `pool_size` nor
`max_overflow`, so both services ran on SQLAlchemy's defaults of 5 and 10: at
most 15 connections per replica, a number nobody in this repository had
chosen and no environment variable could change.

`services/confirm/callback.py` had already recorded the consequence and
deferred the decision, in a comment that also made a stronger claim:

> TWO POOLED CONNECTIONS PER APPROVAL, WHERE THERE USED TO BE ONE... Both
> audit rows open their own session from `db.sessionmaker()` while `_approve`
> below still holds the session that claimed the challenge... This change
> makes that unchosen ceiling bind at half the concurrency it used to.

If that were true it would be the more serious half. A request that holds one
connection and then waits for a second deadlocks a pool at `pool_size +
max_overflow` concurrent requests, with every waiter blocking every other, and
no size removes it: it only moves the concurrency at which it bites. So the
first question is whether the checkouts overlap, and only the second is what
the numbers should be.

## The overlap is not there, and one statement is why

An `AsyncSession` returns its connection to the pool at COMMIT, not at close.
Measured against postgres:17-alpine 17.11 on 2026-09-26, on an engine at
`pool_size=1, max_overflow=0, pool_timeout=1.0`:

| The session has | `pool.checkedout()` | A second session |
|---|---|---|
| run `SELECT 1`, not committed | 1 | `sqlalchemy.exc.TimeoutError` after 1.0s |
| run `SELECT 1` and committed | 0 | served |

`_approve` commits the `pending -> approved` claim before `BackendWriteClient`
exists. The entry audit row is written from the hook that client invokes, which
is after that commit, so it opens its session against a pool this request has
already let go of. The completion row is written by `approve_challenge`, after
`_approve`'s `async with db.sessionmaker()` block has exited, including on
every refusal path where the lookup transaction was never committed at all.

What an approval actually costs is four checkouts in sequence, holding one at a
time:

1. the transaction that reads the challenge, checks ownership and claims it;
2. the entry audit row (`outcome='reaching'`), its own session and commit;
3. the `approved -> executed` transition, on the handler's session again;
4. the completion audit row.

A refusal before the backend costs two: the lookup, then the completion row. A
`tools/call` on the read path costs two to seven the same way, one at a time:
one to five consent lookups, since `services/api/consent.py` caches a
successful answer and never caches a raising one, plus the two audit rows.

So the pool bounds concurrent REQUESTS, not connections per request, and the
comment's "at half the concurrency" was wrong in kind rather than in degree.
Measured through the real handler at `pool_size=1, max_overflow=0` -- a pool
that physically cannot serve two checkouts at once -- a full approval returns
200 with a peak concurrency of one. `tests/test_pool_sizing.py` is that
measurement, kept as a regression test.

### What would create the overlap

Three refactors, of which the first is likely because it reads like an
improvement:

- moving `session.commit()` below the backend write, so the claim is durable
  only once the money has moved;
- writing an audit row on the handler's own session (which
  `dev-docs/decisions/0006-audit-write-failure.md` already forbids, for the
  independent reason that a rolled-back audit row is not an audit row);
- wrapping the handler body in `async with db.sessionmaker.begin()`, which
  holds the transaction open for the whole block.

Any of them turns a pool of N into a deadlock at N concurrent approvals. The
guard is a test that drives a whole approval through a pool of one.

## What `pool_timeout = 1.0` turns exhaustion into

A refusal, not a hang, and the distinction is worth stating precisely because
"degraded into refusals" is close to but not the same as "the property holds".

When the pool is full, a checkout waits `pool_timeout` and then raises
`sqlalchemy.exc.TimeoutError("QueuePool limit of size N overflow M reached,
connection timed out, timeout 1.00")`. That is a bounded, per-request failure:
the connections in use are unaffected, requests already inside the pool finish
normally, and the pool drains as they do. Nothing is held while waiting, so
there is no deadlock available even if a future change introduced the overlap
above at a pool larger than one -- what it would produce is every concurrent
request failing at `pool_timeout` instead of any of them completing.

The cost is paid more than once per request. On the write path the handler's
lookup waits `pool_timeout` and raises, and then the completion audit row that
records the failure waits `pool_timeout` again before failing closed, so a
saturated replica sheds at roughly twice the configured value, not once. At the
default that is about 2 seconds to be told no. `tests/test_pool_sizing.py`
measures both waits at `pool_timeout = 0.25`.

What the customer sees, per service:

- **`services/api`**: the consent lookup denies (`services/api/consent.py`
  denies when its lookup raises) or the audit write fails the call
  (decision 0006). Either way the tool call fails rather than returning
  partial data, and the agent sees a tool error.
- **`services/confirm`**: the approval raises out of the handler, which is a
  500. The challenge is untouched and still `pending`, so the phone can retry
  once the pressure clears. If instead the pool empties at the completion row
  AFTER the backend accepted the write, the customer gets a 500 for a payment
  that went through, and the `Idempotency-Key` plus the conditional
  `approved -> executed` transition are what make the retry safe. That
  asymmetry is the reason this service's headroom matters more than its raw
  number.

## The options, and why sizing was the answer

**A separate engine or pool for audit writes** (considered, rejected). It
removes an overlap that does not exist, and it pays for that with a second
pool per service against the one resource that is actually scarce. Two pools
of 5 + 5 hold more connections than one pool of 5 + 10 does at the same
request concurrency, because each pool keeps its own `pool_size` open whether
or not the other is busy. It would also split the fail-closed audit path onto
a pool whose saturation is independent of the handler's, which makes "the
store is full" produce two different symptoms depending on which pool ran out.

**Restructuring so the checkouts are not nested** (already true, so pinned
rather than built). The comment's constraint is real -- an audit row must not
share the approval's transaction, and the entry row must be durable before the
backend is reached -- but "separate transaction" and "concurrently held
connection" are different requirements, and the code already satisfies the
first without paying the second. What was missing was a test saying so.

**Sizing the pool** (taken). The defect that remains after the overlap
question is answered is real and is three things: the ceiling was a library
default, it was not configurable, and the constraint it has to satisfy was
written down nowhere.

## The arithmetic

Every replica of every service holds up to `pool_size + max_overflow`
connections. They all count against one server-wide limit:

```
  api_replicas     x (POSTERN_DATABASE_POOL_SIZE + POSTERN_DATABASE_MAX_OVERFLOW)
+ confirm_replicas x (POSTERN_CONFIRM_DATABASE_POOL_SIZE + POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW)
+ everything else
<= max_connections - superuser_reserved_connections
```

Measured on an unmodified postgres:17-alpine (17.11) on 2026-09-26:
`max_connections` is 100 and `superuser_reserved_connections` is 3. A managed
instance sets its own, usually derived from instance memory; read it with
`SHOW max_connections` against the instance you are actually going to deploy
against, not from a docs page about an instance class.

**Everything else** is not zero and is easy to forget: `alembic upgrade` during
deploys, the separate migration/owner role if you have split the roles (which
you should -- the `audit_log` append-only control is two statements from off
without it), psql sessions, monitoring agents, backup tooling, and any
read-replica or logical-replication slot that consumes a connection.

Exceeding the limit does not degrade, it refuses at connect:
`asyncpg.exceptions.TooManyConnectionsError: sorry, too many clients already`,
measured at attempt 101 against the default 100.

### The defaults, and where they came from

| | `pool_size` | `max_overflow` | ceiling per replica |
|---|---|---|---|
| `services/api` | 5 | 10 | 15 |
| `services/confirm` | 5 | 5 | 10 |

`services/api` keeps 5 + 10 because that is what it has been running. Moving it
would have made this a capacity change as well as a configurability change, and
those are two things worth finding out about separately when a deployment
starts refusing.

`services/confirm` asks for less for three reasons. Its rate is set by people
tapping approve on a phone after a push notification, where the read path's is
set by an LLM's tool-call fan-out, which nobody here controls. None of its four
checkouts spans the backend write, so a slow payments service cannot drain the
pool (measured: zero connections checked out at the instant the backend request
is made). And both services draw on one `max_connections`, so five connections
this service does not reserve are five an API replica can have.

### A worked example, to be replaced with your own

Four `services/api` replicas and two `services/confirm` replicas, against the
Postgres default:

```
4 x 15 = 60
2 x 10 = 20
       = 80 application connections
    +  3 superuser reserved
       = 83 of 100, leaving 17 for migrations, psql and monitoring
```

That fits. Six API replicas and three confirm replicas would be 120 and does
not: at that shape you raise `max_connections`, lower these ceilings, or put a
transaction-mode connection pooler in front. `tests/test_pool_sizing.py`
carries the example above as an executable assertion, so raising a default
without redoing the arithmetic fails the build.

### When to raise them

Raise the ceiling when the symptom is a `sqlalchemy.exc.TimeoutError` naming
`QueuePool` in the logs while the database itself is healthy -- that is
saturation of this limit and nothing else. Do not raise it to paper over slow
statements: a store whose p99 has moved from milliseconds into the
`POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS` budget will empty any pool, and the
connections are a symptom there rather than the cause.

`max_overflow` is the cheaper half to raise. Overflow connections are opened on
demand and closed on return rather than kept, so they cost a connect (TCP, TLS,
authentication, bounded by `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` at 2.0s)
per use and hold nothing between bursts. `pool_size` is the half that decides
how much of the ceiling is standing cost against the server's limit.

## What is not established

- **No load test.** Every number here is budgeted against a connection limit,
  not against a measured request rate. Nothing in this repository knows how
  many tool calls per second a deployment will see, and no default here should
  be read as a throughput claim.
- **The replica count.** There is no Terraform in this repository, so nothing
  here can check the arithmetic against a real cluster. It is an operator
  duty, alongside the others.
- **Connection poolers.** Putting PgBouncer or RDS Proxy in front changes the
  arithmetic, because the services' pools then connect to the pooler rather
  than to Postgres. Neither was evaluated here and no claim about either is
  made.

---

## Amendment, 27 September 2026: the rejected option, narrowed

The options section rejected **a separate engine or pool for audit writes** on
two grounds. Both stand as written, and both are properties of a pool that
SERVES TRAFFIC. A reserve reached by fallback is neither, and is what shipped
today.

`Database` takes `audit_reserve_size` (read path default 1, floored at 1 in
`from_env`, `Database`'s own default 0) and builds a second engine of that many
connections with `max_overflow=0` fixed in code. `postern_core.store.audit`'s
`append_with_reserve` is its only reader and reaches it from one branch,
`except sqlalchemy.exc.TimeoutError`. The audit write uses the application pool
first, every time.

THE ARITHMETIC GROUND. "Each keeps its own `pool_size` open whether or not the
other is busy" is true of two busy pools and false of a pool nothing has asked.
`QueuePool` opens on demand: measured against `postgres:17-alpine`,
`checkedin()` is 0 before first use and 1 after. A reserve asked only after a
refused checkout costs a ceiling, not a connection.

THE SYMPTOM GROUND. "Two different symptoms depending on which pool ran out"
requires two independently reachable pools. Under a fallback the reserve is
unreachable until the application pool has raised, so an exhausted reserve is
always the second half of a pair and arrives as that exception's `__cause__` --
one traceback, both halves. With both full, the operator sees exactly what they
saw before.

Also priced rather than assumed: SQLAlchemy 2.0.52 cannot express reserved
capacity inside one pool. `QueuePool.__init__` takes `creator, pool_size,
max_overflow, timeout, use_lifo` and nothing else, and a search of
`sqlalchemy/pool/` for reservation or priority returns nothing. The only
in-one-pool approximation is an application-side semaphore in front of every
non-audit checkout, which reserves a slot rather than a connection and leaks
the moment a checkout path forgets to pass through it.

THE NUMBERS MOVE. `services/api` is 5 + 10 + 1 = 16 per replica.
`services/confirm` is unchanged at 10 and has NO reserve, so a saturated
write-path replica still loses its approval rows. The worked example becomes
4 x 16 + 2 x 10 = 84, plus 3 reserved = 87 of 100, leaving 13. Six and three is
126 and still does not fit. `api_ceiling()` in `tests/test_pool_sizing.py`
includes the reserve, so raising the default has to face the arithmetic.

WHAT IT BUYS, MEASURED. With every connection of a `pool_size=1,
max_overflow=0` pool held against a live Postgres, a real `tools/call` through
`create_app` is denied and writes zero rows at `audit_reserve_size=0` and
exactly one row at 1, while still failing closed. `start_session`, which no
consent check gates, writes both its rows and reaches the backend.

WHAT IT DOES NOT BUY: nothing against a store that is down. A second pool to an
unreachable Postgres is a second way to fail to connect. The shape this closes
is saturation of the ceiling against a store that is answering -- which is the
common shape, and the only one a connection could have been reserved for.

`services/confirm` is owed the same and does not have it. Same fail-closed
policy, same one-`Database` shape, no reserve. Scoped out deliberately.

---

## Second amendment, 27 September 2026: the write path, and the one row that stays on the pool

`services/confirm` took the same reserve one commit after `services/api`, with
one exclusion that is the design rather than an omission.

WHICH ROWS. `ConfirmSettings.database_audit_reserve_size` (default 1, floored
at 1, `POSTERN_CONFIRM_DATABASE_AUDIT_RESERVE_SIZE`, its own prefix so one env
file cannot move both services at once) serves `ApprovalAudit._completion` and
`PairingAudit._write`. It does NOT serve `ApprovalAudit._write_entry_row`,
which is now the only audit write in the repository that stays on the
application pool.

WHY. `services/confirm/callback.py` claims the challenge and commits, writes
the entry row, reaches the backend, then runs `approved -> executed` on its own
session -- a fresh checkout on the application pool, and not an audit write, so
no reserve may cover it without becoming a second pool. Routing the entry row
to the reserve would carry a request ACROSS THE MONEY BOUNDARY on a connection
that cannot carry it to the end: the backend accepts the write, the transition
is refused by the very pool the reserve was standing in for, and the challenge
is stranded in `approved` with the money gone. Routinely, because saturation
persists across those milliseconds.

Keeping the pool's refusal stops the request before money moves, which is what
`BackendRequestHook`'s contract is for, and the refusal is then recorded by
`_completion` on the reserve. It also means NO LATENCY IS ADDED ANYWHERE BEFORE
MONEY MOVES -- not a bounded addition, none, by construction.

The read path is not inconsistent: `services/api` has no application-pool
checkout after its touch, so covering its entry row carries the request to
completion.

WHERE THE RESERVE IS WORTH MOST HERE is the worst case rather than the common
one: the row recording that the backend ACCEPTED the write and the `executed`
transition was then refused by the same exhausted pool. That is the
money-moved-and-unrecorded state this record already names as the reason this
service keeps headroom.

ONE RESERVED CONNECTION SERVES TWO SEQUENTIAL WRITES, because an
`AsyncSession` returns its connection at COMMIT -- the same fact this record
rests its four-checkouts-one-at-a-time finding on. What bounds the reserve is
concurrent writes, not writes.

`PairingAudit` volume: one row per recorded `POST /approve`, one per
`POST /token`, none per poll, so two per completed pairing. At `/token` the row
is fail-closed on a mint, so a saturated replica previously issued no
credential and recorded nothing about refusing. At `/approve` a failed row
triggers `_withdraw_pairing`, so a customer who had already compared their
pairing code lost it and needed a fresh QR. Neither happens now.

THE NUMBERS. `services/confirm` is 5 + 5 + 1 = 11. `4 x 16 + 2 x 11 = 86`,
plus 3 reserved = 89 of 100, leaving 11. What fits at the Postgres default:
3+2, 3+3, 4+2 and 5+1. What does not: 4+3 (97), 5+2 (102), 6+3 (129). This
shape is one replica of either service away from not fitting -- and it was
before the reserves too, at 17 spare. The lever is `max_connections` or
`pool_size`, not the one connection that records the refusal.

Guarded by an existing test rather than only a new one: routing the entry row
through the reserve fails
`tests/test_pool_sizing.py::TestAnApprovalNeverHoldsTwoPooledConnectionsAtOnce::test_a_successful_approval_completes_through_a_pool_of_one`,
because the approval's four application-pool checkouts become three.

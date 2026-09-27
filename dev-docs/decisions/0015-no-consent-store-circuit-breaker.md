# 0015. No circuit breaker on the consent store

Date: 27 September 2026

## Status

Accepted. The consent lookup probes once per request and never remembers a
failure past the request boundary.

## Context

`services/api/consent.py` remembers an unreachable consent store for the rest
of the request, which took a `tools/call` carrying arguments from five probes
to one. The obvious next step is a process-wide breaker with a cooldown, which
would cut load far more under a sustained outage. It is not built, and this
records why, because the next person to reach for one should find the argument
rather than the gap.

## What a breaker would save, by outage shape

Three shapes, and only one is interesting.

**A refused connection.** A probe costs `ConnectionRefusedError` in
approximately no time. There is nothing to cut.

**Saturation -- the pool at its ceiling, the store healthy.** One refused
checkout at `pool_timeout`. A breaker here is not a saving but a defect:
saturation is per-instant and clears as requests finish, so a breaker opened by
one refused checkout denies calls the store was about to serve, for its whole
cooldown.

**A store silent in both directions.** A probe holds a pool slot for the full
`connect_timeout`. At 2.0s and a ceiling of 16, connect attempts alone saturate
the pool from roughly 7.5 requests a second. This is the one shape a breaker
would help.

## Decision

One shape is not enough, for three reasons.

**It helps the third shape by hurting the second**, and the second is the one
every deployment meets first. The two arrive wearing ONE exception:
`docs/verification/2026-09-17-query-stall-deadline.md` measured a request
against a silent store holding its pooled connection past a 60-second cap, and
a pool whose connections are all held that way refuses a checkout with the same
`sqlalchemy.exc.TimeoutError` a merely busy one does. Whichever way that
exception is read, it is read wrong half the time.

**The third shape already has a bound that is not this one.**
`RequestDeadline` caps the whole request, and the operator's lever on per-probe
cost is `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` -- lowering it cuts exactly
the pool-slot holding time a breaker would cut, by attempting rather than by
remembering.

**It would write a false row, permanently.** This is the decisive reason and it
is specific to this repository. `refusal_reason = 'consent_store_unavailable'`
is a claim about the operator's infrastructure on a regulator-facing table. A
breaker files it from a cached observation instead of from an attempt, so every
call denied between the store recovering and the cooldown expiring carries a
statement that was true a minute ago and is false on the row. The per-request
memory is defended on the ground that within one request the verdict cannot
change; across requests it plainly can -- the same stale-filing problem
`_clear_refusal` was deleted to remove -- except that nothing can withdraw it,
because migration `f1860c110112` makes `audit_log` refuse `UPDATE` and `DELETE`
inside the database. A per-request memory can be wrong about nothing. A
process-wide one is wrong about every request that never probed.

## What was priced, so that "not worth it" means something

A cooldown duration nobody has evidence for. An admission rule naming which
request pays the half-open probe, which under MCP `2026-07-28` cannot be a
background task on one instance, because protocol sessions are gone and any
request can land on any replica. A close threshold, one success or n. And a
shared-state decision: per replica means R replicas hold R different opinions
about one database, shared means Redis, which turns a Redis outage into a
consent outage.

## Consequence

One probe per request still scales with request rate, so a sustained outage
under load still loads the pool at one attempt per call. That is accepted.

What is kept in exchange: every `consent_store_unavailable` row in `audit_log`
was written because THIS call tried to reach the store and could not. No row
asserts an outage from memory, on a table the database itself will not let
anyone correct.

The argument also lives in `services/api/consent.py`'s module docstring, under
"AND THE MEMORY STOPS AT THE REQUEST BOUNDARY", which is where someone reaching
for a breaker would look first.

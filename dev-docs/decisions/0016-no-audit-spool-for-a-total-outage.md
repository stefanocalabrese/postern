# 0016. No audit spool for a total outage

Date: 27 September 2026

## Status

Accepted. When Postgres is unreachable the record does not survive, and there
is no spool, no queue and no second store. If you are here to add one, this is
the argument you are overturning; it is not an oversight.

## Context

Record 0006 accepts that an audit write failure fails the request. Record 0013
added a reserved connection so a pool at its ceiling still records the denial.
Neither answers the neighbouring question: when the database is not answering
at all, can the fact of a call or an approval survive?

The connection reserve cannot help here and was never claimed to. A second
pool to an unreachable Postgres is a second way to fail to connect.

## What an operator can reconstruct after a total outage

**That nothing happened, and this is the half that matters.** Both entry rows
commit before the operator's backend is reached, and both fail closed, so a
store that cannot take a row cannot be passed. For the duration of the outage:
no `tools/call` reaches a backend read endpoint, no approval reaches a backend
write endpoint, **no money moves**, `POST /token` returns no read token because
the mint is fail-closed on its row, and no device pairing survives, because
`_withdraw_pairing` revokes one whose row could not be written.

So "did customer data leave, or did money move, while the table was blind" is
answerable **without the table**: it did not, and the operator's own backend
access logs corroborate it by being empty. That is a property of the
fail-closed construction, not of a record.

Measured rather than asserted, in `tests/test_asgi_app.py`,
`tests/test_write_audit.py`, `tests/test_pairing_audit.py`, and
`tests/test_audit_reserve.py::TestATotalOutageIsAcceptedAndBounded`, which
drives both paths against an unreachable store with a reserve configured and
asserts no row AND no touch -- the write-path half spying on the backend client
rather than reading a status code.

## What an operator cannot reconstruct

**The attempts.** Who tried, under which token and which OAuth client, against
which tool, with what arguments, and whether they were refused for want of
consent or because the store was down. An attacker probing during the window
leaves no row.

That is a loss of **security monitoring**, not of the money trail. It is the
entire cost of this decision and it should be stated that way rather than as
"the audit trail has a gap", which overstates it in one direction and
understates the monitoring loss in the other.

## Rejected: the log as the record of record

On three grounds, each checked rather than assumed.

**Content.** The lines carry a tool name and an exception type. No
`customer_ref`, no `call_id`, no `client_id`, no arguments, no duration, no
refusal reason. "Show me every call this token made" is unanswerable from logs
however perfectly they are shipped, because the fields are not in them.

**Durability.** Nothing in this repository configures a log handler, formatter,
destination or retention period. Meanwhile `audit_log` has no retention job, no
partitioning and no `DELETE` anywhere: the table's horizon is forever and the
log's is whatever the platform happens to do.

**Integrity.** `f1860c110112` makes the table refuse `UPDATE`, `DELETE` and
`TRUNCATE` inside the database. A log file has no equivalent, and the off-host
shipping that would make one possible is an undischarged operator duty.

So the log is a **detection** signal and is treated as one. It says the window
happened. It is not evidence of what happened in it.

## Rejected: a local spool replayed later

It collects every objection 0006 already made, and adds three of its own.

It is 0006's **"no queue"** verbatim -- "this row will probably exist
eventually" instead of "exists before the caller is told" -- with a failure
mode the queue it considered did not have: the spool dies with the container.
It is also 0006's **"no fallback store"**: two places a regulator-facing record
lives answers "show me every call" with "check both and reconcile".

**Replay cannot be made safe by this schema.** `audit_log.call_id` is
`String(36)`, nullable, with no unique constraint and no index, so nothing
dedupes a row a replay inserts twice -- and the append-only triggers mean a
duplicate on a regulator-facing table cannot be removed afterwards by anyone.

**It demands infrastructure this project tells operators to forbid.** A disk
spool needs a writable filesystem, and asserting `readonlyRootFilesystem = true`
on the ECS task definitions is one of the operator duties the checklist lists.

**And it would have to fail closed itself**, or it reintroduces the silent gap
it was built to close -- at which point a full disk becomes a full outage and
the dependency has moved rather than gone.

## Consequence

The record does not survive a total outage. The outage is bounded and loud
rather than silent and unbounded, which is 0006's own bargain. The money trail
survives by construction, because nothing can be touched without a row. What
is lost is the ability to see who was knocking while the door was shut.

If that ever becomes unacceptable, the next move is not a spool. It is the
tiered policy 0006 already recommends and did not build, or making
`audit_log`'s own availability an operator problem solved with replication.
Both keep one record in one place.

Two residues, named rather than hidden. A device code created by
`POST /device_authorization` during the outage persists in its own store, Redis
or memory rather than Postgres -- unusable, because approving it needs a row,
but state that outlived the blind window. And if `_withdraw_pairing` cannot
reach the device-code store either, an approved code is left with no row, which
is the one shape the design cannot close.

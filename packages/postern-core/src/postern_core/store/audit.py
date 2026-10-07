"""Appending to the audit log, the width bounds its values are written under,
and which connection the append gets.

Append-only by construction: this module exposes no update and no delete.

TWO FUNCTIONS, AND THE SECOND IS ABOUT CONNECTIONS RATHER THAN COLUMNS.
`append` writes the row on a session its caller hands over.
`append_with_reserve` decides WHICH session that is: the application pool's,
or -- when that pool is at its ceiling and nothing else -- the reserve
`postern_core.store.engine`'s `Database` holds for exactly this. It lives
beside `append` because the two are one decision from the caller's side, and
because naming it after the audit path is the cheapest thing that stops a
second caller from quietly turning a reserve into a pool.

===========================================================================
WHAT HAPPENS WHEN POSTGRES IS UNREACHABLE, AND WHY THERE IS NO SPOOL HERE
===========================================================================

Decided 27 September 2026. If you are here to add a local spool, a queue, or
a second store so the record survives an outage, this is the argument you are
overturning; it is not an oversight.

THE RESERVE ANSWERS SATURATION AND NOTHING ELSE. A second set of connections
to an unreachable database is a second way to fail to connect. So the
question below is not about pools at all: it is whether the FACT of an
approval or a denial can survive Postgres being down, by any mechanism.

WHAT AN OPERATOR CAN RECONSTRUCT AFTERWARDS, which is the thing any decision
here is trading, and it splits cleanly in two.

  RECONSTRUCTABLE, AND IT IS THE HALF THAT MATTERS MOST: nothing happened.
  Both entry rows are committed BEFORE the operator's backend is reached and
  both fail closed, so a store that cannot take a row cannot be passed. For
  the duration of a total outage, no `tools/call` reaches a backend read
  endpoint, no approval reaches a backend write endpoint, no money moves, no
  session is returned by `POST /token` (the mint is fail-closed on its
  row), and no device pairing survives -- `services/confirm/device_auth.py`'s
  `_withdraw_pairing` revokes a pairing whose row could not be written. The
  regulator-facing question "did customer data leave, or did money move,
  while the table was blind" is therefore answerable without the table: it
  did not, and the operator's own backend access logs corroborate it by being
  empty. That is a property of the fail-closed construction, not of a record.

  EACH CLAUSE OF THAT IS ALREADY MEASURED, which is why this decision cites
  rather than asserts:
  `tests/test_asgi_app.py::test_a_tool_call_fails_closed_when_the_audit_database_is_unreachable`
  for the read path,
  `tests/test_write_audit.py::test_a_failed_entry_write_stops_the_backend_write`
  for the approval (it counts BACKEND CALLS, not status codes),
  `tests/test_pairing_audit.py::test_a_token_that_cannot_be_audited_is_never_returned`
  for the mint, and
  `tests/test_audit_reserve.py::TestATotalOutageIsAcceptedAndBounded` for the
  claim this section exists to keep honest -- that a configured reserve
  changes none of it.

  NOT RECONSTRUCTABLE: the attempts. Who tried, under which token and which
  OAuth client, against which tool, with what arguments, and whether they
  were refused for want of consent or because the store was down. An attacker
  probing during an outage leaves no row. That is a loss of SECURITY
  MONITORING, not of the money trail, and it is the whole cost of this
  decision. Say it that way rather than "the audit trail has a gap", which
  overstates it in one direction and understates the monitoring loss in the
  other.

  Two residues on top, both named rather than hidden. A device code created
  by `POST /device_authorization` during the outage persists in that store,
  which is Redis or process memory and not Postgres -- it is unusable,
  because approving it needs a row, but it is state that outlived the blind
  window. And if `_withdraw_pairing` cannot reach the device-code store
  either, an approved code is left with no row behind it; that is the one
  shape this design cannot close, and it is the only ERROR line in the tree
  that names an identifier the row would have carried.

THE LOG IS NOT THE RECORD OF RECORD, and three specific things are why.
  * CONTENT. The lines carry a tool name and an exception type. They do not
    carry `customer_ref`, `call_id`, `client_id`, the arguments, the duration
    or the refusal reason. So "show me every call this token made" is
    unanswerable from logs however perfectly they are shipped -- the fields
    are not in them.
  * DURABILITY. Nothing in this repository configures a log handler, a
    formatter, a destination or a retention period; `audit_log` has no
    retention job, no partitioning and no `DELETE` anywhere, so the table's
    horizon is forever and the log's is whatever the platform happens to do.
  * INTEGRITY. Migration `f1860c110112` makes `audit_log` refuse `UPDATE`,
    `DELETE` and `TRUNCATE` inside the database. A log file has no
    equivalent, and the operator duty in CLAUDE.md that would make one
    possible -- shipping off-host before the container dies -- is not
    discharged here.
  The log is a DETECTION signal and is treated as one: it is how an operator
  learns the window happened. It is not evidence of what happened in it.

A LOCAL SPOOL IS REFUSED, and it collects every objection
`dev-docs/decisions/0006-audit-write-failure.md` already made, plus two of its
own.
  * It is that record's "no queue" verbatim. A spool changes the table's
    guarantee from "this row exists before the caller is told the call
    happened" to "this row will probably exist eventually", which is the
    weaker property 0006 refused, with a per-replica failure mode the queue
    it considered did not have: the spool dies with the container.
  * It is also that record's "no fallback store". Two places a
    regulator-facing record lives answers "show me every call" with "check
    both and reconcile".
  * REPLAY CANNOT BE MADE SAFE BY THIS SCHEMA. `audit_log.call_id` is
    `String(36)`, nullable, with no unique constraint and no index
    (`postern_core.store.models`), so nothing dedupes a row a replay inserts
    twice -- and the append-only triggers mean a duplicate on a
    regulator-facing table cannot be removed afterwards by anyone.
  * IT DEMANDS INFRASTRUCTURE THIS PROJECT TELLS OPERATORS TO FORBID. A disk
    spool needs a writable filesystem, and asserting
    `readonlyRootFilesystem = true` on the ECS task definitions is one of the
    operator duties CLAUDE.md lists.
  * AND IT WOULD HAVE TO FAIL CLOSED ITSELF, or it reintroduces exactly the
    silent gap it was built to close. A fail-closed spool makes a full disk
    into a full outage: the dependency moves, it does not go away.

SO: ACCEPTED AND BOUNDED. The record does not survive a total outage, the
outage is bounded and loud rather than silent and unbounded (which is 0006's
own bargain), the money trail survives by construction because nothing can be
touched without a row, and what is lost is the ability to see who was
knocking while the door was shut. If that loss ever becomes unacceptable, the
next move is not a spool: it is the tiered policy 0006 already recommends and
did not build, or making `audit_log`'s own availability the operator's problem
to solve with replication -- both of which keep one record in one place.

WHY THE BOUNDS LIVE HERE. Both services write this table and both need the
same ceilings on what reaches it, and `.importlinter` forbids
`services.api` and `services.confirm` importing each other in either
direction, so a shared home in `postern_core` is the only lawful one. Which
home was already settled in writing before this module had them:
`services/confirm/audit.py` carried a second copy of `TRUNCATED` and
`clamp` from 2026-09-23, with a comment saying the copy was a known cost,
that `postern_core.domain.masking` was the wrong home because these are not
masking but audit-column width management, and that the next person to need
a third copy should promote them. This is that promotion, into the module
it named.

`postern_core.store.audit` rather than a new module beside it, following
the precedent of commit `bdd4214`, which promoted `scrub_text` and
`scrub_tree` into `postern_core.domain.masking` -- the EXISTING module
where `FreeText` and `redaction_budget` already lived -- rather than
inventing a module for them. The concept here is "what `audit_log` will
accept", and `append` below is the one function whose INSERT these bounds
defend.

WHAT A THIRD COPY COSTS, since that is the reason this is a promotion and
not a paste. `services/api/middleware/audit.py` records the precedent: three
copies of `_scrub` existed, the weakest one sat on the money path, and a
NUL-split PAN reached `BackendWriteError.detail` unmasked through it. That
was found by reading the code, not by a test.

THE CONSTANTS ARE THE SAME ON BOTH PATHS, deliberately, though the two
argument trees are nothing alike -- the read path's is an agent's arbitrary
`tools/call` arguments, the write path's is five fixed keys of which two
are caller-supplied (six on a tier-2 approval row, which also carries
`assertion_jti`, a validated value from the verified assertion). The
deciding reason is not the trees, it is the table:
`services/confirm/audit.py`'s module docstring records that NO COLUMN OF
`audit_log` NAMES THE SERVICE THAT WROTE THE ROW, so a query filtering
`arguments @> '{"postern.arguments_truncated": {}}'` returns both services'
rows interleaved. Two different `limit_bytes` values in that result set
would be unattributable by construction: the reader would see two limits
and have nothing on the row to tell them which service each belonged to.
One bound, one marker shape, one query.

The write path's own numbers do not argue for anything tighter either. Its
whole legitimate tree is `route` (a 33-character constant),
`challenge_id` (`challenges.challenge_id` is `String(36)`, so anything
longer can name no challenge that exists), `signature_present` (a boolean),
and the app's own `confirming_device` and `verification_result` --
`challenges.confirming_device` is `String(128)`, which is inside
`MAX_ARGUMENT_VALUE` with 384 characters to spare. (A tier-2 approval row
adds `assertion_jti`, at most 128 printable characters.) A maximal
legitimate write-path tree is under 300 bytes against an 8,192-byte bound
for the five keys, and about 150 bytes more with `assertion_jti`.
"""

import json
import logging
import math
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

import sqlalchemy.exc as sa_exc
from sqlalchemy.ext.asyncio import AsyncSession

from postern_core.store.engine import Database
from postern_core.store.models import AuditEntry

logger = logging.getLogger(__name__)

#: One audit write, given a session to run on.
#:
#: A callable rather than `append`'s own fifteen keyword arguments, and the
#: reason is mypy. `append` requires every one of them with no default, on
#: purpose and with a paragraph each saying why; a wrapper that forwarded
#: ``**row: Any`` would accept a caller that omitted any of them and would
#: undo, at one call site, the guarantee the whole signature exists for.
#: Handing the write itself over keeps the type checking where the row is
#: built.
AuditWrite = Callable[[AsyncSession], Awaitable[None]]

# The marker a clamped value carries, so the VALUE announces its own
# alteration -- the way a masked value already announces itself by containing
# `_MASK`. Chosen over a `truncated: bool` column and over a second column
# holding the untruncated value: both are schema changes, and both put the
# fact somewhere a reader of the value alone never sees it.
#
# U+2026 HORIZONTAL ELLIPSIS, one character:
#
#   * It needs no documentation to read. `xxx…` says "there was more here",
#     which is the whole content of the signal.
#   * It survives the transforms applied to an audited value. Its Unicode
#     category is `Po`, so `postern_core.domain.masking`'s `_strip_invisible`
#     does not remove it -- that function strips `Cf`, `Mn`,
#     `_BLANK_RENDERING_CHARACTERS` and `_DEFAULT_IGNORABLE_UNASSIGNED`,
#     whose lowest member is U+2065, above U+2026 -- and it is neither a
#     digit nor a letter, so it can neither extend a `\\d{12,}` PAN run nor
#     sit inside an IBAN token. An invisible or format character (U+200B,
#     say) would have been stripped and the marker would have vanished
#     without a trace, which is the precise failure this constant exists to
#     end.
#   * It cannot be misread as masking: `_MASK` is `••••`, four of U+2022
#     BULLET, a different character and never one of them alone.
#   * One character costs one character of the clipped value's own content,
#     the least any in-value marker can cost.
TRUNCATED = "…"

# `arguments` is `JSONB` (models.py), and until 2026-09-23 it was the one
# column on the row with NO ceiling of any kind. The `VARCHAR` columns beside
# it each have one because an over-wide value makes the INSERT raise; JSONB
# refuses nothing, so the absence of a width to overflow read as the absence
# of a reason to bound. The reason to bound it is not the column, it is the
# disk.
#
# MEASURED AGAINST THE REAL COLUMN, on both paths, not argued.
#
# READ PATH. `Settings.max_body_bytes` (1 MiB by default) is the only thing
# standing between an authenticated `tools/call` and this column. One call
# carrying 1,037,473 characters of incompressible base64 in an argument wrote,
# per row, 968,430 bytes of JSON text and 954,961 bytes on disk after TOAST --
# and BOTH rows of the call carry the same tree, so one request wrote
# 1,909,922 bytes, 1.82 MiB. With this bound the same call writes 586 bytes
# per row and 1,172 per call, a factor of 1,630.
#
# WRITE PATH, WHERE THE SAME DEFECT IS WORSE IN TWO WAYS. `services/api`
# wires `HeaderBodyValidation` with `max_body_bytes`, and
# `services/confirm/main.py`'s `create_confirm_app` wires no body-size
# middleware at all, so nothing caps the body a `confirming_device` or a
# `verification_result` arrives in. And an approval writes a row on every
# REFUSED path -- 404, 409, 410 -- once the app assertion verifies, so a
# caller needs no valid challenge to write rows at all. Measured 2026-09-24
# against this same column: a 404 aimed at an id naming nothing, carrying
# 1 MiB of incompressible base64 in `confirming_device`, wrote 979,108 bytes
# on disk and 992,895 bytes of JSON text in ONE row; the same 404 carrying
# 10,131,578 characters wrote 7,742,315 bytes on disk, which is the absent
# body limit showing up as bytes. A successful approval carrying 1 MiB in
# `verification_result` wrote 1,958,212 bytes across its pair.
#
# Incompressible matters and cost a measurement to learn: `pg_column_size`
# reports the width AFTER TOAST compression, so a repetitive 1 MiB payload
# stores in about 24 KB and makes the defect look seventy times smaller than
# it is. The numbers above are from random bytes, which is what an attacker
# sends when the goal is bytes on disk rather than meaning.
#
# There is no retention job, no partitioning, and no `DELETE` anywhere in
# production code. So the table only grows, and when the volume fills, the
# audit INSERT fails -- at which point
# `dev-docs/decisions/0006-audit-write-failure.md`'s fail-closed policy turns
# a storage problem into a total outage on BOTH services, which share the
# database: every tool call and every approval fails, for every customer,
# because the audit row cannot be written. That is a denial of service
# costing an attacker a few thousand requests, and the fail-closed policy is
# what converts the cost from "wasted disk" into "the service is down".
#
# TWO BOUNDS, NOT ONE, because either alone leaves the other's attack open.
#
# `MAX_ARGUMENT_VALUE` bounds one string. Without it the tree bound alone
# would be all-or-nothing: one 1 MiB junk value beside a real `account_ref`
# would push the tree over and take the `account_ref` with it, so the
# cheapest attack would also be the one that erases the most forensic value.
# With it, that call records `{"account_ref": "acc_...", "junk": "<511
# chars>…"}` -- the real argument intact, the junk marked as clipped.
#
# `MAX_ARGUMENTS_BYTES` bounds the whole tree, which the per-value bound
# cannot: ten thousand keys of 40 characters each are individually fine and
# collectively 400 KB. It is also the only one of the two that catches a
# value that is not a `str` at all -- masking returns an `int` unchanged, and
# `{"n": 10**100000}` is a 100,001-digit integer no string clamp will ever
# see.
#
# 512 CHARACTERS, the same width as the `client_id` column both services
# clamp to. Derived against what a legitimate value can be rather than picked
# round: the widest identifier this server mints is an `_OPAQUE` ref at 65
# characters (models.py), the widest free-text field in the payments domain
# it models is ISO 20022's unstructured remittance information at 140, and
# the widest caller value on the write path is bounded by
# `challenges.confirming_device` at `String(128)`. 512 is 7.9x the first,
# 3.7x the second and 4x the third.
#
# 8,192 BYTES for the tree. Measured against every argument tree this
# repository's registered tools can actually produce: `start_session`,
# `accounts.list` and `cards.list` take none at all (2 bytes, `{}`),
# `accounts.get_balance` at a maximal ref is 84, `transactions.list` at a
# maximal ref and `days=365` is 97, and a hypothetical `create_payment` with
# a maximal ref, an amount and a 140-character reference is 290. The write
# path's own maximal legitimate tree is under 300 (module docstring). The
# bound is 28x the largest of those and 84x the largest any REGISTERED tool
# produces today, so nothing legitimate is anywhere near it. It also holds
# four values at their own 2,048-byte worst case (512 characters times
# UTF-8's 4-byte maximum), so the per-value bound cannot on its own push a
# tree over this one.
#
# BYTES for the tree and CHARACTERS for the value, deliberately, and the
# mismatch is the point rather than an inconsistency. `clamp` counts
# characters because the columns it defends are `VARCHAR(n)` and Postgres
# counts `n` in characters. Nothing counts characters here: what fills a
# volume is bytes, and masking.py's own byte-width note is the reason not to
# assume the two track each other -- `_MASK` is U+2022, 3 bytes per
# character, so a scrubbed value can grow in bytes while shrinking in
# characters.
MAX_ARGUMENT_VALUE = 512

MAX_ARGUMENTS_BYTES = 8_192

# The marker key. Dotted and namespaced so a JSONB predicate reads
# unambiguously -- `WHERE arguments @> '{"postern.arguments_truncated":
# true}'` -- and so it does not collide with an argument name any tool in
# this repository declares, or with any of the five keys the write path's
# tree carries (or the sixth, `assertion_jti`, on a tier-2 approval row).
#
# It is NOT unforgeable, and that limit is the same one `TRUNCATED`'s own
# comment states for itself: an argument name is arbitrary client-chosen
# text, so a caller can send `{"postern.arguments_truncated": true, ...}` and
# make one row read as truncated when nothing was dropped. No in-value marker
# can close that; a column could, and a column is a migration. What the
# forgery buys is a row that overstates its own loss, never one that
# understates it: a row that really was capped always carries this key,
# because the capped tree is built by `cap_arguments` and contains nothing
# else. The write path is immune to even that, since its five keys (six with
# `assertion_jti` on a tier-2 row) are named by this repository and not by
# the caller.
ARGUMENTS_TRUNCATED_KEY = "postern.arguments_truncated"

# Room held back from `MAX_ARGUMENTS_BYTES` for the marker itself, so the
# capped tree cannot come out wider than the bound that capped it -- the same
# reservation `clamp` makes for `TRUNCATED` when it cuts to
# `limit - len(TRUNCATED)` rather than to `limit`. The marker is four fixed
# keys holding three small integers and a null-or-integer, and its widest
# serialisation is under 150 bytes; 256 is that with room to spare and is
# 3.1% of the bound, which is not a meaningful bite out of what is kept.
_ARGUMENTS_MARKER_RESERVE = 256


def clamp(value: str, limit: int) -> str:
    """`value` cut to fit `limit` characters, carrying `TRUNCATED` when, and
    only when, something was cut.

    The cut is to `limit - len(TRUNCATED)`, not to `limit`: appending the
    marker to a value already cut to the column width would write
    `limit + 1` characters, which is the
    `asyncpg.exceptions.StringDataRightTruncationError` the clamp exists to
    avoid, and under `dev-docs/decisions/0006-audit-write-failure.md` a failed
    audit write takes the call with it. The returned length is therefore at
    most exactly `limit`.

    A value already within `limit` comes back unchanged -- the same string,
    character for character, marker or no marker. That is the invariant that
    matters most: every real tool name in this codebase (`ok_tool`,
    `transactions.list`) is far under 64 characters, and a marker on one of
    those would be the row lying about itself, which is worse than the
    silence this function replaces.
    """
    if len(value) <= limit:
        return value
    return value[: limit - len(TRUNCATED)] + TRUNCATED


def serialized_bytes(tree: Any) -> int | None:
    """`tree` as UTF-8 JSON, measured in bytes, or None when it cannot be
    serialised at all.

    `ensure_ascii=False` because that is what Postgres stores: `JSONB`
    decodes `\\uXXXX` escapes on parse and holds the text, so an
    escaped-ASCII byte count would overstate the width of exactly the
    non-ASCII values this repository's masking produces.

    NEVER RAISES, which is a requirement rather than a nicety: anything
    raised here lands in a caller that has not written its rows yet, and
    under `dev-docs/decisions/0006-audit-write-failure.md` a failed audit
    write takes the call with it. A bound whose whole purpose is preventing
    an outage must not be able to cause one.

    Two things can go wrong in `json.dumps` and `default=str` covers only the
    first. `default` handles an unserialisable TYPE. It does NOT handle a
    serialisable type that raises while being written, which Python 3.12 has
    one of: `int.__str__` refuses beyond `sys.get_int_max_str_digits()`
    (4,300 by default) and raises `ValueError`. Found by a test rather than
    reasoned about -- `{"n": 10**100000}` raised straight through the first
    version of this code, which would have been a tool-call outage caused by
    the bound meant to prevent one. `json.loads` refuses the same literal on
    the way in, so nothing reaches this through an MCP body today, but "an
    earlier layer happens to reject it" is not a property this function
    should rest on.

    None therefore means "unmeasurable", and every caller treats that as OVER
    the limit rather than under it: a value whose size cannot be established
    cannot be stored safely either.
    """
    try:
        return len(json.dumps(tree, ensure_ascii=False, default=str).encode())
    except (ValueError, TypeError, RecursionError, OverflowError):
        return None


def clip_tree(value: Any) -> Any:
    """`clamp` at `MAX_ARGUMENT_VALUE`, applied through an argument tree.

    KEYS AS WELL AS VALUES, for the reason `masking.scrub_tree` gives for
    masking both: arguments are captured before anything validates them, so a
    key is exactly as caller-chosen as a value, and `{"<1 MiB of junk>": 1}`
    is as good a way to fill this column as `{"k": "<1 MiB of junk>"}`. Two
    distinct keys can clip onto the same string and one then wins the dict
    comprehension -- the same collision `scrub_tree` already documents for
    masking, accepted here for the same reason and now reachable one
    additional way. The write path's keys are fixed literals (five, and a sixth,
    `assertion_jti`, on a tier-2 approval row), so that collision is reachable
    only inside a caller-supplied sub-tree there.

    AFTER MASKING, never before, which is the ordering both services spell
    out at length for their other clamped columns: masking reaches
    `masking._strip_invisible`, which deletes characters outright, so a
    marker written before it would depend on a function in another module to
    survive. Clipping afterwards puts `TRUNCATED` where nothing can touch it.

    The cost of that ordering, stated rather than left to be discovered: the
    scrub still walks the whole body before anything here shortens it. That
    cost is already bounded and already measured -- each caller wraps its
    walk in one `redaction_budget`, and masking.py's own journal puts a 1 MiB
    value at 170-200ms of synchronous event-loop stall -- so this bound does
    not make it worse and does not make it better. Moving the clip in front
    of the scrub would cut that stall, and is a separate change with its own
    ordering argument to make.

    Non-`str`, non-`dict`, non-`list` values pass through untouched, exactly
    as they do through `scrub_tree`: an `int`, a `float`, a `bool`, `None`.
    An oversized one of those is the tree bound's job, not this one's.
    """
    if isinstance(value, str):
        return clamp(value, MAX_ARGUMENT_VALUE)
    if isinstance(value, dict):
        return {clip_tree(k): clip_tree(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clip_tree(v) for v in value]
    if isinstance(value, float) and not math.isfinite(value):
        # JSONB has no NaN or Infinity and PostgreSQL refuses the token, which
        # would fail the audit write and, under decision 0006, the call with
        # no row. Recorded as its JSON spelling in a string. Finite floats are
        # untouched.
        return "NaN" if math.isnan(value) else _NON_FINITE_SPELLING[value]
    return value


_NON_FINITE_SPELLING = {math.inf: "Infinity", -math.inf: "-Infinity"}


def cap_arguments(tree: dict[str, Any]) -> dict[str, Any]:
    """`tree` unchanged when its serialised form fits `MAX_ARGUMENTS_BYTES`,
    otherwise a marker object recording that it did not and by how much.

    MARKED, NOT SILENT, AND NEVER A LOST ROW. Dropping the row is what the
    unbounded version already effectively does once the disk is full, and it
    is the failure this bound exists to prevent, so it cannot be the remedy.
    Shortening in silence is the other failure: a row that reads as a
    complete record of a call and is not one, which is what every other bound
    on this row refuses by carrying `TRUNCATED`. So the tree is shortened AND
    says so, in the same object, with the numbers a reader needs to know what
    is missing.

    A FIRST-FIT PREFIX, not all-or-nothing, and the difference is what an
    investigator keeps. Replacing the whole tree was the first version of
    this function, and it hands the attacker more than the disk: one junk
    argument beside a real `account_ref` would take the `account_ref` with
    it, so the cheapest attack would also erase the most forensically
    valuable field. Top-level entries are kept while they fit, so the small
    real arguments survive and the large junk one does not.

    THE WRITE PATH'S KEY ORDER IS THEREFORE LOAD-BEARING, where the read
    path's is merely the caller's. `services/confirm/audit.py`'s `_arguments`
    builds `route`, `challenge_id`, `signature_present`,
    `confirming_device`, `verification_result` in that order, and the first
    three are small and server-chosen while the last two are the
    caller-supplied ones. (A tier-2 approval then inserts `assertion_jti`
    right after the three, in `_with_assertion_jti`, so it too is kept ahead
    of the two.) First-fit therefore keeps exactly the three that
    identify the request and drops the two that carried the junk. Reordering
    that literal would silently change which fields survive an attack.

    FIRST entry that does not fit, then stop, rather than continuing to look
    for smaller ones that would. Best-fit keeps marginally more and costs an
    unbounded number of serialisations on a tree of many large entries -- a
    `tools/call` body is capped at `Settings.max_body_bytes` but that still
    allows on the order of a hundred thousand small keys, and an approval
    body is capped by nothing at all. Stopping at the first miss bounds the
    work to the entries actually kept, plus one.

    WHAT THE MARKER RECORDS. `original_bytes` is the whole tree's serialised
    size before anything was dropped (`null` when it could not be measured,
    see below), `dropped_keys` and `kept_keys` say how the split fell, and
    `limit_bytes` is recorded rather than left implicit so a row stays
    readable after the bound is ever retuned -- a reader comparing two rows
    written under different limits can see which was which without going to
    the git history. Between them they answer both halves of "how much was
    dropped": how many bytes the call really carried, and how much of its
    shape is missing from what is stored.

    The marker key wins a collision with a kept argument of the same name,
    which is the right direction: a row that was capped always says so.

    Sizes come from `serialized_bytes`, which measures what Postgres actually
    stores and never raises; an unmeasurable tree is treated as OVER the
    limit, and `original_bytes` is `null` on that path -- a third
    distinguishable state in the row, valid JSON and queryable, rather than a
    fabricated number.
    """
    original = serialized_bytes(tree)
    if original is not None and original <= MAX_ARGUMENTS_BYTES:
        return tree

    room = MAX_ARGUMENTS_BYTES - _ARGUMENTS_MARKER_RESERVE
    kept: dict[str, Any] = {}
    used = 0
    dropped = 0
    items = list(tree.items())
    for index, (key, value) in enumerate(items):
        size = serialized_bytes({key: value})
        if size is None or used + size > room:
            dropped = len(items) - index
            break
        kept[key] = value
        used += size
    kept[ARGUMENTS_TRUNCATED_KEY] = {
        "original_bytes": original,
        "limit_bytes": MAX_ARGUMENTS_BYTES,
        "dropped_keys": dropped,
        "kept_keys": len(kept),
    }
    return kept


def bound_arguments(tree: dict[str, Any]) -> dict[str, Any]:
    """Both bounds, in the one order they may be applied, for every caller.

    The composition is the point of the function existing at all. Clipping
    before capping is what makes the per-value bound able to save a tree the
    tree bound would otherwise have dropped whole: a 1 MiB value beside a
    real `account_ref` becomes 512 characters first, at which point the tree
    fits and the `account_ref` survives. Capping first would drop the junk
    key and the real one together, which is the failure `cap_arguments`'s
    first-fit paragraph describes.

    Exposed so the two services cannot compose it differently. They each
    scrub before calling this -- differently, and correctly so: the read path
    scrubs one arbitrary tree, the write path scrubs three named values --
    but what happens after the scrub is one decision made here.
    """
    return cap_arguments(clip_tree(tree))


async def append(
    session: AsyncSession,
    *,
    at: datetime,
    customer_ref: str | None,
    # Required, and the one parameter here whose wrong value is rejected by
    # the database rather than merely recorded: `ck_audit_log_customer_ref_xor
    # _absence` (models.py) makes `customer_ref IS NULL` and this being
    # non-NULL the same statement, so a caller that defaults this to None
    # while passing no `customer_ref` loses the whole row and, under the
    # fail-closed policy (dev-docs/decisions/0006-audit-write-failure.md), the
    # call with it. Only the caller knows WHICH absence it saw -- no token,
    # no string subject, or a subject that failed `CustomerRef` -- and that
    # third case is the compromised-issuer signal the column exists to make
    # searchable, so a default that quietly filed it as one of the other two
    # would be worse than no column at all.
    customer_ref_absence_reason: str | None,
    tool_name: str,
    arguments: dict[str, Any],
    outcome: str,
    detail: str | None,
    # Required, not defaulted: `AuditEntry.redaction_budget_exhausted`
    # (models.py) is what this parameter fills in, and `AuditMiddleware
    # ._write` -- the one call site outside tests, reached from both its
    # raised-path and returned-path branches -- always has a real
    # `RedactionScope.exhausted` value to supply. A default here would let
    # a future caller silently record False instead of a measured value.
    redaction_budget_exhausted: bool,
    # Required for the same reason, with a sharper consequence than the
    # boolean above: `AuditEntry.duration_ms` is NULLABLE, and NULL on that
    # column already carries a meaning -- "this row predates the column"
    # (models.py). A default here would let a future caller write NULL from
    # a live call, which is not a gap in the data but a false statement
    # about when the row was written, on a regulator-facing table. Both
    # branches of `AuditMiddleware.on_call_tool` measure a real value,
    # including the one that handles a raised exception.
    #
    # `int | None` since the entry row exists: an `outcome='reaching'` row is
    # written before the tool body runs, so there is no duration in existence
    # to pass. That is the ONLY caller allowed to pass None, and it stays
    # required rather than defaulted precisely so that passing None is a
    # decision a caller writes down rather than one it inherits.
    duration_ms: int | None,
    # Required even though `None` is a legitimate value here, unlike on
    # `duration_ms`: NULL must mean "the middleware looked for a request id
    # and there was none", never "a caller forgot the argument". Only the
    # caller knows which of the two it is, and a default would erase that
    # difference at the one point where it is still known.
    request_id: str | None,
    # Required for the same reason as `request_id`, applied to a column
    # where the wrong value is not a gap but a contradiction: NULL on
    # `AuditEntry.refusal_reason` means "this call was not refused"
    # (models.py), and a call that WAS refused is the row a regulator reads
    # this table for. `AuditMiddleware._write` reaches `append` from both
    # branches of `on_call_tool`, and only one of them can carry a refusal;
    # a default would let a future branch answer "not refused" without ever
    # asking `services/api/consent.py` whether it refused.
    refusal_reason: str | None,
    # Required and never None from any caller, which is the opposite of
    # `request_id` above and is the whole point of the column existing
    # separately from it. `AuditEntry.call_id` is NULLABLE only because rows
    # written before migration 71a4c0d9e3b2 have nothing to put there; a row
    # this function writes always carries the caller's minted value, because
    # a NULL correlation key turns the entry row and the completion row for
    # one call into two unpairable orphans. Typed `str`, so mypy refuses a
    # caller that passes None rather than leaving the guarantee to a comment.
    call_id: str,
    # Required and `datetime | None`, the shape `duration_ms` above has and
    # for the mirror-image reason: `AuditEntry.reaching_at` belongs to the
    # entry row exactly as `duration_ms` belongs to the completion row, and
    # `ck_audit_log_reaching_at_matches_outcome` (models.py) rejects either
    # one written on the wrong row shape -- which under the fail-closed
    # policy (dev-docs/decisions/0006-audit-write-failure.md) costs the row and
    # the call. A default would let a future caller file an entry row that
    # says a touch happened without saying when, which is the hole the column
    # was added to close, or stamp a completion row with a copy of its
    # partner's instant. The caller passing None is writing that decision
    # down rather than inheriting it.
    reaching_at: datetime | None,
    # Required and `str | None`, the shape `request_id` above has and for the
    # same reason applied to a different absence: NULL on
    # `AuditEntry.client_id` must mean "this call carried no access token",
    # never "a caller forgot the argument". Only the caller has seen
    # `get_access_token()`, and it has to pass the SAME value to both of a
    # call's two rows -- `services/api/middleware/audit.py` reads the token
    # once and carries the result on `_PendingEntry` precisely so the entry
    # row and the completion row cannot disagree about who made the call. A
    # default would let a future caller file a row that answers "no client"
    # for a call that had one, on the column that names the party the
    # per-client controls in the design handoff (§"Allowlist clients") act
    # on.
    client_id: str | None,
    # Required and `list[dict] | None`: NULL means "no risk signals recorded
    # for this row", which covers both pre-migration rows and calls where
    # risk tracking was disabled (no session handle). A default would let a
    # future caller silently record NULL instead of the actual signals, which
    # on a regulator-facing table is a gap in the data. Both branches of
    # `AuditMiddleware._write` always have a real value to supply (an empty
    # list when no signals fired, or the signal data when they did).
    risk_signals: list[dict[str, Any]] | None,
) -> None:
    session.add(
        AuditEntry(
            at=at,
            reaching_at=reaching_at,
            customer_ref=customer_ref,
            customer_ref_absence_reason=customer_ref_absence_reason,
            tool_name=tool_name,
            arguments=arguments,
            outcome=outcome,
            detail=detail,
            redaction_budget_exhausted=redaction_budget_exhausted,
            duration_ms=duration_ms,
            request_id=request_id,
            refusal_reason=refusal_reason,
            call_id=call_id,
            client_id=client_id,
            risk_signals=risk_signals,
        )
    )
    await session.commit()


async def append_with_reserve(db: Database, write: AuditWrite) -> None:
    """Run `write` on the pool, and on the reserve when the pool refuses.

    THE ONE CONDITION THAT EARNS A SECOND ATTEMPT is
    `sqlalchemy.exc.TimeoutError`. It is `QueuePool` saying that
    ``pool_size + max_overflow`` connections are checked out and none came
    back within ``pool_timeout``; it says nothing about the database, which
    may be answering every one of those connections in milliseconds. That is
    the only failure a second set of connections can answer, and it is the
    failure that cost the row: under
    `dev-docs/decisions/0006-audit-write-failure.md` the write fails the call,
    and `services/api/consent.py`'s check denies when its own lookup raises,
    so saturation produced both halves of the failure and put neither in the
    table.

    EVERY OTHER FAILURE PROPAGATES UNTOUCHED, and the omission is the
    decision. A refused connect, a `command_timeout`, a schema error, a bug in
    this repository -- a second attempt against a second pool to the SAME
    database reaches the same answer, having first paid another
    ``connect_timeout``. That is the "slower hard outage" decision 0006 named
    when it refused a retry, and this is not an exception to that refusal: the
    reserve is not a second chance at a failed write, it is a connection for a
    write that never got one. `tests/test_audit_reserve.py`'s
    `TestOnlyAPoolCeilingReachesTheReserve` walks the classes that are left
    alone, with a positive control beside them so a predicate that matched
    nothing could not pass as a correct one.

    `completed` IS THE DUPLICATE-ROW GUARD, and it is cheap because the thing
    it guards against is rare rather than impossible. A pooled checkout raises
    before any statement is sent -- measured against postgres:17-alpine on
    2026-09-27, an INSERT through a saturated pool left zero rows behind -- so
    the ordinary path cannot double-write. What this closes is a
    `TimeoutError` arriving from anywhere AFTER `write` returned, a session
    exit included, where running the write again would put a second row on a
    regulator-facing table. Two lines, and the property stops depending on
    which line of `sqlalchemy/pool/impl.py` raises.

    WARNING AND NOT ERROR, matching the outcomes: the row is written and the
    call is unaffected, so this is degradation rather than failure. It is
    still the only signal that the application pool hit its ceiling on a path
    that no longer fails because of it, which makes it the line an operator
    alerts on to learn they are one pool short.

    Nothing about the ROW changes here -- not its columns, not when it is
    written, not whether a failure to write it still fails the call. Only
    whether the write can get a connection.
    """
    completed = False
    try:
        async with db.sessionmaker() as session:
            await write(session)
            completed = True
    except sa_exc.TimeoutError as saturated:
        reserve = db.audit_reserve_sessionmaker
        if completed or reserve is None:
            raise
        logger.warning(
            "the connection pool is at its ceiling; writing this audit row on the "
            "reserve connection instead: %s",
            saturated,
        )
        try:
            async with reserve() as session:
                await write(session)
        except Exception as refused:
            # THE RESERVE'S FAILURE IS WHAT PROPAGATES, with the pool's as its
            # `__cause__`. Both halves are needed and neither alone is the
            # story: the pool's exception says saturation, the reserve's says
            # the row could not be placed anyway, and an operator who sees
            # only the first would go looking for a ceiling to raise while
            # the second names what actually happened. Explicit `from` rather
            # than the implicit `__context__` this would get for free, for the
            # reason decision 0006 gives where it does the same thing on the
            # middleware's raised path: a chain that is deliberate reads as
            # deliberate.
            raise refused from saturated

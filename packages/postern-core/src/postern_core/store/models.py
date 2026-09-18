"""The two tables this plan owns (handoff §9).

`consents` records which banking domains a customer has authorized.
`audit_log` is append-only: the per-operation chain a regulator asks for.
Neither model exposes an update or delete helper, deliberately.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    column,
    false,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from postern_core.store.base import Base

# The closed vocabulary of `AuditEntry.refusal_reason`, kept here rather than
# in `services/api/consent.py` (where the decisions are made) so the values
# and the CHECK constraint that enforces them cannot drift apart: the
# constraint below is built from this tuple, and the consent check imports
# these names instead of retyping the strings. Migration 0eb813c87298
# hardcodes its own copy of both values deliberately -- a migration records
# what the schema became on one date, so importing a tuple that later grows
# would silently change what an already-applied migration claims to have done.
#
# Each value names what the consent check actually established, and nothing
# more. `no_customer_ref`: the request's access token yielded nothing that
# parses as a `CustomerRef`, so there was no customer to look consent up for
# -- it does not say the token was absent, expired or forged, which are
# different facts this column does not carry. `domain_not_consented`: a
# customer reference was read and the tool's domain was not among that
# customer's currently granted domains (`consents.granted_domains`, which
# already treats an expired grant as absent).
REFUSAL_NO_CUSTOMER_REF = "no_customer_ref"
REFUSAL_DOMAIN_NOT_CONSENTED = "domain_not_consented"
REFUSAL_REASONS: tuple[str, ...] = (REFUSAL_NO_CUSTOMER_REF, REFUSAL_DOMAIN_NOT_CONSENTED)

# The closed vocabulary of `AuditEntry.customer_ref_absence_reason`, kept here
# for the same reason `REFUSAL_REASONS` above is: the CHECK constraint on that
# column is built from this tuple, and `services/api/middleware/audit.py`
# imports these names instead of retyping the strings. Migration 3186c04c018c
# hardcodes its own copy of all three, deliberately, so a later widening
# cannot change what an already-applied revision claims to have done.
#
# Each value names the class of absence the middleware established, never the
# value it refused. `no_access_token`: `get_access_token()` returned None, so
# the call carried no validated token at all. `no_string_subject`: a token was
# present and its `sub` claim was absent or was not a string, so there was no
# subject to validate. `subject_not_a_customer_ref`: a token was present, its
# `sub` WAS a string, and that string failed `CustomerRef` validation
# (`postern_core.identity`) -- the one value here that is a security signal
# rather than an ordinary unauthenticated call, because identity.py's own
# warning is that a compromised issuer can mint a `sub` shaped like a bare
# PAN, IBAN or DNI, and `services/api/server.py`'s `token_customer_resolver`
# refuses exactly that shape on the tool path.
#
# `no_access_token` and `no_string_subject` are kept apart even though both
# mean "the caller presented nothing usable": the first is reachable by any
# client that simply did not authenticate (the in-process `fastmcp.Client`
# produces it on every call), while the second requires a token that passed
# signature, issuer and audience verification and still carried no subject,
# which is an issuer-side defect rather than a client-side one. Merging them
# would put a routine unauthenticated call and a malformed-but-verified token
# in the same bucket. The second value does merge two facts the middleware
# could separate -- `sub` absent versus `sub` present with a non-string type
# -- because neither is the compromised-issuer case this column exists for and
# both leave the same hole; splitting them later is a widened CHECK, one
# statement, the same trade `refusal_reason` documents.
#
# The `noqa` below is bandit's S105, which fires on any name ending in TOKEN
# that is assigned a string literal. This one is a value written into an
# audit column, never a credential, and the name has to keep saying "access
# token" because that is the thing whose absence it reports.
ABSENCE_NO_ACCESS_TOKEN = "no_access_token"  # noqa: S105
ABSENCE_NO_STRING_SUBJECT = "no_string_subject"
ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF = "subject_not_a_customer_ref"
CUSTOMER_REF_ABSENCE_REASONS: tuple[str, ...] = (
    ABSENCE_NO_ACCESS_TOKEN,
    ABSENCE_NO_STRING_SUBJECT,
    ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
)

# The closed vocabulary of `AuditEntry.outcome`, and the newest of the three
# in this module even though the column is the oldest: `outcome` carried bare
# string literals at its two call sites in
# `services/api/middleware/audit.py` and no constraint at all until migration
# 71a4c0d9e3b2, while both columns above have been constrained since the
# revision that added them. Adding `OUTCOME_REACHING` is what made that
# inconsistency worth closing rather than noting: a third writer of this
# column is exactly the change that a CHECK constraint exists to catch when
# it misspells the value.
#
# `returned` and `raised` describe the TOOL and are written after it ran, one
# per call, by `AuditMiddleware.on_call_tool`'s two branches.
#
# `reaching` describes the OPERATOR and is written before any customer data
# is reached, by the callable that middleware pre-binds and
# `postern_core.facade.client.BackendClient` invokes before its first HTTP
# request. Present tense deliberately: the row is committed BEFORE the
# request is issued, so at the instant it becomes durable the backend has not
# been reached yet. That direction is the chosen one -- a row claiming a
# touch that a crash then prevented is a false positive an investigator can
# resolve against the backend's own logs, where the reverse (touch first,
# record after) is the hole this value was added to close, and it resolves to
# nothing at all.
#
# A `reaching` row therefore does NOT assert that the backend answered, that
# it was even connected to, or that the data came back. It asserts that this
# process was about to ask for it and had committed to saying so first.
#
# THAT FALSE POSITIVE HAS A MEASURED SHAPE, not merely a licensed direction.
# `tests/test_audit_entry_row.py::test_a_commit_that_then_raises_records_a
# _touch_that_never_happened` drives a call whose entry row COMMITS and whose
# session close then raises: the request is never issued, the backend
# transport records no path, and this table ends up holding `reaching` plus
# `raised` for a call that reached nothing. Nothing in the pair marks it --
# a `raised` completion row next to a `reaching` row is also what a call that
# WAS served and then failed looks like, since `detail` reads `ToolError` for
# both. The two are separated by the backend's own logs, which is what the
# paragraph above means by resolvable.
OUTCOME_REACHING = "reaching"
OUTCOME_RETURNED = "returned"
OUTCOME_RAISED = "raised"
OUTCOMES: tuple[str, ...] = (OUTCOME_REACHING, OUTCOME_RETURNED, OUTCOME_RAISED)


class ConsentRecord(Base):
    __tablename__ = "consents"

    id: Mapped[int] = mapped_column(primary_key=True)
    # 128, not 64: identity.py's `_OPAQUE` accepts `cust` + one separator +
    # up to 60 alphanumerics, 65 characters, which a 64-wide column cannot
    # hold at all (`NOT NULL` here, so the insert fails outright rather
    # than truncating). 128 leaves room for `_OPAQUE`'s suffix bound to
    # widen again without another migration; matching it to 65 exactly
    # would put this column back at the edge on the next such change.
    customer_ref: Mapped[str] = mapped_column(String(128), index=True)
    domain: Mapped[str] = mapped_column(String(32))
    granted: Mapped[bool] = mapped_column(Boolean, default=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("customer_ref", "domain", name="uq_consent_customer_domain"),
    )


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    # When the tool CALL ARRIVED, not when this row was written.
    # `services/api/middleware/audit.py` passes `context.timestamp` to both
    # of a call's rows, so the pair shares one timestamp and a reader can see
    # at a glance that they belong together.
    #
    # ONE MEANING ON EVERY ROW OF THIS TABLE, which is a decision and not the
    # only shape that was available. The instant the operator actually
    # reached the customer's data is a different fact, it was missing
    # entirely until migration 9a7d4e51c6f8, and this column was the obvious
    # place to put it: redefine `at` on an `outcome='reaching'` row to mean
    # the touch, leave it meaning arrival everywhere else, and no migration
    # is needed at all.
    #
    # Rejected, and the reason is this column's own `NOT NULL`. Every dated
    # boundary this table carries is a NULL: `duration_ms`,
    # `customer_ref_absence_reason` and `call_id` each say "NULL means this
    # row predates the column", and `duration_ms`'s SECOND meaning is told
    # from its first by `outcome`. (`request_id` is NOT one of them, though
    # the list it sits in elsewhere implies it: its NULL is a live state,
    # recording that no MCP request context was established.) `at` has
    # neither -- no NULL to carry the reading, and no companion column that
    # dates it, since `call_id` arrived in the same commit that created the
    # entry row. A row written under the old meaning and one written under
    # the new would be the same bytes, on an append-only, regulator-facing
    # table, distinguishable by nothing in it.
    #
    # THE DECIDING ARGUMENT IS SIMPLER AND IS NOT ABOUT MIGRATIONS AT ALL: a
    # request cancelled after the touch writes NO completion row
    # (`tests/test_request_deadline.py` measures exactly that, and it is the
    # shape this pair of rows exists for). Arrival would then survive only on
    # a row that is never written, so redefining the entry row's `at` to mean
    # the touch would not relocate the arrival instant, it would delete it --
    # on precisely the calls where an investigator needs both. `reaching_at`
    # below carries the touch instead, so this column keeps saying exactly
    # one thing, both instants sit on the row that is guaranteed to exist,
    # and the pair keeps sharing the timestamp that shows they are one call.
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # WHEN THE OPERATOR WAS ABOUT TO REACH THE BACKEND, on the one row shape
    # that describes a touch. Non-NULL exactly when `outcome='reaching'`, and
    # `ck_audit_log_reaching_at_matches_outcome` below is what makes that a
    # property of the table rather than of the two Python call sites.
    #
    # THE FIRST BACKEND REQUEST OF THE CALL, not each one. A tool that
    # issues several gets ONE entry row, because `_PendingEntry.record`
    # (`services/api/middleware/audit.py`) writes at most once per call, so
    # this instant dates the moment the operator first reached for this
    # customer's data and says nothing about any request after it. No facade
    # function issues more than one today; the guard is what keeps that from
    # being the reason.
    #
    # Read by `services/api/middleware/audit.py`'s `_PendingEntry
    # ._write_entry_row` immediately before the INSERT, so it PRECEDES the
    # request it describes by the INSERT, the commit and the session exit --
    # it errs early, never late, which is the direction `OUTCOME_REACHING`
    # above already commits this row shape to. It is not the instant the row
    # became durable and it is not the instant the socket opened; it is the
    # last reading taken before either.
    #
    # A WALL CLOCK, deliberately, where `duration_ms` refuses one:
    # `_elapsed_ms` measures an INTERVAL and uses `time.monotonic()` so an
    # NTP correction cannot write a negative number into this table. What is
    # wanted here is an INSTANT comparable with `at`, and `at` is itself a
    # wall-clock reading (`MiddlewareContext.timestamp`, `datetime.now(
    # timezone.utc)`), so a monotonic value would be comparable with nothing.
    # The cost is inherited rather than introduced: a clock step between the
    # two readings makes `reaching_at - at` wrong by the step, and nothing in
    # the row marks that. `duration_ms` on the completion row is the interval
    # this table measures with a clock that cannot step.
    #
    # NOT COPIED ONTO THE COMPLETION ROW, even though the middleware holds
    # the value there. That would be one fact stored twice and free to
    # disagree with itself -- the reasoning `customer_ref_absence_reason`
    # below spells out for its own missing fourth value -- and a call that
    # touched nothing would have nothing to copy.
    #
    # NULL therefore means one of two things, told apart by `outcome` exactly
    # as `duration_ms`'s two NULLs are: on a `returned` or `raised` row it is
    # structural, there is no touch on that row to record; on a `reaching`
    # row it means the row predates migration 9a7d4e51c6f8. Nothing the
    # application wrote is in that second population, but it is not a
    # hypothetical one either: a hand-seeded `reaching` row from an earlier
    # revision's verification run survives on a Docker volume on the machine
    # this was written on, one DELETE and one `alembic upgrade head` from
    # becoming such a row and from failing a later `VALIDATE CONSTRAINT`.
    # The DELETE comes first and is not optional -- an `outcome='invented'`
    # row beside it stops that upgrade a revision early. That migration's
    # docstring carries the measurement and its limits.
    reaching_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # 128, same reasoning as `ConsentRecord.customer_ref` above: `_OPAQUE`'s
    # current maximum is 65 characters, and a failed insert here means no
    # audit row exists for that call at all, on a regulator-facing,
    # append-only table.
    #
    # NULL here says nothing on its own about WHY there is no customer:
    # `customer_ref_absence_reason` at the bottom of this class carries that,
    # one value per class of absence, and the CHECK constraint below makes
    # "this is NULL" and "that is not NULL" the same statement.
    customer_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(64))
    arguments: Mapped[dict[str, Any]] = mapped_column(JSONB)
    outcome: Mapped[str] = mapped_column(String(16))
    # The exception TYPE that ended the call, never its message: a
    # `pydantic.ValidationError` message embeds the raw offending value,
    # which is the leak path CLAUDE.md's masked-type rule describes, and this
    # is a long-lived store. `services/api/middleware/audit.py` writes
    # `type(exc).__name__` and nothing else.
    #
    # ITS REAL VOCABULARY IS THREE VALUES, and only one of them is ever the
    # type the code that failed actually raised. They correspond to the three
    # stages a `tools/call` passes through, so what this column records is
    # HOW FAR the call got:
    #
    # `NotFoundError` -- no tool was reached. The name is unknown, or the
    # consent check refused it: FastMCP's `_get_tool` answers None for both
    # and the dispatch raises one exception for both, which is why
    # `refusal_reason` below exists at all.
    #
    # `ValidationError` -- a tool was found and its ARGUMENTS were rejected,
    # in the dispatch, before the body ran. Not wrapped, because no tool body
    # raised it. It has exactly one cause and that cause is the caller: a
    # malformed tool call, produced on demand. `NotFoundError` above is
    # agent-controllable too (a name nobody registered) but not ONLY that,
    # since it also covers the operator's own refusal, and `refusal_reason`
    # is what separates those. An abuse-detection reader therefore wants the
    # two values apart even though both precede the tool body: one of them is
    # unambiguously the caller, the other is two facts sharing a name.
    #
    # `ToolError` -- the body ran and raised. FastMCP wraps whatever it was
    # (`fastmcp/server/server.py:1555`, `raise ToolError(...) from e`) before
    # this middleware's handler reads the type, so a tool's own `ValueError`,
    # a backend `BackendError`, a masking `ValidationError` on a RESPONSE and
    # a failed entry write all land here as the same four letters. A masking
    # `ValidationError` on ARGUMENTS does not: that one is the stage above.
    #
    # Measured against a DEFAULT server on 2026-09-18, which is what
    # production runs: a wrong-type argument and a missing required argument
    # both record `ValidationError`. `tests/conftest.py`'s
    # `strict_input_validation=True` is needed for one narrower case only,
    # the digit-only string coerced into an `int` -- on a default server that
    # call succeeds and records `outcome='returned'` with NULL here. The
    # third value is not an artefact of that fixture.
    # `tests/test_audit_middleware.py::test_the_detail_records_the_exception_
    # type_not_its_message` asserts the closed set of three.
    #
    # Anything finer has to come from another column (`refusal_reason`) or
    # from the server's own logs, and a reader who treats `detail` as the
    # exception the code raised will be wrong for every row that is not a
    # refusal or an argument rejection.
    #
    # NULL on every `returned` row and on every `reaching` row: nothing went
    # wrong, and this column only ever describes something that did.
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Reports one fact: this call's redaction checksum allowance ran out
    # (`_ScanBudget.exhausted`, masking.py, is `remaining <= 0`). That is
    # neither necessary nor sufficient for "a value on this row was
    # bare-masked instead of scanned": exhaustion can be reached on the
    # checksum that completes a full, correctly-identified scan, so True
    # can mean nothing was degraded; and a token can be bare-masked
    # without the allowance running out at all -- an over-length token
    # spends no budget (masking.py:474, returned before any checksum
    # runs), and an ambiguous token spends checksums but need not spend
    # the last one (masking.py:419-420) -- so False can still accompany a
    # bare-masked value. Named for the budget, not for "degraded", because
    # the budget is the only thing this column actually reports, and this
    # table is regulator-facing, where overclaiming precision is worse
    # than a name that needs this comment. `nullable=False,
    # server_default=false`: every row that predates this column predates
    # the signal, and NULL would invite a reader to treat "unknown" as
    # "fine".
    redaction_budget_exhausted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=false()
    )
    # How long the tool call took, in whole milliseconds, measured with
    # `time.monotonic()` around `call_next` alone
    # (`services/api/middleware/audit.py`'s `_elapsed_ms`) -- not around the
    # argument scrubbing that precedes it, and not with a wall clock, which
    # can step backwards under an NTP correction and write a negative number
    # into a regulator-facing table.
    #
    # Nullable with NO `server_default`, unlike `redaction_budget_exhausted`
    # above, and the difference is the point: NULL here means "this row
    # predates the column", and every row the application writes from now on
    # carries a measured value, on the returned path AND on the raised path
    # (a slow failure is exactly what an investigator looks for). A default
    # would stamp every pre-existing row with a number indistinguishable
    # from a call that genuinely took that long, so the table would be
    # asserting a latency nobody measured.
    #
    # A sub-millisecond call therefore records 0, not NULL: 0 means
    # "measured, under one millisecond", NULL means "no measurement exists
    # for this row". Collapsing the first into the second would make live
    # rows indistinguishable from pre-migration ones.
    #
    # NULL GAINED A SECOND MEANING with migration 71a4c0d9e3b2, and the two
    # are told apart by `outcome`, not by this column. An `outcome='reaching'`
    # row is written BEFORE the tool body runs, so there is no tool duration
    # in existence to record on it and never will be; a NULL on a `returned`
    # or `raised` row still means what the paragraphs above say. Writing 0
    # there instead would claim a call that took under a millisecond, which
    # is a measurement nobody made. The rule is therefore: NULL with
    # `outcome='reaching'` means "this row shape has no duration"; NULL with
    # either other outcome means "this row predates this column".
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # The JSON-RPC id of the client request this call arrived on, stored as
    # its string form: an id may be a string or a number on the wire, and
    # one column cannot hold both shapes without a reader having to guess
    # which it is looking at.
    #
    # What it buys is TRACEABILITY, not deduplication: an investigator can
    # tie this row to one client request and line it up against client-side
    # logs. It does not identify a retry. MCP 2026-07-28 has no SSE
    # resumability, so a dropped stream makes the client re-issue the call,
    # and the re-issued call carries a NEW id -- two rows that a reader
    # cannot collapse, because at the protocol level they were two separate
    # requests. Nothing here detects, counts or merges duplicates.
    #
    # Nullable because the id is genuinely absent sometimes:
    # `MiddlewareContext.fastmcp_context` is typed `Context | None`, and
    # `Context.request_id` raises `RuntimeError` when no MCP request context
    # is established. NULL records that real state; the audit row is written
    # either way, because a missing identifier must never become a missing
    # audit row. `String(128)`, with the middleware truncating to the same
    # bound before the insert, for the reason `tool_name` is clamped there:
    # an over-long value would raise `StringDataRightTruncationError` and
    # cost the whole row.
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Why this call was refused before the tool ran, or NULL.
    #
    # The column exists because a consent denial and a mistyped tool name
    # were byte-identical rows. FastMCP's `_get_tool` returns None both for
    # a name it does not know and for a tool whose `auth=` check said no
    # (fastmcp 4.0.3, `fastmcp/server/server.py:886-915`), and the dispatch
    # turns both into one `NotFoundError`, so both landed here as
    # `outcome='raised'`, `detail='NotFoundError'`, differing only in
    # `tool_name`. Measured against the running server, 2026-09-17: a denied
    # `cards.list` and a nonexistent `no_such_tool` produced the same two
    # fields. One of those rows is a consent record a regulator can act on,
    # the other is an agent spelling a name wrong.
    #
    # The vocabulary is `REFUSAL_REASONS` at the top of this module, held to
    # two values by the CHECK constraint below; each names what the consent
    # check established and not why the caller ended up in that state.
    #
    # NULL is every other row: the call was not refused, or the row was
    # written before this column existed. The column cannot separate those
    # two on its own -- `at`, read against the date migration 0eb813c87298
    # was applied, is what separates them. No third "not a refusal" string
    # exists, because writing one would make a claim about pre-migration
    # rows that nothing in this table can support.
    #
    # `String(32)`: the longest value is 20 characters, and a regulator or a
    # DBA reads the values straight out of a `SELECT` with no enum catalog
    # lookup and no join. A Postgres `ENUM` would put the same closed set
    # one `ALTER TYPE` away from every future change, including one that
    # cannot run in the same transaction that uses it; a widened CHECK is a
    # one-statement migration.
    #
    # This is the ONLY place the distinction is recorded. The MCP client is
    # told `Unknown tool: '<name>'` for a refusal and for an unknown name
    # alike, and that must stay true (see `services/api/consent.py`'s module
    # docstring): naming the refusal on the wire would tell an agent that
    # `cards.list` exists and that this customer holds cards.
    refusal_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Which of three absences produced a NULL `customer_ref` on this row.
    #
    # The column exists because that NULL meant three different things and
    # `services/api/middleware/audit.py`'s `_customer_ref` collapsed all of
    # them: no access token at all; a token whose `sub` claim was absent or
    # not a string; and a token whose `sub` was a string that failed
    # `CustomerRef` validation. The first two are ordinary. The third is the
    # compromised-issuer case identity.py warns about -- `_OPAQUE` is a
    # provenance convention, not proof of opacity, so an issuer under
    # attacker control can mint a `sub` shaped like a bare PAN, IBAN or DNI,
    # which `services/api/server.py`'s `token_customer_resolver` refuses on
    # the tool path. Before this column, that refusal's audit trail was
    # indistinguishable from an anonymous call: same NULL, same everything.
    #
    # One column, so the security case is one predicate --
    # `WHERE customer_ref_absence_reason = 'subject_not_a_customer_ref'` --
    # rather than a join of `customer_ref IS NULL` against `refusal_reason`
    # and `detail`, which cannot separate the three in any combination:
    # `refusal_reason = 'no_customer_ref'` is written for all three alike and
    # only on calls that a consent check actually refused.
    #
    # THE REJECTED SUBJECT'S VALUE IS NEVER STORED, here or in any other
    # column, and that is the deliberate inversion of the obvious design. The
    # rejected string is the PAN-, IBAN- or DNI-shaped value that
    # `_customer_ref` refuses to put in `customer_ref`; writing it into this
    # column instead would be the one write that survives the refusal it
    # documents, in the longest-lived table this system has. Even the
    # rejection is not a safe carrier for it: `CustomerRef` sets
    # `hide_input_in_errors`, which scrubs `str()` and `repr()` of the
    # resulting `ValidationError` but leaves the raw value in its structured
    # `.errors()` (see `token_customer_resolver`'s comment). This column
    # records the CLASS of absence and nothing else.
    #
    # The cost is stated rather than left to be found: an investigator
    # reading this table learns that a subject was minted which is not a
    # customer reference, when, how often, from which tool and under which
    # `request_id` -- never what the string was. Recovering that means going
    # to the identity issuer's own logs, which is where a claim about what an
    # issuer minted belongs. A table that could answer "what did it mint"
    # would also be a table holding attacker-supplied PANs.
    #
    # Vocabulary: `CUSTOMER_REF_ABSENCE_REASONS` at the top of this module,
    # held to three values by the CHECK constraint below.
    #
    # `String(64)`, where `refusal_reason` above is `String(32)`, because the
    # longest value here is 26 characters and 26 of 32 is a column sized at
    # its own maximum. This repo has paid for that once already: migration
    # 1c64b7ed3f4b widened both `customer_ref` columns from 64 to 128 because
    # `_OPAQUE`'s 65-character maximum did not fit the width someone had
    # matched to the then-current bound. 64 leaves room for a fourth value --
    # splitting `no_string_subject` into the absent and wrongly-typed cases,
    # say -- without a second migration for the width alone. A `VARCHAR` plus
    # a CHECK rather than a Postgres `ENUM`, for the reason `refusal_reason`
    # gives: widening is one statement instead of an `ALTER TYPE` that cannot
    # run in the same transaction that uses it.
    #
    # NULL, with no server default: `customer_ref` is present on this row, or
    # the row predates this column. Those two are separated by `customer_ref`
    # itself on every row written since migration 3186c04c018c, and by `at`
    # against that migration's deploy time on the rows before it. No fourth
    # value marks "a customer reference was found" -- that fact is already in
    # `customer_ref`, and a value here saying it would be the same claim
    # stored twice, free to disagree with itself.
    customer_ref_absence_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Which tool call this row belongs to. One value per
    # `AuditMiddleware.on_call_tool` invocation, so the `reaching` row and the
    # `returned`/`raised` row for one call carry the same one and a reader can
    # put them back together.
    #
    # NOT `request_id`, and the difference decides whether the pairing works
    # at all. `request_id` is the JSON-RPC id the CLIENT chose, and its own
    # comment above says it is genuinely absent sometimes -- no
    # `fastmcp_context`, or a `Context.request_id` that raises -- with the row
    # written anyway, because a missing identifier must never become a missing
    # audit row. Two rows keyed on a column that is NULL on both are not a
    # pair, they are two orphans, and they go missing in exactly the degraded
    # conditions where an investigator most wants them joined. This column is
    # minted server-side (`uuid.uuid4()`, `services/api/middleware/audit.py`)
    # from nothing the caller supplies and has no absent case: every row this
    # application writes from now on carries one.
    #
    # NULLABLE at the column level, and only for rows written before
    # migration 71a4c0d9e3b2. A `NOT NULL` column cannot be added to a table
    # with rows in it without a default or a backfill, and this table is
    # append-only and regulator-facing: a backfill would be the only UPDATE
    # it has ever taken (the reasoning
    # `ck_audit_log_customer_ref_xor_absence` below already spells out), and
    # a default would invent a correlation between rows that were never
    # correlated. So NULL here means "this row predates the column", the same
    # meaning `duration_ms` and `request_id` carry.
    #
    # THE DATABASE STILL ENFORCES IT on every new row, through
    # `ck_audit_log_call_id_present` below rather than through this column's
    # own nullability. `NOT NULL` and a `CHECK ... NOT VALID` are not the
    # same trade: the first cannot skip the existing rows, the second is
    # created unvalidated, so PostgreSQL never scans them and enforces on
    # every INSERT from that point on -- which on an append-only table is
    # every row that will ever be written. This repository already made that
    # choice once, for the xor constraint in migration 3186c04c018c.
    #
    # `String(36)`: `str(uuid.uuid4())` is exactly 36 characters, and unlike
    # `tool_name` or `request_id` this value is not agent-controlled, so there
    # is no over-length input to clamp and no reason to leave headroom for one.
    # Stored as text rather than as PostgreSQL `uuid` so a regulator or a DBA
    # reads it out of a `SELECT` unchanged and greps a log for the same string,
    # which is the whole use; the 16-byte-per-row saving is not worth a type
    # that renders differently in every client.
    #
    # NO INDEX, stated rather than left to be discovered. Pairing a row with
    # its partner (`WHERE call_id = ...`) and the query this shape exists for
    # -- entry rows with no completion row, an anti-join on this column --
    # both scan the table today. The index was left out because an audit table
    # is write-heavy and read-rarely and nothing in this repository queries
    # this column yet; whoever writes the first such query should add it
    # deliberately, with the write cost in view, rather than inherit one
    # nobody sized.
    call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)

    __table_args__ = (
        Index("ix_audit_log_customer_at", "customer_ref", "at"),
        # The closed set is enforced by the database, not by convention.
        # Unlike `tool_name` or `arguments`, nothing an agent sends can
        # reach this column: every value is chosen by
        # `services/api/consent.py`, so the only way an unlisted string
        # arrives at the INSERT is a code change that added a refusal reason
        # without the migration that widens this constraint.
        #
        # The cost is stated rather than left to be discovered. Under the
        # fail-closed policy (docs/decisions/0006-audit-write-failure.md) a
        # violation costs the entire audit row and fails the call, and it
        # would land on exactly the refusal rows this column exists to
        # record. That is the same trade that record already made: a loud,
        # bounded failure beats an undocumented string sitting in a
        # regulator-facing table, silently missed by every query that
        # filters on the documented ones.
        #
        # NULL is admitted without being listed: `NULL IN (...)` evaluates
        # to NULL, and a CHECK constraint passes unless it evaluates FALSE.
        CheckConstraint(
            column("refusal_reason").in_(REFUSAL_REASONS),
            name="ck_audit_log_refusal_reason",
        ),
        # The same enforcement for `outcome`, which went without one for five
        # revisions while the two columns added after it both got one. The
        # asymmetry was the argument for adding it: a new value in this column
        # needed no migration and no review of what the vocabulary is, which
        # is how a fourth outcome nobody documented arrives in a
        # regulator-facing table and every query filtering on the documented
        # three silently stops seeing it.
        #
        # NOT NULL on the column itself, so unlike the two constraints around
        # it this one admits no NULL: `audit.append` requires the value and
        # every row that has ever existed carries one.
        #
        # Same cost as the others under the fail-closed policy
        # (docs/decisions/0006-audit-write-failure.md): a violation costs the
        # whole audit row and the call. Nothing an agent sends can reach this
        # column -- all three values are literals chosen by
        # `services/api/middleware/audit.py` -- so the only way an unlisted
        # string reaches an INSERT is a code change that added an outcome
        # without the migration that widens this constraint, which is the
        # failure this is for.
        CheckConstraint(
            column("outcome").in_(OUTCOMES),
            name="ck_audit_log_outcome",
        ),
        # Every row written since migration 71a4c0d9e3b2 carries a
        # correlation key. `call_id` stays nullable at the column level for
        # the rows that predate it; this is what makes the absence
        # unreachable for every row after it, and it is the whole reason the
        # guarantee is not merely "`audit.append` requires the parameter".
        #
        # PRE-EXISTING ROWS ALL VIOLATE THIS -- every one of them has NULL in
        # a column that did not exist -- so the migration creates it
        # `NOT VALID`, exactly as 3186c04c018c does for the xor constraint
        # and for exactly the same reason. The trailing cost is the same one
        # too: `pg_constraint.convalidated` stays false, and running
        # `VALIDATE CONSTRAINT` later scans the table and fails on those
        # rows, so it is not a tidy-up to run blind. SQLAlchemy's
        # `CheckConstraint` cannot express `NOT VALID`; a database built from
        # this metadata rather than from the migrations would get a validated
        # one, which on an empty table is the same thing, and no such path
        # exists in this repo (tests run `alembic upgrade head`).
        CheckConstraint(
            "call_id IS NOT NULL",
            name="ck_audit_log_call_id_present",
        ),
        # A touch instant sits on exactly the rows that describe a touch.
        # Both halves are enforced and each rules out a different false row:
        # a `reaching` row without one cannot answer the question the column
        # was added for, and a `returned` or `raised` row with one would hold
        # a second copy of a fact its partner row already carries, free to
        # disagree with it.
        #
        # An equality of two predicates, the shape and the parenthesisation
        # care `ck_audit_log_customer_ref_xor_absence` below explains. Unlike
        # the `IN` constraints above this one admits nothing by NULL: both
        # sides are TRUE or FALSE on every row, since `outcome` is NOT NULL
        # and `IS NOT NULL` is never itself NULL.
        #
        # Built from `OUTCOME_REACHING` rather than from a literal, for the
        # reason the top of this module gives: the constant and the
        # constraint that depends on it cannot drift apart. Migration
        # 9a7d4e51c6f8 hardcodes its own copy, deliberately, exactly as the
        # three revisions before it do.
        #
        # Created `NOT VALID` there, like the two constraints above it: every
        # row that predates that revision has NULL here, and the `reaching`
        # ones among them would fail. Same trailing cost -- `convalidated`
        # stays false, and a later `VALIDATE CONSTRAINT` scans the table and
        # fails on exactly those rows.
        #
        # Under the fail-closed policy
        # (docs/decisions/0006-audit-write-failure.md) a violation costs the
        # row and the call. Nothing an agent sends reaches either column, so
        # only a code change that writes one without the other can trigger
        # it, which is the failure this exists for.
        CheckConstraint(
            f"(outcome = '{OUTCOME_REACHING}') = (reaching_at IS NOT NULL)",
            name="ck_audit_log_reaching_at_matches_outcome",
        ),
        # Same enforcement, same reasoning, for the absence vocabulary: every
        # value is chosen by `services/api/middleware/audit.py`'s
        # `_customer_ref`, never by an agent, so the only way an unlisted
        # string reaches an INSERT is a code change that added a class of
        # absence without the migration that widens this constraint. NULL is
        # admitted without being listed, because `NULL IN (...)` evaluates to
        # NULL and a CHECK passes unless it evaluates FALSE.
        CheckConstraint(
            column("customer_ref_absence_reason").in_(CUSTOMER_REF_ABSENCE_REASONS),
            name="ck_audit_log_customer_ref_absence_reason",
        ),
        # Every row carries either a customer reference or a reason it has
        # none. Never both, never neither.
        #
        # This is what makes the one-predicate search above trustworthy. A
        # row with neither would be a NULL `customer_ref` whose class of
        # absence went unrecorded, which is the exact defect this column was
        # added to remove, silently reintroduced one code path at a time; a
        # row with both would be a reason contradicting the reference sitting
        # beside it, and nothing in the table would say which to believe.
        # Written with the two `IS NULL` tests parenthesised: in PostgreSQL
        # `IS` binds LOOSER than `=`, so the unparenthesised form parses as
        # something else entirely rather than as this comparison.
        #
        # The cost, under this repo's fail-closed audit policy
        # (docs/decisions/0006-audit-write-failure.md): a violation costs the
        # entire audit row AND fails the tool call, including a call that
        # otherwise succeeded. It can only fire on a future code change,
        # since `_customer_ref` returns exactly one of the two by
        # construction and `audit.append` takes both as required parameters.
        # That is the same trade `ck_audit_log_refusal_reason` above already
        # made, and the failure is loud and immediate rather than a
        # regulator-facing table quietly filling with rows no query can
        # classify.
        #
        # PRE-EXISTING ROWS WOULD VIOLATE THIS. Every row written before
        # migration 3186c04c018c has NULL for both columns whenever its call
        # had no customer, so adding this as an ordinary validated constraint
        # would fail the migration outright on any database that has ever
        # recorded one -- and no test would have caught it, since every test
        # database is built by `alembic upgrade head` against an empty table
        # (tests/conftest.py). That migration therefore creates it
        # `NOT VALID`: PostgreSQL skips the scan of existing rows and still
        # enforces the constraint on every INSERT and UPDATE from that point
        # on, which on an append-only table is every row that will ever be
        # written. The old rows keep the meaning this column's own comment
        # gives them (NULL means the row predates the column) instead of
        # being rewritten by a backfill, which on an append-only,
        # regulator-facing table would be the only UPDATE it has ever taken.
        # The trailing cost is that `pg_constraint.convalidated` stays false
        # for this constraint: running `VALIDATE CONSTRAINT` later scans the
        # whole table and fails on exactly those pre-migration rows, so it
        # needs a decision about them first. SQLAlchemy's `CheckConstraint`
        # cannot express `NOT VALID`, so a database built from this metadata
        # rather than from the migrations gets a validated constraint -- no
        # such path exists in this repo (tests run `alembic upgrade head`,
        # tests/conftest.py), and on an empty table the two are the same
        # thing.
        CheckConstraint(
            "(customer_ref IS NULL) = (customer_ref_absence_reason IS NOT NULL)",
            name="ck_audit_log_customer_ref_xor_absence",
        ),
    )

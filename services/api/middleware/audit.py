"""One audit row per tool call, success or failure.

Failures reach `on_call_tool` as RAISED EXCEPTIONS: the `isError: true`
envelope is built above the middleware chain, so a hook inspecting
`result.is_error` records zero failures. Measured, 2026-09-14.

`detail` records the exception TYPE and never its message: a
`pydantic.ValidationError` message embeds the raw offending value, which is
the leak path CLAUDE.md's hard rule describes, and an audit table is a
long-lived store.

`refusal_reason` is TRANSCRIBED here, never inferred. A consent denial and a
mistyped tool name both arrive as one `NotFoundError`, so this module cannot
tell them apart from what it can see: the exception type is identical, and
reading the reason out of a message string would couple the audit row to
wording nobody promised to keep. `services/api/consent.py` is the only place
that knows it refused and which of its refusals it made, so it files that
decision and this module copies it onto the row. A future third refusal
reason therefore changes that module and this one's vocabulary, not this
module's logic.

`customer_ref_absence_reason` is the opposite: DERIVED here, because this is
the only place that sees the access token at all. It records which of three
things left `customer_ref` NULL -- no token, no usable `sub`, or a `sub` that
failed `CustomerRef` -- and never the subject that failed, for the reason
`_customer_ref` gives below.
"""

import logging
import time
from datetime import datetime
from typing import Any, NamedTuple

from fastmcp.server.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams
from postern_core.domain.masking import FreeText, redaction_budget
from postern_core.identity import CustomerRef
from postern_core.store import audit
from postern_core.store.engine import Database
from postern_core.store.models import (
    ABSENCE_NO_ACCESS_TOKEN,
    ABSENCE_NO_STRING_SUBJECT,
    ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
)
from pydantic import TypeAdapter, ValidationError

from services.api import consent

logger = logging.getLogger(__name__)

_FREE_TEXT: TypeAdapter[str] = TypeAdapter(FreeText)

# `tool_name` is `String(64)` (models.py); `context.message.name` is
# arbitrary agent-controlled text with no length limit of its own. A name
# over 64 characters reaches `on_call_tool` fine but blows up the INSERT
# with `asyncpg.exceptions.StringDataRightTruncationError`, turning "audit a
# failed call" into "the audit write itself raises", which replaces the
# tool's own error with a database error and leaves zero rows. Clamp before
# writing, not before calling the tool.
#
# Accepted trade, not a full fix: two distinct oversized names that share
# the same first 64 characters collapse to the same recorded value, so an
# abuse-detection reader cannot tell one probe repeated 500 times from 500
# distinct probes, and nothing marks a row as truncated, so a genuine
# 64-character name is indistinguishable from a clipped 200-character one.
# Losing the row entirely, the alternative, is worse.
#
# A second, unrelated collision lands on this same field: `_scrub` masks a
# PAN- or IBAN-shaped tool name to a fixed form (`•••• NNNN` for a PAN,
# `XX•• •••• NNNN` for an IBAN), so two different tool names that happen to
# share the same last four digits -- two distinct probe tools, say, or one
# probe repeated behind a different prefix -- collapse to the same recorded
# `tool_name`, and nothing in the row marks a name as having been masked at
# all. The identity field of the audit row is lossy with no flag.
#
# Accepted for the same reason as the truncation case above: the
# alternative is a raw PAN or IBAN sitting in a long-lived table, which is
# worse. It stays contained today because nothing reads this column beyond
# writing it -- no index, no foreign key, no query, no join anywhere in this
# codebase (verified by search, 2026-09-16) -- so no code path currently
# depends on two masked `tool_name` values being distinguishable. It STOPS
# being contained the first time someone writes a query that does -- a
# `GROUP BY tool_name` counting distinct tools called, or an alert rule
# keyed on this column -- at which point the query silently under-counts
# distinct PAN-/IBAN-shaped names, with nothing in the schema or the query
# itself hinting why. A marker column (e.g. a `masked: bool` alongside
# `tool_name`) would close this, but that is a schema change: migrations
# are out of this file's scope, and it belongs wherever `store/models.py`
# and its migrations are owned, not here.
_MAX_TOOL_NAME = 64

# `request_id` is `String(128)` (models.py), and the JSON-RPC id on the wire
# is chosen by the client, which makes its length as agent-controlled as the
# tool name above. Same failure mode, same fix: an over-long value reaches
# the INSERT and raises `asyncpg.exceptions.StringDataRightTruncationError`,
# which under this module's fail-closed policy costs the entire audit row
# and replaces the tool's own error. Clamped before the write. A truncated
# id still correlates with a client-side log whose id shares those first 128
# characters, which is the whole use for this column; nothing marks the row
# as truncated, exactly as with `tool_name`.
_MAX_REQUEST_ID = 128


def _scrub(value: Any) -> Any:
    """Redact PAN- and IBAN-shaped substrings anywhere in the argument tree,
    including dict keys, and strip NUL bytes.

    Keys matter as much as values here: arguments are captured before
    `call_next` validates them, so a key is just as agent-controlled as a
    value (e.g. `{"4111111111114417": "x"}`), and an unmasked key would
    persist a full PAN into a long-lived table exactly like an unmasked
    value would. Two distinct keys can collide onto the same masked string
    (`"41111111111111"` and `"241111111111111"` both end in `1111`); that
    silently drops one during the dict comprehension. That is the right
    trade for an audit log -- it must never hold the raw value either key
    started as -- but a reader needs to know it was a deliberate choice, not
    an oversight.

    NUL bytes are stripped BEFORE redaction, not after, and the order is
    load-bearing: `_PAN_IN_TEXT_RE` (`\\d{12,}`) matches a CONTIGUOUS run of
    12 or more digits, with the 19-digit PAN length cap applied separately
    when deciding what to emit, so a NUL planted inside a PAN splits it into
    two shorter runs that individually fail to match, and validation finds
    nothing to redact. Stripping the NUL afterwards then reassembles the
    full, unmasked PAN in the value that gets written -- one byte of
    attacker input surviving as a raw PAN in a long-lived store, and it
    reaches a dict KEY the same way, bypassing the key-masking above too.
    Stripping first removes the split before `FreeText` ever sees the
    string, so the contiguous run is there to match. Measured directly
    against every split position; do not swap this back to
    validate-then-strip, even though that reads more natural (validate the
    input, then clean it) -- it is the specific ordering this function must
    not have. `FreeText` not handling other separators (spaces, hyphens) is
    a separate, documented limitation (masking.py) with its own rationale;
    NUL is different only because this line is what reassembles it.
    """
    if isinstance(value, str):
        return _FREE_TEXT.validate_python(value.replace("\x00", ""))
    if isinstance(value, dict):
        return {_scrub(k): _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


class _Subject(NamedTuple):
    """What this call's access token yielded: a customer reference, or the
    class of absence that stands in for one.

    Exactly one field is ever non-None, which is the invariant
    `ck_audit_log_customer_ref_xor_absence` (models.py) enforces at the
    database: a row with neither is a NULL `customer_ref` whose cause went
    unrecorded, a row with both is a reason contradicting the reference next
    to it. Returning the pair from one function is what makes that structural
    rather than a rule two call sites have to remember -- the raised and
    returned branches of `on_call_tool` both write this same object's two
    fields, so neither can fill one in and forget the other.
    """

    customer_ref: str | None
    absence_reason: str | None


def _customer_ref(token: AccessToken | None) -> _Subject:
    """The token's `sub` claim, only when it conforms to `CustomerRef`, plus
    which of three absences produced the NULL when it does not.

    Mirrors `services.api.server.token_customer_resolver` rather than
    inventing a second validation path: identity.py's own warning is that a
    compromised issuer could mint a PAN-, IBAN- or DNI-shaped `sub`, and the
    tool path already refuses such a token with a `PermissionError` -- which
    arrives here as the very exception this middleware records, on the
    `except` branch. Persisting the raw, tool-path-rejected subject into
    `customer_ref` would be the one write that survives the refusal it
    documents. Storing `None` for a non-conforming subject, rather than
    raising, keeps this middleware's job (record the call) separate from the
    tool path's job (authorize the call).

    That `None` used to be the END of the record, and it said three different
    things at once: no access token at all, a token carrying no usable `sub`,
    and the compromised-issuer case the paragraph above describes. An
    investigator reading the audit table could not tell an attacker-minted
    subject from somebody calling without logging in. The second return
    value names which one happened, in the vocabulary
    `CUSTOMER_REF_ABSENCE_REASONS` (models.py) holds and a CHECK constraint
    closes, so the security case is one predicate on one column.

    Takes the whole token, not the `sub` it holds, because the caller cannot
    read the claim out without already having collapsed the first two cases:
    `token.claims.get("sub")` answers None both for a token without the claim
    and for no token at all. Doing the split here keeps all three classes in
    the one function that names them.

    What it never returns, on any branch, is the rejected string itself. The
    `except` below discards `subject` and reports its class, and the
    `ValidationError` is neither re-raised nor logged: `CustomerRef` sets
    `hide_input_in_errors`, which scrubs `str()` and `repr()` of that
    exception but leaves the raw value in its structured `.errors()` (see
    `token_customer_resolver`'s own comment on that). The class of absence is
    storable; the value that caused it is the PAN-, IBAN- or DNI-shaped
    string this function exists to keep out of the table.
    """
    if token is None:
        return _Subject(None, ABSENCE_NO_ACCESS_TOKEN)
    subject = token.claims.get("sub")
    if not isinstance(subject, str):
        return _Subject(None, ABSENCE_NO_STRING_SUBJECT)
    try:
        return _Subject(CustomerRef(value=subject).value, None)
    except ValidationError:
        return _Subject(None, ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF)


def _elapsed_ms(started: float) -> int:
    """Whole milliseconds since `started`, a `time.monotonic()` reading.

    `time.monotonic()` and not `datetime.now()`, `time.time()` or
    `context.timestamp`: a wall clock can step backwards under an NTP
    correction in the middle of a call and produce a negative or absurd
    duration, which lands in an append-only, regulator-facing table with
    nothing in the row marking it as a clock artefact. `monotonic` is
    guaranteed non-decreasing for the life of the process, which is exactly
    the span being measured here.

    Rounded DOWN (`int()` truncates a non-negative float toward zero), not
    to nearest: a floor can never report a call as slower than it was, and
    an over-reported latency on this table is a claim about the operator's
    own behaviour that the measurement does not support. The cost is a
    systematic under-report of up to one millisecond per row, stated here
    rather than left for a reader to discover.

    A call faster than a millisecond therefore records 0, never NULL. The
    two are different statements on this column (models.py): 0 means
    "measured, and it was under a millisecond", NULL means "no measurement
    exists for this row", which is true only of rows written before the
    column existed. Writing NULL for a fast call would make a live row
    indistinguishable from a pre-migration one.
    """
    return int((time.monotonic() - started) * 1000)


def _request_id(context: MiddlewareContext[CallToolRequestParams]) -> str | None:
    """The JSON-RPC id of the client request this call arrived on, or None.

    Absent in two distinct ways, both recorded as NULL rather than raised.
    `MiddlewareContext.fastmcp_context` is typed `Context | None` (fastmcp
    4.0.3, `fastmcp/server/middleware/middleware.py`), so there may be no
    context object at all; and `Context.request_id` is a PROPERTY that
    raises `RuntimeError` when `request_context` is None, i.e. when the MCP
    session is not established yet, so a non-None context is not enough on
    its own. An audit row must never be lost because an identifier was
    unavailable -- that would turn a missing correlation key into a missing
    audit trail, which is strictly worse -- so every failure to read it ends
    in None and the row is written regardless.

    The `except` is deliberately broad rather than `except RuntimeError`:
    `request_id` reaches through `request_context` into SDK state this
    module does not own and cannot pin the exception type of across
    versions, and the cost of being wrong about that type is the whole row.

    `str()` because a JSON-RPC id may be a string or a number; fastmcp's
    property already returns `str` today, and the coercion keeps this
    module's own contract independent of that. Truncated to
    `_MAX_REQUEST_ID` for the reason that constant documents.

    What the recorded id buys is TRACEABILITY, not deduplication: an
    investigator can tie one audit row to one client request and correlate
    it with client-side logs. It does not detect a retry. Under MCP
    2026-07-28 there is no SSE resumability, so a dropped stream makes the
    client re-issue the call, and the re-issued call genuinely carries a NEW
    id -- two rows that still read as two calls, because at the protocol
    level they were two requests. Nothing here collapses or counts them.
    """
    fastmcp_context = context.fastmcp_context
    if fastmcp_context is None:
        return None
    try:
        request_id = fastmcp_context.request_id
    except Exception:
        return None
    return str(request_id)[:_MAX_REQUEST_ID]


class AuditMiddleware(Middleware):
    def __init__(self, db: Database) -> None:
        self.db = db

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        # One allowance for the WHOLE tree, not one per string `_scrub`
        # happens to visit: without this, `FreeText` gives every string it
        # validates its own fresh checksum budget (masking.py's
        # `_IBAN_SCAN_BUDGET`), and an agent that spreads junk across many
        # short argument strings -- a list of them, say, rather than one
        # long one -- would buy a fresh allowance per element instead of
        # spending down one shared one. `redaction_budget` makes the
        # allowance ambient for this synchronous call only: see its
        # docstring for why a `ContextVar` rather than a module global, and
        # masking.py's `_redact_free_text` for the measured before/after.
        # Tool RESPONSES validated elsewhere (through pydantic models on
        # data returned from the operator's own backend) do NOT opt in and
        # keep a fresh per-string budget each -- a deliberate choice, not an
        # oversight: that data is not agent-controlled the way tool
        # arguments are, so splitting it into many strings is not an
        # attacker's lever the way it is here.
        #
        # The NAME is scrubbed here too now, through the same `_scrub` path
        # as `arguments`, in this SAME scope -- not a second
        # `redaction_budget()` block of its own. `context.message.name` is
        # exactly as agent-chosen as any argument value: `_MAX_TOOL_NAME`
        # (64) leaves room for a 16-digit PAN or a 31-character IBAN, and an
        # agent that wants one in the operator's audit table does not need an
        # argument at all, it names a tool after one. A separate scope for
        # the name alone would quietly reintroduce a per-string allowance
        # for exactly the value this fix exists to close, defeating the one
        # allowance-per-call invariant the shared scope holds.
        #
        # Scrubbed BEFORE the arguments, deliberately: the name is bounded
        # (clamped to `_MAX_TOOL_NAME` first, so the scan itself is bounded
        # too) while the arguments are not, and a bounded value can only
        # spend a small, fixed amount of the shared allowance -- measured
        # directly against this module's own worst-case shape (a
        # letter-letter-digit-digit opener repeated across the full 64
        # characters, the maximum density `_find_iban_in_token` allows,
        # confirmed by exhaustive derivation over every start position): 223
        # checksums against the 100,000-checksum default, 0.223% of one
        # call's allowance. That percentage is the durable number -- a
        # count of names needed to exhaust the budget outright would be a
        # ratio pinned to `_IBAN_SCAN_BUDGET`'s current value, which has
        # already moved once in this module's history and is fixed by no
        # test, so it is left out rather than stated as if it were stable.
        # An ordinary name (`ok_tool`, `transactions.list`, ...) costs zero
        # checksums -- it never reaches a letter-letter-digit-digit opener
        # at all. Scrubbing this first therefore cannot meaningfully starve
        # the arguments that follow.
        #
        # The converse does not hold for an IBAN-shaped name: scrubbing the
        # name LAST would let an agent that pads its own arguments to
        # exhaust the shared budget get its own IBAN-shaped tool name
        # bare-masked to `••••` as a side effect of that exhaustion
        # (`_redact_iban_match`'s `budget.exhausted` branch) -- verified
        # live, by swapping the order -- destroying the one field an
        # investigator uses to know WHAT was called. A PAN-shaped name is
        # immune to that specific failure: `_redact_pan_match` spends no
        # budget at all, so a PAN-shaped name resolves identically
        # regardless of exhaustion or ordering (also verified live, e.g.
        # `"tool_4111111111114417"` still comes back
        # `"tool_•••• 4417"` even against an already-exhausted budget). The
        # IBAN case alone is enough to require scrubbing the name first;
        # getting it right for both shapes, rather than relying on one
        # shape's accident, is the point. Losing argument detail degrades a
        # row; losing the name degrades the row's identity.
        with redaction_budget() as scope:
            name = _scrub(context.message.name[:_MAX_TOOL_NAME])
            # `_scrub`'s two substitutions never lengthen a match: the
            # shortest possible PAN run (12 digits) becomes `"•••• " +` its
            # last four (9 characters), and the shortest possible IBAN match
            # (14 characters) becomes a fixed 14-character mask; anything
            # longer than either minimum only shrinks further, or (an
            # over-length run, or an ambiguous IBAN token) collapses to the
            # 4-character bare marker. `_strip_invisible` only ever removes
            # characters. Confirmed by direct measurement (see
            # `tests/test_audit_middleware.py`), fuzzed across shapes up to
            # 64 characters plus every real PAN/IBAN in this module's own
            # fixtures at every padding offset: growth was never observed.
            #
            # That guarantee is in CHARACTERS, not bytes, and the distinction
            # is not academic: `_MASK` ("••••") is U+2022 BULLET, 3 bytes
            # each in UTF-8, so masking can grow a string's BYTE length even
            # while shrinking or holding its CHARACTER length -- verified
            # live, four 15-character IBANs joined by "." (63 characters)
            # scrub to 59 characters but 107 UTF-8 bytes. This is safe here
            # only because `audit_log.tool_name` is Postgres `VARCHAR(64)`
            # (models.py), and `VARCHAR`'s length argument is a character
            # count, not a byte count. A byte-counted column (e.g. a
            # `bytea`, or a `VARBINARY` on another database) would need a
            # bound on `len(name.encode())`, not on `len(name)`, and this
            # comment's "never lengthens" claim would not transfer to it
            # unchanged.
            #
            # `tool_name` is the same column the un-scrubbed clamp above
            # already exists to protect (see `_MAX_TOOL_NAME`'s own
            # docstring), so this second clamp is kept as a cheap fail-safe
            # against a future change to `_scrub`'s substitution lengths --
            # or to the column's own type -- not because today's masking
            # can trigger it.
            if len(name) > _MAX_TOOL_NAME:
                name = name[:_MAX_TOOL_NAME]
            arguments = _scrub(dict(context.message.arguments or {}))
        # One call, two fields, exactly one of them non-None: see `_Subject`
        # for why the pair is returned together rather than derived twice.
        subject = _customer_ref(get_access_token())
        at = context.timestamp
        request_id = _request_id(context)

        # Started HERE, on the line before `call_next`, and read on both the
        # returned and the raised path: the recorded number means "how long
        # the tool took", not "how long this middleware spent scrubbing".
        # The `_scrub` pass above is unbounded in the argument tree it walks
        # (masking.py spends up to a 100,000-checksum allowance on one
        # call), so including it would let an agent inflate its own recorded
        # duration by padding its arguments, and would blur the one thing an
        # investigator reads this column for: which TOOL was slow.
        started = time.monotonic()
        try:
            result = await call_next(context)
        except Exception as exc:
            # A failing call has a duration too, and a SLOW failure -- a
            # backend timeout, a lock held to the end of a transaction -- is
            # exactly the shape an investigator looks for, so this branch
            # records one from the same `started` reading rather than
            # leaving NULL and making the row indistinguishable from a
            # pre-migration one. Read before `_write`, on both paths, so the
            # audit write's own database round trip is never attributed to
            # the tool.
            duration_ms = _elapsed_ms(started)
            # Read here and not before `call_next`, because the consent
            # check runs INSIDE it: FastMCP evaluates a tool's `auth=` in
            # `_get_tool` (`fastmcp/server/server.py:886-915`), which the
            # dispatch this `call_next` reaches calls before the tool body,
            # so a denial is always filed by the time this line runs.
            #
            # Keyed on the RAW requested name, not the scrubbed `name` about
            # to be written: `consent._refuse` files its decision under the
            # registered tool's own name, which is the name the client asked
            # for, while `name` may have been clipped to `_MAX_TOOL_NAME` or
            # masked by `_scrub`. Neither of those can be a registered tool,
            # so the lookup can only miss for them, and a miss records NULL
            # -- under-reporting a refusal instead of inventing one.
            refusal_reason = consent.refusal_for(context.message.name)
            # Fail closed (docs/decisions/0006-audit-write-failure.md): an
            # audit-write failure here must never become the exception the
            # caller sees. Before this, an exception from `_write` replaced
            # `exc` by propagating unchanged, which put the DATABASE's
            # exception on the wire in place of the TOOL's -- through
            # implicit `__context__` chaining, since raising while already
            # handling `exc` sets that automatically. `raise exc from
            # audit_exc` re-raises the original exception OBJECT (same type,
            # same message, so `FastMCPError` handling above this middleware
            # still applies to it as before) and attaches the audit failure
            # as its explicit `__cause__` instead, so a traceback shows both
            # without either one hiding the other. The audit failure is
            # logged separately too: `__cause__` only helps someone already
            # looking at a traceback for this one call, and an outage needs
            # to be visible without one.
            try:
                await self._write(
                    at,
                    subject.customer_ref,
                    subject.absence_reason,
                    name,
                    arguments,
                    "raised",
                    type(exc).__name__,
                    scope.exhausted,
                    duration_ms,
                    request_id,
                    refusal_reason,
                )
            except Exception as audit_exc:
                logger.error(
                    "audit write failed for tool %r after it raised %s: %s",
                    name,
                    type(exc).__name__,
                    audit_exc,
                    exc_info=audit_exc,
                )
                raise exc from audit_exc
            raise
        # Same reading, taken before the write for the reason the raised
        # path above states: `_write`'s own database round trip is not the
        # tool's latency by any reading, and it is the slowest thing in this
        # function.
        duration_ms = _elapsed_ms(started)
        try:
            await self._write(
                at,
                subject.customer_ref,
                subject.absence_reason,
                name,
                arguments,
                "returned",
                None,
                scope.exhausted,
                duration_ms,
                request_id,
                # NULL, written literally rather than looked up. A tool that
                # returned a result was not refused: a denied `auth=` check
                # makes `_get_tool` answer None and the dispatch raise
                # `NotFoundError`, so a refused call never reaches this
                # line. Passing the constant makes "outcome='returned'
                # implies refusal_reason IS NULL" a property of this
                # function, instead of a property of whatever the consent
                # module happens to have left on the request -- which, for
                # one `tools/call` carrying arguments, is a decision for
                # every consent-gated tool on the server, not just this one
                # (see `services/api/consent.py`'s module docstring).
                None,
            )
        except Exception as audit_exc:
            # Fail closed here too, and deliberately rather than by
            # accident: the audit table is the artefact a regulator asks
            # for, and CLAUDE.md's operating assumption is that the caller
            # is under adversarial influence at all times -- a call that ran
            # but left no audit trail is worse than a call that failed
            # loudly. The cost is real and is not hidden: a database outage
            # now takes down every tool call, including ones that would
            # otherwise have succeeded. See
            # docs/decisions/0006-audit-write-failure.md for the rejected
            # alternative (write-through-and-log) and the reasoning.
            logger.error(
                "audit write failed for tool %r after it returned successfully; "
                "failing the call because the audit row could not be written",
                name,
                exc_info=audit_exc,
            )
            raise
        return result

    async def _write(
        self,
        at: datetime,
        customer: str | None,
        # Required, no default, and passed straight from the `_Subject` the
        # line above's `customer` came from: the two are one decision, made
        # once per call by `_customer_ref`, and both branches of
        # `on_call_tool` hand over the same object's two fields. A default
        # would let a future branch write NULL next to a NULL `customer`,
        # which `ck_audit_log_customer_ref_xor_absence` (models.py) rejects
        # -- costing the audit row and, under the fail-closed policy, the
        # call -- and would erase the difference between an anonymous call
        # and an issuer-minted PAN at the one point where it is still known.
        customer_ref_absence_reason: str | None,
        name: str,
        arguments: dict[str, Any],
        outcome: str,
        detail: str | None,
        redaction_budget_exhausted: bool,
        # Required, no default, matching `audit.append`'s own parameters:
        # this is the only call site that reaches `append` outside tests,
        # and it is reached from both branches of `on_call_tool`, each of
        # which measures its own value. A default here would let a future
        # branch record NULL, which on `duration_ms` means "this row
        # predates the column" (models.py) and would be false.
        duration_ms: int,
        request_id: str | None,
        # Required, no default, for the reason `duration_ms` and
        # `request_id` above are: the raised branch asks
        # `consent.refusal_for` and the returned branch writes None by
        # construction, so both callers hold a real answer. A default would
        # let a future branch record "not refused" without either branch's
        # reasoning behind it, on the one column that distinguishes a
        # consent record from an agent's typo.
        refusal_reason: str | None,
    ) -> None:
        async with self.db.sessionmaker() as session:
            await audit.append(
                session,
                at=at,
                customer_ref=customer,
                customer_ref_absence_reason=customer_ref_absence_reason,
                tool_name=name,
                arguments=arguments,
                outcome=outcome,
                detail=detail,
                redaction_budget_exhausted=redaction_budget_exhausted,
                duration_ms=duration_ms,
                request_id=request_id,
                refusal_reason=refusal_reason,
            )

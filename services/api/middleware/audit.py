"""Up to two audit rows per tool call: one before the operator touches
customer data, one after the call finishes.

WHY TWO. Until 2026-09-18 this module wrote a single row AFTER `call_next`,
which meant the backend was reached first and the record was attempted
afterwards. `tests/test_request_deadline.py` measured what that costs: with
the audit store on a path silent in both directions, consent answered, the
tool ran, the operator's backend served the customer's accounts, the edge
deadline cancelled the request, and `audit_log` held ZERO rows -- not a
partial row, one `AuditEntry` in one transaction that never committed. capo
ruled the same day that this table records customer data the operator
TOUCHED, not calls it served, so that is a missing row rather than a
documentation gap.

The entry row (`outcome='reaching'`) is committed in its own transaction
before the first backend request of the call, and fails closed
(dev-docs/decisions/0006-audit-write-failure.md). That inverts the failure mode:
an audit outage used to mean data touched with nothing recorded, and now
means the backend is never reached at all.

IT FAILS CLOSED DIFFERENTLY FROM THE OTHER TWO WRITES, in three ways worth
having before reading further. MECHANISM: the completion writes are caught
and re-raised by `on_call_tool` itself, while this one propagates up through
the facade and the tool body, so the guarantee now also depends on no
intermediate frame swallowing it -- nothing does today, and nothing enforces
that. ENVELOPE: because it raises inside the tool, FastMCP returns it as
`CallToolResult(is_error=True)` in an HTTP 200, where a completion-write
failure escapes `on_call_tool` and becomes a top-level JSON-RPC error
(measured both ways in `tests/test_asgi_app.py`). LOGGING: it needs its own
ERROR line, because the middleware never sees it -- `_PendingEntry.record`
carries that line and says why.

Under a cancellation the shape is: entry row committed, tool body runs,
deadline fires, no completion row ever written. The table then says "we
touched this, no outcome was recorded", which is the true statement.

WHERE THE ENTRY ROW IS WRITTEN FROM, and why not from here. This middleware
runs OUTSIDE `call_next`, and FastMCP evaluates a tool's `auth=` consent
check inside `fastmcp/server/server.py::_get_tool`, which `call_next`
reaches (`services/api/consent.py` cites it too). A
write at the top of `on_call_tool` would therefore land before authorization
was decided: its `refusal_reason` could only ever be NULL, and a call consent
then REFUSED -- which touches nothing -- would get an entry row recording an
intent rather than a touch. So the write is bound here and INVOKED from
`postern_core.facade.client.BackendClient`, immediately before its first HTTP
request, which is the actual data-touch boundary. `record_data_touch` below
is the seam; `_PendingEntry` is what this module pre-binds so the façade
never learns a tool name, an argument dict, or that a store exists.

A consent-denied call therefore still produces exactly ONE row, unchanged:
`outcome='raised'`, `detail='NotFoundError'`, with the refusal reason. So
does any call that fails before its first backend request, and so does one
whose tool reaches no backend at all.

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

import asyncio
import logging
import time
import uuid
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, NamedTuple

from fastmcp.exceptions import DisabledError, FastMCPError, NotFoundError
from fastmcp.server.auth import AccessToken
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.shared.exceptions import MCPError
from mcp.types import INTERNAL_ERROR, CallToolRequestParams
from postern_core.auth.revocation import RevocationStoreUnavailable, RevokedError
from postern_core.domain.masking import redaction_budget, scrub_tree
from postern_core.identity import CustomerRef
from postern_core.log_safety import (
    describe_exception,
    exc_info_for_log,
)
from postern_core.risk.session import SessionStoreUnavailable, get_current_session
from postern_core.risk.types import RiskActionError
from postern_core.store import audit
from postern_core.store.audit import (
    ARGUMENTS_TRUNCATED_KEY,
    MAX_ARGUMENT_VALUE,
    MAX_ARGUMENTS_BYTES,
    TRUNCATED,
    bound_arguments,
    cap_arguments,
    clamp,
    clip_tree,
)
from postern_core.store.engine import Database
from postern_core.store.models import (
    ABSENCE_NO_ACCESS_TOKEN,
    ABSENCE_NO_STRING_SUBJECT,
    ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
    OUTCOME_RAISED,
    OUTCOME_REACHING,
    OUTCOME_RETURNED,
)
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from services.api import consent

logger = logging.getLogger(__name__)

# `_scrub` IS NO LONGER DEFINED HERE. It was this module's own function until
# 2026-09-23, when the write path needed the same masking and
# `services/confirm/execute.py` was found to be carrying a second, weaker copy
# of it -- one that validated through `FreeText` without the NUL strip, so a
# NUL-split PAN in a backend error body was reassembled unmasked. Rather than
# write a third copy, both branches were promoted to
# `postern_core.domain.masking` as `scrub_text` and `scrub_tree`, which is
# where `FreeText`, `redaction_budget` and the validator they call already
# live. The reasoning that used to sit in this file's docstring for it --
# above all WHY the NUL strip precedes the contiguous-digit match, which is
# the one ordering this function must not have -- went with the code rather
# than staying behind in the file that no longer has it.
#
# Re-bound to the old private name on purpose, as an assignment rather than
# an `import ... as` so it stays an explicit export that
# `tests/test_audit_middleware.py` can keep importing unchanged. Every comment
# in this module that reasons about `_scrub`'s cost, its bare-masking of
# over-length runs, and its never lengthening a value in characters still
# describes exactly the function being called, so the rebinding keeps them
# true without a rewrite. The behaviour is identical -- `scrub_tree` is the
# same four branches in the same order, and `scrub_text` calls
# `_redact_free_text` directly where this file went through
# `TypeAdapter(FreeText)`, which for a `str` argument is the same operation.
_scrub = scrub_tree

# NEITHER ARE THE ARGUMENT BOUNDS, AS OF 2026-09-24, and for the same reason
# `_scrub` above is no longer defined here. `_TRUNCATED`, `_clamp`,
# `_clip_tree`, `_cap_arguments` and the four constants behind them were this
# module's own until the write path needed the identical bounds on
# `services/confirm/audit.py`'s five-key tree -- which has no body-size
# middleware in front of it and writes a row on every refused approval, so its
# exposure to the same defect is strictly worse than this module's was.
# `.importlinter` forbids the two services importing each other in either
# direction, so a second copy in `services/confirm` was the only alternative
# to promoting them, and `services/confirm/audit.py` had ALREADY carried a
# second copy of `_TRUNCATED` and `_clamp` since 2026-09-23 with a comment
# naming `postern_core.store.audit` as where a third copy should go instead.
# It went there. The reasoning for every constant went with the code rather
# than staying behind in the file that no longer has it.
#
# Re-bound to the old private names on purpose, as assignments rather than
# `import ... as`, so they stay explicit exports that
# `tests/test_audit_arguments_cap.py` and `tests/test_audit_middleware.py`
# can keep importing unchanged -- exactly the shape `_scrub` above uses. The
# behaviour is identical: the promoted functions are the same code, and
# `_arguments` below composes them through `bound_arguments`, which is
# `cap_arguments(clip_tree(...))` in that fixed order.
#
# What it does NOT claim, still true of `_TRUNCATED` here: a JSON-RPC id is
# an arbitrary client-chosen JSON value, so a client can put U+2026 at the
# end of a 128-character id on purpose and make that one row ambiguous. No
# in-value marker can close that; a column could. A registered tool name
# cannot reach the ambiguity at all -- U+2026 is not a Python identifier
# character, so no `@server.tool` function name contains one.
_TRUNCATED = TRUNCATED
_clamp = clamp
_clip_tree = clip_tree
_cap_arguments = cap_arguments
_MAX_ARGUMENT_VALUE = MAX_ARGUMENT_VALUE
_MAX_ARGUMENTS_BYTES = MAX_ARGUMENTS_BYTES
_ARGUMENTS_TRUNCATED_KEY = ARGUMENTS_TRUNCATED_KEY

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
# distinct probes. What that reader CAN now tell is that the value is a
# prefix at all: a clipped name is cut to 63 characters and ends in
# `_TRUNCATED`, so a genuine 64-character name no longer reads the same as a
# clipped 200-character one. Losing the row entirely, the alternative to
# clamping, is worse than either.
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
# id still correlates with a client-side log whose id shares those first 127
# characters, which is the whole use for this column, and it ends in
# `_TRUNCATED` so the investigator doing that correlation knows to match a
# prefix rather than the whole string -- exactly as with `tool_name`.
_MAX_REQUEST_ID = 128

# `client_id` is `String(512)` (models.py), and that column's own comment
# carries the width decision and the two measured costs behind it. What
# belongs here is the same failure this file's other two bounds exist to
# avoid: a value wider than the column raises
# `asyncpg.exceptions.StringDataRightTruncationError` at the INSERT, which
# under dev-docs/decisions/0006-audit-write-failure.md costs the whole audit row
# and the tool call.
#
# The value is NOT agent-chosen, which is the difference from `_MAX_TOOL_NAME`
# and `_MAX_REQUEST_ID` above: it comes off an `AccessToken` this server
# already verified against its configured JWKS and issuer, so producing an
# over-length one takes the issuer's signing key, not a crafted `tools/call`.
# That lowers the likelihood and changes nothing about the consequence, which
# is why the bound is here at all.
_MAX_CLIENT_ID = 512


def _arguments(raw: dict[str, Any] | None) -> dict[str, Any]:
    """What one `tools/call` carried, scrubbed and bounded, for both of its
    rows.

    MUST BE CALLED INSIDE `on_call_tool`'s `with redaction_budget()` BLOCK
    and never inside a second one of its own, for the reason `_client_id`
    states: the scrub below spends from whichever `_ScanBudget` is ambient,
    and a private scope would buy this tree its own allowance on top of the
    one the call already has.

    ONE VALUE, BOTH ROWS. `on_call_tool` computes this once and hands the
    same object to `_PendingEntry` (which writes the `reaching` row) and to
    `_write` (which writes the `returned` or `raised` one), so the bound
    cannot apply to one row and miss the other -- there is only one tree.
    That is pinned by a test rather than left as a reading of the code, in
    `tests/test_audit_arguments_cap.py`.

    `bound_arguments` rather than the two calls spelled out, since 2026-09-24:
    it IS `cap_arguments(clip_tree(...))`, and it exists so that this module
    and `services/confirm/audit.py` cannot come to compose them in different
    orders. Clip before cap is what lets the per-value bound rescue a tree the
    tree bound would otherwise drop whole.
    """
    return bound_arguments(_scrub(dict(raw or {})))


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


def _client_id(token: AccessToken | None) -> str | None:
    """Which OAuth client made this call, scrubbed and clamped to
    `_MAX_CLIENT_ID`, or None when the call carried no access token.

    MUST BE CALLED INSIDE `on_call_tool`'s `with redaction_budget()` BLOCK,
    and never inside a second one of its own. The scrub below spends from
    whichever `_ScanBudget` is ambient, and the one allowance-per-call
    invariant that block holds is exactly what a private scope would
    reintroduce a hole in -- the same hole the tool NAME's own scrub was
    moved into that block to close.

    None means "no access token on this call", which is a live state and not
    a failure: `get_access_token()` returns None for every call arriving over
    the in-process `fastmcp.Client(transport=server)` transport, and
    `_customer_ref` above reports the same absence as
    `ABSENCE_NO_ACCESS_TOKEN`. Both values come from the one token this
    middleware reads per call, so the two can never contradict each other.

    SCRUBBED, unlike anything else that reaches this row from a verified
    token, and the reason is one fallback rather than a general distrust of
    the issuer. fastmcp 4.0.3's `JWTVerifier.load_access_token` fills
    `AccessToken.client_id` with

        claims.get("client_id") or claims.get("azp") or claims.get("sub")
            or "unknown"

    so a token that carries neither `client_id` nor `azp` puts its RAW `sub`
    in this field. `_customer_ref` above refuses to put that same string in
    `customer_ref` and stores `subject_not_a_customer_ref` instead, because
    identity.py's warning is that an issuer under attacker control can mint a
    `sub` shaped like a bare PAN, IBAN or DNI. Writing this field unscrubbed
    would carry that value into the same long-lived table through the column
    next to the one that refused it, which is a bypass, not a second opinion.

    The cost of scrubbing is the one `tool_name` already pays and is worth
    repeating because this column is an identity: a PAN- or IBAN-shaped
    client id collapses to a fixed mask, so two distinct issuers whose ids
    share a last four digits record the same value. Bounded by the same
    accepted trade -- a raw PAN in a regulator-facing table is worse -- and
    by nothing in this repository querying the column yet.

    A SECOND COST LANDS ON THIS COLUMN AND NOT ON `tool_name`, because this
    one is allowed to be longer than 128 characters and that one is not.
    `_scrub` bare-masks any alphanumeric RUN longer than
    `masking._IBAN_SCAN_MAX_TOKEN` (128) to `••••` without spending a
    checksum on it. Measured directly: a run of 128 comes back unchanged, a
    run of 129 comes back as `••••`, and
    `https://client.test/<200 b's>` is recorded as
    `https://client.test/••••`. So a client id carrying one long opaque
    segment -- a base64 tenant token in a path, say -- loses THAT SEGMENT,
    while its scheme, host and every other path segment survive, because a
    URL's separators split it into runs that are individually short. A
    CIMD-shaped id made of ordinary segments is unaffected at any length:
    a 652-character one clips to exactly `_MAX_CLIENT_ID` characters and its
    scrub is the identity (measured).

    CLIPPING FIRST DOES NOT RESCUE THAT CASE, and saying so matters because
    the ordering below invites the opposite reading. The slice happens before
    the scan, but it cuts to `_MAX_CLIENT_ID` (512), which is four times the
    128 that triggers the bare mask, so a client id that is ONE run of 600
    characters is clipped to 511 and still masked: it records `••••…`
    (measured), five characters, naming nobody. The width that would prevent
    it is 128 itself, and that was rejected -- it would clip every ordinary
    CIMD URL past 128 characters instead, trading a rare total loss for a
    routine partial one. What clipping first DOES buy is the checksum bound:
    the scan never sees more than `_MAX_CLIENT_ID` characters, which is where
    the 2,220 figure above comes from.

    THE MARKER GOES ON AFTER THE SCRUB, not before, for the reason
    `on_call_tool` spells out for the tool name: `_scrub` reaches
    `masking._strip_invisible`, which deletes characters outright, so a
    marker chosen for being unstrippable today would still depend on a
    function in another package. Reserving `len(_TRUNCATED)` off the slice up
    front and appending afterwards puts it somewhere nothing can touch. For
    an id at or under `_MAX_CLIENT_ID` the marker is the empty string, so the
    slice is a no-op and the whole expression reduces to `_scrub(raw)`: an id
    the scrub does not touch comes back character for character, with no
    marker, which is what keeps a real 512-character id from reading like a
    clipped 600-character one. The trailing `_clamp` is the same fail-safe
    the name carries:
    `_scrub` never lengthens a value in characters and `VARCHAR(512)` counts
    characters, so it cannot fire today, and if a future change to either
    makes it fire the value still says it was clipped.

    Worst-case cost of the scrub, measured on this repository's own
    adversarial shape (128-character maximum-density letter-letter-digit
    -digit tokens, the shape `_IBAN_SCAN_BUDGET` was sized against): 2,220
    checksums at the full 512 characters, 2.22% of the 100,000-checksum
    allowance. A realistic CIMD id spends ZERO -- measured on
    `https://claude.ai/.well-known/oauth-client-metadata` (51 characters) and
    on a 96-character tenant-scoped URL, neither of which contains a
    letter-letter-digit-digit opener at all. That bound is what lets
    `on_call_tool` scrub this value before the unbounded arguments without
    starving them.
    """
    if token is None:
        return None
    raw = token.client_id
    marker = _TRUNCATED if len(raw) > _MAX_CLIENT_ID else ""
    return _clamp(_scrub(raw[: _MAX_CLIENT_ID - len(marker)]) + marker, _MAX_CLIENT_ID)


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
    return _clamp(str(request_id), _MAX_REQUEST_ID)


@dataclass
class _PendingEntry:
    """Everything the entry row needs, bound before the tool runs and written
    when something is about to reach the operator's backend.

    Every field is settled by the time `on_call_tool` constructs this, which
    is what makes a zero-argument callable possible at all. `redaction_budget
    _exhausted` is the one worth checking rather than assuming: it is
    `RedactionScope.exhausted` read AFTER the `with redaction_budget()` block
    has closed, and nothing spends from that allowance afterwards -- the
    context manager resets the `ContextVar` on exit (masking.py), and tool
    RESPONSES deliberately do not opt in and take a fresh per-string budget
    each. So the value this row carries is measured, not assumed, and it is
    the same value the completion row will carry.

    WRITTEN AT MOST ONCE PER TOOL CALL, which is the guard `record` holds and
    the façade explicitly does not. Every façade function issues exactly one
    `get_json` today -- `facade/accounts.py`'s `list_accounts` and
    `get_balance`, `facade/cards.py`'s `list_cards`,
    `facade/transactions.py`'s `list_transactions` -- so "one entry row per
    call" currently holds by arithmetic rather than by construction, and the
    first tool that reads before it writes (a `payments.create_payment` doing
    a payee lookup) would silently write N rows for one call and break the
    pairing. The guard lives here rather than in `BackendClient` because "one
    tool call" is a concept this module owns and that one does not: this
    object's lifetime IS the call.

    The lock is what makes it at-most-once rather than usually-once. Two
    `get_json` calls issued concurrently from one tool body would both find
    `written` False across the `await` in between and both insert; the lock
    serialises them so the second sees the first's result.

    `written` IS SET INSIDE THE SESSION BLOCK, on the line after the commit,
    and that placement is load-bearing rather than tidy. Set after the block
    instead, a commit that succeeds followed by a raising session exit --
    `AsyncSession.__aexit__` closes the session and can raise on its own --
    leaves a durable `reaching` row with the flag still False, so a caller
    that catches the exception and touches again writes a SECOND `reaching`
    row under the same `call_id`. That is precisely the pairing break this
    guard exists to prevent, arrived at through the guard.

    The two failure shapes that remain are therefore different, both are
    correct, and both are now measured. A write that never commits leaves
    `written` False, so a second toucher retries and fails too, rather than
    reaching the backend on the strength of a row that does not exist
    (`tests/test_audit_entry_row.py::test_a_second_touch_after_a_failed
    _entry_write_fails_too`). A write that commits and then raises leaves
    `written` True, so a second toucher returns quietly -- the row it needed
    is already durable, and the exception the first toucher saw has already
    stopped that first request (`::test_an_entry_write_that_commits_then
    _raises_leaves_the_row_and_the_flag`, which builds a store whose sessions
    commit for real and raise on exit, and fails if this line moves out of
    the block).
    """

    db: Database
    at: datetime
    subject: _Subject
    tool_name: str
    arguments: dict[str, Any]
    redaction_budget_exhausted: bool
    request_id: str | None
    call_id: str
    # Carried here rather than read again in `_write_entry_row`, for the
    # reason `call_id` beside it is: both rows of one call must name the SAME
    # OAuth client, and `get_access_token()` is a `ContextVar` read from a
    # frame the façade reaches, not a constant. Reading it twice would make
    # the pair's agreement an accident of the two reads landing in the same
    # context. One read in `on_call_tool`, one value, both rows.
    client_id: str | None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    written: bool = False

    async def record(self) -> None:
        async with self.lock:
            if self.written:
                return
            try:
                await self._write_entry_row()
            except Exception as audit_exc:
                # The THIRD failure path, and the one
                # dev-docs/decisions/0006-audit-write-failure.md did not have
                # when it enumerated what an operator sees. Logged here
                # because this write is the only one of the three the
                # middleware never sees: it raises inside the tool body, so
                # if that tool's own completion write then SUCCEEDS, the
                # operator is left with a `raised` row and no ERROR line
                # anywhere -- an entry-write outage wearing the shape of
                # ordinary tool failures. Re-raised unchanged: stopping the
                # backend request is the whole point, and the caller needs
                # the exception to do it.
                logger.error(
                    "audit entry write failed for tool %r; the backend request "
                    "it precedes will not be made: %s",
                    self.tool_name,
                    describe_exception(audit_exc),
                    exc_info=exc_info_for_log(audit_exc),
                )
                raise

    async def _write_entry_row(self) -> None:
        """The write itself, split out only so `record` above can wrap it in
        one `try` without burying the row's own field-by-field reasoning
        inside an exception handler.

        THROUGH `append_with_reserve` SINCE 2026-09-27, which changes which
        connection this gets and nothing else about it. A pool at its ceiling
        used to fail this write, and failing this write stops the backend
        request -- so a saturated replica turned every ungated call into a
        failure with no row explaining it. `postern_core.store.audit`'s
        `append_with_reserve` carries which single exception earns the
        reserve and why every other one does not. The `written = True` below
        stays exactly where it was, inside the session block and on the line
        after the commit, because the callable this passes over IS the body of
        that block.
        """

        async def row(session: AsyncSession) -> None:
            await audit.append(
                session,
                at=self.at,
                # THE LAST READING BEFORE THE TOUCH, and the only instant on
                # this row that is not the call's arrival time. `self.at` is
                # `context.timestamp`, read when the call reached the
                # middleware; everything between the two -- the consent
                # lookup, argument validation, whatever the tool body does
                # before its first request -- is invisible to a reader with
                # only one of them.
                #
                # Read HERE, one statement before the INSERT, rather than
                # when `record` was entered or when the commit returns: it
                # is the closest reading to the request that this row can
                # carry and still be durable before the request is made. It
                # therefore precedes the request by the INSERT, the commit
                # and the session exit, and is early rather than late --
                # `AuditEntry.reaching_at` (models.py) states that bound and
                # why the error direction matches `outcome='reaching'`'s own.
                #
                # `datetime.now(UTC)`, a wall clock, where `_elapsed_ms`
                # refuses one: that function measures an interval and a
                # stepping clock would put a negative number in the table,
                # while this is an instant that has to be comparable with
                # `at`, itself a wall-clock reading from fastmcp.
                reaching_at=datetime.now(UTC),
                customer_ref=self.subject.customer_ref,
                customer_ref_absence_reason=self.subject.absence_reason,
                tool_name=self.tool_name,
                arguments=self.arguments,
                outcome=OUTCOME_REACHING,
                # NULL: nothing has gone wrong, and `detail` records what
                # did. The completion row is where an outcome is
                # described.
                detail=None,
                redaction_budget_exhausted=self.redaction_budget_exhausted,
                # NULL, and the one column where that needs saying: the
                # tool body has not finished, so no duration exists to
                # record. `AuditEntry.duration_ms` gives the rule that
                # keeps this distinguishable from a pre-migration row --
                # `outcome` is what separates them, not this column.
                duration_ms=None,
                request_id=self.request_id,
                # NULL, and TRUE rather than merely unknown, which is
                # the whole reason this write sits behind the consent check
                # instead of at the top of `on_call_tool`. FastMCP
                # evaluates `auth=` in `_get_tool`, inside `call_next`, so
                # any refusal has already been decided by the time anything
                # reaches the backend, and a refused call never gets here.
                #
                # The claim is "consent did not refuse this call", NOT
                # "consent allowed it", and the difference is one real tool
                # rather than pedantry: `start_session` is registered with
                # no `auth=` at all (`services/api/tools/bootstrap.py`'s
                # `start_session`, whose `@mcp.tool` decorator passes only a
                # name and annotations, while the other four pass
                # `auth=check`) and it reaches the backend through
                # `accounts_facade.list_accounts`. Its entry row's NULL
                # therefore means no consent check ran, which is
                # exactly what NULL says on this column
                # (`AuditEntry.refusal_reason` lists all three states it
                # covers). Writing the stronger claim would make this
                # comment false for one tool in five.
                #
                # THAT TOOL IS NOW MEASURED, not just described.
                # `tests/test_audit_entry_row.py::test_the_ungated_tool
                # _writes_an_entry_row_and_its_refusal_reason_is_null` drives
                # `start_session` over real HTTP, with a real token, for a
                # customer consented to nothing, and reads the entry row back
                # out of Postgres: the row exists, it carries NULL here, and
                # the SAME customer's `cards.list` in the same test is
                # refused with `domain_not_consented`. That second call is
                # what makes the NULL mean something -- it rules out the
                # stronger reading, since a check that ran for this customer
                # refuses. `tests/test_bootstrap.py::server` still builds its
                # client with `before_backend_request=None`, which is why
                # that file's tools never write an entry row and this one had
                # to be pinned elsewhere.
                refusal_reason=None,
                call_id=self.call_id,
                # The same value the completion row will carry, scrubbed and
                # clamped once in `on_call_tool` rather than derived here:
                # this row exists to say a touch happened, and "which client
                # touched it" has to match the row that says how the touch
                # ended, or the pair names two different callers for one
                # call.
                client_id=self.client_id,
                risk_signals=None,  # entry row precedes the tool call; signals are empty.
            )
            # INSIDE the session block, on the line after the commit: see
            # the class docstring for the duplicate row the other placement
            # produces.
            self.written = True

        await audit.append_with_reserve(self.db, row)


# Set by `AuditMiddleware.on_call_tool` and read by `record_data_touch`,
# which runs deeper in the same call stack.
#
# A `ContextVar` and not `request.state`, where `services/api/consent.py`
# went the other way, and the two are not in conflict. `consent._refuse`
# rejected a `ContextVar` because it writes from DEEPER than the middleware
# that reads it, and a value set in a child task's context does not propagate
# back to the parent. This is the reverse direction -- set in the middleware,
# read further down -- which is the direction a `ContextVar` does carry, and
# `postern_core.domain.masking.redaction_budget()` is this repository's
# existing precedent for it (`AuditMiddleware.on_call_tool`, below, already
# relies on it). That reason decides it on its own.
#
# The second consideration is not a defect in `request.state`, and saying so
# would misread this repository's own use of it. `get_http_request()` RAISES
# for a call arriving through the in-process `Client(transport=server)`
# transport, and a tool called that way still reaches the backend. So a
# `request.state` design has to ANSWER that case, where a `ContextVar` never
# raises it: `consent._refuse` answers it by returning quietly and says why
# -- a call with no HTTP request carries no token, so there was no consent
# decision to file -- and that answer is correct there and would be wrong
# here, since the touch happens regardless. Choosing `request.state` would
# mean choosing to raise on a path its existing reader deliberately does not,
# which is a divergence to maintain rather than a shape to inherit.
_pending_entry: ContextVar[_PendingEntry | None] = ContextVar(
    "postern_pending_audit_entry", default=None
)


async def record_data_touch() -> None:
    """Commit this call's entry row, if it has not been committed already.

    Wired into `postern_core.facade.client.BackendClient` by
    `services/api/main.py::create_app` as its `before_backend_request` hook,
    and invoked immediately before each backend request. The façade holds
    this module-level function, not the per-call callable: a `BackendClient`
    is built once per process and the entry it writes is per request, so
    something has to bridge the two, and this is that bridge.

    RAISES when no entry is pending, rather than returning quietly. Nothing
    in this service reaches the backend outside a tool call, so an empty
    `ContextVar` here means one of two things, and they end differently.

    EITHER the value did not propagate to this frame, with `AuditMiddleware`
    installed. The exception surfaces as the tool call's own failure and the
    completion row records `outcome='raised'` with `detail='ToolError'`, NOT
    `'RuntimeError'`: FastMCP wraps anything a tool body raises before the
    middleware sees it (`fastmcp/server/server.py::call_tool`, `raise
    ToolError(...) from e`), so `type(exc).__name__` never reads the original
    type. That is an established property of this table, not a new one --
    `tests/test_audit_middleware.py::test_an_ordinary_tool_failure_records_no_
    refusal_reason` has pinned it since before this write existed.

    So the ROW DOES NOT IDENTIFY THIS CAUSE, or separate it from any other
    exception raised inside a tool body. What names it is the message below,
    in the traceback and in the error text the client receives.

    OR `AuditMiddleware` is not installed on this server at all, in which
    case there is no completion row either and nothing is recorded anywhere
    -- the raise is the only signal, and it is still the right one, because
    the alternative is a backend request nothing will ever record. The
    message names that cause for whoever reads the traceback.
    """
    entry = _pending_entry.get()
    if entry is None:
        raise RuntimeError(
            "no audit entry is pending for this call, so a backend request "
            "cannot be recorded before it is made; AuditMiddleware must be "
            "installed on any server whose BackendClient carries this hook"
        )
    await entry.record()


#: What the model's channel gets when an exception that leaves this middleware
#: carries a SQL driver error anywhere in its chain. Fixed text: the driver's
#: message names the bound value, and `DETAIL: Failing row contains (...)` is
#: the whole row, both of which land in an AI vendor's chat history.
INTERNAL_ERROR_TEXT = "internal error"


#: The exceptions whose text is known to be fixed and is meant for the client, so
#: that a deliberate refusal still reads as one. Everything NOT in this list that
#: leaves `on_call_tool` is replaced by `INTERNAL_ERROR_TEXT`, because an
#: unlisted class is one whose text nobody here has read: measured, a store
#: method that raised `redis.ConnectionError("...redis://postern_api:<pw>@redis")`
#: put that text, password included, in the JSON-RPC reply.
#:
#: * `FastMCPError` (`ToolError`, `ValidationError`, `AuthorizationError`),
#:   `NotFoundError` and `DisabledError`: FastMCP's own, with fixed sentences
#:   (`Unknown tool: 'x'` is what a consent denial must look like); a
#:   `ToolError` is masked by `mask_error_details=True`, and the tools here
#:   raise fixed strings only.
#: * `MCPError`: a deliberate JSON-RPC error with its own code.
#: * `RevokedError`: `access has been revoked; <what> was refused`
#:   (`RevocationMiddleware`, the one refusal that must reach a revoked caller).
#: * `RiskActionError`: `Session blocked by N risk signal(s): <codes>`, codes are
#:   this repository's constants.
#: * `RevocationStoreUnavailable`, `SessionStoreUnavailable`: every raise site
#:   writes `<what> could not be <verb>: <TypeName>`. For `SessionStoreUnavailable`
#:   `<what>` is `risk context <key.log_ref>`, the first 12 hex characters of a
#:   SHA-256 over the customer and client (`risk/session.py`): a non-reversing
#:   handle for the session, not the customer's reference, and the one
#:   identifier-derived value in an otherwise fixed sentence.
#: * A bare `PermissionError("<fixed sentence>")` (see `_fixed_permission_error`):
#:   `token_customer_resolver` refusing a caller it cannot name.
_CLIENT_FACING: tuple[type[BaseException], ...] = (
    FastMCPError,
    NotFoundError,
    DisabledError,
    MCPError,
    RevokedError,
    RiskActionError,
    RevocationStoreUnavailable,
    SessionStoreUnavailable,
)


def _fixed_permission_error(exc: BaseException) -> bool:
    """A `PermissionError` this repository built from one sentence.

    Not every `PermissionError`, and not a subclass of one: the exact type, with
    ONE string argument. The operating system raises one with an errno, a
    strerror and a path (three arguments), so the single-argument test is what
    keeps an OS-built error out; an `exc.errno is None` check beside it would be
    redundant (`OSError(1 arg)` has no errno, and an OS-built one never has one
    argument), so there is none.
    """
    return type(exc) is PermissionError and len(exc.args) == 1 and isinstance(exc.args[0], str)


def _client_safe(exc: BaseException) -> MCPError | None:
    """A fixed-text `MCPError` to raise in place of ``exc``, or None to keep it.

    Keeps `_CLIENT_FACING` and replaces every other exception, so the call still
    FAILS CLOSED and the client reads `INTERNAL_ERROR_TEXT` in a JSON-RPC error
    (code -32603): the same protocol-level shape an unhandled exception from here
    always had (`tests/test_audit_middleware.py` pins it), with a fixed text. That covers an
    exception whose chain (`__cause__`, `__context__`, exception groups) holds a
    SQL driver error, whose message names the bound value or the failing row,
    and an exception of a class nobody has read the text of.

    A `ToolError` is in the kept list because by the time one reaches here its
    text is safe by construction: this server is built with
    `mask_error_details=True`, so FastMCP turns every other exception a tool
    raised into ``Error calling tool 'x'`` with no detail, and this
    repository's tools raise only fixed strings.
    """
    if isinstance(exc, _CLIENT_FACING) or _fixed_permission_error(exc):
        return None
    return MCPError(INTERNAL_ERROR, INTERNAL_ERROR_TEXT)


class AuditMiddleware(Middleware):
    def __init__(self, db: Database) -> None:
        self.db = db

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        # READ ONCE, HERE, and handed to both readers below. `_client_id`
        # runs inside the redaction scope and `_customer_ref` runs after it,
        # so the two cannot share a call unless the token itself is hoisted
        # out of both. That is not a tidiness point: the two columns they
        # fill are joined by a claim `AuditEntry.client_id` (models.py)
        # spells out -- a NULL client id and
        # `customer_ref_absence_reason = 'no_access_token'` are the same
        # fact -- and two separate `get_access_token()` reads would make that
        # agreement depend on both landing in the same context rather than on
        # there being one value.
        access_token = get_access_token()
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
            # `_clamp` is not called on the raw name here, and the ordering is
            # deliberate: it would put `_TRUNCATED` into the string BEFORE
            # `_scrub` runs, and `_scrub` is free to alter what it is handed
            # (`masking._strip_invisible` deletes characters outright). A
            # marker chosen for being unstrippable today is still a marker
            # whose survival depends on a function in another package that
            # this module does not own. So the marker goes on AFTER scrubbing,
            # where nothing can touch it, and the clip budget is reserved up
            # front by taking `len(marker)` off the slice.
            #
            # `marker` is empty for every name at or under 64 characters, so
            # the slice is `[:_MAX_TOOL_NAME]` and the expression is what it
            # was before this marker existed -- an ordinary name comes back
            # character-for-character identical, which is the point. The scan
            # stays bounded by 64 characters either way, so the 223-checksum
            # worst case measured above still holds as an upper bound (the
            # clipped path now scans 63).
            raw_name = context.message.name
            marker = _TRUNCATED if len(raw_name) > _MAX_TOOL_NAME else ""
            name = _scrub(raw_name[: _MAX_TOOL_NAME - len(marker)]) + marker
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
            # can trigger it. It cannot fire today in either direction:
            # `_scrub` never lengthens, so the clipped path is at most
            # 63 + 1 = 64 and the unclipped path at most 64.
            #
            # `_clamp` rather than a bare slice, so that if it ever DOES fire
            # the value still says so. Two cases, both handled: a name the
            # first clamp did not touch that a future `_scrub` grows past 64
            # gets cut here and gains its marker here; a name that already
            # carries a marker and grew anyway has the old marker cut off with
            # the overflow and a new one appended, never two.
            name = _clamp(name, _MAX_TOOL_NAME)
            # IN THIS SCOPE, AND BEFORE THE ARGUMENTS, for both of the
            # reasons the name above is. Sharing the scope keeps one
            # allowance per call, which is the invariant the name's own
            # paragraph exists to defend; going first keeps the arguments
            # from being able to starve it. The starvation is the same shape
            # too: an agent that pads its arguments to exhaust the allowance
            # would otherwise get an IBAN-shaped client id bare-masked to
            # `••••` by `_redact_iban_match`'s `budget.exhausted` branch, and
            # destroying WHO called is the same class of loss as destroying
            # WHAT was called.
            #
            # It cannot starve them in return: `_client_id` is clamped to
            # `_MAX_CLIENT_ID` (512) before it is scanned, and its measured
            # worst case at that width is 2,220 checksums of the 100,000
            # allowance, 2.22%. A realistic CIMD id spends zero. Both numbers
            # are derived in `_client_id`'s own docstring.
            client_id = _client_id(access_token)
            # Scrubbed AND bounded, in that order, by `_arguments` -- which
            # is where the two bounds and the reasoning behind both live.
            # Until 2026-09-23 this line was a bare `_scrub(...)` and this
            # column had no ceiling but `settings.max_body_bytes`.
            arguments = _arguments(context.message.arguments)
        # One call, two fields, exactly one of them non-None: see `_Subject`
        # for why the pair is returned together rather than derived twice.
        subject = _customer_ref(access_token)
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
        # Minted here, once, for both of this call's rows. `uuid.uuid4()` and
        # not the JSON-RPC `request_id` above: that one is the client's, and
        # `_request_id` returns None whenever it cannot be read, with the row
        # written anyway -- two rows joined on a column that is NULL on both
        # are not a pair. See `AuditEntry.call_id` (models.py).
        pending = _PendingEntry(
            db=self.db,
            at=at,
            subject=subject,
            tool_name=name,
            arguments=arguments,
            redaction_budget_exhausted=scope.exhausted,
            request_id=request_id,
            call_id=str(uuid.uuid4()),
            client_id=client_id,
        )
        token = _pending_entry.set(pending)
        try:
            try:
                result = await call_next(context)
            finally:
                # Reset before either audit write runs, not after: the entry
                # is only ambient while the tool that might touch the backend
                # is running. `reset`, not `set(None)`, so a nested caller's
                # own pending entry -- if this middleware is ever installed
                # twice -- is restored rather than wiped.
                _pending_entry.reset(token)
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
            # WHAT LEAVES THIS MIDDLEWARE, decided once and before any audit
            # write can add a second exception. See `_client_safe`.
            outgoing = _client_safe(exc)
            # Read here and not before `call_next`, because the consent
            # check runs INSIDE it: FastMCP evaluates a tool's `auth=` in
            # `fastmcp/server/server.py::_get_tool`, which the dispatch this
            # `call_next` reaches calls before the tool body, so a denial is
            # always filed by the time this line runs.
            #
            # Keyed on the RAW requested name, not the scrubbed `name` about
            # to be written: `consent._refuse` files its decision under the
            # registered tool's own name, which is the name the client asked
            # for, while `name` may have been clipped to `_MAX_TOOL_NAME` or
            # masked by `_scrub`. Neither of those can be a registered tool,
            # so the lookup can only miss for them, and a miss records NULL
            # -- under-reporting a refusal instead of inventing one.
            refusal_reason = consent.refusal_for(context.message.name)
            # Fail closed (dev-docs/decisions/0006-audit-write-failure.md): an
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
            # Extract risk signals from the current session context so they
            # appear on the completion row.  NULL when there is no active
            # session handle (no risk tracking for this call); [] when a
            # session existed but no signals fired.
            _ctx = get_current_session()
            if _ctx is not None:
                # Always serialize — even an empty list means "session ran,
                # no signals fired" (distinct from NULL = no session).
                _risk_signals: list[dict[str, Any]] | None = [
                    {
                        "code": s.code,
                        "severity": s.severity.name,
                        "description": s.description,
                        "details": s.details,
                    }
                    for s in _ctx.risk_signals
                ]
            else:
                _risk_signals = None
            try:
                await self._write(
                    at,
                    subject.customer_ref,
                    subject.absence_reason,
                    name,
                    arguments,
                    OUTCOME_RAISED,
                    type(exc).__name__,
                    scope.exhausted,
                    duration_ms,
                    request_id,
                    refusal_reason,
                    # The same value the entry row carries, whether or not
                    # that row was ever written. A completion row with no
                    # entry row is a real and common state -- consent refused
                    # the call, the tool failed before its first backend
                    # request, or it reaches no backend at all -- and reads
                    # as exactly that: nothing was touched.
                    pending.call_id,
                    # Off the same object, for the same reason: a call that
                    # failed is one an investigator asks WHO made, and the
                    # answer has to be the one the entry row gave if there
                    # was one.
                    pending.client_id,
                    _risk_signals,
                )
            except Exception as audit_exc:
                logger.error(
                    "audit write failed for tool %r after it raised %s: %s",
                    name,
                    type(exc).__name__,
                    describe_exception(audit_exc),
                    exc_info=exc_info_for_log(audit_exc),
                )
                if outgoing is not None:
                    raise outgoing from None
                raise exc from audit_exc
            if outgoing is not None:
                raise outgoing from None
            raise
        # Same reading, taken before the write for the reason the raised
        # path above states: `_write`'s own database round trip is not the
        # tool's latency by any reading, and it is the slowest thing in this
        # function.
        duration_ms = _elapsed_ms(started)
        # Same extraction as the raised path above: signals were evaluated by
        # RiskMiddleware after the handler ran, so they are available on the
        # context for this completion write.  NULL when no session; [] when
        # session existed but no signals fired.
        _ctx = get_current_session()
        if _ctx is not None:
            # Always serialize — even an empty list means "session ran, no
            # signals fired" (distinct from NULL = no session).
            _risk_signals = [
                {
                    "code": s.code,
                    "severity": s.severity.name,
                    "description": s.description,
                    "details": s.details,
                }
                for s in _ctx.risk_signals
            ]
        else:
            _risk_signals = None
        try:
            await self._write(
                at,
                subject.customer_ref,
                subject.absence_reason,
                name,
                arguments,
                OUTCOME_RETURNED,
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
                # Pairs this row with the `reaching` row the façade wrote for
                # the same call, when there was one. A `returned` row with no
                # partner means the tool answered without reaching the
                # backend.
                pending.call_id,
                # The same client the entry row named, read once for this
                # call in the redaction scope above.
                pending.client_id,
                _risk_signals,
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
            # dev-docs/decisions/0006-audit-write-failure.md for the rejected
            # alternative (write-through-and-log) and the reasoning.
            logger.error(
                "audit write failed for tool %r after it returned successfully; "
                "failing the call because the audit row could not be written: %s",
                name,
                describe_exception(audit_exc),
                exc_info=exc_info_for_log(audit_exc),
            )
            safe = _client_safe(audit_exc)
            if safe is not None:
                raise safe from None
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
        # Required, no default, and typed `str` rather than `str | None`: the
        # value comes off the `_PendingEntry` this call built, so it exists
        # unconditionally, and a NULL here would orphan this row from the
        # entry row that shares its call.
        call_id: str,
        # Required, no default, and `str | None` rather than `call_id`'s
        # `str`: None is a real answer here (no access token on this call)
        # where it never is above. It comes off the same `_PendingEntry`, so
        # this row names the client the entry row named, whether or not that
        # entry row was ever written. A default would answer "no client" for
        # a call that had one, which on a regulator-facing table is a false
        # statement rather than a gap.
        client_id: str | None,
        # Required and `list[dict] | None`: NULL means "no risk signals for
        # this row" (pre-migration or no session handle), while an empty list
        # means "this call ran and no signals fired". A default would let a
        # future caller silently record NULL instead of the actual signal data,
        # which on a regulator-facing table is a gap. Both branches of
        # `on_call_tool` always have a real value to supply.
        risk_signals: list[dict[str, Any]] | None,
    ) -> None:
        """THROUGH `append_with_reserve` SINCE 2026-09-27, for the row this
        repository had recorded three times as its largest remaining gap.

        Both reasons `services/api/consent.py` files for an unreachable store
        arrive on THIS write, on the raised branch of `on_call_tool`, and a
        pool at its ceiling refuses the consent lookup and this write
        together -- so the two values existed in the code and reached
        `audit_log` only for calls whose audit write happened to get a
        connection. During saturation that is none of them.

        The row is unchanged: same columns, same values, same instant, and
        still fail-closed if it cannot be written at all. Only the connection
        is new.
        """

        async def row(session: AsyncSession) -> None:
            await audit.append(
                session,
                at=at,
                # NULL, written as a literal rather than taken as a
                # parameter, because no branch that reaches this method has a
                # touch instant to record: this is the completion write, and
                # the touch is on the entry row or did not happen. Copying
                # the entry row's value here would store one fact twice on
                # rows that are free to disagree, and
                # `ck_audit_log_reaching_at_matches_outcome` (models.py)
                # rejects it outright -- at the cost of the row and the call.
                reaching_at=None,
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
                call_id=call_id,
                client_id=client_id,
                risk_signals=risk_signals,
            )

        await audit.append_with_reserve(self.db, row)

"""Up to two ``audit_log`` rows per approval callback: one before the operator
reaches a backend write endpoint, one after the request finishes.

WHY THIS EXISTS. Until 2026-09-23 this service wrote NO audit rows at all. A
grep for ``audit`` across ``services/confirm/*.py`` returned comments and
nothing else, while ``services/api`` wrote two rows for every tool call. The
asymmetry ran exactly backwards: reading a balance was fully recorded, and
approving a payment -- the highest-consequence action in the system -- left
behind only the ``challenges`` row it mutated, whose ``confirming_device`` and
``signature`` are both caller-supplied and whose ``signature`` is still
unverified (``services/confirm/callback.py``'s module docstring says why). An
investigator after an incident had no approval instant distinct from the row's
own, no record that a write JWT had been minted, and no correlation key tying
any of it to anything. Under GDPR that is a 72-hour notification problem, not
only an operations one.

THE SHAPE IS THE READ PATH'S, and deliberately so, because a regulator reads
one table and must not have to learn two schemas to do it:

- Two rows, correlated by ``call_id``. The entry row (``outcome='reaching'``)
  is committed in its OWN transaction before the backend is reached, so a
  crash between the two still leaves evidence the backend was touched. The
  completion row (``outcome='returned'`` or ``'raised'``) follows.
- ``reaching_at`` carries the last reading taken BEFORE the touch, so it errs
  early rather than late, which is the direction ``OUTCOME_REACHING`` commits
  that row shape to (``postern_core.store.models``).
- Fail closed, per ``dev-docs/decisions/0006-audit-write-failure.md``. An audit
  write that fails fails the request. Every ``except`` here re-raises.

THE RULE FOR WHICH REQUESTS GET WHICH ROWS, which is this module's one real
departure from the read path and follows from that path's own docstring ("a
consent-denied call therefore still produces exactly ONE row ... so does one
whose tool reaches no backend at all"):

    Every approval attempt that reaches the point where a verified subject
    and a non-empty challenge id both exist gets exactly ONE completion row.
    It gets a second -- the entry row -- only when the backend was about to
    be touched.

So a refused transition is recorded: a lost race (409), an expired challenge
(410) and an approval aimed at somebody else's challenge (404) are each a real
event, and the last of them is the single highest-value security signal on
this path. None of the three gets an entry row, because none of them reaches
the backend.

TWO BACKSTOPS BEFORE THAT POINT WRITE NOTHING, both unreachable through the
assembled app and both logged instead. The handler's own 401 fires only when
``AppAssertionMiddleware`` did not run, and at that point there is no subject
at all -- a row would have to invent a class of absence that
``CUSTOMER_REF_ABSENCE_REASONS`` does not name. The empty-``challenge_id``
400 fires only when something other than the route table dispatched the
request, since Starlette cannot match an empty path segment, and a row naming
no challenge names nothing an investigator can act on.

WHAT ``tool_name`` HOLDS, AND THE LIMITATION THAT COMES WITH IT. The
challenge's own ``tool_name`` (``payments.create_payment``), verbatim, so that
one filter returns both halves of a payment -- the read-path rows for the tool
call that PROPOSED it and the write-path rows for the approval that EXECUTED
it. Never the HTTP route: that string is identical on every row this module
writes and would tell a reader nothing. Where no challenge was resolved, the
literal ``challenges.approve``, which is not a registered MCP tool name and so
can never collide with a read-path row; ``WHERE tool_name =
'challenges.approve'`` is by itself the challenge-id-enumeration query.

The limitation, stated here because the next person will meet it in a result
set otherwise: NO COLUMN OF ``audit_log`` NAMES THE SERVICE THAT WROTE THE
ROW. A query filtering ``tool_name = 'payments.create_payment'`` returns
``services/api`` rows and ``services/confirm`` rows interleaved, and what
separates them is ``arguments['route']`` (present only on this service's rows)
plus the pairing of ``reaching_at`` with a challenge id. A ``service`` column
would settle it and is a migration; it was considered and not authorised.

WHAT ``arguments`` HOLDS, AND WHAT IT DELIBERATELY DOES NOT. Nothing from
``challenges.payload``. The payload is server-written at challenge creation,
never updated by any statement in this tree, and already stored -- copying the
amount and the payee here would be one fact on two rows free to disagree
(``AuditEntry.reaching_at`` makes the same argument for not copying itself
onto the completion row) and would put payee-shaped data into a second
long-lived table for no gain.

The cost of that choice is a join, and it is worth naming precisely so nobody
is surprised by it during an incident: ``audit_log`` ALONE answers "was a
payment approved, by whom, from what, and did it execute". ``challenges``
answers "for how much, and to whom". An investigator needs both tables, and
``arguments['challenge_id']`` is the key between them -- the same string the
backend received as its ``Idempotency-Key`` header, so a backend access log
joins to both by eye.

What IS recorded is the caller-influenced input, which is the part that exists
nowhere else on a refused path: ``update_challenge_status`` writes
``confirming_device`` and ``verification_result`` onto the challenge row only
on the winning transition, so on every 404, 409 and 410 those values would
otherwise vanish with the request. ``signature`` is recorded as a BOOLEAN
PRESENCE and never as a value: CLAUDE.md forbids a raw signature in this
table, and a digest of an unverified string with no defined meaning would be
ceremony rather than evidence.

``refusal_reason`` IS NULL ON EVERY ROW THIS MODULE WRITES, which is a gap and
not a decision anybody is happy with. ``REFUSAL_REASONS``
(``postern_core.store.models``) is closed at ``no_customer_ref`` and
``domain_not_consented``, both consent-specific, and ``ck_audit_log_refusal
_reason`` enforces the closure at the database. There is no admissible value
for "this challenge belongs to another customer", "this challenge was already
terminal" or "this challenge had expired", and inventing one is a migration
plus a constraint widening. So the refusal class lands in ``detail`` instead,
as a stable literal from ``_REFUSAL_DETAILS`` below, and a query that wants
write-path refusals reads ``detail`` rather than ``refusal_reason``. Widening
the vocabulary is the right fix and is somebody's decision, not this module's.
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any

from postern_core.domain.masking import redaction_budget, scrub_text, scrub_tree
from postern_core.identity import CustomerRef
from postern_core.store import audit
from postern_core.store.engine import Database
from postern_core.store.models import (
    ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
    OUTCOME_RAISED,
    OUTCOME_REACHING,
    OUTCOME_RETURNED,
)
from pydantic import ValidationError

logger = logging.getLogger(__name__)

__all__ = [
    "APPROVE_ROUTE",
    "OUTCOME_RAISED",
    "OUTCOME_RETURNED",
    "UNRESOLVED_TOOL_NAME",
    "ApprovalAudit",
    "DETAIL_ALREADY_TERMINAL",
    "DETAIL_CHALLENGE_NOT_FOUND",
    "DETAIL_CHALLENGE_NOT_OWNED",
    "DETAIL_CHALLENGE_VANISHED",
    "DETAIL_EXPIRED",
    "DETAIL_MISSING_SIGNATURE",
    "DETAIL_UPDATE_MATCHED_NO_ROW",
]

#: What ``tool_name`` carries when no challenge was resolved -- the id named
#: nothing, or the request never got far enough to look. Not a registered MCP
#: tool name, so it cannot collide with a ``services/api`` row, and queryable
#: on its own as the id-enumeration signal.
UNRESOLVED_TOOL_NAME = "challenges.approve"

#: The route template, recorded in ``arguments`` rather than in ``tool_name``.
#: Constant today, which is exactly why it is not the tool name; it earns its
#: place because it is the only value on the row that says which service wrote
#: it (see the module docstring's limitation).
APPROVE_ROUTE = "/challenges/{challenge_id}/approve"

# The closed vocabulary this module writes into ``detail``, standing in for
# the ``refusal_reason`` values that do not exist (module docstring).
#
# ``detail``'s documented meaning on the read path is "the exception TYPE that
# ended the call", and its own column comment widens that to "what this column
# records is HOW FAR the call got", which is what these are: each names the
# stage at which the approval stopped. They are literals rather than
# ``type(exc).__name__`` because nothing raises on these paths -- the handler
# returns a response -- and manufacturing an exception class per refusal just
# to read its name back off would be worse.
#
# Unlike ``refusal_reason`` and ``outcome``, ``detail`` is an unconstrained
# ``Text`` column, so nothing at the database enforces this set. That is the
# reason to keep the names here in one place rather than inline at six call
# sites: a misspelling is then a diff in this block rather than a value
# nothing filters on.
DETAIL_MISSING_SIGNATURE = "missing_signature"
DETAIL_CHALLENGE_NOT_FOUND = "challenge_not_found"
DETAIL_CHALLENGE_NOT_OWNED = "challenge_not_owned"
DETAIL_ALREADY_TERMINAL = "already_terminal"
DETAIL_EXPIRED = "expired"
DETAIL_CHALLENGE_VANISHED = "challenge_vanished"
DETAIL_UPDATE_MATCHED_NO_ROW = "update_matched_no_row"

# `audit_log.client_id` is `String(512)` (models.py). The value here comes off
# a verified assertion's claims, so producing an over-length one takes the
# operator's app-backend signing key rather than a crafted request -- the same
# likelihood `services/api/middleware/audit.py`'s `_MAX_CLIENT_ID` reasons
# about, and the same consequence, which is why the bound exists at all: a
# value wider than the column raises
# `asyncpg.exceptions.StringDataRightTruncationError` at the INSERT, which
# under the fail-closed policy costs the audit row and the approval.
_MAX_CLIENT_ID = 512

# U+2026 HORIZONTAL ELLIPSIS, the same marker
# `services/api/middleware/audit.py` uses and for the reasons its own constant
# gives at length: it survives `_strip_invisible` (category `Po`), it is
# neither a digit nor a letter so it can neither extend a PAN run nor sit
# inside an IBAN token, and it cannot be misread as `_MASK`.
#
# A SECOND COPY, and that is a known cost rather than an oversight. Promoting
# `_clamp` and this marker alongside `scrub_text`/`scrub_tree` was considered
# and left out of that change: they are not masking, they are audit-column
# width management, so `postern_core.domain.masking` is the wrong home and
# `postern_core.store.audit` would be a second unrequested promotion. Recorded
# here so the next person to need a third copy promotes it instead.
_TRUNCATED = "…"


def _clamp(value: str, limit: int) -> str:
    """``value`` cut to fit ``limit`` characters, carrying ``_TRUNCATED`` when,
    and only when, something was cut.

    The cut is to ``limit - len(_TRUNCATED)``, not to ``limit``: appending the
    marker to a value already cut to the column width would write
    ``limit + 1`` characters, which is the truncation error the clamp exists
    to avoid. A value already within ``limit`` comes back unchanged, character
    for character -- a marker on a value nothing touched would be the row
    lying about itself.
    """
    if len(value) <= limit:
        return value
    return value[: limit - len(_TRUNCATED)] + _TRUNCATED


def _client_id(claims: dict[str, Any]) -> str | None:
    """Which client the verified assertion names, scrubbed and clamped.

    ``client_id`` then ``azp``, which is the order
    ``fastmcp``'s ``JWTVerifier`` uses, MINUS its final two fallbacks: that
    implementation ends ``or claims.get("sub") or "unknown"``, and neither is
    wanted here. Falling back to ``sub`` would copy the customer reference
    into the client column, where ``services/api/middleware/audit.py``'s own
    ``_client_id`` has to scrub it back out again; falling back to
    ``"unknown"`` would write a literal that names nobody while reading like
    an identity.

    A DIVERGENCE FROM ``AuditEntry.client_id``'S STATED AGREEMENT, recorded
    at the write site because that is where the next reader will be standing.
    That column's comment says a NULL ``client_id`` and
    ``customer_ref_absence_reason = 'no_access_token'`` are the same fact.
    They are, on the read path, where both come from one ``AccessToken``. On
    THIS path they are not: there is no OAuth client at all. The caller is the
    operator's own banking app, authenticated by a signed assertion whose
    ``iss`` identifies it and for which this table has no column. So a NULL
    here sits beside a NON-NULL ``customer_ref`` on every row whose assertion
    carried neither claim, and that combination -- impossible on a read-path
    row -- is not a defect. It means "the assertion named no client".

    Scrubbed for the reason the read path scrubs the same column: a
    compromised assertion issuer can mint a PAN-, IBAN- or DNI-shaped claim,
    and this is a long-lived table. Clamped afterwards as the fail-safe
    against the column width, with the marker appended after the scrub so
    nothing in the masking layer can strip it.
    """
    raw = claims.get("client_id") or claims.get("azp")
    if not isinstance(raw, str) or not raw:
        return None
    marker = _TRUNCATED if len(raw) > _MAX_CLIENT_ID else ""
    return _clamp(scrub_text(raw[: _MAX_CLIENT_ID - len(marker)]) + marker, _MAX_CLIENT_ID)


def _subject_columns(subject: str) -> tuple[str | None, str | None]:
    """``(customer_ref, customer_ref_absence_reason)`` for a verified subject.

    Exactly one is ever non-None, which is what
    ``ck_audit_log_customer_ref_xor_absence`` enforces at the database and
    what returning the pair from one function makes structural rather than a
    rule two call sites have to remember.

    ONLY ONE OF THE THREE ABSENCES IS REACHABLE HERE, and that is worth
    writing down because the vocabulary was built for the read path.
    ``AppAssertionMiddleware`` refuses any request whose token is missing,
    unverifiable, or carries no ``sub`` -- ``verified is None or not
    verified.subject`` is a 401 before routing -- so by the time this runs
    there is always a non-empty string subject. ``no_access_token`` and
    ``no_string_subject`` are therefore unreachable on this path and this
    service will never write either.

    ``subject_not_a_customer_ref`` IS reachable, and it is the one that
    matters: ``postern_core.identity``'s warning is that a compromised issuer
    can mint a ``sub`` shaped like a bare PAN, IBAN or DNI, and the issuer
    here is the operator's app backend. Storing such a subject raw would put
    the value in a regulator-facing table through the very column that exists
    to keep it out. Separately, ``audit_log.customer_ref`` is ``String(128)``,
    so an over-long subject would raise at the INSERT and, fail-closed, kill
    the approval.

    A free property falls out of this and is worth stating: a non-conforming
    subject can NEVER own a challenge, because ``challenges.customer_ref`` is
    only ever written by the read path, which validates through the same type.
    So every row this branch produces is a 404 -- a clean, unambiguous
    compromised-issuer signal rather than a mixed population.

    The rejected string is never returned on any branch. ``CustomerRef`` sets
    ``hide_input_in_errors``, which scrubs ``str()`` and ``repr()`` of the
    exception but leaves the raw value in its structured ``.errors()``, so the
    ``ValidationError`` is neither re-raised nor logged.
    """
    try:
        return CustomerRef(value=subject).value, None
    except ValidationError:
        return None, ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF


class ApprovalAudit:
    """One approval request's pair of audit rows.

    Built once per request by ``services/confirm/callback.py``, immediately
    after a verified subject and a non-empty challenge id both exist. The
    mirror of ``services/api/middleware/audit.py``'s ``_PendingEntry``, with
    one simplification the write path is entitled to: the read path binds its
    entry into a ``ContextVar`` because ``BackendClient`` is built once per
    process while the row is per call, whereas ``BackendWriteClient`` is
    constructed inside the handler, so ``record`` is handed to it directly and
    no ambient state exists to propagate or to leak between requests.

    WHERE THE ENTRY ROW IS WRITTEN FROM, and why not from the handler. It is
    passed as ``BackendWriteClient``'s ``before_backend_request`` hook and
    invoked as the last statement before the outbound request, AFTER the write
    JWT has been minted. That placement is what makes the row's existence mean
    something stronger than "we intended to call the backend": it means a
    write token was minted for this challenge and the socket was next. A mint
    that fails therefore writes no entry row, correctly -- nothing was
    reached, and nothing could have been.

    It also means a second write endpoint added to this service tomorrow
    cannot reach a backend unaudited, because the hook parameter on
    ``BackendWriteClient`` has no default.
    """

    __slots__ = (
        "_arguments",
        "_at",
        "_call_id",
        "_client_id",
        "_customer_ref",
        "_customer_ref_absence_reason",
        "_db",
        "_lock",
        "_redaction_budget_exhausted",
        "_started",
        "_tool_name",
        "_written",
    )

    def __init__(
        self,
        *,
        db: Database,
        call_id: str,
        at: datetime,
        started: float,
        subject: str,
        claims: dict[str, Any],
        challenge_id: str,
        body: dict[str, Any],
    ) -> None:
        self._db = db
        self._call_id = call_id
        self._at = at
        self._started = started
        self._customer_ref, self._customer_ref_absence_reason = _subject_columns(subject)
        # ONE ALLOWANCE FOR THE WHOLE REQUEST, not one per string. Without
        # this, every string validated gets its own fresh checksum budget
        # (`masking._IBAN_SCAN_BUDGET`), and a caller that spreads junk across
        # `confirming_device` and `verification_result` rather than
        # concentrating it in one would buy a fresh allowance per field
        # instead of spending down one shared one. The read path's
        # `on_call_tool` holds the same invariant for the same reason.
        #
        # `_client_id` runs INSIDE the scope, like the read path's does, so an
        # assertion claim cannot get a private allowance either.
        with redaction_budget() as scope:
            self._client_id = _client_id(claims)
            self._arguments = _arguments(challenge_id, body)
        self._redaction_budget_exhausted = scope.exhausted
        # `challenges.tool_name` is `String(64)`, the same width as
        # `audit_log.tool_name`, and `scrub_tree` never lengthens a value in
        # characters, so no clamp is needed on this column and none is
        # applied. Filled in by `resolve` once the challenge is read; until
        # then the row would name the unresolved literal, which is what every
        # path that never resolves a challenge records.
        self._tool_name = UNRESOLVED_TOOL_NAME
        self._lock = asyncio.Lock()
        self._written = False

    @property
    def call_id(self) -> str:
        """The correlation key both of this request's rows carry."""
        return self._call_id

    def resolve(self, tool_name: str) -> None:
        """Name the operation, once the challenge row has been read.

        Scrubbed like every other value that reaches this table. The cost is
        nil for a real tool name -- an ordinary dotted identifier contains no
        letter-letter-digit-digit opener and spends no checksums at all -- and
        it keeps this module from being the one place where a value reaches
        ``audit_log`` unmasked because somebody reasoned that it could not
        have been attacker-influenced.

        Not inside the ``redaction_budget`` scope the constructor opened: that
        scope has closed by the time the challenge is read, and re-entering it
        is not possible. The value is bounded at 64 characters by the column
        it came out of, so the fresh per-string allowance it gets cannot be
        spent to any meaningful degree -- the read path measures 223 checksums
        of 100,000 for a maximum-density 64-character worst case.
        """
        self._tool_name = scrub_text(tool_name)

    async def record(self) -> None:
        """Commit this request's entry row, at most once.

        The signature is ``BackendWriteClient``'s ``before_backend_request``
        hook: zero arguments, awaited, and a raise stops the request.

        AT MOST ONCE, behind a lock. ``BackendWriteClient.execute`` is called
        once per approval today, so "one entry row per request" would hold by
        arithmetic; the guard is what keeps it holding when a future handler
        issues two writes for one challenge, where two ``reaching`` rows under
        one ``call_id`` would break the pairing rather than describe it. The
        lock makes it at-most-once rather than usually-once: two concurrent
        calls would both find ``_written`` False across the ``await`` between
        the check and the commit.

        ``_written`` is set INSIDE the session block, on the line after the
        commit, and that placement is load-bearing exactly as it is on the
        read path. Set after the block, a commit that succeeds followed by a
        raising session exit leaves a durable ``reaching`` row with the flag
        still False, so a caller that catches and touches again writes a
        SECOND row under the same ``call_id``.
        """
        async with self._lock:
            if self._written:
                return
            try:
                await self._write_entry_row()
            except Exception as audit_exc:
                # ITS OWN ERROR LINE, because this is the one write of the two
                # that the handler's completion path may paper over: the
                # exception propagates out of `BackendWriteClient.execute`,
                # the handler's outer `except` records an ordinary `raised`
                # completion row for it, and the operator would otherwise be
                # left with a routine-looking failure row and no signal
                # anywhere that the audit store is what failed.
                #
                # Re-raised unchanged: stopping the backend request is the
                # whole point, and the caller needs the exception to do it.
                logger.error(
                    "audit entry write failed for challenge approval of %r; the backend "
                    "write it precedes will not be made",
                    self._tool_name,
                    exc_info=audit_exc,
                )
                raise

    async def _write_entry_row(self) -> None:
        """The entry write itself, split out only so ``record`` can wrap it in
        one ``try`` without burying the row's field-by-field reasoning inside
        an exception handler."""
        async with self._db.sessionmaker() as session:
            await audit.append(
                session,
                at=self._at,
                # THE LAST READING BEFORE THE TOUCH, and the only instant on
                # this row that is not the request's arrival. Read HERE, one
                # statement before the INSERT, rather than when `record` was
                # entered: it is the closest reading to the request that this
                # row can carry and still be durable before the request is
                # made. It therefore precedes the request by the INSERT, the
                # commit and the session exit, and is early rather than late.
                #
                # A wall clock, where the duration below refuses one: this is
                # an instant that has to be comparable with `at`, which is
                # itself a wall-clock reading.
                reaching_at=datetime.now(UTC),
                customer_ref=self._customer_ref,
                customer_ref_absence_reason=self._customer_ref_absence_reason,
                tool_name=self._tool_name,
                arguments=self._arguments,
                outcome=OUTCOME_REACHING,
                # NULL: nothing has gone wrong. The completion row is where an
                # outcome is described.
                detail=None,
                redaction_budget_exhausted=self._redaction_budget_exhausted,
                # NULL, and the one column where that needs saying: the
                # backend write has not finished, so no duration exists to
                # record. `outcome` is what keeps this distinguishable from a
                # pre-migration row, not this column.
                duration_ms=None,
                # NULL for the reason `_completion` states: this service has
                # no request-id header convention to read one from.
                request_id=None,
                # NULL on every row this service writes. The module docstring
                # carries the vocabulary gap that forces it.
                refusal_reason=None,
                call_id=self._call_id,
                client_id=self._client_id,
                # NULL, not `[]`, and the difference is the documented one:
                # `[]` means "a risk session ran and no signals fired", NULL
                # means no session handle existed. There is no risk session on
                # this path at all -- `RiskEngine` and `IpAnomalyDetector` are
                # wired into `services/api`'s tool middleware and nothing in
                # this service establishes a session -- so NULL is the true
                # statement and `[]` would be a false one.
                risk_signals=None,
            )
            self._written = True

    async def returned(self) -> None:
        """Record that the approval finished its work successfully."""
        await self._completion(OUTCOME_RETURNED, None)

    async def raised(self, detail: str) -> None:
        """Record that the approval stopped, and at which stage.

        ``detail`` is one of the ``DETAIL_*`` literals above for a refusal, or
        ``type(exc).__name__`` for a genuine exception -- never an exception's
        MESSAGE, which for a ``pydantic.ValidationError`` embeds the raw
        offending value and would be the leak CLAUDE.md's masked-type rule
        describes, into a long-lived store.
        """
        await self._completion(OUTCOME_RAISED, detail)

    async def _completion(self, outcome: str, detail: str | None) -> None:
        async with self._db.sessionmaker() as session:
            await audit.append(
                session,
                at=self._at,
                # NULL, written as a literal rather than taken as a parameter,
                # because no path that reaches here has a touch instant to
                # record: the touch is on the entry row or did not happen.
                # Copying the entry row's value would store one fact twice on
                # rows free to disagree, and
                # `ck_audit_log_reaching_at_matches_outcome` rejects it
                # outright -- at the cost of the row and the request.
                reaching_at=None,
                customer_ref=self._customer_ref,
                customer_ref_absence_reason=self._customer_ref_absence_reason,
                tool_name=self._tool_name,
                arguments=self._arguments,
                outcome=outcome,
                detail=detail,
                redaction_budget_exhausted=self._redaction_budget_exhausted,
                # `time.monotonic()` and not a wall clock: a wall clock can
                # step backwards under an NTP correction mid-request and put a
                # negative duration into an append-only table. Rounded DOWN,
                # so the row can never report the operator as slower than it
                # was. A sub-millisecond request records 0, never NULL -- the
                # two are different statements on this column, and NULL means
                # "this row predates the column".
                duration_ms=int((time.monotonic() - self._started) * 1000),
                # NULL, and it is a live state rather than a forgotten
                # argument, which is the distinction that column's comment
                # insists on. The read path fills it with the JSON-RPC id of
                # the `tools/call` the row describes. This service speaks
                # plain HTTP with no JSON-RPC envelope and no request-id header
                # convention anywhere in the repository, so there is no
                # identifier to read: the handler looked and there was none.
                # `arguments['challenge_id']` is what correlates a row here
                # with the backend's access log, through the `Idempotency-Key`
                # header carrying the same string.
                request_id=None,
                refusal_reason=None,
                call_id=self._call_id,
                client_id=self._client_id,
                risk_signals=None,
            )


def _arguments(challenge_id: str, body: dict[str, Any]) -> dict[str, Any]:
    """What this request carried, scrubbed, with nothing duplicated from the
    ``challenges`` row.

    MUST BE CALLED INSIDE A ``redaction_budget()`` BLOCK, and never inside a
    second one of its own: the scrubs below spend from whichever budget is
    ambient, and the one-allowance-per-request invariant the constructor holds
    is exactly what a private scope would reintroduce a hole in.

    ``challenge_id`` arrives from the URL path and the other two from the JSON
    body, so all three are caller-influenced and all three are scrubbed.
    ``signature`` is reduced to a boolean before it reaches this table at all.

    Not clamped, unlike ``tool_name`` and ``client_id``: this is a ``JSONB``
    column with no width to overflow. The read path makes the same choice for
    the same reason -- it clamps ``tool_name``, ``request_id`` and
    ``client_id``, and leaves the argument tree unbounded.
    """
    return {
        "route": APPROVE_ROUTE,
        "challenge_id": scrub_text(challenge_id),
        # PRESENCE, NEVER THE VALUE. CLAUDE.md forbids a raw signature in this
        # table. A digest was considered as a middle path -- it would let an
        # investigator spot one signature replayed across challenges without
        # storing it -- and rejected: the value is unverified and carries no
        # defined meaning (`services/confirm/callback.py`'s docstring is
        # explicit that presence is the entire check), so a digest of it would
        # look like cryptographic evidence and be none.
        "signature_present": bool(body.get("signature")),
        # Recorded here because on every refused path they exist NOWHERE else:
        # `update_challenge_status` writes them onto the challenge row only on
        # the winning transition, so a 404, 409 or 410 would otherwise lose
        # what the caller sent.
        "confirming_device": scrub_tree(body.get("confirming_device")),
        "verification_result": scrub_tree(body.get("verification_result")),
    }

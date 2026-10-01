"""What this service writes to ``audit_log``: up to two rows per challenge
approval, and exactly one per device-grant pairing.

TWO WRITERS, ONE MODULE. ``ApprovalAudit`` records
``POST /challenges/{challenge_id}/approve`` and is what everything above the
heading "THE SHAPE IS THE READ PATH'S" describes. ``PairingAudit``, at the
bottom of this file, records ``POST /approve`` -- the RFC 8628 pairing that
authorises a client to reach the first endpoint at all -- and carries its own
reasoning under its own heading. They share this module because
``services/confirm/callback.py`` already says that every decision about this
service's rows lives in one place, and a second writer in a second file would
make that sentence false the day it landed.

``ApprovalAudit``: WHY IT EXISTS. Until 2026-09-23 this service wrote NO
audit rows at all. A
grep for ``audit`` across ``services/confirm/*.py`` returned comments and
nothing else, while ``services/api`` wrote two rows for every tool call. The
asymmetry ran exactly backwards: reading a balance was fully recorded, and
approving a payment -- the highest-consequence action in the system -- left
behind only the ``challenges`` row it mutated, whose ``confirming_device`` and
``signature`` were both caller-supplied and neither of which was verified. An
investigator after an incident had no approval instant distinct from the row's
own, no record that a write JWT had been minted, and no correlation key tying
any of it to anything. Under GDPR that is a 72-hour notification problem, not
only an operations one.

``signature`` STOPPED BEING CALLER-SUPPLIED-AND-UNCHECKED ON 2026-09-24.
``services/confirm/device_signature.py`` verifies it against a key the
operator enrolled for that customer, over bytes built from the stored row, and
three of the ``DETAIL_*`` literals below exist to tell its refusals apart. The
value on the ``challenges`` row is now evidence rather than an echo; what this
table records about it is unchanged, and the reasoning for that is at
``_arguments`` below.

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
the backend. A ZT-7 revocation refusal (403) joins them for the same reason
and is recorded even earlier -- it is decided before the challenge is read, so
its row names no tool, which is the same shape a 404 for an unknown id takes.

TWO BACKSTOPS BEFORE THAT POINT WRITE NOTHING, both unreachable through the
assembled app and both logged instead. The handler's own 401 fires only when
``AppAssertionMiddleware`` did not run, and at that point there is no subject
at all -- a row would have to invent a class of absence that
``CUSTOMER_REF_ABSENCE_REASONS`` does not name. The empty-``challenge_id``
400 fires only when something other than the route table dispatched the
request, since Starlette cannot match an empty path segment, and a row naming
no challenge names nothing an investigator can act on.

A THIRD WRITES NOTHING AND IS REACHABLE, as of 2026-09-24: an oversized body
is refused with 413 by ``services/confirm/body_limit.py``, which runs in front
of ``AppAssertionMiddleware`` and so has no verified subject to record and no
database handle to record it with. Giving it one would let an unauthenticated
caller drive an INSERT per request, which is a cheaper denial of service than
the one that middleware closes. So an oversized body IS a way to make a
request this table does not see. What that costs is bounded by what such a
request does, which is nothing: no challenge is read, none moves, and no write
JWT is minted. The refusal is logged and that is its only trace. A MALFORMED
body is the opposite case and gets a row (``DETAIL_MALFORMED_BODY``), because
by the time it is found the subject and the challenge id both exist and this
module's rule above already owed one.

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
table, and the verified one is already on the ``challenges`` row that
``arguments['challenge_id']`` joins to.

``refusal_reason`` IS NULL ON EVERY ROW THIS MODULE WRITES, which is a gap and
not a decision anybody is happy with. ``REFUSAL_REASONS``
(``postern_core.store.models``) is closed at ``no_customer_ref``,
``domain_not_consented`` and ``consent_store_unavailable``, all three about
the read path's consent check, and ``ck_audit_log_refusal
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
import hashlib
import logging
import time
from datetime import UTC, datetime
from typing import Any

from postern_core.domain.masking import redaction_budget, scrub_text, scrub_tree
from postern_core.identity import CustomerRef
from postern_core.net import client_ip
from postern_core.store import audit
from postern_core.store.audit import TRUNCATED, bound_arguments, clamp
from postern_core.store.engine import Database
from postern_core.store.models import (
    ABSENCE_SUBJECT_NOT_A_CUSTOMER_REF,
    OUTCOME_RAISED,
    OUTCOME_REACHING,
    OUTCOME_RETURNED,
)
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

logger = logging.getLogger(__name__)

__all__ = [
    "APPROVE_ROUTE",
    "OUTCOME_RAISED",
    "OUTCOME_RETURNED",
    "PAIRING_ROUTE",
    "PAIRING_TOOL_NAME",
    "SCAN_ROUTE",
    "SCAN_TOOL_NAME",
    "TOKEN_ROUTE",
    "TOKEN_TOOL_NAME",
    "UNRESOLVED_TOOL_NAME",
    "ApprovalAudit",
    "DETAIL_ALREADY_APPROVED",
    "DETAIL_ALREADY_SCANNED",
    "DETAIL_ALREADY_TERMINAL",
    "DETAIL_CHALLENGE_NOT_FOUND",
    "DETAIL_CHALLENGE_NOT_OWNED",
    "DETAIL_CHALLENGE_VANISHED",
    "DETAIL_DEVICE_CODE_NOT_FOUND",
    "DETAIL_DEVICE_CODE_SPENT",
    "DETAIL_DEVICE_NOT_ENROLLED",
    "DETAIL_EXPIRED",
    "DETAIL_ISSUANCE_DISABLED",
    "DETAIL_INVALID_SUBJECT",
    "DETAIL_MALFORMED_BODY",
    "DETAIL_MISSING_SIGNATURE",
    "DETAIL_NOT_SCANNED",
    "DETAIL_QR_INVALID",
    "DETAIL_QR_STALE",
    "DETAIL_REVOKED",
    "DETAIL_SCANNED_BY_OTHER",
    "DETAIL_SCAN_CONFLICT",
    "DETAIL_SIGNATURE_INVALID",
    "DETAIL_SIGNATURE_MALFORMED",
    "DETAIL_STORED_IDENTITY_MALFORMED",
    "DETAIL_UPDATE_MATCHED_NO_ROW",
    "DETAIL_USER_CODE_BUDGET_EXHAUSTED",
    "DETAIL_USER_CODE_MISMATCH",
    "DETAIL_USER_CODE_NOT_FOUND",
    "PairingAudit",
    "device_code_handle",
    "pairing_client_ip",
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
#: ZT-7. The one refusal here that is decided BEFORE the challenge is read, so
#: the row it lands on carries ``UNRESOLVED_TOOL_NAME`` and no entry row --
#: nothing was resolved and nothing was reached. ``WHERE detail = 'revoked'``
#: is how an operator confirms their revocation took effect on the write path,
#: and it is the only place that is durable: this service has no client id to
#: put in a log line the way `services/api/middleware/revocation.py` does.
DETAIL_REVOKED = "revoked"
#: The body could not be read as an approval -- not JSON, not decodable as
#: UTF-8, nested past the interpreter's recursion limit, or well-formed JSON
#: that is not an object. Until 2026-09-24 every one of those was an unhandled
#: exception from a bare ``await request.json()``, so the request 500ed and
#: wrote NO row -- a silent refusal path beyond the two
#: ``services/confirm/callback.py``'s docstring enumerates, and one this
#: module's own rule already said should be recorded, since it is reached well
#: past the point where a verified subject and a non-empty challenge id both
#: exist. One literal covers all four shapes because ``detail`` records the
#: STAGE an approval stopped at, and all four stopped at the same one.
DETAIL_MALFORMED_BODY = "malformed_body"
DETAIL_MISSING_SIGNATURE = "missing_signature"
#: THE THREE THE SIGNATURE CHECK OWNS, and the reason they are three rather
#: than one literal spanning "the signature did not get us through". All three
#: answer 403 and none of them moves a challenge, so the caller cannot tell
#: two of them apart and the table must.
#:
#: ``device_not_enrolled`` is the store answering that this customer has no
#: phone enrolled -- a support event, and in bulk the shape of an enrolment
#: pipeline that stopped publishing. It is DISTINCT FROM AN OUTAGE, which
#: raises `postern_core.auth.device_keys.DeviceKeyStoreUnavailable` and lands
#: on a row whose ``detail`` is that exception's type: an operator must never
#: read "the store is down" as "every customer un-enrolled at once".
#:
#: ``signature_malformed`` is a value that is not a spelling of an Ed25519
#: signature at all, which is a client defect rather than an attack.
#:
#: ``signature_invalid`` is the one to alert on: a well-formed signature that
#: verifies against none of this customer's enrolled devices, which is what
#: something holding a stolen app assertion produces.
DETAIL_DEVICE_NOT_ENROLLED = "device_not_enrolled"
DETAIL_SIGNATURE_MALFORMED = "signature_malformed"
DETAIL_SIGNATURE_INVALID = "signature_invalid"
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

# NO LONGER A SECOND COPY, AS OF 2026-09-24. This constant and ``_clamp``
# below were duplicated here from ``services/api/middleware/audit.py`` on
# 2026-09-23, with a comment recording that as a known cost and naming
# ``postern_core.store.audit`` as where a third copy should be promoted
# instead. The third copy became due immediately: ``_arguments`` below needed
# the argument bounds the read path had just grown, and ``.importlinter``
# forbids ``services.confirm`` importing ``services.api`` in either
# direction, so promotion was the only lawful way to share them. Both
# services now re-bind the promoted names, and the reasoning for each went
# with the code.
#
# U+2026 HORIZONTAL ELLIPSIS, for the reasons the promoted constant gives at
# length: it survives ``_strip_invisible`` (category ``Po``), it is neither a
# digit nor a letter so it can neither extend a PAN run nor sit inside an
# IBAN token, and it cannot be misread as ``_MASK``.
#
# Re-bound to the old private names as assignments rather than
# ``import ... as``, matching how ``services/api/middleware/audit.py`` rebinds
# ``_scrub``: every comment in this file that reasons about ``_clamp``'s
# reservation of the marker's own character still describes exactly the
# function being called.
_TRUNCATED = TRUNCATED
_clamp = clamp


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
        an exception handler.

        THE ONE AUDIT WRITE IN THIS REPOSITORY THAT DOES **NOT** USE THE
        RESERVE, and the omission is the decision rather than an oversight.
        ``postern_core.store.audit``'s ``append_with_reserve`` gives a refused
        checkout a second, reserved connection, and both completion writes
        below use it. This one keeps the pool's answer.

        WHY. This write is the last statement before a backend WRITE endpoint
        is reached, and the ``approved -> executed`` transition that follows
        the money moving runs on ``_approve``'s own session -- the application
        pool, not an audit write, and nothing a reserve may cover without
        becoming a second pool. Routing this row to the reserve would carry a
        request across the money boundary on a connection that cannot carry it
        to the end: the backend accepts the write, the transition is then
        refused by the very pool the reserve was standing in for, and the
        challenge is stranded in ``approved`` with the money gone. Refusing
        here instead stops the request BEFORE the money moves, which is what
        ``BackendRequestHook``'s contract already says this raise is for, and
        the refusal is then recorded by ``_completion`` on the reserve.

        It is also why the read path's equivalent DOES use the reserve and is
        not inconsistent with this: ``services/api`` has no application-pool
        checkout after its touch -- its completion row is an audit write -- so
        covering its entry row carries the request to completion, where
        covering this one would not.

        NO LATENCY BEFORE MONEY MOVES, as a consequence rather than as an aim:
        this path gains no second wait, so the interval between the claim and
        the outbound write is exactly what it was.
        """
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
        """THROUGH ``append_with_reserve`` SINCE 2026-09-27.

        This is the row that says what happened to an approval, and a pool at
        its ceiling used to lose it in both of the states where it is worth
        most: the refusal of an approval this service never attempted, and --
        worse -- the case the backend ACCEPTED the write and the
        ``approved -> executed`` transition was then refused by the same
        exhausted pool, which is the money-moved-and-unrecorded state
        ``dev-docs/decisions/0013-connection-pool-ceiling.md`` already names as
        this service's reason to keep headroom.

        Nothing about the row changes: same columns, same instant, same
        duration, and a failure to write it still fails the request.
        """

        async def row(session: AsyncSession) -> None:
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

        await audit.append_with_reserve(self._db, row)


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

    BOUNDED SINCE 2026-09-24, and the paragraph this replaces said the
    opposite: "not clamped ... this is a ``JSONB`` column with no width to
    overflow. The read path makes the same choice for the same reason." Both
    halves were wrong by the time they were read. The reason to bound this
    column is the disk and not the column's width, the read path had already
    stopped making that choice in ``1a97160``, and the same defect is strictly
    worse here on two counts that were measured rather than argued
    (2026-09-24, against this column):

    1. NO BODY LIMIT AT ALL. ``services/api`` wires ``HeaderBodyValidation``
       with ``max_body_bytes``, which is what capped the read path's version
       of this attack at 1 MiB. ``services/confirm/main.py``'s
       ``create_confirm_app`` passes only ``AppAssertionMiddleware``, so
       nothing bounds an approval body: a 404 carrying 10,131,578 characters
       in ``confirming_device`` wrote 7,742,315 bytes to this column in ONE
       row.
    2. A ROW ON EVERY REFUSED PATH. The module docstring's own rule is that
       every attempt past a verified subject and a non-empty challenge id
       gets a completion row, so a caller needs NO valid challenge to write
       one. A 404 aimed at an id naming nothing, carrying 1 MiB, wrote 979,108
       bytes on disk and 992,895 bytes of JSON text. That is the cheap attack:
       no challenge to create, no race to win, no expiry to beat.

    Fail closed (``dev-docs/decisions/0006-audit-write-failure.md``) is what
    turns a full volume into an outage, and the two services SHARE the
    database, so filling it from here takes down every tool call in
    ``services/api`` as well as every approval here.

    THE SAME BOUNDS AS THE READ PATH, from the one place both import, with
    the reasoning for every constant in ``postern_core.store.audit``. The
    same per-value clip, the same tree ceiling and the same
    ``postern.arguments_truncated`` marker, so one query finds truncation
    across both services -- which matters here more than anywhere, because
    the module docstring above records that no column of ``audit_log`` names
    the service that wrote the row.

    THE KEY ORDER BELOW IS LOAD-BEARING and must not be tidied.
    ``cap_arguments`` keeps a first-fit prefix of top-level entries, so the
    three server-chosen keys are listed before the two caller-supplied ones:
    an over-limit tree therefore keeps ``route``, ``challenge_id`` and
    ``signature_present`` -- everything an investigator needs to identify the
    request -- and drops exactly the two fields that carried the junk.
    Measured: a 404 carrying 1 MiB now writes a row whose ``arguments`` names
    the challenge it was aimed at, says two keys were dropped, and records
    what the caller really sent in ``original_bytes``.

    WHAT THIS DOES NOT CLOSE, stated here because bounding the column makes
    it easy to believe otherwise: the body is still parsed in full before any
    of this runs, so the MEMORY cost of a 10 MiB approval body is unchanged.
    Only the bytes that reach the disk are bounded. Closing the other half is
    an ASGI body-size middleware on this service, which is a separate change
    with its own ordering question against ``AppAssertionMiddleware``.
    """
    return bound_arguments(
        {
            "route": APPROVE_ROUTE,
            # Clipped at `MAX_ARGUMENT_VALUE` like everything else, which
            # costs this column nothing it was worth keeping:
            # `challenges.challenge_id` is `String(36)` (models.py), so an id
            # past 512 characters can name no challenge that exists and the
            # join this value serves -- to `challenges`, and to the backend's
            # access log through the `Idempotency-Key` header carrying the
            # same string -- was never going to resolve for it. What is
            # clipped is only ever an enumeration probe, and it still records
            # its own first 511 characters and says it was cut.
            "challenge_id": scrub_text(challenge_id),
            # PRESENCE, NEVER THE VALUE. CLAUDE.md forbids a raw signature in
            # this table, and the reason to keep it that way survived the
            # value becoming meaningful on 2026-09-24. A digest was considered
            # as a middle path -- it would let an investigator spot one
            # signature replayed across challenges without storing it -- and
            # rejected twice over: while the value was unverified a digest of
            # it would have looked like cryptographic evidence and been none,
            # and now that `services/confirm/device_signature.py` verifies it,
            # the signature that actually approved a payment is on the
            # `challenges` row this column's `challenge_id` joins to. One fact,
            # one table. What no row here records is a signature that was
            # presented and REFUSED, which `detail` names by class instead.
            #
            # It is also the one caller-supplied field of the five that the
            # bounds never had to reach, because a boolean has no width.
            "signature_present": bool(body.get("signature")),
            # Recorded here because on every refused path they exist NOWHERE
            # else: `update_challenge_status` writes them onto the challenge
            # row only on the winning transition, so a 404, 409 or 410 would
            # otherwise lose what the caller sent.
            #
            # LAST, AND IN THIS ORDER, for the first-fit reason above: these
            # two are the unbounded caller input, so they are the two a capped
            # tree drops.
            "confirming_device": scrub_tree(body.get("confirming_device")),
            "verification_result": scrub_tree(body.get("verification_result")),
        }
    )


# ---------------------------------------------------------------------------
# PairingAudit -- one row per recorded ``/scan``, ``/approve`` or ``/token``.
# ---------------------------------------------------------------------------
#
# WHY THIS EXISTS. Until 2026-09-26 ``services/confirm/device_auth.py`` wrote
# no row on any branch of ``POST /approve``: every occurrence of the string
# ``audit`` in that file was prose about findings C-01 and C-04. So the
# highest-consequence action in the system was recorded twice over and the
# pairing that grants a client the standing to attempt it was recorded not at
# all. An attacker who paired a rogue client left exactly one trace, the
# payments that followed, and left none if none followed. That is the same
# asymmetry ``ApprovalAudit`` above was built to end, one endpoint later.

#: What ``tool_name`` carries on a pairing row.
#:
#: Not a registered MCP tool name, for the reason ``UNRESOLVED_TOOL_NAME``
#: gives: this column is shared with ``services/api``'s rows and nothing on
#: the row says which service wrote it, so a value that could collide with a
#: tool would make ``WHERE tool_name = ...`` ambiguous. The five registered
#: tools are ``start_session``, ``accounts.list``, ``accounts.get_balance``,
#: ``transactions.list`` and ``cards.list``, and this is none of them, so
#: ``WHERE tool_name = 'device_grant.approve'`` is by itself the "every
#: pairing, successful or refused" query.
#:
#: Distinct from ``UNRESOLVED_TOOL_NAME`` rather than reusing it: that literal
#: means "a challenge approval that resolved no challenge", and an operator
#: counting challenge-id enumeration must not have pairings mixed into the
#: result.
PAIRING_TOOL_NAME = "device_grant.approve"

#: The route template, in ``arguments`` for the reason ``APPROVE_ROUTE`` is:
#: constant on every row this writer produces, and therefore useless as a
#: ``tool_name``, but the one value that says which service and which endpoint
#: wrote the row when the two services' rows are read interleaved.
PAIRING_ROUTE = "/approve"

#: What ``tool_name`` carries on a token-exchange row.
#:
#: ITS OWN LITERAL AND NOT THE PAIRING'S, because the two questions are asked
#: separately: "which pairings completed" and "which tokens were issued" have
#: different answers whenever a device code is replayed, and one literal for
#: both would hide exactly that. Both are ``device_grant.*`` so one prefix
#: filter returns the whole flow, and neither is one of the five registered MCP
#: tools (``start_session``, ``accounts.list``, ``accounts.get_balance``,
#: ``transactions.list``, ``cards.list``), so neither can collide with a
#: ``services/api`` row on a column no service name qualifies.
TOKEN_TOOL_NAME = "device_grant.token"  # noqa: S105

#: The route, in ``arguments`` for the reason ``PAIRING_ROUTE`` is there.
TOKEN_ROUTE = "/token"  # noqa: S105

#: What ``tool_name`` carries on a ``POST /scan`` row.
#:
#: ITS OWN LITERAL, for the reason ``TOKEN_TOOL_NAME`` has one: "which
#: pairings were scanned" and "which were approved" differ exactly when a scan
#: conflicts or a code is scanned and abandoned, and one literal would hide
#: both. Under ``device_grant.*`` like the other two, so
#: ``WHERE tool_name LIKE 'device_grant.%'`` still returns the whole flow, and
#: none of the five registered MCP tools.
SCAN_TOOL_NAME = "device_grant.scan"

#: The route, in ``arguments`` for the reason ``PAIRING_ROUTE`` is there.
SCAN_ROUTE = "/scan"

#: The stored ``customer_ref`` on an approved device code will not parse as a
#: ``CustomerRef``.
#:
#: A DIFFERENT LITERAL FROM ``DETAIL_INVALID_SUBJECT``, and the provenance is
#: the whole reason. That one means the operator's app backend minted a
#: non-conforming ``sub`` on an assertion this service verified. This one means
#: a value read back off a device code that ``POST /approve`` had ALREADY
#: validated through the same type does not validate any more -- so either the
#: stored row was altered, or something other than ``approve_callback`` wrote
#: ``customer_ref``, which is the field whose overload was half of audit
#: finding C-01. Those are different incidents with different first responders,
#: and one literal would make a reader guess which a row describes.
DETAIL_STORED_IDENTITY_MALFORMED = "stored_identity_malformed"
#: ``POST /token`` was presented an approved, unexpired, unspent device code
#: for a customer who is not revoked, and refused to issue anything, because
#: issuance was disabled (on 2026-09-30) until the layer-1 session token
#: existed.
#:
#: HISTORICAL SINCE THE LAYER-1 SESSION TOKEN, and kept for the rows that
#: carry it: ``POST /token`` issues a session again and no code in this
#: repository writes this literal any more. ``audit_log`` is append-only, so
#: deleting the name would leave those rows carrying a value nothing in the
#: tree names -- the precedent ``DETAIL_USER_CODE_MISMATCH`` set.
#:
#: WHY IT IS DISABLED. The token this endpoint used to return was a layer-2
#: backend token: ``aud=accounts.svc``, ``scope=accounts:read``,
#: ``act.sub=svc:postern``, signed with the READ key. Under Vault both
#: services sign with the same transit key, which ``services/api`` publishes
#: at its JWKS and Istio trusts, so any client that completed a pairing held a
#: credential the accounts backend accepts. That conflates handoff §7.1's two
#: authentication layers. The row keeps the event countable: every one of
#: these is a pairing that completed and a client that got nothing for it.
#:
#: THE CODE IS NOT SPENT on this refusal, so a browser that keeps polling
#: writes another of these rows, under the same device code handle, each time
#: a poll arrives at least ``device_poll_interval_seconds`` after the last one
#: that did. A poll inside the interval is answered ``slow_down`` and writes
#: nothing, so a code yields at most one row per interval, not one per poll.
DETAIL_ISSUANCE_DISABLED = "issuance_disabled"

# THE CLOSED VOCABULARY OF ``detail`` ON A PAIRING ROW, and the same
# ``refusal_reason`` gap applies: ``REFUSAL_REASONS`` is closed at
# ``no_customer_ref``, ``domain_not_consented`` and
# ``consent_store_unavailable``, all three about the read path's consent
# check, with ``ck_audit_log_refusal_reason`` enforcing it at the database.
# There is no admissible value for "this device code does not exist" or "the
# pairing code did not match", so the refusal class lands in ``detail``, as
# ``ApprovalAudit``'s refusals already do.
#
# ``DETAIL_REVOKED`` above is REUSED rather than duplicated, and that is the
# one decision in this block worth arguing. All three endpoints refuse a
# revoked customer through the same ``services/confirm/revocation.py`` call,
# and one literal makes ``WHERE detail = 'revoked'`` the whole answer to "did my
# revocation take effect on the write path". Two literals would make it an
# answer that silently omits part of it, which is the failure mode
# ``services/confirm/customer_rate_limit.py`` names: a query that undercounts
# by exactly the half nobody thought about is worse than one that returns
# nothing, because the first is trusted.

#: The assertion verified and its ``sub`` is not a ``CustomerRef``. The
#: compromised-issuer signal ``postern_core.identity`` warns about, and the
#: one refusal here whose row carries a NULL ``customer_ref``:
#: ``customer_ref_absence_reason`` names the class and the offending string
#: is stored nowhere, for the reason ``_subject_columns`` gives.
DETAIL_INVALID_SUBJECT = "invalid_subject"
#: A ``device_code`` at ``POST /approve`` that named nothing, the endpoint's
#: enumeration signal while the app sent a ``device_code``.
#:
#: HISTORICAL SINCE 2026-09-30, and kept for the rows that carry it.
#: ``POST /approve`` takes a ``user_code`` now and writes
#: ``DETAIL_USER_CODE_NOT_FOUND`` for its miss, and ``POST /token``'s unknown
#: code writes no row at all, so no code in this repository writes this literal
#: any more. ``audit_log`` is append-only, so deleting the name would leave
#: those rows carrying a value nothing in the tree names.
DETAIL_DEVICE_CODE_NOT_FOUND = "device_code_not_found"
#: A ``user_code`` that names no live pairing: unknown, or expired, at
#: ``POST /scan`` or ``POST /approve``, including a row revoked or expired
#: between ``POST /approve``'s lookup and its re-read after a refused
#: ``approve_scanned``.
#:
#: NEW RATHER THAN A REUSE OF ``DETAIL_DEVICE_CODE_NOT_FOUND``, because the two
#: guesses are not the same size. A ``device_code`` miss is a guess at 256 bits
#: of ``secrets`` entropy; a ``user_code`` miss is a guess at 30 bits, which is
#: exactly the enumeration signal keying on the pairing code opens. One literal
#: for both would mix the cheap guess into the expensive one's history.
DETAIL_USER_CODE_NOT_FOUND = "user_code_not_found"
#: ``POST /approve`` for a code nobody has scanned. Approval requires the
#: approving customer to have scanned first, so this is either an app skipping
#: ``POST /scan`` or something guessing ``user_code`` values.
DETAIL_NOT_SCANNED = "not_scanned"
#: ``POST /approve`` for a code another customer scanned. The response is the
#: same ``invalid_grant`` every other refusal gets; this literal is where an
#: operator sees one customer trying to approve a pairing another one holds.
DETAIL_SCANNED_BY_OTHER = "scanned_by_other"
#: ``POST /scan`` with a rotation token that is malformed, forged, for another
#: pairing, or for a slot ahead of the server's window. Answered with the same
#: ``invalid_grant`` as an unknown code, because nothing about it proves the
#: caller ever held a real QR.
DETAIL_QR_INVALID = "qr_invalid"
#: ``POST /scan`` with a genuine token older than the window. The direct trace
#: of a screenshot relay, and the one refusal here answered with its own
#: ``qr_stale``: a MAC that verifies proves the caller held a real QR for this
#: pairing, so telling them to scan again leaks nothing they did not know.
DETAIL_QR_STALE = "qr_stale"
#: ``POST /scan`` by a second customer inside the token window, whether the
#: pairing was revoked by it (``ScanClaim.CONFLICT_REVOKED``) or had already
#: been exchanged (``ScanClaim.CONFLICT_EXCHANGED``). The trace of one QR seen
#: by two phones, and of a session swap attempted in either order.
DETAIL_SCAN_CONFLICT = "scan_conflict"
#: A second exchange of a code the first one spent, at ``POST /token``. The
#: replay signal, and the highest-value row this table can hold about the
#: device grant: the code was approved by a verified assertion, so something
#: presenting it again either copied it from the browser that earned it or
#: guessed 256 bits of ``secrets`` entropy.
#:
#: A DISTINCT LITERAL FROM ``DETAIL_DEVICE_CODE_NOT_FOUND``, and the response
#: deliberately does not make the same distinction: both answer
#: ``invalid_grant`` in one identical body, so a party holding a guessed code
#: cannot learn from it that the value ever existed. That asymmetry is the
#: point. ``WHERE detail = 'device_code_spent'`` is the whole replay query and
#: there is no other trace of the event -- `services/confirm/device_auth.py`
#: has no client id to put in a log line, which is the argument
#: `services/confirm/revocation.py`'s ``log_refusal`` already makes for the
#: revocation refusal beside it.
#:
#: WHY THE STORE ROW HAS TO SURVIVE FOR THIS TO EXIST. Revoking a spent code
#: instead of marking it would answer a replay from ``token_endpoint``'s
#: unknown-code branch, which runs before ``customer_ref`` is read, so
#: ``PairingAudit``'s rule would owe nothing and this literal would be
#: unreachable. ``dev-docs/decisions/0012-device-code-single-use.md`` carries
#: that trade.
DETAIL_DEVICE_CODE_SPENT = "device_code_spent"
#: A repeat approval by the customer who scanned the code, normally a retried
#: request: at ``POST /approve`` when the code is already approved, and at
#: ``POST /scan`` through ``ScanClaim.APPROVED_MINE``.
#:
#: ``RETURNED`` ON BOTH ROUTES SINCE 2026-09-30. On ``POST /approve`` it is
#: the one ``detail`` a ``returned`` row carries, and on ``POST /scan`` one of
#: the two, with ``DETAIL_ALREADY_SCANNED``: the approver's retry, typically
#: after a lost 200, is answered with the 200 the first request got (on
#: ``POST /scan`` the stored pairing's context, reached only with a genuine
#: in-window rotation token), because the approval it follows stands and only
#: the customer who scanned and approved the code can reach this answer.
#: ``returned`` because the request succeeded; a non-NULL ``detail`` so this
#: repeat is never counted with the NULL rows of a first approval or a first scan.
#: It writes nothing to the store. On ``POST /approve`` it can still be a refusal
#: (``outcome='raised'``), for a code approved for another customer.
#:
#: REWRITTEN ON 2026-09-30, because the rationale it carried stopped being
#: possible. It used to be a caller holding an assertion of their own swapping
#: ``customer_ref`` to themselves in the window before the browser polls
#: ``POST /token``. ``approve_scanned`` now approves only for the customer in
#: ``scanned_by``, in one compare-and-set, so nobody else can reach an
#: approved code's identity at all; another customer's attempt is
#: ``DETAIL_SCANNED_BY_OTHER``.
DETAIL_ALREADY_APPROVED = "already_approved"
#: A repeat scan by the customer who already scanned the code and has not
#: approved it yet: ``POST /scan`` through ``ScanClaim.ALREADY_MINE``,
#: normally a retry after a lost response inside the rotation-token window.
#:
#: SINCE 2026-09-30. Until then this exit wrote the same ``returned`` row
#: with a NULL ``detail`` that a first scan writes, so ``tool_name =
#: 'device_grant.scan' AND outcome = 'returned' AND detail IS NULL`` counted
#: retries as scans. It is still ``returned``, because the request is answered
#: with the first scan's 200, and the non-NULL ``detail`` is what keeps that
#: filter at exactly one row per pairing first scanned. The repeat claims
#: nothing and writes nothing to the store.
DETAIL_ALREADY_SCANNED = "already_scanned"
#: A wrong pairing code with attempts left, from the per-code attempt budget.
#:
#: HISTORICAL SINCE 2026-09-30, like the literal below: the budget went when
#: the pairing code became the lookup key, where a per-code budget means
#: nothing, and nothing writes either literal any more. Both stay defined
#: because ``audit_log`` is append-only and rows carrying them exist.
DETAIL_USER_CODE_MISMATCH = "user_code_mismatch"
#: The wrong pairing code that spent the last attempt and revoked the device
#: code. Historical since 2026-09-30; see the literal above.
DETAIL_USER_CODE_BUDGET_EXHAUSTED = "user_code_budget_exhausted"


def device_code_handle(device_code: str) -> str:
    """A non-reversing handle for a device code, for the audit row.

    THE VALUE ITSELF NEVER REACHES THIS TABLE. ``device_code`` is 43
    characters of ``secrets.token_urlsafe`` and is the entire authority to
    exchange at ``POST /token``; ``audit_log`` is append-only, regulator-facing
    and outlives the code's 900-second lifetime by years. Writing a live
    bearer credential into it is the same class of mistake
    ``ApprovalAudit``'s ``signature_present`` refuses one endpoint over, where
    CLAUDE.md states the rule outright.

    WHAT THE HANDLE BUYS, which is the reason it is not simply omitted. Two
    rows carrying the same handle are two attempts on the same pairing, so a
    caller guessing codes produces many handles and a caller retrying one
    produces one; and an operator holding a device code from a support call
    confirms the match by hashing it. Neither is possible against an absent
    field.

    Sixteen hex characters of SHA-256, the construction
    ``services/confirm/customer_rate_limit.py``'s ``customer_handle`` already
    uses, so this repository has one spelling of "a handle in a record" rather
    than two. Unsalted for the same reason it is there: a salt would break the
    confirm-by-hashing operation, which is the point.

    The privacy claim ``customer_handle`` has to disclaim does not arise here
    and the difference is worth stating, because the two functions look
    identical and are not. A customer reference is drawn from a set the
    operator enumerates, so hashing that set recovers the mapping. A device
    code carries 256 bits of entropy from ``secrets``, so no enumeration
    exists and the digest is non-reversing in fact and not only in form.
    """
    return hashlib.sha256(device_code.encode("utf-8")).hexdigest()[:16]


def pairing_client_ip(request: Request, trusted_proxy_hops: int) -> str | None:
    """Which address to attribute this pairing to, or ``None``.

    ONE LINE OF ADAPTER AND NO LOGIC, which is the shape
    ``postern_core.net``'s module docstring requires of both its callers.
    ``services/confirm/rate_limit.py`` reads the same header from a raw ASGI
    scope and ``services/api/middleware/risk.py`` from a Starlette request;
    deriving an address from a hop count a second time in this file is the
    defect that module was created to prevent, and ``.importlinter`` forbids
    reaching the existing copy across services.

    ``client_ip`` and not ``ip_bucket``: bucketing an IPv6 address to its /64
    is a rate-limiting decision that makes two addresses in one prefix
    indistinguishable, which is exactly the resolution an investigator asking
    "where was this paired from" needs kept. The read path records the address
    for the same reason.

    NOT SCRUBBED, and that is safe rather than overlooked: every value this
    returns has been through ``ipaddress.ip_address``, so it is dotted quads
    or hex groups and cannot carry the twelve consecutive digits a PAN run
    needs, nor an IBAN's letter-letter-digit-digit opener.

    ``None`` on this deployment's default of zero trusted hops whenever the
    transport has no peer. ``httpx2.ASGITransport`` is not such a transport: its
    ``client`` defaults to ``('127.0.0.1', 123)``, so an in-process test client
    has a peer and this returns ``127.0.0.1`` for it. A missing peer is a
    missing field on the row and not an error: the alternative is trusting a
    header the caller writes, which is the defect the zero default exists for.
    """
    peer = request.client
    return client_ip(
        forwarded=request.headers.get("x-forwarded-for"),
        peer_host=peer.host if peer else None,
        trusted_proxy_hops=trusted_proxy_hops,
    )


class PairingAudit:
    """One ``audit_log`` row per recorded device-grant request.

    THREE ENDPOINTS, ONE WRITER. ``POST /scan`` claims a pairing for the
    customer whose app scanned it, ``POST /approve`` pairs the client, and
    ``POST /token`` issues the layer-1 session that pairing authorises; all three
    write through this class, which is why ``tool_name`` and ``route`` are
    constructor arguments. ``POST /device_authorization``, where the grant
    begins, writes nothing at all -- see the rule below and that handler's
    own docstring.

    ONE ROW, NOT THE READ PATH'S TWO, and the reason is that the second row's
    reason is absent on all three. ``ApprovalAudit`` writes an entry row because the
    request reaches an operator backend, the touch leaves nothing on this
    side, and a crash mid-call would otherwise erase that customer data was
    reached at all. No endpoint here reaches a backend: ``/scan`` and
    ``/approve`` each set fields on a device code held in this deployment's
    own store, and ``/token`` signs a string in this process. There is no touch to record
    early.

    The same conclusion is forced by the schema, which matters more than the
    argument because it cannot be reasoned around. ``OUTCOME_REACHING`` is
    documented in ``postern_core.store.models`` as the operator being about to
    issue its first backend request, ``ck_audit_log_reaching_at_matches
    _outcome`` makes ``reaching_at`` non-NULL exactly on those rows, and both
    are enforced at the database. Writing a ``reaching`` row for a store write
    would put a second meaning into a closed vocabulary a CHECK constraint
    holds, on a table shared with ``services/api``, and every existing query
    for backend touches would start returning pairings. ``ApprovalAudit``
    already refuses an entry row for the same reason on each of its refusal
    paths: none of them reaches the backend either.

    WHICH ATTEMPTS GET A ROW, stated as a rule because a list of cases goes
    stale the first time a branch is added. The rule is now in its second
    form: the first one said "what the server CONCLUDED about a customer or
    about a device code", and that second disjunct was wrong, because
    ``POST /device_authorization`` concludes something about a device code on
    every single call -- it creates one -- and that endpoint must write
    nothing. The device code identifies WHICH pairing a row is about; it is
    never the reason there is a row.

        A row is owed when the server resolved an identity AND then reached a
        conclusion about that identity's authority. Neither half alone earns
        one: an endpoint that resolves no identity writes nothing however much
        state it creates, and a refusal that inspected only the request's
        shape writes nothing however well the caller authenticated.

    BOTH HALVES ARE LOAD-BEARING, and each excludes a different family.

    The FIRST half excludes every unauthenticated exit.
    ``POST /device_authorization`` resolves nobody at all: it is in
    ``services/confirm/auth.py``'s ``PUBLIC_PATHS`` because the browser holds
    no credential by the device grant's premise, so every row it could write
    would carry a NULL ``customer_ref`` and ``no_access_token`` in
    ``customer_ref_absence_reason`` -- a column whose value is constant across
    an endpoint's entire population, which tells a reader nothing. And the row
    would be an INSERT per unauthenticated request, bounded only by a
    60-per-minute address bucket, on a table whose exhaustion takes both
    services down under decision 0006. Fail-closed would then mean no pairing
    can even BEGIN while the audit store is slow, bought for a row that names
    nobody. It also excludes most of ``POST /token``: an unknown device code,
    an expired one, ``slow_down`` and ``authorization_pending`` are all
    answered before ``customer_ref`` is read off the code, so none of them has
    resolved anybody either.

    The SECOND half excludes the malformed-request exits of ``POST /approve``,
    where the caller IS authenticated: a body that is not a JSON object, a
    missing ``user_code``, a ``user_code`` that arrives as a list, a body
    still carrying the removed ``device_code``. Each is answered by looking
    at the request and consulting nothing, and recording them would hand a
    caller holding one valid assertion an INSERT per malformed body. The 401
    for an absent assertion is excluded by the first half, for the reason
    ``services/confirm/callback.py``'s own first backstop gives.

    What the rule ADMITS, on each endpoint. At ``POST /approve``: a revoked
    customer, a subject that is not a customer reference, a ``user_code``
    naming no live pairing, a code nobody scanned, a code another customer
    scanned, a code already approved for somebody else, and the approver's
    own repeat of an approval that stands, which is answered 200 and
    recorded as ``returned`` with ``DETAIL_ALREADY_APPROVED``.
    At ``POST /token``: the mint itself, a revoked customer, a stored identity
    that will not parse, and a revocation store that could not answer -- four
    exits, all of them past the point where the code named a customer.

    THE VOLUME THIS BUYS, in the numbers this deployment actually ships.
    ``device_poll_interval_seconds`` is 5 and ``device_code_ttl_seconds`` is
    900, so a browser whose customer never picks up their phone polls up to
    180 times and writes zero rows. A pairing that completes writes one row at
    ``POST /approve`` and one at the exchange. So the table holds two rows per
    pairing and none per poll, where a row-per-call design would have held up
    to 182 and been mostly a record of a browser waiting.

    TWO PLACES THAT VOLUME IS NOT BOUNDED, and both are worth knowing before
    reading a result set. A device code is NOT consumed by a successful
    exchange -- ``token_endpoint`` mints and returns without revoking -- so a
    code replayed inside its 900 seconds writes one row per exchange. That is
    a feature of the row rather than a cost: N mint rows under one handle is
    exactly how a replayed device code becomes visible, and nothing else in
    this system makes it so. A revoked customer's browser is the cost: it
    resolves a customer on every poll, so it writes a ``revoked`` row per
    poll, and the ``slow_down`` throttle does not apply to it because that
    check only runs while the code is unapproved. The bound is
    ``rate_limit_token``, 300 a minute per address bucket. A compliant client
    stops, because RFC 8628 §3.5 makes ``access_denied`` terminal; a client
    that does not stop is a bug or an attacker, and in both cases the rows are
    the evidence.

    WHAT THAT RULE COSTS, named rather than left to be discovered. Two
    populations are invisible here. A caller who sends only malformed bodies to
    ``POST /approve``, bounded by the two rate limiters in front of the
    handler and recorded in a log line. And every device code that is created
    and never approved: ``POST /device_authorization`` writes nothing, so what
    bounds that population is the 10,000-code store cap and the address
    bucket, not this table. The second is the larger admission and it is
    narrower than it sounds: a code that ever reaches a customer is named on
    the pairing row by its handle, so the unrecorded population is exactly the
    codes that touched nobody.

    FAIL CLOSED, AND IT MEANS SOMETHING STRONGER HERE THAN ON THE MONEY PATH.
    Decision 0006 is fail closed everywhere, and one endpoint over that has to
    settle for a 500 reported over a backend write that already happened,
    because a payment cannot be unmade from this process. A pairing can:
    the device code is in this deployment's own store and
    ``revoke_device_code`` undoes it. ``services/confirm/device_auth.py``
    therefore withdraws the pairing when this writer raises, so an
    un-audited pairing does not survive its own audit failure. A 500 alone
    would have been fail-closed in the response and fail-open in substance --
    the browser polls ``POST /token``, is handed a read token, and no row
    anywhere names who authorised it.

    FAIL CLOSED AT A MINT, WHICH IS A THIRD SHAPE AGAIN. ``POST /token``
    signs a token, and once it has been returned nothing in this process can
    unmint it: there is no revocation list for a 60-second read token and
    ``services/api`` will accept it until it expires. So neither of the two
    obvious orders is right. Writing the row first refuses a customer who did
    nothing wrong whenever the store blinks, and still allows a row that
    claims a mint the key source then failed to produce. Returning first and
    writing after hands out a token no row accounts for, which is the
    fail-open shape ``POST /approve`` rejected.

    The order actually taken is: mint, commit the row, THEN return. It works
    because the mint's only effect is a string in this process's memory -- it
    reaches no store, no log and no other party -- so discarding it IS the
    undo that a payment does not have. ``services/confirm/device_auth.py``
    raises when this writer raises, the response object is dropped, and the
    token is never serialised to anybody. NO ROW THEREFORE MEANS NO TOKEN
    EVER LEFT THIS PROCESS, which is the property that matters rather than
    "no token was computed".

    The residual is the mirror image and is the licensed direction: a crash
    between the commit and the response reaching the socket leaves a row
    saying a token was minted that the caller never received.
    ``OUTCOME_REACHING``'s own docstring argues for exactly this direction --
    a row claiming something a crash then prevented is resolvable against
    other evidence, where the reverse resolves to nothing -- and here the
    over-report is bounded twice over, by the 60-second token life and by
    ``services/api``'s own two rows for anything that token is used for.

    WHAT THAT COSTS, and it is the sharpest cost in this file: a customer
    standing at a browser with their phone out, mid-QR-scan, is refused
    because a database they will never hear of is slow. Decision 0006's
    amendment makes that reachable rather than hypothetical -- a 3.0-second
    command timeout means merely slow is enough. It is paid anyway, and the
    reason is that the window costs the customer nothing they could have
    used: while the audit store is unreachable every tool call in
    ``services/api`` fails closed too, so the client this pairing would
    authorise cannot read an account balance in that window either. Refusing
    to pair adds no outage the deployment does not already have, which is the
    same argument ``CustomerRateLimitStoreUnavailable`` makes for its own
    refusal.
    """

    __slots__ = (
        "_at",
        "_call_id",
        "_client_id",
        "_client_ip",
        "_customer_ref",
        "_customer_ref_absence_reason",
        "_db",
        "_device_code_handle",
        "_paired_client_id",
        "_redaction_budget_exhausted",
        "_route",
        "_session_id",
        "_started",
        "_tool_name",
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
        client_ip_value: str | None,
        tool_name: str = PAIRING_TOOL_NAME,
        route: str = PAIRING_ROUTE,
    ) -> None:
        # ONE WRITER FOR BOTH DEVICE-GRANT ENDPOINTS, parameterised rather
        # than subclassed or copied. The row shape is identical -- same four
        # ``arguments`` keys in the same order, same NULL columns, same
        # ``_subject_columns`` -- and the only differences are these two
        # literals and the fact that ``POST /token`` has no verified claims to
        # read a client id from. A second near-identical class is how the
        # three copies of ``_scrub`` that ``services/api/middleware/audit.py``
        # records happened, and the weakest of those sat on the money path.
        self._tool_name = tool_name
        self._route = route
        self._db = db
        self._call_id = call_id
        self._at = at
        self._started = started
        self._customer_ref, self._customer_ref_absence_reason = _subject_columns(subject)
        self._client_ip = client_ip_value
        # ONE ALLOWANCE FOR THE WHOLE REQUEST, the invariant
        # ``ApprovalAudit.__init__`` holds for the same reason: without it
        # every string validated gets a fresh checksum budget, and a caller
        # who spreads junk across two fields buys two allowances instead of
        # spending down one.
        with redaction_budget() as scope:
            self._client_id = _client_id(claims)
        self._redaction_budget_exhausted = scope.exhausted
        # Both filled in by ``names`` below as the request learns them, and
        # both OMITTED from ``arguments`` while they are None rather than
        # written as nulls: a key that is absent says the request never got
        # far enough to know, where a key holding null reads as "we looked and
        # there was nothing", which on the revoked path would be false.
        self._device_code_handle: str | None = None
        self._session_id: str | None = None
        self._paired_client_id: str | None = None

    @property
    def call_id(self) -> str:
        """The correlation key this request's row carries.

        One row per request today, so nothing joins on it yet. It is still
        minted and still written, because ``ck_audit_log_call_id_present``
        requires it on every new row and because a future second row for one
        pairing must be pairable with this one rather than orphaned beside it.
        """
        return self._call_id

    def names(
        self,
        *,
        device_code: str | None = None,
        session_id: str | None = None,
        paired_client_id: str | None = None,
    ) -> None:
        """Record which pairing this attempt was aimed at, as it becomes known.

        Two values arriving at two different points, through one method, so
        that the ORDER of the keys in ``arguments`` is decided once, at the
        write, rather than by whichever call site happened to run first. That
        order is load-bearing: ``cap_arguments`` keeps a first-fit prefix of
        top-level entries, so ``_arguments`` below lists the server-chosen
        keys before the caller-supplied one and an over-limit tree drops
        exactly the field that carried the junk.

        ``device_code`` is reduced to a handle immediately and the raw value
        is never held on this object. ``paired_client_id`` is the
        ``client_id`` the BROWSER supplied, unauthenticated, at
        ``POST /device_authorization`` -- the only answer this system has to
        "which client did this customer authorise" and, being caller-supplied,
        scrubbed like every other such value.

        SCRUBBED OUTSIDE THE CONSTRUCTOR'S BUDGET, exactly as
        ``ApprovalAudit.resolve`` is and for the same reason: that scope has
        closed by the time the device code is read and re-entering it is not
        possible. The fresh per-string allowance cannot be spent to any
        meaningful degree, because ``ConfirmSettings.max_client_id_length``
        bounds this value at 256 characters at the endpoint that stored it and
        ``/device_authorization`` rejects rather than truncates a longer one.

        ``session_id`` is a refresh family's id, written RAW: it is in every
        access token of that family and so not a secret, and an operator
        revoking a family needs it verbatim. No token, no segment of one and
        no digest of one is ever written.
        """
        if device_code is not None:
            self._device_code_handle = device_code_handle(device_code)
        if session_id is not None:
            self._session_id = session_id
        if paired_client_id is not None:
            self._paired_client_id = scrub_text(paired_client_id)

    async def approved(self, *, risk_signals: list[dict[str, Any]] | None = None) -> None:
        """Record that this pairing was granted.

        ``risk_signals`` is passed by ``POST /scan`` alone, for a first scan:
        the one serialized ``PAIRING_NETWORK`` signal. Every other caller
        leaves it ``None`` and the column NULL.
        """
        await self._write(OUTCOME_RETURNED, None, risk_signals)

    async def approved_again(
        self,
        detail: str = DETAIL_ALREADY_APPROVED,
        *,
        risk_signals: list[dict[str, Any]] | None = None,
    ) -> None:
        """Record a repeat that is answered with the first request's 200.

        ``returned``, because the request is answered with the same 200 the
        first one was, and a non-NULL ``detail`` rather than NULL, so the
        table never counts a retry as a second pairing granted or a second
        first scan. ``DETAIL_ALREADY_APPROVED`` by default, for the approver's
        repeat on either route; ``POST /scan`` passes
        ``DETAIL_ALREADY_SCANNED`` for a repeat before approving. Each
        literal's comment carries the reasoning.

        ``risk_signals`` is passed by ``POST /scan`` for the
        ``DETAIL_ALREADY_SCANNED`` repeat, whose row compares the creator with
        that repeat's own address; without it those rows would silently lose
        the signal. The ``DETAIL_ALREADY_APPROVED`` repeat passes none.
        """
        await self._write(OUTCOME_RETURNED, detail, risk_signals)

    async def minted(self) -> None:
        """Record that a session was issued for this customer.

        The same row as ``approved`` above writes and a separate name on
        purpose. Both are ``outcome='returned'`` with a NULL ``detail``,
        because the table's vocabulary has one value for "this finished its
        work" and inventing a fourth is a migration plus a widened CHECK. What
        differs is what the caller is claiming when it calls one of them, and
        the call site is where the next reader looks: at ``POST /approve``
        a pairing was granted, at ``POST /token`` a credential was issued. A
        single method named for neither would make both call sites read as
        though nothing in particular had happened.

        MUST BE AWAITED BEFORE THE TOKEN IS RETURNED, never after. The class
        docstring's "FAIL CLOSED AT A MINT" section is the whole argument; the
        short form is that a raise here has to be able to stop the token
        reaching the caller, and it can only do that while the response is
        still an object in this process.
        """
        await self._write(OUTCOME_RETURNED, None)

    async def refused(self, detail: str) -> None:
        """Record that this pairing was refused, and at which stage.

        ``detail`` is one of the ``DETAIL_*`` literals above for a refusal
        this handler decided, or ``type(exc).__name__`` for a genuine
        exception -- never an exception's MESSAGE, which for a
        ``pydantic.ValidationError`` embeds the raw offending value and would
        put the thing a masked type exists to protect into a long-lived store.
        """
        await self._write(OUTCOME_RAISED, detail)

    async def _write(
        self,
        outcome: str,
        detail: str | None,
        risk_signals: list[dict[str, Any]] | None = None,
    ) -> None:
        """THROUGH ``append_with_reserve`` SINCE 2026-09-27, and this writer has
        only completion rows, so there is no entry-row exception to make.

        Neither endpoint reaches a backend -- the class docstring's "ONE ROW,
        NOT THE READ PATH'S TWO" is the argument -- so nothing here can be
        carried across a money boundary the way ``ApprovalAudit``'s entry row
        could. Every row this writer produces is the record of a conclusion
        already reached, which is exactly what a reserve is for.

        THE VOLUME IS THE REASON IT MATTERS AT ``POST /token``. That row is
        fail-closed on a mint: it is awaited before the token is returned, so a
        saturated pool used to mean no credential issued AND no record of the
        refusal. At ``POST /approve`` the failure was louder and worse in a
        different way -- ``services/confirm/device_auth.py``'s
        ``_withdraw_pairing`` revokes a pairing whose row could not be written,
        so a customer who had already compared their pairing code had the
        pairing taken away and had to start from a fresh QR. With the row
        written, neither happens.
        """

        async def row(session: AsyncSession) -> None:
            await audit.append(
                session,
                at=self._at,
                # NULL, written as a literal: this path reaches no backend, so
                # there is no touch instant in existence, and
                # ``ck_audit_log_reaching_at_matches_outcome`` rejects a
                # non-NULL value beside any outcome but ``reaching``.
                reaching_at=None,
                customer_ref=self._customer_ref,
                customer_ref_absence_reason=self._customer_ref_absence_reason,
                tool_name=self._tool_name,
                arguments=self._arguments(),
                outcome=outcome,
                detail=detail,
                redaction_budget_exhausted=self._redaction_budget_exhausted,
                # ``time.monotonic()`` for the reason the challenge path uses
                # it: a wall clock can step backwards under an NTP correction
                # and write a negative duration into an append-only table.
                # Rounded down, so the row never reports the operator slower
                # than it was.
                duration_ms=int((time.monotonic() - self._started) * 1000),
                # NULL: this service speaks plain HTTP with no JSON-RPC
                # envelope and no request-id header convention anywhere in
                # this repository, so the handler looked and there was none.
                request_id=None,
                # NULL on every row this module writes, pairing or approval.
                # The module docstring carries the vocabulary gap that forces
                # it.
                refusal_reason=None,
                call_id=self._call_id,
                client_id=self._client_id,
                # NULL on every row but a successful scan, and never ``[]``:
                # ``[]`` means a risk session ran and no signal fired.
                # ``RiskEngine`` and ``IpAnomalyDetector`` are wired into
                # ``services/api``'s tool middleware and nothing in this
                # service establishes a session, so NULL is still the true
                # statement everywhere else. A successful ``POST /scan`` row
                # carries exactly one signal, ``PAIRING_NETWORK``, and no
                # session: the comparison of where the pairing was created
                # with where it was scanned.
                risk_signals=risk_signals,
            )

        await audit.append_with_reserve(self._db, row)

    def _arguments(self) -> dict[str, Any]:
        """What this pairing attempt was, bounded the way both services bound it.

        FIVE KEYS AT MOST, IN THIS ORDER, and the order is the first-fit rule
        ``cap_arguments`` applies: server-chosen keys first, the one
        caller-supplied key last, so an over-limit tree keeps what identifies
        the request and drops what carried the junk.

        WHAT IS DELIBERATELY ABSENT. The ``user_code`` presented, in every
        branch including the mismatches. A correct one is the second half of
        the A2 pairing credential and belongs in this table no more than the
        device code does; a wrong one is a guess, and storing guesses would
        let a reader of the table learn how close an attacker got, which is
        worth less than not accumulating attacker-chosen strings. ``detail``
        names the class, which is what a query filters on.

        Also absent: the scopes the pairing grants. They are on the device
        code, which the handle joins to while it lives, and they are the same
        ``DEFAULT_DEVICE_SCOPES`` string on every pairing a browser starts
        without asking for something narrower.
        """
        tree: dict[str, Any] = {"route": self._route}
        if self._device_code_handle is not None:
            tree["device_code_handle"] = self._device_code_handle
        if self._session_id is not None:
            tree["session_id"] = self._session_id
        if self._client_ip is not None:
            tree["client_ip"] = self._client_ip
        if self._paired_client_id is not None:
            tree["paired_client_id"] = self._paired_client_id
        return bound_arguments(tree)

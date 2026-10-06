"""Approval callback handler (handoff §6.3, §8.3).

Receives signed approvals from the mobile app for verification challenges,
marks them approved in Postgres, and delegates execution to ``execute.py``.

Execution belongs to the server, never the agent (handoff §6.2). After a
confirmation arrives, this handler calls the backend write endpoint — not
the tool handler and not the agent. The agent only polls and observes a
status change.

The confirm service holds the write key, so it can mint internal JWTs with
the ``challenge_id`` claim (§7.2) and reach backend write endpoints that
require tokens from the write issuer.

Request format (POST /challenges/{challenge_id}/approve)::

    Authorization: Bearer <assertion minted by the operator's app backend>

    {
        "signature": "<86 base64url chars: Ed25519 over the stored row>",
        "verification_result": "<tier-2 selfie match reference, if applicable>"
    }

Response format::

    {
        "challenge_id": "...",
        "status": "approved" | "executed" | "expired" | "not_found",
        "message": "<human-readable summary>"
    }

The confirmation payload is built server-side from the stored challenge
row — never re-sent or re-specified by the agent (handoff §6.3).

WHAT AUTHENTICATES (audit finding C-02). This handler used to take a bare
``Request`` and verify nothing: the challenge id came from the URL path, and
possession of that id was the entire authority to approve. That id is minted
on the read path and travels back through the model's channel, which means it
lands in a third-party AI vendor's chat history. It now requires a verified
app assertion (``services/confirm/auth.py``), and the challenge's
``customer_ref`` must equal that assertion's ``sub``. Knowing an id is no
longer enough; being the customer the challenge was raised for is.

WHAT STOPS THIS MID-FLOW (ZT-7). Until 2026-09-23 nothing did. An operator who
revoked a compromised session stopped every read on every replica and did not
stop this handler: a challenge already created could still be approved, a
write JWT was still minted, and the backend write endpoint was still reached.
``_approve`` now refuses a revoked customer as its first act, before the
challenge is read and therefore before any of the three writes below.
``services/confirm/revocation.py`` holds which revocation scope reaches this
service and which two cannot; the short form is that only a revocation naming
the CUSTOMER stops a payment, because nothing on this path carries the AI
client's ``jti`` or its ``client_id``.

WHAT THE ``signature`` FIELD IS. Until 2026-09-24 it was checked for PRESENCE
and stored, and the local variable was named ``unverified_signature`` at every
use site so no reader had to take a docstring's word for it. This paragraph
used to say what would close that: "a per-customer device public key,
registered at enrolment, with this handler verifying a signature over the
stored challenge row's own fields rather than over anything the caller
supplies". That is now what happens. ``services/confirm/device_signature.py``
is the check, `postern_core.auth.approval_signature` is the message, and every
byte of that message comes from the row this handler read -- the same property
CLAUDE.md requires of the confirmation payload, applied to the signature,
because a signature over something the caller chose proves only that the
caller can sign what it chose.

WHAT IT STILL IS NOT. A verified signature says the private half of an
enrolled key signed exactly these bytes. It does not say a human read the
amount, and it does not say the phone was not compromised: both of those live
behind the device's secure element and the unlock the operator's app requires
before it signs, and nothing in this repository can attest either. The
assertion and the signature answer different questions and the pair is the
control -- the assertion says the operator's APP is calling for this customer,
the signature says that customer's own enrolled DEVICE produced this approval.
Enrolment itself is the operator's, in the same sense Vault is
(`postern_core.auth.device_keys`).

WHAT IS RECORDED. Until 2026-09-23 this handler wrote nothing to
``audit_log``. The only trace an approval left was the ``challenges`` row it
mutated -- whose ``confirming_device`` and ``signature`` were both
caller-supplied, neither of them verified, and which carries no instant for
the approval distinct from its own. Meanwhile ``services/api``
recorded two rows for reading a balance. The asymmetry ran backwards: the
highest-consequence action in the system was the least recorded one.

Every path below now writes at least one ``audit_log`` row, and the paths
that reach the operator's backend write two, correlated by ``call_id``, the
first committed BEFORE the backend is touched.
``services/confirm/audit.py`` owns every decision about those rows and is
where to read about them; what matters here is that the writes FAIL CLOSED
(``dev-docs/decisions/0006-audit-write-failure.md``), so an audit store that
is down or merely slow stops money from moving rather than letting it move
unrecorded.

"EVERY PATH BELOW" WAS NOT TRUE UNTIL 2026-09-24. A body that was not a JSON
object raised out of a bare ``await request.json()``, three lines above where
the audit object is built, so the request 500ed and recorded nothing --
measured on four shapes, all 500s, row count unchanged. ``_read_body`` below
holds them and the handler now refuses each with a 400 and one row.

WHAT BOUNDS THE BODY THIS READS. ``services/confirm/body_limit.py``, wired in
front of ``AppAssertionMiddleware`` by ``services/confirm/main.py``. Before it
existed this handler parsed whatever arrived -- measured at 9,999,984 bytes
for one 404 -- and a request it refuses with 413 is the one class of request
that reaches neither this handler nor the table.
"""

from __future__ import annotations

import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any

from postern_core.store.challenges import get_challenge, update_challenge_status
from postern_core.store.engine import Database
from starlette.requests import Request
from starlette.responses import JSONResponse

from services.confirm.audit import (
    DETAIL_ALREADY_TERMINAL,
    DETAIL_CHALLENGE_NOT_FOUND,
    DETAIL_CHALLENGE_NOT_OWNED,
    DETAIL_CHALLENGE_VANISHED,
    DETAIL_EXPIRED,
    DETAIL_MALFORMED_BODY,
    DETAIL_MISSING_SIGNATURE,
    DETAIL_REVOKED,
    DETAIL_UPDATE_MATCHED_NO_ROW,
    ApprovalAudit,
)
from services.confirm.auth import unauthenticated_response, verified_claims, verified_subject
from services.confirm.device_signature import signature_refusal
from services.confirm.execute import (
    WRITE_OPERATIONS,
    BackendWriteClient,
    BackendWriteError,
    resolve_endpoint,
)
from services.confirm.revocation import customer_revoked, log_refusal, revoked_response
from services.confirm.tier_proof import check_tier, tier_refusal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Approval callback — POST /challenges/{challenge_id}/approve.
# ---------------------------------------------------------------------------


async def approve_challenge(request: Request) -> JSONResponse:
    """Handle a verification challenge approval from the mobile app, and
    record what it did in ``audit_log``.

    This is called by the confirmation service (the operator's banking app)
    after the user completes identity verification and approves the operation.

    Flow:
        0. Verify the app assertion; the customer is its ``sub``.
        0b. Refuse if that customer's access is revoked (ZT-7), before
           anything here is read or written.
        1. Look up the challenge by ID (from stored row, not agent input).
        2. Reject unless the challenge belongs to that customer.
        2b. Verify the approval signature against a device key the operator
           enrolled for that customer, over bytes built from the row read in
           step 1. Before step 3 because step 3 WRITES, and a caller who
           cannot sign must not be able to move anybody's challenge.
        3. Claim it: one conditional ``UPDATE`` that carries "still pending"
           and "not yet expired" in its ``WHERE`` and records the verified
           signature + verification_result. Winning it is what authorizes
           step 4; zero rows goes to ``_refused_transition_response``.
        4. Execute the backend write endpoint server-side via execute.py,
           then mark the row executed, conditional on ``approved``.

    The confirmation payload is built server-side from the stored challenge
    row — never re-sent or re-specified by the agent (handoff §6.3).

    Steps 2 and 3 read the row twice, and only step 3's read decides
    anything. Step 2's is a plain ``SELECT``, but the column it tests --
    ``customer_ref`` -- is written once at challenge creation and never
    updated, so there is no version of it that a lock would protect.

    WHAT THIS FUNCTION OWNS IN THE AUDIT TRAIL, and what it delegates.
    ``services/confirm/audit.py`` holds every decision about the rows -- which
    columns carry what, which requests get one row and which get two, and why
    ``refusal_reason`` is NULL throughout. This function owns only the two
    instants at the top, the correlation id, and the mapping from each exit to
    an outcome. Both instants are read as the FIRST statements of the handler,
    before the subject is looked at: everything this function does is then
    inside the measurement, and the only thing outside it is
    ``AppAssertionMiddleware``'s verification, which is the same boundary the
    read path's ``context.timestamp`` sits behind.

    FAIL CLOSED, per ``dev-docs/decisions/0006-audit-write-failure.md``. An
    audit write that fails fails the request, which means a failed completion
    write turns a 200 into a 500 AFTER the backend write succeeded and the
    money moved. That is deliberate and it is the same bargain the read path
    already makes (it fails a call whose tool returned). What makes it safe to
    retry is the ``Idempotency-Key: <challenge_id>`` header
    ``BackendWriteClient`` sends, plus the ``approved -> executed`` transition
    being conditional: the backend sees the same key and the row is already
    out of ``pending``. Do not "fix" this into a logged warning.
    """
    # FIRST TWO STATEMENTS, before anything is inspected. `at` is a wall clock
    # because it has to be comparable with `reaching_at`; `started` is
    # monotonic because it measures an interval and a clock that steps
    # backwards under an NTP correction would write a negative duration into
    # an append-only table.
    at = datetime.now(UTC)
    started = time.monotonic()

    subject = verified_subject(request)
    if subject is None:
        # Unreachable through the assembled app: `AppAssertionMiddleware`
        # refused before routing. Kept because a handler that derives
        # authority from ambient state must fail closed when that state is
        # absent, not proceed with none.
        #
        # NO AUDIT ROW, and this is the first of the two places that write
        # none. There is no verified subject here, so a row would have to
        # invent a class of absence that `CUSTOMER_REF_ABSENCE_REASONS` does
        # not name -- the middleware's own refusal is already logged, and that
        # is the record of this event.
        return unauthenticated_response()

    challenge_id: str = request.path_params.get("challenge_id", "")
    if not challenge_id:
        # The second place that writes no row. Also unreachable through the
        # assembled app: this handler is only ever mounted on
        # `/challenges/{challenge_id}/approve` and Starlette's router cannot
        # match an empty path segment, so reaching here means something other
        # than the route table dispatched the request. A row naming no
        # challenge names nothing an investigator can act on, so this is
        # logged instead -- which it was not before the audit trail landed,
        # making it the one refusal in this file that left no trace anywhere.
        logger.warning("challenge approve: dispatched with no challenge_id in the path")
        return _error(400, "invalid_request", "challenge_id is required in path")

    # NOT a bare `await request.json()` any more. Until 2026-09-24 it was one,
    # outside any `try`, three lines above where `ApprovalAudit` is built --
    # so a body that was not a JSON object raised before the audit existed and
    # the request failed with NO ROW AT ALL. Measured, all four 500s with an
    # unchanged row count: `{not json` (`JSONDecodeError`), `[1,2,3]`
    # (`AttributeError` from `.get` on a list), 200,000 nested arrays
    # (`RecursionError`) and an empty body (`JSONDecodeError`). That was a
    # silent refusal path beyond the two enumerated above, and
    # `services/confirm/audit.py`'s own rule already owed a row here: the
    # verified subject and the non-empty challenge id both exist by this line.
    body = await _read_body(request)

    # Typed rather than left as the `Any` that `app.state` hands back, so
    # `_approve` and `ApprovalAudit` below are both checked against the real
    # sessionmaker rather than against anything at all.
    db: Database = request.app.state.postern_database

    # Built HERE: the first point at which a verified subject and a non-empty
    # challenge id both exist, which is exactly the boundary
    # `services/confirm/audit.py` defines for "this request gets a completion
    # row". Everything below this line writes one.
    #
    # FOUR POOLED CHECKOUTS PER APPROVAL, ONE AT A TIME, and the second half
    # of that sentence is what this comment got wrong until 2026-09-26. Both
    # audit rows open their own session from `db.sessionmaker()`, and they
    # must: an audit row that shared the approval's transaction would be
    # rolled back with it, which is the opposite of what an append-only,
    # regulator-facing table is for, and the entry row has to be durable
    # BEFORE the backend request that the approval's own transaction has not
    # committed yet.
    #
    # WHAT THAT DOES NOT COST IS A SECOND CONNECTION HELD AT THE SAME TIME,
    # which this comment previously implied by saying the audit rows open
    # their sessions "while `_approve` still holds" its own. It holds the
    # SESSION and not the connection: `_approve` commits its claim before
    # `BackendWriteClient` is built, and an `AsyncSession` hands its
    # connection back at COMMIT rather than at close. Measured through this
    # handler at ``pool_size=1, max_overflow=0``, a pool that cannot serve two
    # checkouts at once: a whole approval completes, four checkouts, peak
    # concurrency of one, 200 (``tests/test_pool_sizing.py``). The difference
    # is not academic -- a request that held one connection while waiting for
    # a second would exhaust any pool at ``pool_size + max_overflow``
    # concurrent approvals, with every waiter blocking every other and no
    # size removing it. DO NOT move that commit below the backend write; that
    # single change introduces the overlap, and it reads like a safety
    # improvement.
    #
    # THE CEILING IS NOW CHOSEN. Neither `pool_size` nor `max_overflow` was
    # passed until 2026-09-26, so this service inherited SQLAlchemy's 5 + 10;
    # it now takes 5 + 5 from `services/confirm/settings.py`, which says why
    # it asks for less than the read path, and
    # `dev-docs/decisions/0013-connection-pool-ceiling.md` carries the
    # arithmetic an operator redoes against their own `max_connections`.
    audit = ApprovalAudit(
        db=db,
        call_id=str(uuid.uuid4()),
        at=at,
        started=started,
        subject=subject,
        claims=verified_claims(request),
        challenge_id=challenge_id,
        # `{}` when the body was unreadable, which records the truth: this
        # caller supplied no `confirming_device`, no `verification_result` and
        # no signature that reached the handler. `detail` below is what says
        # a body arrived and could not be read, as against none arriving.
        body=body if body is not None else {},
    )

    # Declared before the branch rather than inferred from whichever arm mypy
    # meets first: the malformed arm below always names a `DETAIL_*` literal,
    # so an inferred `str` would make `_approve`'s `str | None` an error on
    # the other arm, and widening at the assignment instead would put the
    # annotation where the reader is not looking.
    response: JSONResponse
    detail: str | None

    if body is None:
        # THE REFUSAL DEFECT 2 EXISTS FOR, and it deliberately does not call
        # `_approve`. That means the ZT-7 revocation check, which is
        # `_approve`'s first statement, does not run: a revoked customer who
        # sends a malformed body is recorded as `malformed_body` rather than
        # `revoked`, so `WHERE detail = 'revoked'` undercounts them by
        # whatever they send that cannot be parsed. They are still refused,
        # still move no challenge and still mint no write JWT, which is every
        # property `services/confirm/revocation.py` claims for that placement;
        # what is lost is only a row's label. Checking revocation first would
        # mean building `ApprovalAudit` before the body is known, and its
        # constructor computes `arguments` from the body inside the one
        # `redaction_budget()` scope a request gets -- so the order here is
        # forced by that contract rather than chosen.
        logger.warning(
            "challenge approve: %s refused, the body is not a JSON object",
            challenge_id,
        )
        response, detail = (
            _error(400, "invalid_request", "body must be a JSON object"),
            DETAIL_MALFORMED_BODY,
        )
    else:
        # Named for what it is at every use site, and the name changed with
        # the control: this is what the caller PRESENTED. `_approve` verifies
        # it against an enrolled device key before anything is written, and
        # only a verified value ever reaches the `challenges` row.
        presented_signature: str = body.get("signature", "")
        verification_result: str | None = body.get("verification_result")
        try:
            response, detail = await _approve(
                request,
                audit,
                db=db,
                subject=subject,
                challenge_id=challenge_id,
                body=body,
                presented_signature=presented_signature,
                verification_result=verification_result,
            )
        except Exception as exc:
            # `raise exc from audit_exc`, never a bare `raise` from inside
            # this handler: an audit-write failure must not REPLACE the
            # exception that actually ended the request. Raising while already
            # handling `exc` would chain implicitly through `__context__` and
            # put the database's exception where the request's own belongs, so
            # the operator reading the traceback would learn what the audit
            # store did and not what the approval did. Same shape, same
            # reasoning, as `services/api/middleware/audit.py`'s raised branch.
            try:
                await audit.raised(type(exc).__name__)
            except Exception as audit_exc:
                logger.error(
                    "audit write failed for challenge %r after the approval raised %s: %s",
                    challenge_id,
                    type(exc).__name__,
                    audit_exc,
                    exc_info=audit_exc,
                )
                raise exc from audit_exc
            raise

    try:
        if detail is None:
            await audit.returned()
        else:
            await audit.raised(detail)
    except Exception as audit_exc:
        logger.error(
            "audit write failed for challenge %r after the approval finished with "
            "status %d; failing the request because the audit row could not be written",
            challenge_id,
            response.status_code,
            exc_info=audit_exc,
        )
        raise
    return response


async def _approve(
    request: Request,
    audit: ApprovalAudit,
    *,
    db: Database,
    subject: str,
    challenge_id: str,
    body: dict[str, Any],
    presented_signature: str,
    verification_result: str | None,
) -> tuple[JSONResponse, str | None]:
    """The approval itself, returning ``(response, detail)``.

    ``detail`` is ``None`` when the work succeeded and one of
    ``services/confirm/audit.py``'s ``DETAIL_*`` literals otherwise. Split out
    from ``approve_challenge`` so that every exit below names its own outcome
    exactly once, at the point the decision is made, and the completion row is
    written in exactly one place rather than at each return, where a new one
    could forget to join. The signature check is the one exit that names its
    detail somewhere else -- ``services/confirm/device_signature.py`` returns
    the same ``(response, detail)`` pair, because it owns three of them and
    the difference between them is its subject, not this function's.

    The status code and the detail are deliberately NOT derived from each
    other. Two exits return 404 with the same body for different reasons (no
    such challenge, and not yours), which is an intentional absence of an
    existence oracle in the RESPONSE and would be a loss of the most valuable
    signal on this path in the TABLE.
    """
    # --- 0. ZT-7: is this customer's access revoked? ---
    #
    # THE FIRST STATEMENT, and every part of that placement is load-bearing.
    #
    # Before the signature check and before `get_challenge`, so a revoked
    # caller's answer depends on nothing but their own revocation state: they
    # cannot use the difference between 400, 403 and 404 to learn whether a
    # challenge id exists, and challenge ids leave this system through the
    # model's channel into a third party's chat history.
    #
    # Necessarily before the conditional ``UPDATE`` below, so a revoked caller
    # cannot burn a challenge into a terminal state -- ``pending ->
    # approved`` and the ``pending -> expired`` retirement inside
    # `_refused_transition_response` are both writes, and neither must be
    # reachable by an identity the operator has cut.
    #
    # And before `BackendWriteClient` exists at all, so no write JWT is
    # minted, which is the difference between refusing a payment and
    # recording one.
    #
    # `RevocationStoreUnavailable` is deliberately NOT caught. It propagates
    # to `approve_challenge`'s ``except Exception``, which writes a completion
    # row carrying the exception type and re-raises: the caller gets a 500 and
    # the challenge is untouched, still ``pending``. Reporting a store outage
    # as "not revoked" would un-revoke every entry the operator holds, at the
    # moment they most believe they have acted.
    if await customer_revoked(request, subject):
        log_refusal("a challenge approval")
        return (
            revoked_response("this customer's access has been revoked"),
            DETAIL_REVOKED,
        )

    # STILL HERE, AHEAD OF THE ROW, and still a 400 rather than one of the
    # 403s the verification below returns. An empty field is a malformed
    # REQUEST, answerable without reading anything: keeping it here means a
    # caller who sends no signature at all learns nothing about which
    # challenge ids exist, which is the same reason the revocation check
    # above sits where it does.
    if not presented_signature:
        return (
            _error(400, "invalid_request", "signature is required"),
            DETAIL_MISSING_SIGNATURE,
        )

    # --- 1. Look up the challenge (from DB, not agent input) ---
    async with db.sessionmaker() as session:
        challenge_record = await get_challenge(session, challenge_id)

        if challenge_record is None:
            # `tool_name` stays the unresolved literal on this row: no
            # challenge was found, so there is no operation to name. That is
            # what makes `WHERE tool_name = 'challenges.approve'` the
            # id-enumeration query.
            return (
                _error(404, "not_found", f"challenge {challenge_id} not found"),
                DETAIL_CHALLENGE_NOT_FOUND,
            )

        # The operation is known from here on, so every row below names it.
        # Recorded even on the refusals -- an investigator asking "what did
        # this caller try to approve" gets an answer whether or not they were
        # allowed to.
        audit.resolve(challenge_record.tool_name)

        # --- 2. The challenge must belong to the authenticated customer ---
        #
        # Deliberately the SAME 404 body as "no such challenge". A distinct
        # 403 would answer "does this id exist?" for any id an attacker got
        # hold of, and challenge ids leave this system through the model's
        # channel into a third party's chat history. Whoever is not the owner
        # learns nothing either way.
        #
        # Placed before every check below, all of which are more specific
        # than "is this yours", and before the expiry branch in particular:
        # that branch WRITES, and a stranger must not be able to drive a
        # state transition on another customer's challenge.
        if challenge_record.customer_ref != subject:
            logger.warning(
                "challenge approve: %s requested by a subject that does not own it",
                challenge_id,
            )
            # THE HIGHEST-VALUE ROW THIS MODULE WRITES. The response is
            # byte-identical to "no such challenge" on purpose, so the caller
            # learns nothing; the audit row is where the two are told apart.
            # `customer_ref` names the CALLER, `tool_name` names what they
            # tried to approve, so a cross-customer probe is one predicate on
            # `detail` and the target is on the same row.
            return (
                _error(404, "not_found", f"challenge {challenge_id} not found"),
                DETAIL_CHALLENGE_NOT_OWNED,
            )

        # --- 2b. Did the customer's own enrolled device sign THIS row? ---
        #
        # AFTER the ownership check and BEFORE the ``UPDATE``, and both edges
        # are load-bearing: after, so a 403 from here cannot answer "does this
        # challenge id exist" for a caller who does not own it, which the
        # byte-identical 404 above exists to refuse; before, so a signature
        # that does not verify leaves the row exactly ``pending`` and the
        # customer's real phone can still approve it.
        #
        # It cannot run any earlier than ``get_challenge``, because the bytes
        # being verified ARE the row: challenge id, customer, tool, payload
        # and deadline, canonically encoded by
        # `postern_core.auth.approval_signature`. Nothing from ``body``
        # reaches that message; the caller contributes the signature alone.
        #
        # `DeviceKeyStoreUnavailable` and `UncanonicalChallengeError` are both
        # deliberately NOT caught, for the reason the revocation check states:
        # they propagate to `approve_challenge`'s ``except Exception``, which
        # writes a completion row carrying the exception type and re-raises,
        # so the caller gets a 500 and the challenge is untouched. An
        # enrolment store that cannot answer must not read as a customer who
        # has not enrolled.
        refusal = await signature_refusal(
            request, record=challenge_record, presented_signature=presented_signature
        )
        if refusal is not None:
            return refusal

        # --- 2c. Does the assertion prove what the row's tier requires? ---
        #
        # AFTER the signature and BEFORE the claim, for the two reasons the
        # signature check gives for its own position: a caller who cannot
        # sign learns nothing here about the row's tier, and a refusal leaves
        # the row exactly `pending`, since nothing in this session has
        # written yet. `services/confirm/tier_proof.py` holds the rule
        # (decision record 0023). The tier is read off the stored row and
        # checked against the tier its operation DECLARES, because the row is
        # writable by `postern_app` and the declaration is not.
        #
        # This also runs before the row's status and deadline are looked at,
        # so an expired or already-terminal tier-2 row presented with bad
        # claims gets this 403 and is not retired by the request; with good
        # claims it falls through to the claim and gets 410 `expired` (with
        # the expiry transition) or 409 `already_terminal`.
        verdict = check_tier(
            record=challenge_record,
            challenge_id=challenge_id,
            claims=verified_claims(request),
            expected_idv=request.app.state.settings.idv_value,
            now=time.time(),
            operations=WRITE_OPERATIONS,
        )
        if verdict.assertion_jti is not None:
            audit.note_assertion_jti(verdict.assertion_jti)
        if verdict.refusal is not None:
            return tier_refusal(challenge_id, verdict.refusal)
        # Tier 2 stores the assertion's `jti`, never the body's string: what
        # lands on the row is then the identifier of an assertion that carried
        # the configured `idv` and this challenge's id. Tier 1 is unchanged.
        stored_verification_result = (
            verification_result if verdict.assertion_jti is None else verdict.assertion_jti
        )

        # --- 3. Claim the challenge: pending -> approved, in one statement ---
        #
        # There is no ``if status != "pending"`` and no ``if now >=
        # expires_at`` here any more (audit finding C-03). Both were Python
        # checks against a snapshot taken by an unlocked ``SELECT``, so N
        # concurrent approvals all passed them and all reached the backend.
        # Both preconditions are now inside the ``UPDATE``'s ``WHERE``, which
        # PostgreSQL re-evaluates under the row lock: exactly one caller gets
        # a row back, and losing is indistinguishable from never having been
        # eligible. Claiming the row IS the authorization to execute.
        try:
            updated = await update_challenge_status(
                session,
                challenge_id,
                status="approved",
                expected_status="pending",
                expiry="unexpired",
                confirming_device=body.get("confirming_device"),
                verification_result=stored_verification_result,
                # Verified by step 2b before this line could be reached, so
                # what lands on the row is evidence: an Ed25519 signature by
                # an enrolled device over this row's own contents.
                signature=presented_signature,
            )
        except Exception as exc:
            # `type(exc).__name__` and never `str(exc)` on the audit row, even
            # though the RESPONSE interpolates the message: a store exception
            # can embed the offending value, and this table is a long-lived
            # one. The response's own disclosure predates this change.
            return (
                _error(500, "internal_error", f"approval update failed: {exc}"),
                type(exc).__name__,
            )

        if updated is None:
            return await _refused_transition_response(session, challenge_id)

        await session.commit()

        # --- 4. Execute the backend write endpoint (server-side, not agent) ---
        #
        # Everything below reads ``updated``, the row the statement above
        # proved was ``pending`` and unexpired at the instant it was claimed,
        # rather than ``challenge_record``, which is only what a ``SELECT``
        # saw some microseconds earlier.
        settings = request.app.state.settings
        minter = request.app.state.write_minter

        try:
            audience, path, body_payload = resolve_endpoint(updated.tool_name, updated.payload)

            write_client = BackendWriteClient(
                base_url=settings.backend_base_url,
                minter=minter,
                # THE ENTRY ROW. Invoked by `execute` immediately before the
                # outbound request and AFTER the write JWT is minted, so the
                # row it commits says a write token existed for this challenge
                # and the socket was next. If it raises, the backend is never
                # reached -- that is `BackendRequestHook`'s contract, and it is
                # what makes an audit outage stop money movement rather than
                # merely fail to describe it.
                before_backend_request=audit.record,
            )

            try:
                await write_client.execute(
                    customer_ref=updated.customer_ref,
                    audience=audience,
                    path=path,
                    body=body_payload,
                    challenge_id=challenge_id,
                )
            finally:
                await write_client.aclose()

            # Mark as executed on success. Conditional on ``approved`` like
            # every other transition, and deliberately NOT conditional on the
            # deadline: the money has moved, so a clock that ran out while the
            # backend was answering must not be able to strand the row in
            # ``approved`` and leave the execution unrecorded.
            executed = await update_challenge_status(
                session,
                challenge_id,
                status="executed",
                expected_status="approved",
            )
            if executed is None:
                # Unreachable while this handler is the only writer of the
                # approved -> executed edge: nothing else moves a row out of
                # ``approved``. Logged rather than returned, because the
                # backend write already succeeded and the caller must not be
                # told otherwise -- what is wrong here is the audit trail, and
                # silence is how that goes unnoticed.
                logger.error(
                    "challenge %s executed at the backend but was not in 'approved' "
                    "when the executed transition ran; the row does not record the "
                    "execution",
                    challenge_id,
                )
            await session.commit()

            # THE ONLY EXIT THAT RECORDS `returned`. It is reached when, and
            # only when, the backend accepted the write, so `outcome` on this
            # row means the money moved -- not that the server answered.
            return (
                _json(
                    200,
                    {
                        "challenge_id": challenge_id,
                        "status": "executed",
                        "message": f"{updated.tool_name} executed successfully",
                    },
                ),
                None,
            )

        except BackendWriteError as exc:
            # Execution failed — challenge is approved but not executed.
            # The backend may have partially processed the request; audit trail
            # captures this state for investigation.
            #
            # `raised`, not `returned`, and the 207 does not change that: the
            # `outcome` vocabulary describes what the WORK did, not what HTTP
            # said. This row is paired with an entry row, because the backend
            # was reached -- which is exactly the state an investigator needs,
            # since a challenge sitting in `approved` may or may not have been
            # partially processed on the other side.
            #
            # `exc.detail` is already scrubbed by `_scrub_response`, but it is
            # still a backend MESSAGE, so what reaches the table is the
            # exception type alone. The status code lives in the response, and
            # the `Idempotency-Key` in the backend's own access log is what
            # joins this row to what actually happened there.
            return (
                _json(
                    207,
                    {
                        "challenge_id": challenge_id,
                        "status": "approved",  # Approved but not executed.
                        "message": f"approval recorded, backend execution failed: {exc.detail}",
                        "backend_status": exc.status,
                    },
                ),
                type(exc).__name__,
            )

        except ValueError as exc:
            # Tool not registered or payload missing required fields.
            #
            # A SINGLE ROW, no entry row, and that asymmetry is the point.
            # `resolve_endpoint` raises before `BackendWriteClient` is
            # constructed, so nothing was reached and the hook never ran -- but
            # the challenge has ALREADY been claimed and committed as
            # `approved` by step 3. This row is the only record that a
            # challenge is stranded in `approved` with no execution behind it
            # and no backend to reconcile against.
            return (
                _error(500, "internal_error", f"execution setup failed: {exc}"),
                type(exc).__name__,
            )


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


async def _read_body(request: Request) -> dict[str, Any] | None:
    """The approval body as a dict, or ``None`` if it is not one.

    FOUR SHAPES COLLAPSE TO ``None``, and each was a 500 with no audit row
    until 2026-09-24:

    - bytes that are not JSON (``json.JSONDecodeError``, a ``ValueError``);
    - bytes that are not decodable as UTF-8 (``UnicodeDecodeError``, which is
      a ``ValueError`` too but is named anyway, because the pairing is the one
      ``services/api/asgi/header_validation.py::_parse`` writes and a reader
      comparing them should not have to work out that one implies the other);
    - JSON nested past the interpreter's recursion limit. ``json.loads``
      raises ``RecursionError`` there, which is a ``RuntimeError`` subclass
      and therefore NOT caught by ``except (ValueError, UnicodeDecodeError)``
      -- the same gap the read path's ``_parse`` carries. Measured: 200,000
      nested arrays, well inside ``ConfirmSettings.max_body_bytes``, raised it;
    - well-formed JSON that is not an object. ``[1,2,3]`` parsed fine and then
      raised ``AttributeError`` on the first ``body.get``, which is why the
      ``isinstance`` below is part of this function and not a separate check:
      the caller's contract is "a dict or ``None``", so nothing downstream has
      to ask a second time.

    ``request.json()`` is left to buffer the body because
    ``services/confirm/body_limit.py`` has already bounded what it can buffer.
    Without that middleware this function would be reading an unbounded body
    into memory in order to refuse it.
    """
    try:
        parsed = await request.json()
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return parsed if isinstance(parsed, dict) else None


async def _refused_transition_response(
    session: Any, challenge_id: str
) -> tuple[JSONResponse, str | None]:
    """Name the reason a conditional ``pending`` -> ``approved`` matched no row.

    The statement that refused carried three predicates -- the id, ``status =
    'pending'`` and ``expires_at > now()`` -- and a rowcount of zero does not
    say which one failed. This handler owes three different answers (409
    already terminal, 410 expired, 404 gone), so it reads the row once more
    to tell them apart.

    THAT READ IS NOT A SECOND RACE, and it is worth saying why rather than
    leaving the next reader to work it out. Every reason the ``UPDATE`` can
    refuse is permanent once it has happened:

    - ``status`` is no longer ``pending``. The four other values are terminal
      and no transition in this tree leads back, so the status this read
      returns is the status it will have forever.
    - the deadline has passed. ``expires_at`` is written once at challenge
      creation and never updated, and time does not run backwards.

    So the row cannot become eligible again between the refusal and this
    read, and no answer derived from it can be stale. This would NOT hold in
    the other direction -- reading first and then deciding, which is the
    defect (audit finding C-03) this function exists behind.

    ``refresh=True`` is not optional here. This session has already loaded
    this row (the ownership check did), and without it the ORM answers from
    its identity map and reports the status this session saw BEFORE the
    winner committed -- measured: five of six concurrent losers answered 500
    instead of 409 until it was passed.
    """
    current = await get_challenge(session, challenge_id, refresh=True)

    if current is None:
        # The row was there for the ownership check and is gone now. Nothing
        # deletes challenges, so this is a real anomaly rather than a routine
        # 404, but the answer a caller gets is the ordinary one: the same body
        # as "no such challenge", because splitting it would be the existence
        # oracle the ownership check above is careful not to be.
        logger.error(
            "challenge %s vanished between the ownership read and the update",
            challenge_id,
        )
        # The response is the ordinary 404; the audit row is not. This detail
        # is the only place the anomaly is durable -- the log line above is
        # whatever the deployment does with stderr, and the row is in the
        # table a regulator reads.
        return (
            _error(404, "not_found", f"challenge {challenge_id} not found"),
            DETAIL_CHALLENGE_VANISHED,
        )

    if current.status != "pending":
        # A lost race and a replayed approval are the same row. Both are
        # normal enough not to be an anomaly and interesting enough to count:
        # MCP 2026-07-28 removed SSE resumability, so a client re-issuing a
        # dropped request is specified behaviour, and a spike in these is how
        # a replay attempt would look.
        return (
            _error(409, "already_terminal", f"challenge is already {current.status}"),
            DETAIL_ALREADY_TERMINAL,
        )

    # Still pending, so the deadline is what refused the claim. Record that,
    # conditionally and in SQL like every other transition: ``expiry="expired"``
    # asserts ``expires_at <= now()``, the exact negation of the predicate that
    # just failed, so this cannot retire a challenge that is actually live.
    expired = await update_challenge_status(
        session,
        challenge_id,
        status="expired",
        expected_status="pending",
        expiry="expired",
    )
    if expired is not None:
        await session.commit()
        # This path WRITES -- it retires the challenge -- and is the one
        # refusal that changes state. The row records that the transition to
        # `expired` was driven by this caller at this instant, which the
        # `challenges` row itself does not say.
        return (
            _error(410, "expired", f"challenge {challenge_id} has expired"),
            DETAIL_EXPIRED,
        )

    # Pending, unexpired, and yet a statement whose only other predicate was
    # the primary key matched nothing. There is no state of the table that
    # produces this, so it is a defect in this file or in the store layer, not
    # a condition the caller can act on.
    logger.error(
        "challenge %s: the conditional approval matched no row while the row reads "
        "pending and unexpired",
        challenge_id,
    )
    return (
        _error(500, "internal_error", "approval update matched no row"),
        DETAIL_UPDATE_MATCHED_NO_ROW,
    )


def _error(status: int, code: str, description: str) -> JSONResponse:
    """Return an error response."""
    return JSONResponse(
        status_code=status,
        content={"error": code, "error_description": description},
    )


def _json(status: int, body: dict[str, Any]) -> JSONResponse:
    """Return a success response."""
    return JSONResponse(status_code=status, content=body)


# ---------------------------------------------------------------------------
# Route assembly.
# ---------------------------------------------------------------------------


def callback_routes() -> list:  # type: ignore[type-arg]
    """Build the approval callback route list.

    Returns:
        Starlette Route objects to mount on the confirm service app.
    """
    from starlette.routing import Route

    return [
        Route(
            "/challenges/{challenge_id}/approve",
            approve_challenge,
            methods=["POST"],
        ),
    ]

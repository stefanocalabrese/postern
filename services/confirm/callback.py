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
        "signature": "<recorded, NOT verified — see below>",
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

WHAT THE ``signature`` FIELD IS, AND WHAT IT IS NOT. It is checked for
PRESENCE and stored. That is the whole check, today, and the local variable is
named ``unverified_signature`` at every use site so no reader has to take this
paragraph's word for it.

Verifying it for real means answering "which public key belongs to this
customer's enrolled device", and this repository has no device public-key
registry, no enrolment flow and no key-rotation story for one — that is the
operator's app platform's to build (handoff §10.10 is the nearest open
question). Inventing one here would produce a control that looks like
cryptographic proof of user presence and is not.

The residual risk, stated plainly: the assertion proves the CALLER is the
operator's app acting for this customer. Nothing proves the human held the
device and consented. Anything able to mint or steal an app assertion for a
customer can approve that customer's pending challenges without touching
their phone. What closes it is a per-customer device public key, registered
at enrolment, with this handler verifying a signature over the stored
challenge row's own fields (id, amount, payee, nonce) rather than over
anything the caller supplies.
"""

from __future__ import annotations

import logging
from typing import Any

from postern_core.store.challenges import get_challenge, update_challenge_status
from starlette.requests import Request
from starlette.responses import JSONResponse

from services.confirm.auth import unauthenticated_response, verified_subject
from services.confirm.execute import BackendWriteClient, BackendWriteError, resolve_endpoint

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Approval callback — POST /challenges/{challenge_id}/approve.
# ---------------------------------------------------------------------------


async def approve_challenge(request: Request) -> JSONResponse:
    """Handle a verification challenge approval from the mobile app.

    This is called by the confirmation service (the operator's banking app)
    after the user completes identity verification and approves the operation.

    Flow:
        0. Verify the app assertion; the customer is its ``sub``.
        1. Look up the challenge by ID (from stored row, not agent input).
        2. Reject unless the challenge belongs to that customer.
        3. Claim it: one conditional ``UPDATE`` that carries "still pending"
           and "not yet expired" in its ``WHERE`` and records the unverified
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
    """
    subject = verified_subject(request)
    if subject is None:
        # Unreachable through the assembled app: `AppAssertionMiddleware`
        # refused before routing. Kept because a handler that derives
        # authority from ambient state must fail closed when that state is
        # absent, not proceed with none.
        return unauthenticated_response()

    challenge_id: str = request.path_params.get("challenge_id", "")
    if not challenge_id:
        return _error(400, "invalid_request", "challenge_id is required in path")

    body = await request.json()
    # Named for what it is at every use site. Presence is the entire check;
    # the module docstring records why there is no real one and what would
    # close it.
    unverified_signature: str = body.get("signature", "")
    verification_result: str | None = body.get("verification_result")

    if not unverified_signature:
        return _error(400, "invalid_request", "signature is required")

    # --- 1. Look up the challenge (from DB, not agent input) ---
    db = request.app.state.postern_database

    async with db.sessionmaker() as session:
        challenge_record = await get_challenge(session, challenge_id)

        if challenge_record is None:
            return _error(404, "not_found", f"challenge {challenge_id} not found")

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
            return _error(404, "not_found", f"challenge {challenge_id} not found")

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
                verification_result=verification_result,
                signature=unverified_signature,
            )
        except Exception as exc:
            return _error(500, "internal_error", f"approval update failed: {exc}")

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

            return _json(
                200,
                {
                    "challenge_id": challenge_id,
                    "status": "executed",
                    "message": f"{updated.tool_name} executed successfully",
                },
            )

        except BackendWriteError as exc:
            # Execution failed — challenge is approved but not executed.
            # The backend may have partially processed the request; audit trail
            # captures this state for investigation.
            return _json(
                207,
                {
                    "challenge_id": challenge_id,
                    "status": "approved",  # Approved but not executed.
                    "message": f"approval recorded, backend execution failed: {exc.detail}",
                    "backend_status": exc.status,
                },
            )

        except ValueError as exc:
            # Tool not registered or payload missing required fields.
            return _error(500, "internal_error", f"execution setup failed: {exc}")


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


async def _refused_transition_response(session: Any, challenge_id: str) -> JSONResponse:
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
        return _error(404, "not_found", f"challenge {challenge_id} not found")

    if current.status != "pending":
        return _error(409, "already_terminal", f"challenge is already {current.status}")

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
        return _error(410, "expired", f"challenge {challenge_id} has expired")

    # Pending, unexpired, and yet a statement whose only other predicate was
    # the primary key matched nothing. There is no state of the table that
    # produces this, so it is a defect in this file or in the store layer, not
    # a condition the caller can act on.
    logger.error(
        "challenge %s: the conditional approval matched no row while the row reads "
        "pending and unexpired",
        challenge_id,
    )
    return _error(500, "internal_error", "approval update matched no row")


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

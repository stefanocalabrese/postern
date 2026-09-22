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
from datetime import UTC, datetime
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
        3. Validate it is pending and not expired.
        4. Mark as approved (records the unverified signature +
           verification_result).
        5. Execute the backend write endpoint server-side via execute.py.

    The confirmation payload is built server-side from the stored challenge
    row — never re-sent or re-specified by the agent (handoff §6.3).
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

        # --- 3. Validate state ---
        if challenge_record.status != "pending":
            return _error(
                409,
                "already_terminal",
                f"challenge is already {challenge_record.status}",
            )

        # Check expiry — the store layer does not filter on this for get_challenge.
        if datetime.now(UTC) >= challenge_record.expires_at:
            # Mark as expired before returning.
            await update_challenge_status(
                session,
                challenge_id,
                status="expired",
            )
            await session.commit()
            return _error(410, "expired", f"challenge {challenge_id} has expired")

        # --- 4. Mark as approved ---
        try:
            updated = await update_challenge_status(
                session,
                challenge_id,
                status="approved",
                confirming_device=body.get("confirming_device"),
                verification_result=verification_result,
                signature=unverified_signature,
            )
        except Exception as exc:
            return _error(500, "internal_error", f"approval update failed: {exc}")

        if updated is None:
            return _error(500, "internal_error", "approval update returned no row")

        await session.commit()

        # --- 5. Execute the backend write endpoint (server-side, not agent) ---
        settings = request.app.state.settings
        minter = request.app.state.write_minter

        try:
            audience, path, body_payload = resolve_endpoint(
                challenge_record.tool_name, challenge_record.payload
            )

            write_client = BackendWriteClient(
                base_url=settings.backend_base_url,
                minter=minter,
            )

            try:
                await write_client.execute(
                    customer_ref=challenge_record.customer_ref,
                    audience=audience,
                    path=path,
                    body=body_payload,
                    challenge_id=challenge_id,
                )
            finally:
                await write_client.aclose()

            # Mark as executed on success.
            await update_challenge_status(
                session,
                challenge_id,
                status="executed",
            )
            await session.commit()

            return _json(
                200,
                {
                    "challenge_id": challenge_id,
                    "status": "executed",
                    "message": f"{challenge_record.tool_name} executed successfully",
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

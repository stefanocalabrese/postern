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

    {
        "signature": "<device-bound key signature over payload>",
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
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from postern_core.store.challenges import get_challenge, update_challenge_status
from starlette.requests import Request
from starlette.responses import JSONResponse

from services.confirm.execute import BackendWriteClient, BackendWriteError, resolve_endpoint

# ---------------------------------------------------------------------------
# Approval callback — POST /challenges/{challenge_id}/approve.
# ---------------------------------------------------------------------------


async def approve_challenge(request: Request) -> JSONResponse:
    """Handle a verification challenge approval from the mobile app.

    This is called by the confirmation service (the operator's banking app)
    after the user completes identity verification and approves the operation.

    Flow:
        1. Look up the challenge by ID (from stored row, not agent input).
        2. Validate it is pending and not expired.
        3. Mark as approved (writes signature + verification_result).
        4. Execute the backend write endpoint server-side via execute.py.

    The confirmation payload is built server-side from the stored challenge
    row — never re-sent or re-specified by the agent (handoff §6.3).
    """
    challenge_id: str = request.path_params.get("challenge_id", "")
    if not challenge_id:
        return _error(400, "invalid_request", "challenge_id is required in path")

    body = await request.json()
    signature: str = body.get("signature", "")
    verification_result: str | None = body.get("verification_result")

    if not signature:
        return _error(400, "invalid_request", "signature is required")

    # --- 1. Look up the challenge (from DB, not agent input) ---
    db = request.app.state.postern_database

    async with db.sessionmaker() as session:
        challenge_record = await get_challenge(session, challenge_id)

        if challenge_record is None:
            return _error(404, "not_found", f"challenge {challenge_id} not found")

        # --- 2. Validate state ---
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

        # --- 3. Mark as approved ---
        try:
            updated = await update_challenge_status(
                session,
                challenge_id,
                status="approved",
                confirming_device=body.get("confirming_device"),
                verification_result=verification_result,
                signature=signature,
            )
        except Exception as exc:
            return _error(500, "internal_error", f"approval update failed: {exc}")

        if updated is None:
            return _error(500, "internal_error", "approval update returned no row")

        await session.commit()

        # --- 4. Execute the backend write endpoint (server-side, not agent) ---
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

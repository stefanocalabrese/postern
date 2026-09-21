"""RFC 8628 device authorization endpoints for the confirm service.

Endpoints:
- ``POST /device_authorization`` — Generate device code + QR pairing data.
- ``POST /token`` with ``grant_type=device_code`` — Exchange device code for
  tokens (polling; returns error until mobile app approves).
- ``POST /approve`` — Mobile app approval callback (marks device code as
  approved).

The confirm service is the right home for these because:
1. It already holds both read and write signing keys (a controlled exception
   to the key-split architecture — see ``ConfirmSettings`` docstring).
2. Device code exchange mints both read and write tokens atomically.
3. The approval callback needs to update device code state, which lives in
   the same service as the token minting.

QR data encoding: the verification URI with ``user_code`` as a query
parameter (``verification_uri_complete``). The mobile app deep-links to this
URI; the browser shows a QR encoding it.

Pairing code (``user_code``): 6 uppercase alphanumeric chars, displayed as
XXX-XXX on both surfaces. The user must confirm they match before identity
verification proceeds (§7.3, anti-phishing control A2).

Usage in ``main.py``::

    from services.confirm.device_auth import (
        device_auth_routes,
        build_device_code_store,
    )

    store = build_device_code_store(settings)
    routes = device_auth_routes(
        store=store,
        settings=settings,
        read_minter=read_minter,
        write_minter=write_minter,
    )
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from postern_core.auth.device_codes import (
    DeviceCode,
    DeviceCodeStoreBase,
    InMemoryDeviceCodeStore,
    create_device_code_store,
)
from postern_core.auth.internal_jwt import InternalTokenMinter
from postern_core.identity import CustomerRef

from services.confirm.settings import ConfirmSettings


# ---------------------------------------------------------------------------
# Error responses — RFC 8628 §3.3 and §3.4 error codes.
# ---------------------------------------------------------------------------

def _error(status: int, code: str, description: str) -> JSONResponse:
    """Return an RFC 8628-compatible error response."""
    return JSONResponse(
        status_code=status,
        content={
            "error": code,
            "error_description": description,
        },
    )


# ---------------------------------------------------------------------------
# Device authorization endpoint — POST /device_authorization.
# ---------------------------------------------------------------------------

async def device_authorization(request: Request) -> JSONResponse:
    """Generate a device code and return QR pairing data.

    Request body (application/x-www-form-urlencoded or JSON):
        client_id: OAuth client identifier (required).
        scopes: Space-separated scope list (optional, defaults to all read).

    Response (200):
        device_code: Opaque code for token exchange.
        user_code: Human-readable pairing code (XXX-XXX).
        verification_uri: Base URI for the verification page.
        verification_uri_complete: Full URI with user_code (for deep-linking).
        expires_in: Lifetime in seconds.
        interval: Seconds between token polls.

    RFC 8628 §3.1 — the device_code is 40+ chars, user_code is 6+ chars
    of uppercase alphanumeric (no ambiguous characters).
    """
    # Parse form or JSON body.
    content_type = request.headers.get("content-type", "")
    if "application/json" in content_type:
        body = await request.json()
    else:
        form = await request.form()
        body = dict(form)

    client_id: str = body.get("client_id", "")
    if not client_id:
        return _error(400, "invalid_request", "client_id is required")

    scopes: str = body.get("scopes", "accounts:read transactions:read cards:read")

    store: DeviceCodeStoreBase = request.app.state.device_code_store
    settings: ConfirmSettings = request.app.state.settings

    code: DeviceCode = await store.create_device_code(
        client_id=client_id,
        scopes=scopes,
        verification_uri=settings.device_verification_uri,
        expires_in=settings.device_code_ttl_seconds,
        interval=settings.device_poll_interval_seconds,
    )

    return JSONResponse(
        status_code=200,
        content={
            "device_code": code.device_code,
            "user_code": code.user_code_display,
            "verification_uri": code.verification_uri,
            "verification_uri_complete": code.verification_uri_complete,
            "expires_in": settings.device_code_ttl_seconds,
            "interval": settings.device_poll_interval_seconds,
        },
    )


# ---------------------------------------------------------------------------
# Token endpoint — POST /token with grant_type=device_code.
# ---------------------------------------------------------------------------

async def token_endpoint(request: Request) -> JSONResponse:
    """Exchange a device code for access tokens.

    Handles ``grant_type=device_code`` (RFC 8628 §3.4) and forwards all
    other grant types to the existing JWKS-only app (which will 404).

    Request body:
        grant_type: "device_code" (required for this path).
        device_code: The opaque device code from /device_authorization.

    Response while pending (400):
        {"error": "authorization_pending", "error_description": "..."}

    Response after approval (200):
        {
            "access_token": "<read token>",
            "refresh_token": null,  # not yet implemented
            "token_type": "Bearer",
            "expires_in": 60,
            "write_token": "<write token>",  # for the approval callback
        }

    Error codes per RFC 8628 §3.4:
        authorization_pending — not yet approved, keep polling.
        slow_down — client is polling too fast (adds 5s to interval).
        access_denied — user explicitly denied on mobile app.
        expired_token — device code has passed its TTL.
    """
    form = await request.form()
    grant_type_raw = form.get("grant_type", "")
    grant_type: str = (
        grant_type_raw.file.read().decode() if hasattr(grant_type_raw, "file") else str(grant_type_raw)
    )

    if grant_type != "device_code":
        # Not a device code request — let the 404 handler deal with it.
        return _error(404, "unsupported_grant_type", "only device_code grant is supported")

    device_code_raw = form.get("device_code", "")
    device_code_value: str = (
        device_code_raw.file.read().decode() if hasattr(device_code_raw, "file") else str(device_code_raw)
    )
    if not device_code_value:
        return _error(400, "invalid_request", "device_code is required")

    store: DeviceCodeStoreBase = request.app.state.device_code_store
    settings: ConfirmSettings = request.app.state.settings

    code: DeviceCode | None = await store.get_device_code(device_code_value)
    if code is None:
        return _error(400, "invalid_grant", "device code not found or already revoked")

    if code.is_expired:
        await store.revoke_device_code(device_code_value)
        return _error(400, "expired_token", "device code has expired")

    # RFC 8628 §3.4 — "slow_down": client is polling faster than the
    # ``interval`` parameter. Only enforced while authorization is pending;
    # once approved the client should get tokens immediately.
    if not code.approved:
        poll_times: dict[str, datetime] = getattr(request.app.state, "_poll_times", {})
        if not poll_times:
            request.app.state._poll_times = poll_times
        last_poll = poll_times.get(device_code_value)
        if last_poll is not None:
            elapsed = (datetime.now(UTC) - last_poll).total_seconds()
            if elapsed < settings.device_poll_interval_seconds:
                return _error(
                    400,
                    "slow_down",
                    f"Poll again in {int(settings.device_poll_interval_seconds - elapsed)}s",
                )
        # Record this poll time.
        poll_times[device_code_value] = datetime.now(UTC)

    if not code.approved:
        return _error(400, "authorization_pending", "waiting for user approval on mobile app")

    # Approved — mint read + write tokens.
    # The device_code carries the customer identity via the approval callback;
    # we store it in the DeviceCode at approval time. For now, the approval
    # callback stores the subject_value on the code's client_id field.
    # In production, this would be a dedicated field.
    subject_value: str = code.client_id
    if not subject_value:
        return _error(500, "invalid_state", "approval missing customer identity")

    # Mint read token.
    read_minter: InternalTokenMinter = request.app.state.read_minter
    read_token = read_minter.mint(
        subject=CustomerRef(value=subject_value),
        audience="accounts.svc",
        scope="accounts:read",
    )

    # Mint write token (for the approval callback / future write operations).
    write_minter: InternalTokenMinter = request.app.state.write_minter
    write_token = write_minter.mint(
        subject=CustomerRef(value=subject_value),
        audience="payments.svc",
        scope="payments:execute",
    )

    return JSONResponse(
        status_code=200,
        content={
            "access_token": read_token,
            "token_type": "Bearer",
            "expires_in": 60,
            "write_token": write_token,
        },
    )


# ---------------------------------------------------------------------------
# Approval callback — POST /approve.

# This is called by the mobile app after the user completes identity
# verification and approves the device pairing. It marks the device code
# as approved so the browser can exchange it for tokens.

# The mobile app sends:
#   device_code — the opaque device code.
#   subject_value — the customer identity (from the app's authenticated session).
#   approval_signature — a signature proving the user approved (optional,
#                        for audit trail; the actual auth comes from the
#                        app's own session).

async def approve_callback(request: Request) -> JSONResponse:
    """Mobile app approval callback.

    Called by the banking app after the user completes identity verification
    and confirms the device pairing. Marks the device code as approved so
    the browser can exchange it for tokens.

    Request body:
        device_code: The opaque device code (required).
        subject_value: Customer identity / sub claim (required).
        approval_signature: Optional signature for audit trail.

    Response (200): {"status": "approved"}
    Response (400): error if device code not found or already approved.
    """
    body = await request.json()

    device_code_value: str = body.get("device_code", "")
    subject_value: str = body.get("subject_value", "")

    if not device_code_value or not subject_value:
        return _error(400, "invalid_request", "device_code and subject_value are required")

    store: DeviceCodeStoreBase = request.app.state.device_code_store

    existing: DeviceCode | None = await store.get_device_code(device_code_value)
    if existing is None:
        return _error(400, "invalid_grant", "device code not found")

    if existing.approved:
        return _error(400, "already_approved", "device code already approved")

    # Mark as approved and attach the customer identity.
    # We update client_id to carry the subject_value (it was the OAuth client
    # ID at creation; after approval it becomes the customer identity).
    approved: bool = await store.approve_device_code(device_code_value)
    if not approved:
        return _error(500, "approval_failed", "could not mark device code as approved")

    # Fetch the now-approved code and update client_id with subject_value.
    approved_code: DeviceCode | None = await store.get_device_code(device_code_value)
    if approved_code is None:
        return _error(500, "approval_failed", "approved code disappeared")
    updated = approved_code.__class__(
        **{**_device_code_to_dict(approved_code), "client_id": subject_value},
    )
    await store.update_device_code(device_code_value, updated)

    return JSONResponse(
        status_code=200,
        content={"status": "approved"},
    )


def _device_code_to_dict(dc: DeviceCode) -> dict[str, Any]:
    """Helper to convert frozen dataclass to mutable dict."""
    import dataclasses

    return {f.name: getattr(dc, f.name) for f in dataclasses.fields(dc)}


# ---------------------------------------------------------------------------
# Route assembly.
# ---------------------------------------------------------------------------

def device_auth_routes(
    store: DeviceCodeStoreBase,
    settings: ConfirmSettings,
    read_minter: InternalTokenMinter,
    write_minter: InternalTokenMinter,
) -> list[Route]:
    """Build the device authorization route list.

    Args:
        store: Device code storage backend.
        settings: Service settings (TTL, URIs).
        read_minter: Minter for read tokens (during device code exchange).
        write_minter: Minter for write tokens (during device code exchange).

    Returns:
        Starlette Route objects to mount on the confirm service app.
    """
    return [
        Route(
            "/device_authorization",
            device_authorization,
            methods=["POST"],
        ),
        Route(
            "/token",
            token_endpoint,
            methods=["POST"],
        ),
        Route(
            "/approve",
            approve_callback,
            methods=["POST"],
        ),
    ]


# ---------------------------------------------------------------------------
# Factory — picks the right backend based on environment.
# ---------------------------------------------------------------------------

def build_device_code_store() -> DeviceCodeStoreBase:
    """Create a device code store from environment.

    Reads ``POSTERN_REDIS_URL``: if set, returns a Redis-backed store;
    otherwise returns an in-memory store.

    This mirrors ``postern_core.risk.session.create_session_store``'s pattern.
    """
    return create_device_code_store()


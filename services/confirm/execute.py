"""Backend write execution infrastructure (handoff §6.3, §8.3).

Tool-to-endpoint mapping and the HTTP client that executes approved
challenges against backend write endpoints.

Execution belongs to the server, never the agent (handoff §6.2). This
module lives in ``services/confirm`` and holds the write key, so it can
mint internal JWTs with ``challenge_id`` claims (§7.2).

The tool-handler process (services/api) does NOT import this module —
the structural separation in handoff §8.3 is enforced by import
boundaries, not code review.
"""

from __future__ import annotations

import re
from typing import Any, Protocol

import httpx2
from postern_core.domain.masking import FreeText
from pydantic import TypeAdapter

from services.confirm.minter import WRITE_SCOPES, WriteTokenMinter


class _MinterProtocol(Protocol):
    """Minimal minter interface — stubs in tests implement this."""

    def mint(
        self,
        *,
        subject_value: str,
        audience: str,
        scope: str,
        challenge_id: str = ...,
    ) -> str: ...


# Built once at import time: validating a bare string against `FreeText`
# doesn't need a wrapping `BaseModel`, just its `AfterValidator`.
_FREE_TEXT: TypeAdapter[str] = TypeAdapter(FreeText)


def _scrub(text: str) -> str:
    return _FREE_TEXT.validate_python(text)


# ---------------------------------------------------------------------------
# Tool-to-endpoint registry.
# ---------------------------------------------------------------------------

# Maps tool_name → (audience, path_template, method).
# The path template is a format string that receives the payload fields.
# The payload dict from the challenge is passed as kwargs to .format().

TOOL_REGISTRY: dict[str, tuple[str, str, str]] = {
    # Payments — tier-1 and tier-2 operations.
    "payments.create_payment": ("payments.svc", "/payments", "POST"),
    # Cards — tier-1 operations.
    "cards.freeze_card": ("cards.svc", "/cards/{card_id}/freeze", "POST"),
    "cards.unfreeze_card": ("cards.svc", "/cards/{card_id}/unfreeze", "POST"),
    "cards.set_label": ("cards.svc", "/cards/{card_id}/label", "PATCH"),
    # Accounts — tier-1 operations.
    "accounts.rename": ("accounts.svc", "/accounts/{account_id}/rename", "PATCH"),
    # Standing orders — tier-1 operations.
    "standing_orders.cancel": ("payments.svc", "/standing-orders/{order_id}/cancel", "POST"),
}


def resolve_endpoint(tool_name: str, payload: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    """Resolve a tool name to (audience, path, body).

    Args:
        tool_name: The MCP tool name from the challenge (e.g., "payments.create_payment").
        payload: The operation payload stored at challenge creation time.

    Returns:
        (audience, path, body) tuple for the backend write endpoint.

    Raises:
        ValueError: If the tool_name is not registered or required payload fields are missing.
    """
    if tool_name not in TOOL_REGISTRY:
        raise ValueError(f"unknown tool: {tool_name}")

    audience, path_template, _method = TOOL_REGISTRY[tool_name]
    # Validate that required path parameters are present in the payload.
    placeholders = re.findall(r"\{(\w+)\}", path_template)
    for placeholder in placeholders:
        if placeholder not in payload:
            raise ValueError(
                f"tool {tool_name!r} requires payload field {placeholder!r} "
                f"for path resolution, got: {list(payload.keys())}"
            )

    # Build the final path with payload values interpolated.
    path = path_template.format(**payload)

    # The body is the full payload — it was stored server-side at challenge
    # creation, never re-sent or re-specified by the agent.
    body = payload

    return audience, path, body


# ---------------------------------------------------------------------------
# Write client — POST/PATCH to backend write endpoints.
# ---------------------------------------------------------------------------


class BackendWriteClient:
    """Sends POST/PATCH requests to backend write endpoints.

    Unlike ``postern_core.facade.client.BackendClient`` (read-only GET), this
    client handles write operations. It lives in ``services/confirm`` and holds
    the write key, so it can mint internal JWTs with ``challenge_id`` claims.

    The tool-handler process (services/api) does NOT import this module — the
    structural separation in handoff §8.3 is enforced by import boundaries,
    not code review.
    """

    def __init__(
        self,
        base_url: str,
        minter: _MinterProtocol | WriteTokenMinter,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._minter = minter
        self._client = httpx2.AsyncClient(
            base_url=base_url,
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
        )

    async def execute(
        self,
        *,
        customer_ref: str,
        audience: str,
        path: str,
        body: dict[str, Any],
        challenge_id: str,
    ) -> httpx2.Response:
        """Execute a backend write endpoint.

        Args:
            customer_ref: The customer who initiated the operation (from challenge).
            audience: Backend service audience (e.g., "payments.svc").
            path: The backend endpoint path.
            body: The operation payload (stored server-side at challenge creation).
            challenge_id: The challenge ID — included in the JWT claim.

        Returns:
            The backend response. Raises BackendWriteError on non-2xx.
        """
        # Mint an internal JWT with challenge_id in claims (§7.2).
        token = self._minter.mint(
            subject_value=customer_ref,
            audience=audience,
            scope=WRITE_SCOPES.get(audience, "write:execute"),
            challenge_id=challenge_id,
        )

        response = await self._client.post(
            path,
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )

        if response.status_code not in (200, 201, 202):
            raise BackendWriteError(
                status=response.status_code,
                detail=_scrub_response(response),
            )

        return response

    async def aclose(self) -> None:
        await self._client.aclose()


class BackendWriteError(RuntimeError):
    """A backend write endpoint returned an error."""

    def __init__(self, *, status: int, detail: str) -> None:
        super().__init__(f"{status}: {detail}")
        self.status = status
        self.detail = detail


def _scrub_response(response: httpx2.Response) -> str:
    """Scrubbed, length-capped summary of a backend error body.

    Mirrors ``postern_core.facade.client._detail`` but for write responses.
    Scrubbing runs on the full body *before* the 200-character cut: cutting
    first could split a PAN or IBAN in half, leaving an unmasked digit
    fragment past the cut instead of a masked value before it.
    """
    try:
        body = response.json()
    except ValueError:
        text = response.text
    else:
        text = str(body.get("detail", body)) if isinstance(body, dict) else str(body)
    return _scrub(text)[:200]

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
from postern_core.domain.masking import scrub_text

# The same Protocol `BackendClient` uses for the same job, imported rather
# than redeclared so the read and write paths cannot drift into two
# incompatible hook shapes. `.importlinter` permits it: the forbidden edges
# are `postern_core.facade -> postern_core.store` and `services.api <->
# services.confirm`, and this is neither.
from postern_core.facade.client import BackendRequestHook

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


# A LIVE GAP CLOSED, not a tidy-up. This module used to carry its own
# `_scrub`, `TypeAdapter(FreeText).validate_python(text)`, which is
# `postern_core.domain.masking.scrub_text` MINUS the NUL strip. That omission
# was exploitable on exactly one path and it is the money path: a NUL byte
# planted inside a PAN in a backend error body splits the digits into two runs
# that `_PAN_IN_TEXT_RE` (`\d{12,}`) individually fails to match, so
# `_scrub_response` below found nothing to redact and the raw PAN reached
# `BackendWriteError.detail` -- and from there the 207 response body this
# service returns. `scrub_text` strips the NUL first, so the contiguous run is
# there to match. Its docstring carries the full ordering argument.


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
        # REQUIRED with no default, though `None` is a legitimate value, and
        # for exactly the reason `postern_core.facade.client.BackendClient`
        # gives for the identical parameter one package over: a hook left off
        # reaches a backend WRITE endpoint with nothing recorded first, which
        # is the hole it exists to close, and a default lets a future
        # construction site inherit that silently instead of writing the
        # decision down. The stake is higher here than on the read path --
        # what sits at the end of this call is money movement, not a masked
        # balance -- so if the two ever diverge this is the one that keeps the
        # requirement.
        #
        # `None` stays legal because this package has callers with genuinely
        # nothing to record: `tests/test_execute.py` exercises path
        # resolution, minting and response scrubbing with no store behind
        # them. What is NOT enforced anywhere is that
        # `services/confirm/callback.py` passes a real one;
        # `tests/test_write_audit.py` fails if it stops.
        before_backend_request: BackendRequestHook | None,
    ) -> None:
        self._minter = minter
        self._before_backend_request = before_backend_request
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
            challenge_id: The challenge ID — sent as the JWT ``challenge_id``
                claim and as the ``Idempotency-Key`` header.

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

        if self._before_backend_request is not None:
            # LAST, with nothing between it and the request but the request
            # itself, and AFTER the mint above. Both halves of that placement
            # are load-bearing and they say different things.
            #
            # AFTER THE MINT: the audit row this hook commits therefore means
            # "a write token was minted for this challenge and the socket was
            # next", which is strictly stronger than "the server intended to
            # call the backend". A mint that fails writes no row, correctly --
            # nothing was reached and nothing could have been. That a write
            # JWT existed at all was one of the facts an investigator had no
            # way to establish before this hook.
            #
            # LAST: from this line on, the next thing that happens is a socket
            # carrying this customer's identity and a payment instruction to
            # the operator's backend.
            #
            # Not guarded by try/except on purpose. `BackendRequestHook`'s own
            # contract is that a raise stops the request, which is the entire
            # value of running first: a caller that cannot record the write
            # can prevent it.
            await self._before_backend_request()

        # `Idempotency-Key` is defence in depth behind the conditional
        # `pending -> approved` transition in
        # `postern_core.store.challenges.update_challenge_status`, not a
        # substitute for it (audit finding C-03). The transition is what makes
        # a duplicate execution impossible when this process and its database
        # agree; the header is what stops one when they do not -- a request
        # retried at the transport layer after the response was lost, a
        # process killed between the backend call and the `executed`
        # transition, a second replica resuming work it could not tell had
        # finished.
        #
        # WHY THE CHALLENGE ID ITSELF, unhashed and underived. It is already
        # exactly one-per-operation: the row is the unit of work, the backend
        # is called at most once per row, and no two operations share an id.
        # A hash or a salted derivation would buy nothing -- the backend
        # already receives this same value as a JWT claim it verifies, so
        # nothing is concealed from it that it does not already hold -- and
        # would cost the property that matters when someone is reading a
        # backend access log next to this table: the key in the log and the
        # `challenge_id` in the audit row are the same string, so the two
        # sides of one payment can be joined by eye. The value is opaque, not
        # a secret shared with anyone but the operator's own backend.
        response = await self._client.post(
            path,
            json=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": challenge_id,
            },
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
    return scrub_text(text)[:200]

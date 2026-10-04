"""Backend write execution infrastructure (handoff §6.3, §8.3).

Tool-to-endpoint mapping and the HTTP client that executes approved
challenges against backend write endpoints.

THE MAPPING IS NO LONGER A LITERAL. `TOOL_REGISTRY` used to be a hand-edited
dict of six entries, which made "add a write operation" mean "fork this
repository". It is built now, by `build_write_operations`, from the three built-in
operations below plus every `postern_core.modules.write.WriteModule` an installed
distribution declares. The three card operations moved to the
`postern_cards_write` distribution; the merged registry still has the same six
keys and byte-identical tuples, which `tests/test_execute.py` pins.

THIS MODULE IS THE IMPORT `services.api` MUST NEVER MAKE, transitively included:
it imports `postern_core.modules.write`, and `.importlinter`'s
``api-not-module-write-half`` contract forbids the read path from reaching either.
`tests/test_module_seam_write_half.py` measures the same refusal at runtime,
where an entry point resolves and a graph cannot see.

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
from postern_core.domain.verification import VerificationTier

# The same Protocol `BackendClient` uses for the same job, imported rather
# than redeclared so the read and write paths cannot drift into two
# incompatible hook shapes. `.importlinter` permits it: the forbidden edges
# are `postern_core.facade -> postern_core.store` and `services.api <->
# services.confirm`, and this is neither.
from postern_core.facade.client import BackendRequestHook
from postern_core.modules.write import WriteOperation, WriteSeamViolation, load_write_modules
from postern_core.payments import CREATE_PAYMENT_TOOL, PAYMENT_TIER

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

# WHAT CHANGED WHEN THE MODULE SEAM LANDED, and what deliberately did not.
#
# `TOOL_REGISTRY` was a literal dict of six entries edited by hand, which made
# "add a write operation" mean "edit this file", i.e. fork the repository. It is
# now BUILT, from two sources merged by `build_write_operations`: the built-in
# operations below, and every `postern_core.modules.write.WriteModule` an
# installed distribution declares through the ``postern.write_modules`` entry
# point. `postern_cards_write` is the first of those, and the three card
# operations that used to sit in this dict now live there.
#
# WHAT DID NOT CHANGE IS THE SHAPE. The merged registry is still
# ``dict[str, tuple[audience, path_template, method]]`` with the same six keys
# and byte-identical tuples, because `resolve_endpoint` below reads it and
# `tests/test_execute.py` pins every entry. That is what makes this a move
# rather than a rewrite: the six entries are proven unchanged by tests written
# against the literal.
#
# THE TIER IS DECLARED ON THE OPERATION AND NOTHING HERE READS IT. CLAUDE.md is
# explicit that the verification tier belongs on the tool definition and must
# never be derived from the HTTP verb, so a `WriteOperation` carries one; this
# module needs only the triple, and `WriteOperation.as_registry_entry` is what
# narrows it. The tier reaches ``tool-surface.json``, so raising or lowering one
# is a reviewable diff, and it is what a future `create_challenge` producer will
# read when it decides which tier a challenge row is created at. No code path
# consumes it today, because no production caller creates a challenge at all.

#: The write operations this repository ships without a distribution of its own.
#:
#: Three remain, and the reason is scope rather than principle: `cards` was the
#: family moved onto the seam, and moving payments, accounts and standing orders
#: as well would have cost three more distribution pairs to prove a mechanism
#: one pair already proves. Each is a candidate to move unchanged -- they are
#: already `WriteOperation`s, so the move is a packaging change.
#:
#: ``payments.create_payment`` is the one tier-2 operation. `postern_core.domain.verification`
#: is where that comes from: tier 2 covers payments, new payees, high value and
#: limit increases, and tier 1 is the default for everything else a write does.
BUILTIN_WRITE_OPERATIONS: tuple[WriteOperation, ...] = (
    WriteOperation(
        tool_name=CREATE_PAYMENT_TOOL,
        audience="payments.svc",
        path_template="/payments",
        method="POST",
        tier=PAYMENT_TIER,
    ),
    WriteOperation(
        tool_name="accounts.rename",
        audience="accounts.svc",
        path_template="/accounts/{account_id}/rename",
        method="PATCH",
        tier=VerificationTier.APP_APPROVAL,
    ),
    WriteOperation(
        tool_name="standing_orders.cancel",
        audience="payments.svc",
        path_template="/standing-orders/{order_id}/cancel",
        method="POST",
        tier=VerificationTier.APP_APPROVAL,
    ),
)


def build_write_operations() -> dict[str, WriteOperation]:
    """Every write operation this process routes, built-in and installed.

    Raises:
        WriteSeamViolation: if an installed module routes a tool name a
            built-in already routes. Last-wins would mean a module could
            silently redirect ``payments.create_payment`` at its own backend
            audience and path, which is the single worst thing this seam could
            be made to do. `postern_core.modules.write.load_write_modules`
            already refuses two modules colliding with each other; this is the
            collision it cannot see.
    """
    operations = {operation.tool_name: operation for operation in BUILTIN_WRITE_OPERATIONS}
    for module in load_write_modules():
        for operation in module.operations:
            if operation.tool_name in operations:
                raise WriteSeamViolation(
                    f"module {module.name!r} routes write operation "
                    f"{operation.tool_name!r}, which this repository already routes as "
                    "a built-in. A module cannot redirect a shipped write operation: "
                    "the audience, path and method decide which backend endpoint an "
                    "approved operation reaches."
                )
            operations[operation.tool_name] = operation
    return operations


#: Every write operation, keyed by tool name, tier included.
#:
#: Read by the ``tool-surface.json`` gate, which is what makes a module's write
#: routing diffable between deploys.
WRITE_OPERATIONS: dict[str, WriteOperation] = build_write_operations()


#: Maps tool_name → (audience, path_template, method).
#:
#: The path template is a format string that receives the payload fields. The
#: payload dict from the challenge is passed as kwargs to ``.format()``.
#:
#: NARROWED FROM `WRITE_OPERATIONS` rather than built by a second pass over the
#: entry points, so the two cannot disagree about what is installed: one scan,
#: one snapshot, at import. `resolve_endpoint` below has never needed the tier,
#: and `WriteOperation.as_registry_entry` is what drops it.
TOOL_REGISTRY: dict[str, tuple[str, str, str]] = {
    name: operation.as_registry_entry() for name, operation in WRITE_OPERATIONS.items()
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

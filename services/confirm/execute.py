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

import asyncio
import re
from typing import Any, Protocol

import httpx2
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


# NO BACKEND TEXT LEAVES THIS MODULE. This module used to scrub a backend
# error body (NUL, PAN and IBAN shapes, cut to 200 characters) and hand it on
# as `BackendWriteError.detail`, and from there into the 207 response. A
# scrubber that knows two shapes does not make a body safe: a DSN or a bearer
# token in it went through untouched. `BackendWriteError` now carries the
# numeric status and nothing else, and the body is never read.
#
# "NEVER READ" IS A PROPERTY OF HOW THE REQUEST IS SENT, not of what is done with
# the response afterwards. `AsyncClient.post()` buffers and decodes the whole body
# before it returns, for every status, so a corrupt gzip body behind an accepted
# 200 raised `DecodingError` out of an accepted write, a short `Content-Length`
# behind a 201 raised `RemoteProtocolError`, and a body of any size was held in
# memory (the 10 second timeout bounds each read, not the total). `execute` uses
# `stream()` and leaves the block as soon as the status line is in hand, which
# closes the connection with the body unread.
#
# THE SECOND LEAK WAS IN THE EXCEPTIONS. `h11` and `httpcore2` quote the bytes
# they refuse (`illegal status line: bytearray(b'...')`, and a line of the BODY in
# `illegal chunk header`), and the chain `h11 -> httpcore2 -> httpx2` carried them
# to whatever logs an unhandled exception. `BackendTransportError` replaces that
# chain with fixed text and the original exception's type name.


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
# THE TIER IS DECLARED ON THE OPERATION; `resolve_endpoint` NEVER READS IT, THE
# APPROVAL CALLBACK DOES. CLAUDE.md is explicit that the verification tier
# belongs on the tool definition and must never be derived from the HTTP verb,
# so a `WriteOperation` carries one; this
# module needs only the triple, and `WriteOperation.as_registry_entry` is what
# narrows it. The tier reaches ``tool-surface.json``, so raising or lowering one
# is a reviewable diff. `payments.create_payment` stores `PAYMENT_TIER` on each
# row it creates, when `POSTERN_PAYMENTS_ENABLED` is on. The approval callback
# reads the declared tier from `WRITE_OPERATIONS` below: a row stored under
# it is refused (`tier_mismatch`), and a tier-2 row needs the proof decision
# record 0023 describes (`services/confirm/tier_proof.py`).

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


#: The whole header phase of one write call, in seconds: connect, send and wait
#: for a complete status line and header block. The client's own `timeout=10.0`
#: applies to each read separately and so bounds nothing in total. 30 is ECS's
#: default `stopTimeout`: an approval in flight when a task is stopped is given
#: the same 30 seconds to finish as the container is, so no call outlives the
#: SIGKILL that follows. The outcome on expiry is ambiguous, as for every
#: transport failure (the backend may have received and committed the write): the
#: row stays `approved`, the audit detail is `TotalTimeout`, and the operator
#: reconciles by `Idempotency-Key`.
WRITE_TOTAL_TIMEOUT_SECONDS = 30.0


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
        # resolution, minting and status handling with no store behind
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
            # `HTTP_PROXY` and friends would send this request, with the write
            # JWT, the Idempotency-Key and the payment payload, to whatever host
            # the variable names, and `SSL_CERT_FILE` / `SSL_CERT_DIR` would
            # swap the CA bundle. Proxy environment variables are ignored: route
            # egress with the network (PrivateLink, security groups).
            trust_env=False,
        )

    async def execute(
        self,
        *,
        customer_ref: str,
        audience: str,
        path: str,
        body: dict[str, Any],
        challenge_id: str,
    ) -> int:
        """Execute a backend write endpoint.

        Args:
            customer_ref: The customer who initiated the operation (from challenge).
            audience: Backend service audience (e.g., "payments.svc").
            path: The backend endpoint path.
            body: The operation payload (stored server-side at challenge creation).
            challenge_id: The challenge ID — sent as the JWT ``challenge_id``
                claim and as the ``Idempotency-Key`` header.

        Returns:
            The accepted status code (200, 201 or 202) and nothing else: the
            response is not handed back, because reading any part of it is how
            backend text got into the logs.

        Raises:
            BackendWriteError: the backend answered with any other status. It
                carries that status and nothing else.
            BackendTransportError: no status arrived, or the exchange failed
                before one could be taken (unreachable, timed out, or a reply
                the HTTP parser refused). It carries the original exception's
                TYPE NAME as ``kind`` and no text from it. ``kind`` is
                ``"TotalTimeout"`` when `WRITE_TOTAL_TIMEOUT_SECONDS` ran out
                before a status arrived. Any exception that is not an
                ``httpx2.HTTPError`` is a bug and propagates unwrapped.
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
        #
        # `stream()`, and ONLY `response.status_code` is taken inside the block.
        # Never `aread()`, `.text`, `.content`, `.json()`, `.headers`,
        # `.reason_phrase` or `.extensions`: each is backend-controlled text (a
        # DSN, a token, a stack trace), and scrubbing it for PAN and IBAN shapes
        # never made it safe to forward. Leaving the block closes the connection
        # without reading the body, so an accepted status with a garbled body is
        # an accepted write.
        status: int | None = None
        failure: str | None = None
        # THE TOTAL BOUND. `timeout=` on the client is per read, so a backend
        # dribbling one header byte every nine seconds never trips it and the
        # approval waits for days (measured: 1 byte per 2 s held an approval at
        # 40 s). This bounds the whole header phase. `asyncio.timeout` converts
        # only ITS OWN cancellation to `TimeoutError`: an outer `task.cancel()`
        # still arrives as `CancelledError`, which is why nothing below catches
        # `BaseException` or names `CancelledError`.
        total = asyncio.timeout(WRITE_TOTAL_TIMEOUT_SECONDS)
        try:
            async with total:
                async with self._client.stream(
                    "POST",
                    path,
                    json=body,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Idempotency-Key": challenge_id,
                    },
                ) as response:
                    status = response.status_code
        except TimeoutError:
            # Ours only: another `TimeoutError` is not this bound's and escapes
            # as what it is. If the status was already taken, a deadline that
            # lands while the unread body is being closed changes nothing.
            if not total.expired():
                raise
            if status is None:
                failure = "TotalTimeout"
        except httpx2.HTTPError as exc:
            # `HTTPError` only, so a cancellation (a `BaseException`) propagates.
            # If the status was already taken, a failure while closing the unread
            # body changes nothing: the status is the answer.
            if status is None:
                failure = type(exc).__name__

        if status is None:
            # RAISED OUTSIDE THE `except`, with `from None`: raising inside it
            # would set `__context__` to the original exception, whose message
            # is backend text.
            raise BackendTransportError(kind=failure or "UnknownError") from None

        if status not in (200, 201, 202):
            # The number only, raised outside the stream block.
            raise BackendWriteError(status=status)

        return status

    async def aclose(self) -> None:
        await self._client.aclose()


class BackendWriteError(RuntimeError):
    """A backend write endpoint answered outside 200, 201 and 202.

    Carries the numeric HTTP status and NOTHING from the response body, in
    ``str``, ``repr``, ``args`` or any attribute. There is deliberately no
    ``detail`` field: it held a scrubbed copy of the body, and every place it
    could travel (the 207 response, a log line, an exception traceback) was a
    place a backend's internal credential could travel too.
    """

    def __init__(self, *, status: int) -> None:
        super().__init__(f"backend write endpoint answered {status}")
        self.status = status


class BackendTransportError(RuntimeError):
    """The backend write endpoint could not be reached or answered improperly.

    No status arrived: the connection failed, timed out, or the reply was one
    the HTTP parser refused. ``str`` is FIXED TEXT. ``kind`` is the TYPE NAME of
    the exception that was caught (``ConnectError``, ``ReadTimeout``,
    ``RemoteProtocolError``) and never its message, because ``h11`` and
    ``httpcore2`` quote the bytes they refused. The original exception is not
    chained (``from None``, raised outside the ``except``), so no traceback
    printer, logger or ``__context__`` walker can reach it.

    Not a ``BackendWriteError``: that one means a status was received and the
    write was refused, which the approval answers with a 207. This one means the
    outcome is unknown, and the approval callback answers it with a 502
    `outcome_unknown` (`services/confirm/callback.py`).
    """

    def __init__(self, *, kind: str) -> None:
        super().__init__("the backend write endpoint could not be reached or answered improperly")
        self.kind = kind

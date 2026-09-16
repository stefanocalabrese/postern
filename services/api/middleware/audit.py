"""One audit row per tool call, success or failure.

Failures reach `on_call_tool` as RAISED EXCEPTIONS: the `isError: true`
envelope is built above the middleware chain, so a hook inspecting
`result.is_error` records zero failures. Measured, 2026-09-14.

`detail` records the exception TYPE and never its message: a
`pydantic.ValidationError` message embeds the raw offending value, which is
the leak path CLAUDE.md's hard rule describes, and an audit table is a
long-lived store.
"""

from datetime import datetime
from typing import Any

from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams
from postern_core.domain.masking import FreeText, redaction_budget
from postern_core.identity import CustomerRef
from postern_core.store import audit
from postern_core.store.engine import Database
from pydantic import TypeAdapter, ValidationError

_FREE_TEXT: TypeAdapter[str] = TypeAdapter(FreeText)

# `tool_name` is `String(64)` (models.py); `context.message.name` is
# arbitrary agent-controlled text with no length limit of its own. A name
# over 64 characters reaches `on_call_tool` fine but blows up the INSERT
# with `asyncpg.exceptions.StringDataRightTruncationError`, turning "audit a
# failed call" into "the audit write itself raises", which replaces the
# tool's own error with a database error and leaves zero rows. Clamp before
# writing, not before calling the tool.
#
# Accepted trade, not a full fix: two distinct oversized names that share
# the same first 64 characters collapse to the same recorded value, so an
# abuse-detection reader cannot tell one probe repeated 500 times from 500
# distinct probes, and nothing marks a row as truncated, so a genuine
# 64-character name is indistinguishable from a clipped 200-character one.
# Losing the row entirely, the alternative, is worse.
_MAX_TOOL_NAME = 64


def _scrub(value: Any) -> Any:
    """Redact PAN- and IBAN-shaped substrings anywhere in the argument tree,
    including dict keys, and strip NUL bytes.

    Keys matter as much as values here: arguments are captured before
    `call_next` validates them, so a key is just as agent-controlled as a
    value (e.g. `{"4111111111114417": "x"}`), and an unmasked key would
    persist a full PAN into a long-lived table exactly like an unmasked
    value would. Two distinct keys can collide onto the same masked string
    (`"41111111111111"` and `"241111111111111"` both end in `1111`); that
    silently drops one during the dict comprehension. That is the right
    trade for an audit log -- it must never hold the raw value either key
    started as -- but a reader needs to know it was a deliberate choice, not
    an oversight.

    NUL bytes are stripped BEFORE redaction, not after, and the order is
    load-bearing: `_PAN_IN_TEXT_RE` (`\\d{12,}`) matches a CONTIGUOUS run of
    12 or more digits, with the 19-digit PAN length cap applied separately
    when deciding what to emit, so a NUL planted inside a PAN splits it into
    two shorter runs that individually fail to match, and validation finds
    nothing to redact. Stripping the NUL afterwards then reassembles the
    full, unmasked PAN in the value that gets written -- one byte of
    attacker input surviving as a raw PAN in a long-lived store, and it
    reaches a dict KEY the same way, bypassing the key-masking above too.
    Stripping first removes the split before `FreeText` ever sees the
    string, so the contiguous run is there to match. Measured directly
    against every split position; do not swap this back to
    validate-then-strip, even though that reads more natural (validate the
    input, then clean it) -- it is the specific ordering this function must
    not have. `FreeText` not handling other separators (spaces, hyphens) is
    a separate, documented limitation (masking.py) with its own rationale;
    NUL is different only because this line is what reassembles it.
    """
    if isinstance(value, str):
        return _FREE_TEXT.validate_python(value.replace("\x00", ""))
    if isinstance(value, dict):
        return {_scrub(k): _scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _customer_ref(subject: object) -> str | None:
    """The token's `sub` claim, only when it conforms to `CustomerRef`.

    Mirrors `services.api.server.token_customer_resolver` rather than
    inventing a second validation path: identity.py's own warning is that a
    compromised issuer could mint a PAN-, IBAN- or DNI-shaped `sub`, and the
    tool path already refuses such a token with a `PermissionError` -- which
    arrives here as the very exception this middleware records, on the
    `except` branch. Persisting the raw, tool-path-rejected subject into
    `customer_ref` would be the one write that survives the refusal it
    documents. Storing `None` for a non-conforming subject, rather than
    raising, keeps this middleware's job (record the call) separate from the
    tool path's job (authorize the call).
    """
    if not isinstance(subject, str):
        return None
    try:
        return CustomerRef(value=subject).value
    except ValidationError:
        return None


class AuditMiddleware(Middleware):
    def __init__(self, db: Database) -> None:
        self.db = db

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        name = context.message.name[:_MAX_TOOL_NAME]
        # One allowance for the WHOLE tree, not one per string `_scrub`
        # happens to visit: without this, `FreeText` gives every string it
        # validates its own fresh checksum budget (masking.py's
        # `_IBAN_SCAN_BUDGET`), and an agent that spreads junk across many
        # short argument strings -- a list of them, say, rather than one
        # long one -- would buy a fresh allowance per element instead of
        # spending down one shared one. `redaction_budget` makes the
        # allowance ambient for this synchronous call only: see its
        # docstring for why a `ContextVar` rather than a module global, and
        # masking.py's `_redact_free_text` for the measured before/after.
        # Tool RESPONSES validated elsewhere (through pydantic models on
        # data returned from the bank's own backend) do NOT opt in and keep
        # a fresh per-string budget each -- a deliberate choice, not an
        # oversight: that data is not agent-controlled the way tool
        # arguments are, so splitting it into many strings is not an
        # attacker's lever the way it is here.
        with redaction_budget() as scope:
            arguments = _scrub(dict(context.message.arguments or {}))
        token = get_access_token()
        subject = token.claims.get("sub") if token is not None else None
        customer = _customer_ref(subject)
        at = context.timestamp

        try:
            result = await call_next(context)
        except Exception as exc:
            await self._write(
                at, customer, name, arguments, "raised", type(exc).__name__, scope.exhausted
            )
            raise
        await self._write(at, customer, name, arguments, "returned", None, scope.exhausted)
        return result

    async def _write(
        self,
        at: datetime,
        customer: str | None,
        name: str,
        arguments: dict[str, Any],
        outcome: str,
        detail: str | None,
        redaction_budget_exhausted: bool,
    ) -> None:
        async with self.db.sessionmaker() as session:
            await audit.append(
                session,
                at=at,
                customer_ref=customer,
                tool_name=name,
                arguments=arguments,
                outcome=outcome,
                detail=detail,
                redaction_budget_exhausted=redaction_budget_exhausted,
            )

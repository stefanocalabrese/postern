"""One audit row per tool call, success or failure.

Failures reach `on_call_tool` as RAISED EXCEPTIONS: the `isError: true`
envelope is built above the middleware chain, so a hook inspecting
`result.is_error` records zero failures. Measured, 2026-09-14.

`detail` records the exception TYPE and never its message: a
`pydantic.ValidationError` message embeds the raw offending value, which is
the leak path CLAUDE.md's hard rule describes, and an audit table is a
long-lived store.
"""

import logging
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

logger = logging.getLogger(__name__)

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
        #
        # The NAME is scrubbed here too now, through the same `_scrub` path
        # as `arguments`, in this SAME scope -- not a second
        # `redaction_budget()` block of its own. `context.message.name` is
        # exactly as agent-chosen as any argument value: `_MAX_TOOL_NAME`
        # (64) leaves room for a 16-digit PAN or a 31-character IBAN, and an
        # agent that wants one in the bank's audit table does not need an
        # argument at all, it names a tool after one. A separate scope for
        # the name alone would quietly reintroduce a per-string allowance
        # for exactly the value this fix exists to close, defeating the one
        # allowance-per-call invariant the shared scope holds.
        #
        # Scrubbed BEFORE the arguments, deliberately: the name is bounded
        # (clamped to `_MAX_TOOL_NAME` first, so the scan itself is bounded
        # too) while the arguments are not, and a bounded value can only
        # spend a small, fixed amount of the shared allowance -- measured
        # directly against this module's own worst-case shape (a
        # letter-letter-digit-digit opener repeated across the full 64
        # characters, the maximum density `_find_iban_in_token` allows,
        # confirmed by exhaustive derivation over every start position): 223
        # checksums against the 100,000-checksum default, 0.223% of one
        # call's allowance. That percentage is the durable number -- a
        # count of names needed to exhaust the budget outright would be a
        # ratio pinned to `_IBAN_SCAN_BUDGET`'s current value, which has
        # already moved once in this module's history and is fixed by no
        # test, so it is left out rather than stated as if it were stable.
        # An ordinary name (`ok_tool`, `transactions.list`, ...) costs zero
        # checksums -- it never reaches a letter-letter-digit-digit opener
        # at all. Scrubbing this first therefore cannot meaningfully starve
        # the arguments that follow.
        #
        # The converse does not hold for an IBAN-shaped name: scrubbing the
        # name LAST would let an agent that pads its own arguments to
        # exhaust the shared budget get its own IBAN-shaped tool name
        # bare-masked to `••••` as a side effect of that exhaustion
        # (`_redact_iban_match`'s `budget.exhausted` branch) -- verified
        # live, by swapping the order -- destroying the one field an
        # investigator uses to know WHAT was called. A PAN-shaped name is
        # immune to that specific failure: `_redact_pan_match` spends no
        # budget at all, so a PAN-shaped name resolves identically
        # regardless of exhaustion or ordering (also verified live, e.g.
        # `"tool_4111111111114417"` still comes back
        # `"tool_•••• 4417"` even against an already-exhausted budget). The
        # IBAN case alone is enough to require scrubbing the name first;
        # getting it right for both shapes, rather than relying on one
        # shape's accident, is the point. Losing argument detail degrades a
        # row; losing the name degrades the row's identity.
        with redaction_budget() as scope:
            name = _scrub(context.message.name[:_MAX_TOOL_NAME])
            # `_scrub`'s two substitutions never lengthen a match: the
            # shortest possible PAN run (12 digits) becomes `"•••• " +` its
            # last four (9 characters), and the shortest possible IBAN match
            # (14 characters) becomes a fixed 14-character mask; anything
            # longer than either minimum only shrinks further, or (an
            # over-length run, or an ambiguous IBAN token) collapses to the
            # 4-character bare marker. `_strip_invisible` only ever removes
            # characters. Confirmed by direct measurement (see
            # `tests/test_audit_middleware.py`), fuzzed across shapes up to
            # 64 characters plus every real PAN/IBAN in this module's own
            # fixtures at every padding offset: growth was never observed.
            #
            # That guarantee is in CHARACTERS, not bytes, and the distinction
            # is not academic: `_MASK` ("••••") is U+2022 BULLET, 3 bytes
            # each in UTF-8, so masking can grow a string's BYTE length even
            # while shrinking or holding its CHARACTER length -- verified
            # live, four 15-character IBANs joined by "." (63 characters)
            # scrub to 59 characters but 107 UTF-8 bytes. This is safe here
            # only because `audit_log.tool_name` is Postgres `VARCHAR(64)`
            # (models.py), and `VARCHAR`'s length argument is a character
            # count, not a byte count. A byte-counted column (e.g. a
            # `bytea`, or a `VARBINARY` on another database) would need a
            # bound on `len(name.encode())`, not on `len(name)`, and this
            # comment's "never lengthens" claim would not transfer to it
            # unchanged.
            #
            # `tool_name` is the same column the un-scrubbed clamp above
            # already exists to protect (see `_MAX_TOOL_NAME`'s own
            # docstring), so this second clamp is kept as a cheap fail-safe
            # against a future change to `_scrub`'s substitution lengths --
            # or to the column's own type -- not because today's masking
            # can trigger it.
            if len(name) > _MAX_TOOL_NAME:
                name = name[:_MAX_TOOL_NAME]
            arguments = _scrub(dict(context.message.arguments or {}))
        token = get_access_token()
        subject = token.claims.get("sub") if token is not None else None
        customer = _customer_ref(subject)
        at = context.timestamp

        try:
            result = await call_next(context)
        except Exception as exc:
            # Fail closed (docs/decisions/0006-audit-write-failure.md): an
            # audit-write failure here must never become the exception the
            # caller sees. Before this, an exception from `_write` replaced
            # `exc` by propagating unchanged, which put the DATABASE's
            # exception on the wire in place of the TOOL's -- through
            # implicit `__context__` chaining, since raising while already
            # handling `exc` sets that automatically. `raise exc from
            # audit_exc` re-raises the original exception OBJECT (same type,
            # same message, so `FastMCPError` handling above this middleware
            # still applies to it as before) and attaches the audit failure
            # as its explicit `__cause__` instead, so a traceback shows both
            # without either one hiding the other. The audit failure is
            # logged separately too: `__cause__` only helps someone already
            # looking at a traceback for this one call, and an outage needs
            # to be visible without one.
            try:
                await self._write(
                    at, customer, name, arguments, "raised", type(exc).__name__, scope.exhausted
                )
            except Exception as audit_exc:
                logger.error(
                    "audit write failed for tool %r after it raised %s: %s",
                    name,
                    type(exc).__name__,
                    audit_exc,
                    exc_info=audit_exc,
                )
                raise exc from audit_exc
            raise
        try:
            await self._write(at, customer, name, arguments, "returned", None, scope.exhausted)
        except Exception as audit_exc:
            # Fail closed here too, and deliberately rather than by
            # accident: the audit table is the artefact a regulator asks
            # for, and CLAUDE.md's operating assumption is that the caller
            # is under adversarial influence at all times -- a call that ran
            # but left no audit trail is worse than a call that failed
            # loudly. The cost is real and is not hidden: a database outage
            # now takes down every tool call, including ones that would
            # otherwise have succeeded. See
            # docs/decisions/0006-audit-write-failure.md for the rejected
            # alternative (write-through-and-log) and the reasoning.
            logger.error(
                "audit write failed for tool %r after it returned successfully; "
                "failing the call because the audit row could not be written",
                name,
                exc_info=audit_exc,
            )
            raise
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

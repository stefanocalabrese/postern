"""Consent as a per-tool authorization check.

FastMCP's `auth=` parameter takes an AuthCheck, which may be async
(`fastmcp/utilities/authorization.py`'s `AuthCheck` union, awaited by
`_evaluate_check` in that module). FastMCP applies it in
BOTH places: `list_tools` filters the catalogue with it, and `_get_tool`
returns None when it fails, so the call reports `Unknown tool`.

That pairing is the point. Filtering `tools/list` alone is NOT enforcement:
a hidden tool remains callable by name. Measured, 2026-09-14.

The check is cached per request because a `tools/call` carrying non-empty
arguments triggers a full internal `tools/list` dispatch to validate
Mcp-Param headers (`mcp/server/_streamable_http_modern.py`'s
`_mcp_param_rejection`, which reaches that dispatch through
`_tool_input_schema`), gated on the real `MCP-Protocol-Version` HTTP header
naming a non-handshake version (`mcp/server/streamable_http_manager.py`'s
`_handle_request`) -- absent that header (every helper in this task's own
tests omits it) the internal dispatch never runs at all. Measured with it
present, against `accounts.get_balance`: that one internal `tools/list` pass
alone evaluates every consent-gated tool's check once each (`accounts.list`,
`accounts.get_balance`, `transactions.list`,
`cards.list` -- 4 calls, since `accounts.list` and `accounts.get_balance`
share one `consent_for("accounts", db)` closure but are still two separate
`Tool` objects), plus one more from the real dispatch's own `_get_tool`
check: 5 evaluations of `check()` for a single real call, not 2. Without
this cache every one of those 5 hits the database; with it, only the first
does, because all 5 share one `customer.value` cache key on
`request.state` regardless of which domain's closure runs first.

A denial also FILES ITSELF, for the audit row. `auth=` answers a bare bool
and the wire answer is `Unknown tool: '<name>'` either way, so before this
the audit table recorded a consent refusal and a mistyped tool name as the
same `outcome='raised'`, `detail='NotFoundError'` pair. Only this check
knows which of the two happened, and only it knows which of its own two
refusals it made, so it records that here rather than leaving the
middleware to infer a reason from an exception type or a message string --
an inference that breaks the first time a third refusal reason exists.
`refusal_for` is what `services/api/middleware/audit.py` reads back, after
`call_next` raises: FastMCP evaluates `auth=` inside `_get_tool`
(`fastmcp/server/server.py::_get_tool`), which the middleware's own `call_next`
reaches, so the decision is always filed before the middleware looks.

Filed PER TOOL NAME, and that is not a detail. One `tools/call` evaluates
several tools' checks, and most of them are for tools nobody called:
measured on 2026-09-17, `accounts.get_balance` with arguments and a real
`MCP-Protocol-Version` header, for a customer consented to `accounts` only,
ran accounts.list=True, accounts.get_balance=True, transactions.list=False,
cards.list=False, accounts.get_balance=True -- two denials recorded during
one call that succeeded. A single "last denial" slot could not touch that
successful row: `audit.py`'s `OUTCOME_RETURNED` path writes `refusal_reason`
as a literal `None` and never reads the cache. The row it would corrupt
is the `raised` path's, which DOES read the cache
(`consent.refusal_for(context.message.name)`, in `audit.py`'s
`on_call_tool`) -- a call consent ALLOWED but whose tool body then raised,
stamped there with a stale `domain_not_consented` left by some other tool's
check earlier in the same request. That is still a false statement on a
regulator-facing table.
Keying by `AuthContext.component.name` -- the registered name, which is the
name the client asked for -- keeps each decision attached to the tool it
was made about.
"""

from collections.abc import Awaitable, Callable

from fastmcp.server.auth import AuthContext
from fastmcp.server.dependencies import get_http_request
from postern_core.identity import CustomerRef
from postern_core.store import consents
from postern_core.store.engine import Database
from postern_core.store.models import (
    REFUSAL_DOMAIN_NOT_CONSENTED,
    REFUSAL_NO_CUSTOMER_REF,
)
from pydantic import ValidationError

_CACHE_ATTR = "postern_consent_domains"
_Cache = dict[str, set[str]]

_REFUSALS_ATTR = "postern_consent_refusals"
_Refusals = dict[str, str]


def _customer(ctx: AuthContext) -> CustomerRef | None:
    token = ctx.token
    subject = token.claims.get("sub") if token is not None else None
    if not isinstance(subject, str):
        return None
    try:
        return CustomerRef(value=subject)
    except ValidationError:
        return None


async def _domains(db: Database, customer: CustomerRef) -> set[str]:
    request = None
    try:
        request = get_http_request()
    except Exception:
        request = None

    if request is not None:
        cached: _Cache | None = getattr(request.state, _CACHE_ATTR, None)
        if isinstance(cached, dict) and customer.value in cached:
            return cached[customer.value]

    async with db.sessionmaker() as session:
        granted: set[str] = await consents.granted_domains(session, customer)

    if request is not None:
        cache: _Cache | None = getattr(request.state, _CACHE_ATTR, None)
        if not isinstance(cache, dict):
            cache = {}
            setattr(request.state, _CACHE_ATTR, cache)
        cache[customer.value] = granted
    return granted


def _refuse(ctx: AuthContext, reason: str) -> None:
    """File this denial against the tool it was made about, for the audit row.

    `request.state` carries it, the same place and lifetime as the domain
    cache above: the audit middleware and this check run inside one HTTP
    request, and `request.state` is scoped to exactly that request, so a
    decision cannot outlive the call it describes or reach a concurrent one.
    A `ContextVar` would be the other candidate and is rejected here -- this
    check runs deeper in the call stack than the middleware that reads it,
    and a value set in a child task's context does not propagate back to the
    parent, which would make the route depend on whether FastMCP or the MCP
    SDK spawns a task between the two. Neither is this module's to pin.

    No HTTP request means no route and no record: `get_http_request` raises
    when a call arrives through the in-process `Client` transport, which
    carries no access token at all (`Client(transport=server)` accepts no
    auth argument), so there is no consent decision to file in the first
    place. The middleware records NULL for that call, which is what a call
    nobody refused should read as.

    Never raises. A refusal whose bookkeeping failed must still BE a
    refusal: this returns and the caller answers False regardless, so the
    worst outcome is an audit row that under-reports a denial as NULL, never
    a tool call that goes through because recording the denial went wrong.
    """
    try:
        request = get_http_request()
    except Exception:
        return
    refusals: _Refusals | None = getattr(request.state, _REFUSALS_ATTR, None)
    if not isinstance(refusals, dict):
        refusals = {}
        setattr(request.state, _REFUSALS_ATTR, refusals)
    refusals[ctx.component.name] = reason


def refusal_for(tool_name: str) -> str | None:
    """Why this request's consent check refused `tool_name`, or None.

    None covers three states that share one answer: no consent check ran for
    this name (an unknown tool never reaches one -- FastMCP raises
    `NotFoundError` before evaluating `auth=`), the check ran and allowed the
    call, or there is no HTTP request to have filed anything on. All three
    mean "this call was not refused by consent", which is exactly what NULL
    says on `audit_log.refusal_reason`.

    The lookup is by the name the client asked for, which is the name the
    tool is registered under and therefore the name `_refuse` filed the
    decision under. A transform that ever makes those two differ turns a
    denial into a miss, and a miss reads as None: this under-reports a
    refusal rather than inventing one, which is the direction this column
    must fail in.
    """
    try:
        request = get_http_request()
    except Exception:
        return None
    refusals: _Refusals | None = getattr(request.state, _REFUSALS_ATTR, None)
    if not isinstance(refusals, dict):
        return None
    reason = refusals.get(tool_name)
    return reason if isinstance(reason, str) else None


def consent_for(domain: str, db: Database) -> Callable[[AuthContext], Awaitable[bool]]:
    """An AuthCheck granting access to `domain` only if the customer consented."""

    async def check(ctx: AuthContext) -> bool:
        customer = _customer(ctx)
        if customer is None:
            # Distinct from the domain refusal below, and the distinction is
            # the whole reason this column exists: nothing identified a
            # customer here, so no consent was ever looked up. Every way
            # `_customer` returns None collapses into this one value -- no
            # token, a `sub` that is not a string, a `sub` that does not
            # parse as a `CustomerRef` -- because separating them is a
            # statement about the TOKEN, and `audit_log.customer_ref_absence_reason`
            # is where that question belongs.
            _refuse(ctx, REFUSAL_NO_CUSTOMER_REF)
            return False
        if domain in await _domains(db, customer):
            return True
        _refuse(ctx, REFUSAL_DOMAIN_NOT_CONSENTED)
        return False

    return check

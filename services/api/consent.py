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
knows which of the two happened, and only it knows which of its own three
refusals it made, so it records that here rather than leaving the
middleware to infer a reason from an exception type or a message string --
an inference that breaks the first time a third refusal reason exists.

THAT THIRD REASON ARRIVED ON 26 SEPTEMBER 2026 and is not a fact about the
caller at all. `consent_store_unavailable` is filed when the database read
below raises, which until then left `check` through FastMCP's
`_evaluate_check`, was masked there into the same bare False, and produced
the row a mistyped tool name produces. A saturated connection pool and a
customer who never granted access were one row. The denial did not change
and must not: a check that established nothing has to refuse. What changed
is that an operator reading `audit_log` during an incident can now tell
which one they are looking at, and the value says infrastructure rather
than intent so an alerting rule built on it cannot attribute an outage to
customer behaviour.

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

import logging
from collections.abc import Awaitable, Callable

from fastmcp.exceptions import AuthorizationError
from fastmcp.server.auth import AuthContext
from fastmcp.server.dependencies import get_http_request
from postern_core.identity import CustomerRef
from postern_core.store import consents
from postern_core.store.engine import Database
from postern_core.store.models import (
    REFUSAL_CONSENT_STORE_UNAVAILABLE,
    REFUSAL_DOMAIN_NOT_CONSENTED,
    REFUSAL_NO_CUSTOMER_REF,
)
from pydantic import ValidationError

logger = logging.getLogger(__name__)

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


def _clear_refusal(ctx: AuthContext) -> None:
    """Withdraw an earlier refusal for this tool, because the check now allows.

    A refusal is filed per tool name and read back once, after the tool
    ran, so it has to describe the evaluation the dispatch actually used --
    which is the LAST one, not the first. One `tools/call` evaluates a
    tool's check more than once (the module docstring above measures five
    evaluations for one call), and a consent store that is saturated rather
    than down answers some of them and raises on others. Without this, an
    evaluation that raised early would leave `consent_store_unavailable`
    behind for a call that a later evaluation allowed, and the raised path
    in `services/api/middleware/audit.py` -- the one path that reads the
    cache -- would stamp it onto the row of a tool whose BODY failed. That
    is a false statement on an append-only, regulator-facing table, and it
    is the same class of error `_refuse`'s per-tool keying exists to
    prevent, except that here the stale entry and the live call share a
    name, so the keying cannot catch it.

    Nothing was withdrawable before 26 September 2026 and this function
    would have been dead code: the two refusals `check` could file were both
    decided from a domain set that the request cache pins for the rest of
    the request, so a tool refused once in a request was refused by every
    later evaluation in it. The unreachable-store refusal is the first one
    that a later evaluation can contradict, because the failure it records
    is not cached.

    Never raises, for `_refuse`'s reason applied in the other direction: a
    withdrawal whose bookkeeping failed must still leave the call ALLOWED.
    The caller returns True regardless, so the worst outcome is an audit row
    over-reporting a refusal, which is why this is the one place in this
    module where the safe direction is not NULL.
    """
    try:
        request = get_http_request()
    except Exception:
        return
    refusals: _Refusals | None = getattr(request.state, _REFUSALS_ATTR, None)
    if isinstance(refusals, dict):
        refusals.pop(ctx.component.name, None)


def refusal_for(tool_name: str) -> str | None:
    """Why this request's consent check refused `tool_name`, or None.

    None covers three states that share one answer: no consent check ran for
    this name (an unknown tool never reaches one -- FastMCP raises
    `NotFoundError` before evaluating `auth=`), the check ran and allowed the
    call, or there is no HTTP request to have filed anything on. All three
    mean "this call was not refused by consent", which is exactly what NULL
    says on `audit_log.refusal_reason`.

    A fourth state left that list on 26 September 2026: a check that could
    not reach the consents table used to read as None here too, and now
    answers `consent_store_unavailable`. It was the worst of the four to
    have in this bucket, because it is the only one that is not a statement
    about the caller.

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
        try:
            granted = await _domains(db, customer)
        except AuthorizationError:
            # FastMCP's own denial, which `_evaluate_check` propagates
            # rather than masking. Nothing under `_domains` raises it today
            # -- it opens a session and runs one SELECT -- and this branch
            # is here so that if anything ever does, a deliberate denial is
            # not refiled as an outage. Recording infrastructure where the
            # cause was authorization is the same error as the reverse, in
            # the direction that hides a real refusal.
            raise
        except Exception as exc:
            # DENIES, exactly as before. What changes is that the row now
            # says which of the three things happened. Until 26 September
            # 2026 this exception left `check` entirely and
            # `fastmcp/utilities/authorization.py`'s `_evaluate_check`
            # caught it, logged a warning and returned False, so the
            # `domain_not_consented` refusal below this line was unreachable
            # on an outage and the audit row read `outcome='raised'`,
            # `detail='NotFoundError'`, reason NULL -- a row a mistyped tool
            # name produces byte for byte. Catching it here is what puts a
            # class on it; the verdict is the same denial FastMCP was
            # already making.
            #
            # `Exception` and not `BaseException`, which is load-bearing
            # rather than habitual: `asyncio.CancelledError` derives from
            # `BaseException`, so a request the edge cancelled passes
            # through untouched instead of being filed as a store outage.
            # A cancelled call is not a call this check refused.
            #
            # LOGGED HERE BECAUSE FASTMCP NO LONGER SEES IT. `_evaluate_check`
            # logged this at WARNING with a full traceback and was the only
            # place an operator could learn the type of the failure, so
            # catching it without logging would trade one blind spot for
            # another. ERROR rather than WARNING: a consent store this
            # process cannot reach is denying real customers, and the audit
            # row now carries a matching literal an operator can join
            # against. The volume is unchanged -- one line per evaluation,
            # as before. Measured against a refused connection: one line for
            # a `tools/call` carrying no arguments, and one per evaluation on
            # the five-evaluation path the module docstring above measures.
            #
            # The traceback can carry the SQL and its bound parameters, so
            # this line can put a `cust_`-prefixed customer reference in the
            # log. That value is already written to `audit_log.customer_ref`
            # in the clear on every call this customer makes, and `_customer`
            # admits nothing that `CustomerRef` rejects, so the PAN-, IBAN-
            # and DNI-shaped subjects `postern_core.identity`'s `_OPAQUE`
            # warns about never reach this line.
            logger.error(
                "consent store unreachable, denying %s: %s",
                ctx.component.name,
                type(exc).__name__,
                exc_info=exc,
            )
            _refuse(ctx, REFUSAL_CONSENT_STORE_UNAVAILABLE)
            return False
        if domain in granted:
            # This evaluation allowed, so any refusal an earlier one in this
            # same request filed for this same tool is now wrong. Only the
            # unreachable-store refusal can be standing here; see
            # `_clear_refusal`.
            _clear_refusal(ctx)
            return True
        _refuse(ctx, REFUSAL_DOMAIN_NOT_CONSENTED)
        return False

    return check

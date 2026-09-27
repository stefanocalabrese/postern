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

A FAILURE IS REMEMBERED THE SAME WAY, since 27 September 2026, and until
then it was not: the cache above was written on the success path only, so an
unreachable store was re-probed by every one of those 5 evaluations and each
waited the full `pool_timeout`. Measured against a blackholed listener with
the connect timeout at 1.0s, one `tools/call` took 5.11 seconds to be
denied; it now takes 1.03. That is load the outage was adding to the pool
whose exhaustion caused it, from evaluations that were all going to deny.

The second thing that buys is COHERENCE, and on `tools/list` it matters
more than the latency. That method evaluates one check per gated tool, so a
single contended moment used to produce a catalogue reflecting no
authorization state at all: measured with consent granted to all four
domains and exactly one attempt failing, the catalogue listed three of the
four and split the two `accounts` tools, hiding `accounts.list` while
listing `accounts.get_balance`. `tools/list` writes no audit row in any
state, so that was invisible to the operator and visible only to the agent.
One probe per request means the whole gated surface is present or absent
together.

The cost is a salvage given up. A store that raised on an early evaluation
and answered a later one used to let the call through; now the first probe
decides the request. Nobody chose five attempts -- five is what the SDK's
internal `tools/list` pass happens to cost -- and a client re-issues a
dropped call anyway, so the retry still exists one layer out, where it holds
no connection for five seconds.

WHY NOTHING NEEDS WITHDRAWING, which is the second thing remembering a
failure bought and the reason a function was deleted rather than added. A
`_clear_refusal` stood on `check`'s allow path from 26 to 27 September 2026,
erasing a `consent_store_unavailable` that an earlier evaluation of the same
tool had filed before the store recovered mid-request: the filing is read
back once, after the tool ran, so it has to describe the evaluation the
dispatch used, and per-tool keying cannot separate a stale filing from a
live one when both carry the same name.

Remembering the failure removed the state it cleaned up. Within one request
the verdict for a (customer, tool) pair cannot change, because each of the
three ways `check` refuses is pinned by something that does not vary across
evaluations: `no_customer_ref` by `ctx.token`, which is the request's own
validated token; `domain_not_consented` by the domain set the success cache
holds; and `consent_store_unavailable` by the failure memory. No evaluation
can contradict an earlier one, so no filing can go stale, so there is
nothing to withdraw. Restoring a per-evaluation probe without restoring a
withdrawal reopens it, and this is the test that fails when someone does:
`tests/test_consent_check_failure_mode.py::test_a_recovery_mid_request_no_longer_recovers_the_call`

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

# The second request-scoped cache, and the only one that remembers a
# FAILURE. It holds the customer references whose consent lookup already
# raised in this request, so the rest of the request's evaluations deny
# without opening another session. One `tools/call` carrying arguments is
# five evaluations, and before 27 September 2026 an unreachable store cost
# five connection attempts and five `pool_timeout` waits, serially, during
# the event that exhausted the pool: measured at 5.11 seconds against a
# blackholed listener with the connect timeout at 1.0s, where one attempt
# costs 1.03. It is a set of customer references and not of exceptions, so
# nothing here keeps a traceback (and the frames and connections a traceback
# holds) alive for the rest of the request.
_FAILED_ATTR = "postern_consent_lookup_failed"
_Failed = set[str]

_REFUSALS_ATTR = "postern_consent_refusals"
_Refusals = dict[str, str]


class _ConsentStoreUnavailable(Exception):
    """Raised INSTEAD of probing, once this request has already failed once.

    It exists to carry one bit that the original exception cannot: whether
    `check` is seeing the failure for the first time. The first failure
    propagates as whatever the driver raised, gets logged with its traceback
    and is remembered; every later evaluation gets this instead, files the
    same refusal reason and logs nothing, because nothing new happened. A
    reader comparing the two branches in `check` is looking at "measure and
    report" against "already measured".

    Private, and never reaches a caller: `check` catches it, and FastMCP's
    `_evaluate_check` would mask it as a denial anyway. It is not part of
    `_domains`' contract with anything outside this module.
    """


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
        # A failure this request already paid for. Checked AFTER the success
        # cache and not before it, which costs nothing today and keeps the
        # order honest: a customer cannot be in both, because the two writes
        # are on mutually exclusive paths, and if that ever stopped being
        # true the answer this returns should be the one that was
        # established, not the one that was not.
        failed: _Failed | None = getattr(request.state, _FAILED_ATTR, None)
        if isinstance(failed, set) and customer.value in failed:
            raise _ConsentStoreUnavailable(customer.value)

    try:
        async with db.sessionmaker() as session:
            granted: set[str] = await consents.granted_domains(session, customer)
    except Exception:
        # REMEMBER, then re-raise unchanged. `check` still sees the driver's
        # own exception for this first failure, so the log line it writes
        # still names the real type and carries the real traceback.
        #
        # `Exception`, so `asyncio.CancelledError` (a `BaseException`) is
        # neither remembered nor re-raised through here: a request the edge
        # cancelled must not leave a verdict behind for evaluations that will
        # never run, and it is not a statement about the store.
        #
        # No HTTP request means no memory and no coherence to protect -- the
        # in-process `Client` transport has no `request.state` for any of
        # this module's three stores, so it re-probes per evaluation exactly
        # as before. Those calls carry no access token either, so their
        # checks refuse on `no_customer_ref` long before reaching this line.
        if request is not None:
            remembered: _Failed | None = getattr(request.state, _FAILED_ATTR, None)
            if not isinstance(remembered, set):
                remembered = set()
                setattr(request.state, _FAILED_ATTR, remembered)
            remembered.add(customer.value)
        raise

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
        except _ConsentStoreUnavailable:
            # An evaluation earlier in THIS request already established that
            # the store cannot be reached, logged it with its traceback and
            # remembered it. This one files the same reason against its own
            # tool name -- which is what `audit_log.refusal_reason` needs,
            # since the called tool's evaluation is usually not the one that
            # paid for the probe -- and neither probes nor logs again.
            #
            # The row count is unaffected: `AuditMiddleware` writes per call,
            # never per evaluation, so an outage produced one completion row
            # per `tools/call` before this and produces one after it. What
            # dropped is connection attempts and ERROR lines, from one per
            # evaluation to one per request.
            _refuse(ctx, REFUSAL_CONSENT_STORE_UNAVAILABLE)
            return False
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
            # against. ONE LINE PER REQUEST, not one per evaluation: this
            # branch is only reached by the evaluation that actually probed,
            # and `_FAILED_ATTR` sends every later one to the branch above.
            # It was one per evaluation until 27 September 2026, which on the
            # five-evaluation path meant five tracebacks for one measurement.
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
            # NOTHING TO WITHDRAW HERE, and that is a property of the two
            # request-scoped caches rather than an omission. A
            # `_clear_refusal` stood on this line until 27 September 2026;
            # the module docstring's "WHY NOTHING NEEDS WITHDRAWING" carries
            # what it did, why remembering a failure retired it, and the test
            # that fails if the state it cleaned up ever comes back.
            return True
        _refuse(ctx, REFUSAL_DOMAIN_NOT_CONSENTED)
        return False

    return check

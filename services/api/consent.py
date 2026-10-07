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

A FAILURE IS REMEMBERED THE SAME WAY, with its classified cause, since 27
September 2026, and until then it was not: the cache above was written on the
success path only, so an unreachable store was re-probed by every one of
those 5 evaluations and each waited the full `pool_timeout`. Measured against
a blackholed listener with the connect timeout at 1.0s, one `tools/call` took
5.11 seconds to be
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

AND THE MEMORY STOPS AT THE REQUEST BOUNDARY. THERE IS NO CIRCUIT BREAKER,
and there is not going to be one. Decided 27 September 2026, after the
question was asked properly for the second time, because one probe per
request still scales with request rate and a sustained outage under load
still loads the pool at one attempt per call.

WHAT A BREAKER WOULD ACTUALLY SAVE, per outage shape, since the answer is
not the same in all three and only one of them is interesting.

  * REFUSED CONNECTION (Postgres down, nothing listening). A probe costs a
    `ConnectionRefusedError` in about 0.0s and holds a pool slot for that
    long. There is nothing to cut.
  * SATURATION (the pool at its ceiling, the store answering normally). A
    probe costs one refused checkout at `pool_timeout`. A breaker here is
    not a saving but a defect: saturation is per-instant and clears as
    requests finish, so a breaker opened by one refused checkout denies calls
    the store was about to serve, and it denies them for its whole cooldown.
  * SILENT IN BOTH DIRECTIONS (a blackholing firewall rule, a security group
    closed under an incident, a failed-over primary whose old address still
    accepts). A probe holds a pool slot for the full
    `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS`, so at 2.0s and a ceiling of
    15 the pool is saturated by connect attempts alone from about 7.5
    requests per second up -- arithmetic from those two numbers, not a load
    measurement, and nothing here has one. This is the one shape where a
    breaker would cut real load.

ONE SHAPE IS NOT ENOUGH, FOR THREE REASONS, and the third is the one that
settles it.

  * It would MAKE THE SECOND SHAPE WORSE while helping the third, and the
    second is the one every deployment meets first. The two arrive wearing one
    exception, so nothing here can tune for the case it helps:
    `docs/verification/2026-09-17-query-stall-deadline.md` measured a request
    against a silent store holding its pooled connection past a 60-second cap,
    and a pool whose connections are all held that way refuses a checkout with
    the same `sqlalchemy.exc.TimeoutError` a merely busy one does. Whichever
    way that exception is read, it is read wrong half the time.
  * The third shape already has a bound that is not this one.
    `services/api/asgi/request_deadline.py`'s `RequestDeadline` caps the
    whole HTTP request, and the operator's lever on the per-probe cost is
    `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` itself -- lowering it cuts
    exactly the pool-slot holding time a breaker would cut, and it does so
    by attempting rather than by remembering.
  * IT WOULD WRITE A FALSE ROW, PERMANENTLY. `refusal_reason` is a claim
    about the operator's infrastructure on a regulator-facing table, and
    `REFUSAL_CONSENT_STORE_UNAVAILABLE` says the store could not be reached.
    A breaker files that from a cached observation instead of from an
    attempt, so every call denied in the window between the store recovering
    and the cooldown expiring carries a statement that was true a minute ago
    and is false on the row. This module's per-request memory is defended,
    two paragraphs down, on the ground that within one request the verdict
    for a (customer, tool) pair CANNOT change; across requests it plainly
    can, which is the same stale-filing problem `_clear_refusal` was deleted
    to remove -- except that nothing can withdraw it, because migration
    `f1860c110112` makes `audit_log` refuse `UPDATE` and `DELETE` inside the
    database. A per-request memory can be wrong about nothing; a
    process-wide one is wrong about every request that never probed.

WHAT IT WOULD HAVE COST TO BUILD, priced rather than waved at, because "not
worth it" is only an answer if the alternative was costed. A half-open policy
needs a cooldown duration nobody has evidence for; an admission rule saying
WHICH request pays the probe, which under MCP `2026-07-28` cannot be a
background task on one instance because protocol-level sessions are gone and
any request can land on any replica; a close threshold (one success, or n);
and a decision about shared state -- per replica means R replicas hold R
different opinions about one database, and shared means Redis, which makes a
Redis outage into a consent outage. What the customer sees in the window the
whole design turns on: every consent-gated tool absent from `tools/list` and
`Unknown tool` on call, against a store that is answering, for up to the
cooldown, with a permanent audit row blaming infrastructure that was fine.

The denial is unchanged either way. This is a decision about how the denial
is REACHED: by asking the store, every request, or by remembering that it
once said no.

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
four ways `check` refuses is pinned by something that does not vary across
evaluations: `no_customer_ref` by `ctx.token`, which is the request's own
validated token; `domain_not_consented` by the domain set the success cache
holds; and both `consent_store_unavailable` and `consent_check_faulted` by
the failure memory, which holds the classified reason and not merely the
fact. No evaluation can contradict an earlier one, so no filing can go
stale, so there is nothing to withdraw. Restoring a per-evaluation probe
without restoring a withdrawal reopens it, and this is the test that fails
when someone does:
`tests/test_consent_check_failure_mode.py::test_a_recovery_mid_request_no_longer_recovers_the_call`

TWO CAUSES, NOT ONE, and the second was being filed as the first until 27
September 2026. `except Exception` wrote `consent_store_unavailable` for
whatever had been raised, so a migration nobody applied and a connection pool
at its ceiling produced the same row, and an operator alerting on the
operator's-infrastructure value was being woken for this repository's SQL.
Remembering the cause made that worse before it was fixed: one misclassified
exception labelled every refusal in the request rather than one.
`_classify` below is the split, its two class tuples are read off the
installed SQLAlchemy and asyncpg rather than recalled, and the denial is
identical either way -- a defect in the consent lookup must never become a
reason to allow a call.

A `tools/list` WRITES NO AUDIT ROW, in any state, and that is a ruling rather
than an oversight. `services/confirm/audit.py`'s `PairingAudit` states when a
row is owed -- the server resolved an identity AND reached a conclusion about
that identity's authority -- and an authenticated catalogue fetch during an
outage satisfies both halves, so a row is owed by that rule. `audit_log` is
not where it goes: `tool_name` is a per-tool column and a catalogue is not
one tool, `outcome` is a closed vocabulary of `reaching`, `returned` and
`raised` and none of them describes a tool filtered out of a list nobody
called, and the volume is measured rather than feared. `on_list_tools` fires
for the SDK's internal dispatch as well as for a real fetch, so a row per
withheld tool would turn one `tools/call` carrying arguments into five audit
INSERTs during an outage instead of one, each of them fail-closed under
decision 0006, against the pool whose exhaustion caused the outage. The
record therefore lives in the ERROR line `check` writes, which is why that
line has to describe the whole request.

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

import sqlalchemy.exc as sa_exc
from fastmcp.exceptions import AuthorizationError
from fastmcp.server.auth import AuthContext
from fastmcp.server.dependencies import get_http_request
from postern_core.identity import CustomerRef
from postern_core.log_safety import describe_exception, exc_info_for_log
from postern_core.store import consents
from postern_core.store.engine import Database
from postern_core.store.models import (
    REFUSAL_CONSENT_CHECK_FAULTED,
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
# Maps a customer reference to the refusal reason its lookup established, so
# the four evaluations that never probe file what the one that did found.
# `dict` and not `set` since 27 September 2026: the memory has to carry WHICH
# kind of failure it was, because a misremembered kind is now wrong on every
# refusal in the request rather than on one.
_FAILED_ATTR = "postern_consent_lookup_failed"
_Failed = dict[str, str]

_REFUSALS_ATTR = "postern_consent_refusals"
_Refusals = dict[str, str]

# COULD NOT REACH OR COMPLETE AGAINST THE STORE. Read off the installed
# SQLAlchemy 2.0.52 and asyncpg 0.31.0 rather than recalled, and two findings
# from that reading shape the list.
#
# `sqlalchemy.exc.TimeoutError` is the connection pool at its ceiling, raised
# in `sqlalchemy/pool/impl.py`, and it descends straight from
# `SQLAlchemyError` -- NOT from `DBAPIError`. Any list built out of the DBAPI
# tree alone misses the exact condition this whole line of work started from.
#
# `DBAPIError` itself is here, the generic parent and not only its
# operational children, because the asyncpg dialect's error map is coarse.
# `_asyncpg_error_translate` in `sqlalchemy/dialects/postgresql/asyncpg.py`
# keys on seven asyncpg classes and sends everything else under
# `PostgresError` to the bare DBAPI `Error`, so `TooManyConnectionsError`,
# `CannotConnectNowError`, `AdminShutdownError` and
# `ConnectionDoesNotExistError` all arrive as a generic `DBAPIError` rather
# than as `OperationalError`. Naming only `OperationalError` and
# `InterfaceError` would file a database that is refusing connections because
# it is shutting down as a defect in this software.
#
# `OSError` covers both raw shapes measured on this path, because the failure
# can happen during connect, before SQLAlchemy has a DBAPI error to wrap:
# `ConnectionRefusedError` from nothing listening, and the builtin
# `TimeoutError` from a socket that accepts and never speaks, which is an
# `OSError` subclass since it merged with `asyncio.TimeoutError`.
_UNAVAILABLE: tuple[type[BaseException], ...] = (
    sa_exc.TimeoutError,
    sa_exc.DisconnectionError,
    sa_exc.DBAPIError,
    OSError,
)

# THIS SOFTWARE IS WRONG. Every member is a `DBAPIError` subclass, which is
# the only reason the tuple needs to exist at all: anything that is not a
# database or socket error already falls to the default below, so this list
# is exactly the specific DBAPI children that the generic entry above would
# otherwise swallow.
#
# `ProgrammingError` is where the asyncpg dialect sends `SyntaxOrAccessError`,
# and therefore `UndefinedTableError` and `UndefinedColumnError` -- a
# migration nobody applied, or a model that has drifted from the schema, which
# is the case that prompted the split. `DataError` and `IntegrityError` cannot
# happen on this read except through a defect: the lookup is one `SELECT` with
# three bound predicates and writes nothing.
#
# `InternalError` is deliberately NOT here, though it is tempting. The
# dialect maps both asyncpg `InternalServerError` and `InternalClientError` to
# it, meaning PostgreSQL or the driver malfunctioned. Neither is this
# repository's code being wrong, so both stay on the operator's side of the
# line.
_FAULT: tuple[type[BaseException], ...] = (
    sa_exc.ProgrammingError,
    sa_exc.DataError,
    sa_exc.IntegrityError,
    sa_exc.NotSupportedError,
)


def _classify(exc: BaseException) -> str:
    """Which refusal reason this exception earns.

    ORDER IS THE DECISION, not the lists. `_FAULT` is consulted first
    because every one of its members is a `DBAPIError` subclass and
    `_UNAVAILABLE` carries `DBAPIError` itself, so reversing these two lines
    files a schema error as an outage and this function silently becomes the
    thing it was written to stop.

    THE DEFAULT IS THE FAULT REASON, which is the other half of the design
    and the half a reader is most likely to get backwards. `granted_domains`
    is one `SELECT` with three bound predicates; an exception out of it that
    is neither a database error nor a socket error is this repository's, and
    the most obvious example is the most common bug there is -- an
    `AttributeError`. A design that enumerated reachability and defaulted the
    rest to unavailability would file that as infrastructure, which is the
    complaint the split exists to answer.

    THE RESIDUE IS STATED RATHER THAN HIDDEN, and it runs the other way: a
    few genuine data defects reach the store as `PostgresError` subclasses
    outside `SyntaxOrAccessError` -- `InvalidTextRepresentationError`, say --
    and the coarse dialect map lands them in the generic `DBAPIError` bucket,
    so they are called an outage. Both reasons log at ERROR with distinct
    literals, so either mislabel costs an operator a wrong first hypothesis
    and never silence.
    """
    if isinstance(exc, _FAULT):
        return REFUSAL_CONSENT_CHECK_FAULTED
    if isinstance(exc, _UNAVAILABLE):
        return REFUSAL_CONSENT_STORE_UNAVAILABLE
    return REFUSAL_CONSENT_CHECK_FAULTED


class _LookupFailed(Exception):
    """The consent lookup did not answer, with the reason already classified.

    `_domains` raises this for EVERY failure, first or repeat, so `check` has
    one branch instead of two and cannot classify the same exception twice
    and differently. Two attributes carry what that branch needs.

    `reason` is the `audit_log.refusal_reason` value `_classify` chose. It is
    decided once, where the exception was caught, and then remembered for the
    request, so every evaluation files the same value.

    `probed` says whether THIS evaluation is the one that reached the
    database. Only that one logs: it holds the original exception as
    `__cause__` and writes a line with its traceback, while the rest of the
    request's evaluations file the reason and say nothing, because nothing
    new happened. That is what took an outage from five ERROR lines per call
    to one.

    Private, and never reaches a caller: `check` is `_domains`' only caller
    and catches it, and FastMCP's `_evaluate_check` would mask it as a denial
    anyway.
    """

    def __init__(self, reason: str, *, probed: bool) -> None:
        super().__init__(reason)
        self.reason = reason
        self.probed = probed


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
        if isinstance(failed, dict) and customer.value in failed:
            raise _LookupFailed(failed[customer.value], probed=False)

    try:
        async with db.sessionmaker() as session:
            granted: set[str] = await consents.granted_domains(session, customer)
    except AuthorizationError:
        # FastMCP's own denial, which `_evaluate_check` propagates rather
        # than masking. Nothing under here raises it today, and this branch
        # is what stops the wrap below turning one into a refusal this module
        # invented a reason for. `check` has the matching branch, and the two
        # are not redundant: this one must not WRAP it, that one must not
        # FILE it.
        raise
    except Exception as exc:
        # CLASSIFY ONCE, HERE, and remember the answer rather than the
        # exception. Doing it at the point of failure is what keeps every
        # evaluation in the request agreeing: `check` cannot look at the same
        # exception twice and reach two verdicts, because it never sees it
        # again -- only `_LookupFailed`, carrying the reason this line chose.
        # The original is attached as `__cause__` so the one evaluation that
        # logs still has the real type and the real traceback.
        #
        # `Exception`, so `asyncio.CancelledError` (a `BaseException`) is
        # neither classified nor remembered: a request the edge cancelled must
        # not leave a verdict behind for evaluations that will never run, and
        # it is not a statement about the store or about this code.
        #
        # No HTTP request means no memory and no coherence to protect -- the
        # in-process `Client` transport has no `request.state` for any of
        # this module's three stores, so it re-probes per evaluation exactly
        # as before. Those calls carry no access token either, so their
        # checks refuse on `no_customer_ref` long before reaching this line.
        reason = _classify(exc)
        if request is not None:
            remembered: _Failed | None = getattr(request.state, _FAILED_ATTR, None)
            if not isinstance(remembered, dict):
                remembered = {}
                setattr(request.state, _FAILED_ATTR, remembered)
            remembered[customer.value] = reason
        raise _LookupFailed(reason, probed=True) from exc

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
        except _LookupFailed as failure:
            # DENIES, exactly as before, and that is the half that has never
            # moved through three changes to this branch. Until 26 September
            # 2026 the exception left `check` entirely and
            # `fastmcp/utilities/authorization.py`'s `_evaluate_check` caught
            # it, logged a warning and returned False, so the audit row read
            # `outcome='raised'`, `detail='NotFoundError'`, reason NULL -- the
            # row a mistyped tool name produces byte for byte. The verdict is
            # still the denial FastMCP was already making; what this branch
            # adds is a row that says which of four things happened.
            #
            # THE REASON IS NOT DECIDED HERE. `_domains` classified it where
            # the exception was caught and remembered it for the request, so
            # every evaluation files the same value: an outage and a defect in
            # this software cannot swap places between the internal
            # `tools/list` pass and the real dispatch. This branch files it
            # against its OWN tool name, which is what
            # `audit_log.refusal_reason` needs, since the called tool's
            # evaluation is usually not the one that paid for the probe.
            #
            # ONE LINE PER REQUEST, from the one evaluation that probed.
            # `_evaluate_check` logged at WARNING with a traceback and was the
            # only place an operator could learn the type, so catching without
            # logging would trade one blind spot for another. ERROR on both
            # paths, and distinct literals: a mislabel then costs a wrong
            # first hypothesis, never silence, which is what makes the
            # classifier's residue survivable.
            #
            # THE MESSAGE NAMES THE REQUEST, NOT A TOOL, and it used to name
            # `ctx.component.name`. That was measured under-reporting: a
            # `tools/list` against a refused connection logged
            # `denying accounts.list` while all four gated tools were denied,
            # because the other three were answered from the memory and never
            # reached this line. Remembering the failure is what makes the
            # request-wide claim true, so the line now makes it.
            #
            # THE LINE CARRIES NO STATEMENT, NO BOUND PARAMETER AND NO DRIVER
            # MESSAGE. It logs `describe_exception(cause)` (the exception's
            # type and, for a driver error, its SQLSTATE or `client-side`), and
            # passes `exc_info` only when the cause is NOT a driver error
            # (`exc_info_for_log`), so a customer reference bound in the lookup
            # never reaches the log through this line. Before 2026-10-07 the
            # traceback was attached and could carry the SQL and its
            # parameters.
            if failure.probed:
                cause = failure.__cause__
                if failure.reason == REFUSAL_CONSENT_STORE_UNAVAILABLE:
                    logger.error(
                        "consent store unreachable, denying every consent-gated tool "
                        "for this request: %s",
                        describe_exception(cause),
                        exc_info=exc_info_for_log(cause),
                    )
                else:
                    logger.error(
                        "consent check FAULTED, denying every consent-gated tool for "
                        "this request: %s. The store answered; this software is wrong",
                        describe_exception(cause),
                        exc_info=exc_info_for_log(cause),
                    )
            _refuse(ctx, failure.reason)
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

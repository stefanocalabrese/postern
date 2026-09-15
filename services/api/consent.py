"""Consent as a per-tool authorization check.

FastMCP's `auth=` parameter takes an AuthCheck, which may be async
(fastmcp/utilities/authorization.py:47 and :230-250). FastMCP applies it in
BOTH places: `list_tools` filters the catalogue with it, and `_get_tool`
returns None when it fails, so the call reports `Unknown tool`.

That pairing is the point. Filtering `tools/list` alone is NOT enforcement:
a hidden tool remains callable by name. Measured, 2026-09-14.

The check is cached per request because a `tools/call` carrying non-empty
arguments triggers a full internal `tools/list` dispatch to validate
Mcp-Param headers (mcp/server/_streamable_http_modern.py:285-359), gated on
the real `MCP-Protocol-Version` HTTP header naming a non-handshake version
(mcp/server/streamable_http_manager.py:191-196) -- absent that header (every
helper in this task's own tests omits it) the internal dispatch never runs
at all. Measured with it present, against `accounts.get_balance`: that one
internal `tools/list` pass alone evaluates every consent-gated tool's check
once each (`accounts.list`, `accounts.get_balance`, `transactions.list`,
`cards.list` -- 4 calls, since `accounts.list` and `accounts.get_balance`
share one `consent_for("accounts", db)` closure but are still two separate
`Tool` objects), plus one more from the real dispatch's own `_get_tool`
check: 5 evaluations of `check()` for a single real call, not 2. Without
this cache every one of those 5 hits the database; with it, only the first
does, because all 5 share one `customer.value` cache key on
`request.state` regardless of which domain's closure runs first.
"""

from collections.abc import Awaitable, Callable

from fastmcp.server.auth import AuthContext
from fastmcp.server.dependencies import get_http_request
from postern_core.identity import CustomerRef
from postern_core.store import consents
from postern_core.store.engine import Database
from pydantic import ValidationError

_CACHE_ATTR = "postern_consent_domains"
_Cache = dict[str, set[str]]


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


def consent_for(domain: str, db: Database) -> Callable[[AuthContext], Awaitable[bool]]:
    """An AuthCheck granting access to `domain` only if the customer consented."""

    async def check(ctx: AuthContext) -> bool:
        customer = _customer(ctx)
        if customer is None:
            return False
        return domain in await _domains(db, customer)

    return check

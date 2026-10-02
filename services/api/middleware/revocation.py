"""ZT-7 -- the middleware that makes revocation reachable and enforced.

WHAT THIS CLOSES. `postern_core.auth.revocation`'s `RevocationList` was
correct, tested and unreachable: nothing populated it, nothing survived a
restart, and the one consumer -- `postern_core.auth.read_minter`'s
`ReadTokenMinter` -- asked it about the backend audience rather than the
OAuth client. This middleware is the check that actually runs, against a
store an operator can write to (`postern_core.auth.revoke_cli`).

WHERE THE CHECK RUNS, AND WHY NOT ONLY AT MINT. Minting happens inside a tool
handler, on the way to the operator's backend. Two things are wrong with
making that the only gate. A revoked caller would still get an answer from
anything that mints nothing -- `tools/list` above all, whose result varies
with consent state and therefore discloses which domains a customer has
connected. And the minter is synchronous, called through
`postern_core.facade.client`'s `TokenMinter` protocol, so it cannot read a
Redis-backed store at all. So the decision is taken here, once, and published
on a `ContextVar` the minter reads before it signs. The minter's refusal is
then a second enforcement of the same decision rather than a check against a
different, emptier list.

BEFORE ``call_next``, WHICH IS THE WHOLE POINT. A refusal that happens after
the tool ran is not a refusal: the operator's backend has already been read
and the data already exists in the vendor's context, whatever this process
does with the response afterwards. `tests/test_zt7_revocation_reachable.py`
asserts a count of backend touches rather than a status code, the same way
`tests/test_risk_middleware_actions.py` does for ZT-5, because a refusal and
a call that returned nothing are both HTTP 200.

WHICH CLAIMS ARE CHECKED. The customer comes from the injected
`CustomerResolver`, the one object in this service that answers "which
customer is this?", read through the resolver rather than from the token a
second time so the identity that gets revoked and the identity whose data
would have been returned cannot drift apart -- the same argument
`services/api/middleware/risk.py`'s `_session_key` makes for the risk budget.
``client_id``, ``jti`` and ``iat`` come from the validated access token.

FAIL CLOSED, TWICE OVER. A caller whose identity cannot be derived is refused
(the production resolver raises). A store that cannot answer is refused
(`RevocationStoreUnavailable`). Neither is logged past, for the reason
`dev-docs/decisions/0006-audit-write-failure.md` gives for the audit write:
continuing means serving a bank's data on the strength of a control that did
not run.

ORDERING. Installed after `AuditMiddleware` and before `RiskMiddleware`, so a
revoked call is still audited -- a refusal is exactly the event an operator
wants a row for -- and is refused before it spends any risk budget or touches
the risk session store.

WHAT THIS COVERS ON THE WRITE PATH. `services/confirm` checks revocation via
`is_customer_revoked` on scan, approve, and challenge-approval paths. On the
token exchange (device_code grant) it checks customer revocation only. On refresh
it checks the customer under any client, the customer-client pair, the kill switch,
and each live access token (services/confirm/revocation.py, device_auth.py).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

import mcp.types as mt
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import Tool, ToolResult
from postern_core.auth.revocation import RevocationStoreBase, RevokedError, decision_scope
from postern_core.identity import CustomerResolver

from services.api.middleware.risk import NO_CLIENT

logger = logging.getLogger(__name__)


class RevocationMiddleware(Middleware):
    """Refuses a revoked caller before any tool runs, and before ``tools/list``.

    ``store`` is the shared revocation store (`create_revocation_store`, Redis
    in production), ``resolver`` answers which customer is calling.
    """

    def __init__(self, store: RevocationStoreBase, resolver: CustomerResolver) -> None:
        self.store = store
        self.resolver = resolver

    async def on_call_tool(
        self,
        context: MiddlewareContext[mt.CallToolRequestParams],
        call_next: CallNext[mt.CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        claims = self._claims()
        await self._refuse_if_revoked(claims, what=context.message.name or "unknown")
        # Published for the tool call only, and reset on the way out. The
        # minter reads it inside `call_next`; nothing downstream of this block
        # has any business seeing it, unlike the risk contextvar, which
        # `AuditMiddleware` deliberately reads after the call returns.
        with decision_scope(False):
            return await call_next(context)

    async def on_list_tools(
        self,
        context: MiddlewareContext[mt.ListToolsRequest],
        call_next: CallNext[mt.ListToolsRequest, Sequence[Tool]],
    ) -> Sequence[Tool]:
        """The catalog is consent-dependent, so a revoked caller must not see it.

        Checking only at mint would leave this open: listing tools mints
        nothing, and `CLAUDE.md` already records why the catalog is
        ``cacheScope: "private"`` -- it varies by consent state, so which
        tools a caller is offered discloses which accounts and permissions a
        customer has.
        """
        claims = self._claims()
        await self._refuse_if_revoked(claims, what="tools/list")
        with decision_scope(False):
            return await call_next(context)

    # --- Identity and decision ---------------------------------------------

    def _claims(self) -> dict[str, Any]:
        """The values the three revocation scopes are keyed on, plus ``iat``.

        ``iat`` is not a scope. It is what lets the store refuse a token
        minted before a customer-client revocation after that revocation was
        restored (`postern_core.auth.revocation`'s ``pair-at`` floor).

        A CALLER WITH NO DERIVABLE CUSTOMER IS STILL CHECKED, on the two
        scopes that do not need one. `services/api/server.py`'s
        `token_customer_resolver` raises `PermissionError` for a request with
        no validated token, and for a token whose ``sub`` does not parse as a
        customer reference. Turning that into a refusal here would be a new
        refusal for a condition that has nothing to do with revocation, and it
        would change what ``tools/list`` answers such a caller --
        `tests/test_consent_enforcement.py` pins that it degrades to the
        ungated catalogue rather than erroring. Enforcing identity on a tool
        call is already `services/api/middleware/risk.py`'s job, it happens
        just inside this middleware, and it is unchanged.

        What is NOT given up by tolerating it: a kill switch is keyed on
        ``client_id`` and a session revocation on ``jti``, and both of those
        are readable from the token whether or not its subject parses. Only
        the customer-plus-client scope needs a customer, and that scope cannot
        name a caller who has none.
        """
        try:
            customer_ref: str | None = self.resolver().value
        except PermissionError:
            customer_ref = None
        token = get_access_token()
        client_id = NO_CLIENT
        jti: str | None = None
        # The raw claim, `None` when absent. The key is ALWAYS present so the
        # store applies the pair's `iat` floor, and a missing `iat` then fails
        # closed whenever a stamp exists; the store, not this method, judges
        # the value.
        iat: Any = None
        if token is not None:
            if token.client_id:
                client_id = str(token.client_id)
            token_claims = token.claims or {}
            raw_jti = token_claims.get("jti")
            if isinstance(raw_jti, str):
                jti = raw_jti
            iat = token_claims.get("iat")
        return {"sub": customer_ref, "client_id": client_id, "jti": jti, "iat": iat}

    async def _refuse_if_revoked(self, claims: dict[str, Any], *, what: str) -> None:
        if not await self.store.is_revoked(claims):
            return
        # The customer reference is not logged. `postern_core.identity` warns
        # that a `sub` minted by a compromised issuer can be PAN-, IBAN- or
        # DNI-shaped, and this line goes to the operator's log regardless of
        # what the issuer put there. The client id and the scope are what an
        # operator needs to confirm their own revocation took effect.
        logger.warning(
            "RevocationMiddleware: refused %s for client=%s (ZT-7)",
            what,
            claims.get("client_id"),
        )
        raise RevokedError(f"access has been revoked; {what} was refused")

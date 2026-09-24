"""Risk session middleware — the thing that makes ZT-5 execute.

For every tool call it derives the caller's identity, loads (or creates) that
identity's `RiskContext`, records the client IP, and evaluates the risk engine
and the IP anomaly detector twice: once BEFORE the tool runs, as an admission
check, and once after, to account for what the handlers recorded.

Action model (per ZT-5 design):

* ``LOW`` signals → logged, the tool continues normally.
* ``MEDIUM`` signals → the verification tier is escalated (tier 0 → 1, or
  1 → 2) so that subsequent calls require stronger verification.
* ``HIGH`` signals → the call is refused with a ``RiskActionError``.

WHY TWICE. Evaluating only after ``call_next`` -- what this module did until
2026-09-22 -- means the FIRST call that exhausts a budget has already reached
the operator's backend, and so has every call after it, because a refusal
that happens after the request is not a refusal of the request. The
pre-call pass is what makes "the record budget is exhausted" cost the backend
nothing: `tests/test_risk_middleware_actions.py` counts backend touches
rather than status codes, and asserts zero. The post-call pass still runs
because only the handlers know how many records they returned.

WHAT A FAILURE DOES. Every exit below is closed. A caller whose identity
cannot be derived is refused; a store that cannot answer refuses the call
(`session.py`'s `SessionStoreUnavailable`); and the evaluation itself is no
longer wrapped in a blanket ``except Exception``. The version that was
wrapped caught the ``RiskActionError`` it had raised two lines earlier and
logged it as "risk evaluation failed; continuing" -- the HIGH branch
existed, had tests, and blocked nothing, which is why the tests in this
module's test file now drive a real server instead of raising the exception
they assert on.

Wiring: ``server.add_middleware(RiskMiddleware(store, resolver, ...))`` in
`main.py`'s `create_app`, after `AuditMiddleware`.
"""

from __future__ import annotations

import logging

from fastmcp.server.dependencies import get_access_token, get_http_request
from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams
from postern_core.identity import CustomerResolver
from postern_core.net import client_ip
from postern_core.risk.context import RiskContext
from postern_core.risk.engine import RiskConfig, RiskEngine
from postern_core.risk.ip_anomaly import IpAnomalyConfig, IpAnomalyDetector
from postern_core.risk.session import SessionKey, SessionStoreBase, set_current_session
from postern_core.risk.types import RiskActionError, RiskSignal, Severity

logger = logging.getLogger(__name__)

#: `SessionKey.client_id` for a call that carried no access token. A literal
#: no OAuth client id can collide with, because `_client_id` below only ever
#: stores a value fastmcp read off a validated token.
NO_CLIENT = "-"


class RiskMiddleware(Middleware):
    """Loads the caller's `RiskContext`, evaluates it, and refuses HIGH risk.

    ``store`` holds the contexts, ``resolver`` answers which customer is
    calling, and the two configs carry the thresholds (injectable so a test
    can drive a small budget rather than 500 records).

    ``trusted_proxy_hops`` is how many proxies in front of this process
    append to ``X-Forwarded-For``; see `_client_ip` for what the number
    selects and why the default trusts the header for nothing.
    """

    def __init__(
        self,
        store: SessionStoreBase,
        resolver: CustomerResolver,
        *,
        config: RiskConfig | None = None,
        ip_config: IpAnomalyConfig | None = None,
        trusted_proxy_hops: int = 0,
    ) -> None:
        if trusted_proxy_hops < 0:
            raise ValueError(
                f"trusted_proxy_hops must be zero or positive, got {trusted_proxy_hops}"
            )
        self.store = store
        self.resolver = resolver
        self.engine = RiskEngine(config or RiskConfig())
        self.ip_detector = IpAnomalyDetector(ip_config or IpAnomalyConfig())
        self.trusted_proxy_hops = trusted_proxy_hops

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool_name = context.message.name or "unknown"

        # FIRST, before anything can fail: clear the contextvar. It is left
        # SET on the way out (see the bottom of this method), so a call
        # refused before it has a context of its own must not be able to read
        # the previous call's.
        set_current_session(None)

        key = self._session_key()
        ctx = await self.store.context_for(key)

        ip = self._client_ip()
        if ip is not None:
            ctx.ip_tracker.record_ip(ip)

        set_current_session(ctx)

        # --- Admission: what this identity has already spent ---
        admission = self._evaluate(ctx, key, tool_name)
        blocking = [s for s in admission if s.severity is Severity.HIGH]
        if blocking:
            # Persisted before the raise: the IP just recorded, and the
            # signals the audit row is about to read, are part of the record
            # of the refusal.
            await self.store.save(key, ctx)
            self._log_block(key, tool_name, blocking, when="before")
            raise RiskActionError(blocking)

        try:
            result = await call_next(context)
        except Exception:
            # A failed call still touched whatever it touched before failing,
            # so it is accounted for like any other.
            self._settle(ctx, key, tool_name)
            await self.store.save(key, ctx)
            raise

        # --- Accounting: what this call itself spent ---
        blocking = self._settle(ctx, key, tool_name)
        await self.store.save(key, ctx)
        if blocking:
            # The backend was already reached, so this does not un-read the
            # data -- it withholds it from the model and guarantees the next
            # call is refused at admission, above, before any request.
            self._log_block(key, tool_name, blocking, when="after")
            raise RiskActionError(blocking)

        # The contextvar is deliberately NOT reset here. `AuditMiddleware` is
        # installed outside this one and reads `get_current_session()` after
        # this method returns, to copy the signals onto the completion row;
        # resetting would make `audit_log.risk_signals` NULL for every call.
        # The `set_current_session(None)` at the top of this method is what
        # keeps a stale context from outliving its call.
        return result

    # --- Identity -----------------------------------------------------------

    def _session_key(self) -> SessionKey:
        """Which identity this call is budgeted against.

        The customer comes from the injected `CustomerResolver`, which is the
        one place in this service that answers "which customer is this?"
        (`server.py`'s `token_customer_resolver` reads the validated token's
        ``sub`` and refuses anything that is not a customer reference). Read
        through the resolver rather than from the token a second time on
        purpose: the tools resolve the customer the same way, so the context a
        budget is charged to and the customer whose data was returned cannot
        drift apart. In the documented no-auth path a test or the compose
        stack injects a fixed customer, and in production a call with no token
        raises ``PermissionError`` here and is refused.
        """
        customer = self.resolver()
        return SessionKey(customer_ref=customer.value, client_id=self._client_id())

    def _client_id(self) -> str:
        """The OAuth client on the validated token, or `NO_CLIENT`.

        ``AccessToken.client_id`` is fastmcp's own
        ``client_id`` / ``azp`` / ``sub`` fallback chain, so this is the
        ``client_id``-or-``azp`` the design asks for without re-deriving it.
        ``get_access_token()`` returns ``None`` for a call arriving over the
        in-process ``Client(transport=server)`` transport, which carries no
        token at all.
        """
        token = get_access_token()
        if token is None or not token.client_id:
            return NO_CLIENT
        return str(token.client_id)

    # --- Client IP ----------------------------------------------------------

    def _client_ip(self) -> str | None:
        """The client address to record, or ``None`` to record nothing.

        TWO DEFECTS ARE FIXED HERE, and decision record 0010 is why they
        matter: with DPoP absent from the MCP spec, IP anomaly detection is
        the primary compensating control for a stolen token replayed from
        other infrastructure (A4).

        The first: this used to read ``context.fastmcp_context.request``,
        which fastmcp 4.0.3's ``Context`` does not have, so the address was
        unconditionally ``None`` and the detector always saw zero IPs.
        `get_http_request` is what `consent.py`'s `_domains` already uses.

        The second: it took the LEFTMOST ``X-Forwarded-For`` element, which
        is the one the client writes. An attacker could pin their apparent
        address to defeat the diversity and impossible-travel checks outright,
        or rotate it to spend the budget at will.

        THAT SECOND FIX NO LONGER LIVES HERE. `postern_core.net`'s
        `client_ip` holds it, and this method is the adapter that hands it
        what a fastmcp request carries: the header value and the socket peer.
        The move is not a tidy-up. `services/confirm/rate_limit.py` needs the
        same derivation on a public endpoint, `.importlinter` forbids it from
        importing this module, and the alternative was a second copy of a
        hop-counted address derivation -- which is the shape
        `services/api/middleware/audit.py` records going wrong once already,
        when three copies of ``_scrub`` existed and the weakest of them sat on
        the money path. The reasoning for every branch, including why the
        default of zero hops trusts the header for nothing and why
        ``POSTERN_TRUSTED_PROXY_HOPS`` must be set behind any proxy, moved
        with the code.

        What stays here is the one thing that is this service's and not the
        shared function's: a call arriving over the in-process client
        transport has no HTTP request at all.
        """
        try:
            request = get_http_request()
        except RuntimeError:
            # No HTTP request: the in-process client transport. Nothing to
            # record, and nothing about that is an error.
            return None

        peer = request.client
        return client_ip(
            forwarded=request.headers.get("x-forwarded-for"),
            peer_host=None if peer is None else peer.host,
            trusted_proxy_hops=self.trusted_proxy_hops,
        )

    # --- Evaluation ---------------------------------------------------------

    def _evaluate(self, ctx: RiskContext, key: SessionKey, tool_name: str) -> list[RiskSignal]:
        """Run both detectors, record the signals on the context, log them.

        NOT wrapped in ``try``. Everything here is arithmetic over state this
        process already holds, so an exception is a defect in the risk layer
        itself, and a risk layer that cannot evaluate must not be the reason a
        call to a bank's data succeeds. The blanket handler this replaces is
        what swallowed the block.
        """
        signals = [*self.engine.evaluate(ctx), *self.ip_detector.evaluate(ctx.ip_tracker)]
        ctx.record_signals(signals)
        if signals:
            snap = ctx.snapshot()
            for signal in signals:
                logger.warning(
                    "RiskSignal[%s] session=%s tool=%s records=%s accounts=%s ips=%s "
                    "severity=%s: %s",
                    signal.code,
                    key.log_ref,
                    tool_name,
                    snap.get("records"),
                    snap.get("distinct_accounts"),
                    snap.get("distinct_ips"),
                    signal.severity.name,
                    signal.description,
                )
        return signals

    def _settle(self, ctx: RiskContext, key: SessionKey, tool_name: str) -> list[RiskSignal]:
        """Post-call evaluation: escalate on MEDIUM, report what blocks.

        Tier escalation happens here and not in the admission pass, so one
        call escalates at most one level however many times the same standing
        condition is re-detected.
        """
        signals = self._evaluate(ctx, key, tool_name)
        if any(s.severity is Severity.MEDIUM for s in signals):
            ctx.escalate_tier()
            logger.info(
                "RiskMiddleware: escalated session=%s to tier %s",
                key.log_ref,
                ctx.verification_tier,
            )
        return [s for s in signals if s.severity is Severity.HIGH]

    def _log_block(
        self, key: SessionKey, tool_name: str, signals: list[RiskSignal], *, when: str
    ) -> None:
        logger.warning(
            "RiskMiddleware: refused %s for session=%s %s the call, on: %s",
            tool_name,
            key.log_ref,
            when,
            ", ".join(s.code for s in signals),
        )

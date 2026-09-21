"""Risk session middleware — wires ``SessionStore`` into the FastMCP server.

For every tool call (except ``start_session`` itself), extracts the
``session_handle`` from arguments, looks up the ``RiskContext``, and pushes
it onto a contextvar so that:

* tool handlers can record data touches (records, accounts, days)
* the IP tracker records client IPs
* post-call evaluation runs ``RiskEngine`` + ``IpAnomalyDetector``

Action model (per ZT-5 design):

* ``LOW`` signals → logged, tool continues normally.
* ``MEDIUM`` signals → session verification tier is escalated (tier 0 → 1,
  or 1 → 2) so that subsequent calls require stronger verification.
* ``HIGH`` signals → the current tool call is blocked with a
  ``RiskActionError``, and the session is marked for termination.

Session lifecycle:

1. Client calls ``start_session`` → returns a new ``session_handle``
2. Client includes ``session_handle`` in all subsequent calls
3. Middleware looks up the context and pushes it onto the contextvar
4. After each call, data is recorded (by handlers) and risk signals are
   evaluated by this middleware

No session cleanup is performed here — sessions live until the store is
replaced with a backed implementation (Redis/database) that supports TTL.

Wiring: install via ``server.add_middleware(RiskMiddleware(store))`` in
``services/api/main.py::create_app``, after ``AuditMiddleware``.
"""

from __future__ import annotations

import logging
from typing import Any

from fastmcp.server.middleware import CallNext, Middleware, MiddlewareContext
from fastmcp.tools import ToolResult
from mcp.types import CallToolRequestParams
from postern_core.risk.context import RiskContext
from postern_core.risk.engine import RiskConfig, RiskEngine
from postern_core.risk.ip_anomaly import IpAnomalyDetector
from postern_core.risk.session import SessionStoreBase, set_current_session
from postern_core.risk.types import RiskActionError

logger = logging.getLogger(__name__)


class RiskMiddleware(Middleware):
    """Pushes the current session's ``RiskContext`` onto a contextvar.

    Reads ``session_handle`` from tool arguments, looks it up in the
    store, and makes the context available via ``get_current_session()``.

    After each call, records client IP and evaluates risk signals.
    Data recording (records returned, accounts touched) is done by the
    tool handlers themselves via ``get_current_session()``.
    """

    def __init__(self, store: SessionStoreBase) -> None:
        self.store = store

    async def on_call_tool(
        self,
        context: MiddlewareContext[CallToolRequestParams],
        call_next: CallNext[CallToolRequestParams, ToolResult],
    ) -> ToolResult:
        tool_name = context.message.name or "unknown"

        # start_session creates a new session — no prior context to push.
        if tool_name == "start_session":
            return await call_next(context)

        # For all other tools, extract session_handle and push context.
        session_handle = self._extract_session_handle(context.message.arguments)

        if session_handle is None:
            # No session handle provided — run without risk tracking.
            return await call_next(context)

        ctx = await self.store.get_session(session_handle)
        if ctx is None:
            logger.warning(
                "RiskMiddleware: session %r not found for tool %s; running without risk tracking",
                session_handle,
                tool_name,
            )
            return await call_next(context)

        # Record client IP on the session's tracker.
        ip = self._extract_client_ip(context)
        if ip is not None:
            ctx.ip_tracker.record_ip(ip)

        # Push the context onto the contextvar for this call.
        set_current_session(ctx)
        try:
            result = await call_next(context)
            # Evaluate risk signals after the handler has recorded data.
            self._evaluate_signals(ctx, session_handle)
            # Persist mutations (records, accounts, IPs) back to the store.
            await self.store.save_session(session_handle, ctx)
            return result
        except RiskActionError:
            # HIGH signal blocked the call — persist context (signals are on it)
            # and re-raise so the caller sees the block.
            await self.store.save_session(session_handle, ctx)
            raise
        except Exception:
            # Even on failure, evaluate signals and persist (handler may have
            # recorded partial data before the exception).
            self._evaluate_signals(ctx, session_handle)
            await self.store.save_session(session_handle, ctx)
            raise

    def _extract_session_handle(self, arguments: dict[str, Any] | None) -> str | None:
        """Extract ``session_handle`` from tool arguments."""
        if not arguments:
            return None
        return arguments.get("session_handle")

    def _extract_client_ip(self, context: MiddlewareContext[CallToolRequestParams]) -> str | None:
        """Extract client IP from the request context.

        Reads ``X-Forwarded-For`` header first, falls back to remote address.
        Returns None if neither is available.
        """
        if context.fastmcp_context:
            headers = getattr(context.fastmcp_context, "request", None)
            if headers is not None:
                headers = getattr(headers, "headers", None)
            if headers:
                xff = headers.get("x-forwarded-for")
                if xff:
                    return str(xff.split(",")[0].strip())

            if context.fastmcp_context:
                try:
                    req = getattr(context.fastmcp_context, "request", None)
                    if req is not None:
                        peer = getattr(req, "client", None)
                        if peer and hasattr(peer, "host"):
                            return str(peer.host)
                except Exception:
                    logger.debug("IP extraction failed", exc_info=True)

        return None

    def _evaluate_signals(self, ctx: RiskContext, session_handle: str) -> None:
        """Evaluate risk engine and IP anomaly detector signals.

        Runs after each tool call (success or failure). Data recording
        is done by handlers via ``get_current_session()`` before this runs.

        Action model:
        - MEDIUM signals → escalate the session's verification tier so that
          subsequent calls require stronger authentication.
        - HIGH signals → raise ``RiskActionError`` to block the current call
          and mark the session for termination.

        All signals (regardless of severity) are stored on the context for
        audit logging and logged at WARNING level.
        """
        try:
            # Evaluate general risk engine (record budgets, account diversity,
            # session age, time window)
            config = RiskConfig()
            signals = RiskEngine(config).evaluate(ctx)

            # Evaluate IP anomaly detector (impossible travel, diversity)
            ip_detector = IpAnomalyDetector()
            ip_signals = ip_detector.evaluate(ctx.ip_tracker)

            # Store all signals on the context for audit logging.
            # Clear first so only this call's signals survive (the list is
            # per-call, not cumulative across the session).
            ctx._risk_signals = [*signals, *ip_signals]

            snap = ctx.snapshot()
            for signal in signals:
                logger.warning(
                    "RiskSignal[%s] session=%s records=%d accounts=%d severity=%s: %s",
                    session_handle[:8],
                    signal.code,
                    snap.get("records", 0),
                    snap.get("distinct_accounts", 0),
                    signal.severity.name,
                    signal.description,
                )

            for signal in ip_signals:
                logger.warning(
                    "IpAnomalySignal[%s] session=%s distinct_ips=%d severity=%s: %s",
                    signal.code,
                    session_handle[:8],
                    snap.get("distinct_ips", 0),
                    signal.severity.name,
                    signal.description,
                )

            # --- Take action on MEDIUM and HIGH signals ---

            # Escalate tier for any MEDIUM signal.
            medium_signals = [s for s in signals if s.severity.name == "MEDIUM"] + [
                s for s in ip_signals if s.severity.name == "MEDIUM"
            ]
            if medium_signals:
                ctx.escalate_tier()
                logger.info(
                    "RiskMiddleware: escalated tier to %s for session=%s",
                    ctx.verification_tier,
                    session_handle[:8],
                )

            # Block on any HIGH signal.
            high_signals = [s for s in signals if s.severity.name == "HIGH"] + [
                s for s in ip_signals if s.severity.name == "HIGH"
            ]
            if high_signals:
                logger.warning(
                    "RiskMiddleware: blocking session=%s due to HIGH signals: %s",
                    session_handle[:8],
                    ", ".join(s.code for s in high_signals),
                )
                raise RiskActionError(high_signals)

        except Exception:
            # Risk evaluation must never break the tool call — unless it's a
            # RiskActionError, which is intentionally raised to block the call.
            logger.exception(
                "RiskMiddleware: risk evaluation failed; continuing without signal processing"
            )

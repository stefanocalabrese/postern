"""Risk signals on audit completion rows.

Verifies that when a tool call runs with an active risk session, the
RiskEngine + IpAnomalyDetector signals are serialized and passed through
AuditMiddleware._write into the audit_log completion row.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from postern_core.risk.context import RiskContext
from postern_core.risk.engine import RiskConfig, RiskEngine
from postern_core.risk.ip_anomaly import IpAnomalyDetector
from postern_core.risk.session import set_current_session


@dataclass(frozen=True)
class _CapturedWrite:
    """What _write received from on_call_tool."""

    outcome: str
    risk_signals: list[dict[str, Any]] | None


class _MockContext:
    """Minimal MiddlewareContext for on_call_tool."""

    def __init__(self, tool_name: str = "test_tool", arguments: dict[str, Any] | None = None):
        self.message = MagicMock()
        self.message.name = tool_name
        self.message.arguments = arguments or {}
        self.timestamp = None
        self.fastmcp_context = None


@dataclass(frozen=True)
class _FakeToken:
    """Minimal AccessToken mock."""

    token_id: str = "fake"  # noqa: S105


async def test_no_session_handle_yields_null_risk_signals() -> None:
    """When no session handle is provided, risk_signals is NULL."""
    from services.api.middleware.audit import AuditMiddleware

    middleware = AuditMiddleware(db=None)  # type: ignore[arg-type]
    captured: list[_CapturedWrite] = []

    async def call_next(context: Any) -> Any:
        return MagicMock()

    # Patch _write to capture arguments without hitting the DB.
    _original_write = middleware._write  # noqa: F841

    async def capture_write(*args: Any, **kwargs: Any) -> None:
        # _write signature: at, customer, absence_reason, name, arguments,
        # outcome, detail, redaction_budget_exhausted, duration_ms, request_id,
        # refusal_reason, call_id, client_id, risk_signals
        captured.append(_CapturedWrite(outcome=args[5], risk_signals=args[13]))

    with patch.object(middleware, "_write", capture_write):
        ctx = _MockContext("test_tool", {"some": "arg"})
        await middleware.on_call_tool(ctx, call_next)  # type: ignore[arg-type]

    assert len(captured) == 1
    assert captured[0].outcome == "returned"
    # No session handle → no risk context → NULL risk_signals.
    assert captured[0].risk_signals is None


async def test_session_with_no_signals_yields_empty_list() -> None:
    """When a session handle is provided but no signals fired, risk_signals is []."""
    from services.api.middleware.audit import AuditMiddleware

    middleware = AuditMiddleware(db=None)  # type: ignore[arg-type]
    captured: list[_CapturedWrite] = []

    async def call_next(context: Any) -> Any:
        return MagicMock()

    # Create a risk context and push it onto the contextvar.
    ctx = RiskContext(session_id="test-session")
    set_current_session(ctx)

    try:

        async def capture_write(*args: Any, **kwargs: Any) -> None:
            captured.append(_CapturedWrite(outcome=args[5], risk_signals=args[13]))

        with patch.object(middleware, "_write", capture_write):
            mock_ctx = _MockContext("test_tool", {"some": "arg"})
            await middleware.on_call_tool(mock_ctx, call_next)  # type: ignore[arg-type]

        assert len(captured) == 1
        assert captured[0].outcome == "returned"
        # Session exists but no signals evaluated → empty list.
        assert captured[0].risk_signals == []
    finally:
        set_current_session(None)


async def test_session_with_risk_signals_serialized_correctly() -> None:
    """Signals from RiskEngine are serialized with code, severity, description, details."""
    from services.api.middleware.audit import AuditMiddleware

    middleware = AuditMiddleware(db=None)  # type: ignore[arg-type]
    captured: list[_CapturedWrite] = []

    async def call_next(context: Any) -> Any:
        return MagicMock()

    # Create a risk context that will trigger signals.
    ctx = RiskContext(session_id="test-session")
    ctx.record_records(100)  # Exceeds default budget of 100
    set_current_session(ctx)

    try:
        # Pre-populate risk signals (simulating what RiskMiddleware does).
        config = RiskConfig(max_records_per_session=100)
        engine_signals = RiskEngine(config).evaluate(ctx)
        ip_detector = IpAnomalyDetector()
        ip_signals = ip_detector.evaluate(ctx.ip_tracker)
        ctx._risk_signals = [*engine_signals, *ip_signals]

        async def capture_write(*args: Any, **kwargs: Any) -> None:
            captured.append(_CapturedWrite(outcome=args[5], risk_signals=args[13]))

        with patch.object(middleware, "_write", capture_write):
            mock_ctx = _MockContext("test_tool", {"some": "arg"})
            await middleware.on_call_tool(mock_ctx, call_next)  # type: ignore[arg-type]

        assert len(captured) == 1
        assert captured[0].outcome == "returned"
        signals = captured[0].risk_signals
        assert signals is not None
        assert len(signals) > 0

        # Check structure of each signal.
        for sig in signals:
            assert "code" in sig
            assert "severity" in sig
            assert "description" in sig
            assert "details" in sig
            assert isinstance(sig["code"], str)
            assert sig["severity"] in ("LOW", "MEDIUM", "HIGH")

        # Verify the RECORD_BUDGET_EXHAUSTED signal is present.
        codes = {s["code"] for s in signals}
        assert "RECORD_BUDGET_EXHAUSTED" in codes

        # Verify the severity is HIGH for budget exhaustion.
        budget_sig = next(s for s in signals if s["code"] == "RECORD_BUDGET_EXHAUSTED")
        assert budget_sig["severity"] == "HIGH"
    finally:
        set_current_session(None)


async def test_raised_path_includes_risk_signals() -> None:
    """The raised (exception) path also captures risk signals."""
    from fastmcp.exceptions import ToolError

    from services.api.middleware.audit import AuditMiddleware

    middleware = AuditMiddleware(db=None)  # type: ignore[arg-type]
    captured: list[_CapturedWrite] = []

    tool_error = ToolError("tool failed")

    async def call_next(context: Any) -> Any:
        raise tool_error

    # Create a risk context with signals.
    ctx = RiskContext(session_id="test-session")
    ctx.record_records(100)
    set_current_session(ctx)

    try:
        config = RiskConfig(max_records_per_session=100)
        engine_signals = RiskEngine(config).evaluate(ctx)
        ctx._risk_signals = list(engine_signals)

        async def capture_write(*args: Any, **kwargs: Any) -> None:
            captured.append(_CapturedWrite(outcome=args[5], risk_signals=args[13]))

        with patch.object(middleware, "_write", capture_write):
            mock_ctx = _MockContext("failing_tool")
            with pytest.raises(ToolError):
                await middleware.on_call_tool(mock_ctx, call_next)  # type: ignore[arg-type]

        assert len(captured) == 1
        assert captured[0].outcome == "raised"
        signals = captured[0].risk_signals
        assert signals is not None
        codes = {s["code"] for s in signals}
        assert "RECORD_BUDGET_EXHAUSTED" in codes
    finally:
        set_current_session(None)


async def test_risk_signals_null_without_session() -> None:
    """When get_current_session returns None, risk_signals is NULL even if _write is called."""
    from services.api.middleware.audit import AuditMiddleware

    middleware = AuditMiddleware(db=None)  # type: ignore[arg-type]
    captured: list[_CapturedWrite] = []

    async def call_next(context: Any) -> Any:
        return MagicMock()

    # Ensure no session is active.
    set_current_session(None)

    async def capture_write(*args: Any, **kwargs: Any) -> None:
        captured.append(_CapturedWrite(outcome=args[5], risk_signals=args[13]))

    with patch.object(middleware, "_write", capture_write):
        mock_ctx = _MockContext("test_tool")
        await middleware.on_call_tool(mock_ctx, call_next)  # type: ignore[arg-type]

    assert len(captured) == 1
    assert captured[0].risk_signals is None

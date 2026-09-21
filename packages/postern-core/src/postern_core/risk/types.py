"""Shared types for the risk engine.

Kept separate from ``engine.py`` to avoid circular imports: both the main
risk engine and the IP anomaly detector need ``RiskSignal`` and ``Severity``,
and neither should import from each other.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


class Severity(Enum):
    """How urgently the signal demands action."""

    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()


class RiskAction(Enum):
    """What the middleware should do when a signal fires.

    Maps severity to concrete action:
    - ``LOW`` → log only, continue normally.
    - ``MEDIUM`` → escalate the session's verification tier for subsequent
      calls (tier 0 → tier 1, or tier 1 → tier 2).
    - ``HIGH`` → hard-fail the current tool call and mark the session for
      termination.
    """

    LOG = auto()
    ESCALATE = auto()
    BLOCK = auto()


class RiskActionError(Exception):
    """Raised by ``RiskMiddleware`` when a HIGH signal blocks a tool call.

    Carries the signals that triggered the block so the caller can report
    them to the user (e.g. "your session has been terminated due to
    suspicious activity").

    Attributes:
        signals: The HIGH-severity signals that caused the block.
    """

    def __init__(self, signals: list[RiskSignal]) -> None:
        self.signals = signals
        super().__init__(
            f"Session blocked by {len(signals)} risk signal(s): "
            + ", ".join(s.code for s in signals)
        )


@dataclass(frozen=True)
class RiskSignal:
    """One anomaly detected by the risk engine.

    Immutable so it can be logged, serialized, or passed to a tier-escalation
    decision without mutation concerns.
    """

    code: str
    """Machine-readable identifier (e.g. ``RECORD_BUDGET_80PCT``)."""

    description: str
    """Human-readable explanation for logs and audit trails."""

    severity: Severity
    """What kind of response this signal demands."""

    details: dict[str, Any] = field(default_factory=dict)
    """Structured data for alerting systems (record counts, thresholds, etc.)."""

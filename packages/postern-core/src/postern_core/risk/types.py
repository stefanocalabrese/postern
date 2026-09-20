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

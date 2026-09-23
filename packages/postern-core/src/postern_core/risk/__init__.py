"""Session risk tracking and anomaly detection (ZT-5).

Tracks per-session budgets (total records returned, distinct accounts
touched, time span requested) and emits risk signals when thresholds are
exceeded. Signals escalate the tier rather than hard-failing, per the
zero-trust plan §4.

ZT-5 follow-up: IP/ASN anomaly detection via ``IpAnomalyDetector`` and
``IpTracker`` — detects impossible travel, excessive IP diversity, and
suspicious ASN connections (compensating control for ZT-6).

Session management: a pluggable store (in-memory or Redis) keyed on the
caller's verified identity -- ``SessionKey``, the customer plus the OAuth
client -- and a contextvar so tool handlers can reach the current call's
``RiskContext`` without threading it through every function. A store that
cannot answer raises ``SessionStoreUnavailable``, which refuses the call.

Production deployments set ``POSTERN_REDIS_URL`` to enable the Redis
backend (compatible with AWS ElastiCache, Google Memorystore, Azure Cache
for Redis).  Without it, the in-memory store is used.
"""

from postern_core.risk.context import IpTracker, RecordCount, RiskContext
from postern_core.risk.engine import RiskConfig, RiskEngine, Severity
from postern_core.risk.ip_anomaly import IpAnomalyConfig, IpAnomalyDetector
from postern_core.risk.session import (
    InMemorySessionStore,
    RedisSessionStore,
    SessionKey,
    SessionStore,
    SessionStoreBase,
    SessionStoreUnavailable,
    create_session_store,
    get_current_session,
)
from postern_core.risk.types import RiskSignal

__all__ = [
    "InMemorySessionStore",
    "IpAnomalyConfig",
    "IpAnomalyDetector",
    "IpTracker",
    "RecordCount",
    "RedisSessionStore",
    "RiskConfig",
    "RiskContext",
    "RiskEngine",
    "RiskSignal",
    "Severity",
    "SessionKey",
    "SessionStore",
    "SessionStoreBase",
    "SessionStoreUnavailable",
    "create_session_store",
    "get_current_session",
]

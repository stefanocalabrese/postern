# Risk Engine (ZT-5)

Per-session anomaly detection, tier escalation, and severity model.

## Overview

The risk engine evaluates session context against configurable thresholds and emits
signals that drive verification tier escalation or call blocking. It is the core of
ZT-5 (per-session anomaly detection).

```
packages/postern-core/src/postern_core/risk/engine.py       RiskEngine + RiskConfig
packages/postern-core/src/postern_core/risk/context.py      RiskContext, RecordCount, IpTracker
packages/postern-core/src/postern_core/risk/types.py        Severity, RiskSignal, RiskAction
packages/postern-core/src/postern_core/risk/session.py      SessionStoreBase (in-memory + Redis)
packages/postern-core/src/postern_core/risk/ip_anomaly.py   IP/ASN anomaly detection
services/api/middleware/risk.py                             RiskMiddleware (FastMCP middleware)
```

## Severity Model

Signals carry a `Severity` that maps to the appropriate response:

| Severity | Response | Action |
|----------|----------|--------|
| `LOW` | Informational, log only | `RiskAction.LOG` |
| `MEDIUM` | Escalate tier for the next call (tier 0 → tier 1) | `RiskAction.ESCALATE` |
| `HIGH` | Hard-fail the call and end the session | `RiskAction.BLOCK` |

```python
from postern_core.risk.types import Severity, RiskSignal

signal = RiskSignal(
    code="RECORD_BUDGET_80PCT",
    description="Session has returned 400 records (≥80% of budget). Escalate tier.",
    severity=Severity.MEDIUM,
    details={"records_returned": 400, "budget_limit": 500},
)
```

## RiskConfig, Thresholds

All values are **hard limits**, exceeding them triggers a HIGH signal that ends the
session. Sub-thresholds (80% of hard limit) trigger MEDIUM signals that escalate tier.

```python
@dataclass(frozen=True)
class RiskConfig:
    # Record budget (cumulative across all tool calls)
    max_records_per_session: int = 500       # Hard limit on total records

    # Account diversity budget
    max_distinct_accounts: int = 10          # Hard limit on distinct accounts

    # Time window budget (per call, not cumulative)
    max_days_per_call: int = 365             # Maximum days parameter per call

    # Session lifetime
    max_session_age_minutes: float = 480.0   # Maximum session age (8 hours)

    # Sub-thresholds (fraction of hard limit → MEDIUM escalation)
    record_escalation_pct: float = 0.8       # 80% of record budget
    account_escalation_pct: float = 0.8      # 80% of account budget
```

### Sizing rationale

- `max_records_per_session = 500` is 2.5× the handoff's "not 200 records" framing and
  5× the `MAX_ROWS=100` per-call cap, allowing a customer to reasonably ask for balances
  on all accounts plus a wide transaction window.
- `max_distinct_accounts = 10` matches the implicit assumption that a personal banking
  customer has fewer than 10 accounts. Corporate multi-account customers are out of scope.
- `max_days_per_call = 365` matches `MAX_DAYS` in the transactions façade, a session
  budget wider than one call is pointless.
- `max_session_age_minutes = 480` (8 hours) is a generous session lifetime; ZT-1's
  token refresh will be the primary shortening mechanism.

## RiskEngine, Evaluation

The engine is **stateless**: it takes context + config and returns a list of signals.
The caller decides what to do with them (log, escalate tier, hard-fail).

```python
from postern_core.risk.engine import RiskEngine, RiskConfig

config = RiskConfig()
engine = RiskEngine(config)
signals = engine.evaluate(context)

for signal in signals:
    if signal.severity == Severity.HIGH:
        raise RiskActionError(signal)  # Block call, end session
    elif signal.severity == Severity.MEDIUM:
        context.escalate_tier()         # Next call requires stronger verification
```

### Checks performed (in order)

1. **Record budget sub-threshold**, 80% reached → MEDIUM (escalate tier)
2. **Record budget hard limit**, exhausted → HIGH (end session)
3. **Account diversity sub-threshold**, 80% reached → MEDIUM (escalate tier)
4. **Account diversity hard limit**, exhausted → HIGH (end session)
5. **Session age**, exceeds max → HIGH (end session)
6. **Time window**, days requested exceeds max → HIGH (reject call)

### Signal codes

| Code | Severity | Description |
|------|----------|-------------|
| `RECORD_BUDGET_80PCT` | MEDIUM | Session has returned ≥80% of record budget |
| `RECORD_BUDGET_EXHAUSTED` | HIGH | Session record budget exhausted |
| `ACCOUNT_DIVERSITY_80PCT` | MEDIUM | Session has touched ≥80% of account budget |
| `ACCOUNT_DIVERSITY_EXHAUSTED` | HIGH | Session account budget exhausted |
| `SESSION_AGE_EXCEEDED` | HIGH | Session age exceeds maximum (8 hours) |
| `TIME_WINDOW_EXCEEDED` | HIGH | Time window exceeds maximum days per call |

## RiskContext, Per-Session State

Tracks how many records have been returned, which accounts were touched, the widest
time span requested in one call, and client IP addresses with timestamps.

```python
class RiskContext:
    _records: int                          # Cumulative records returned
    _accounts: set[str]                    # Distinct accounts touched
    _max_days: int                         # Widest time window requested
    _start_time: float                     # Session start (time.monotonic())
    _ip_tracker: IpTracker                 # IP addresses with timestamps
    _session_id: str | None                # Opaque session identifier
    _verification_tier: VerificationTier   # Current tier (starts at SESSION_ONLY)

    def escalate_tier(self) -> None:       # SESSION_ONLY → APP_APPROVAL → APP_IDENTITY_VERIFICATION
    def record_records(self, count: int) -> None:  # Add records to session total
    def record_account(self, account_ref: str) -> None:  # Track an account was touched
    def record_days(self, days: int) -> None:  # Track widest time window requested
```

### IP Tracking (`IpTracker`)

Tracks client IP addresses per session for anomaly detection:

```python
class IpTracker:
    _entries: list[IpEntry]                # Bounded to max 100 entries (FIFO eviction)
    _max_entries: int = 100

    @property
    def distinct_ips(self) -> int          # Number of unique IPs seen
    @property
    def last_ip(self) -> str | None        # Most recently recorded IP
    @property
    def entries(self) -> list[IpEntry]     # All recorded IPs in chronological order

    def time_since_last_change(self) -> float | None  # Seconds since last IP changed
```

**Bounded:** oldest entries are dropped when the list exceeds 100 (FIFO eviction).
This prevents unbounded memory growth from a session that cycles through many IPs.

## IP Anomaly Detection (`packages/postern-core/src/postern_core/risk/ip_anomaly.py`)

The `IpAnomalyConfig` defines thresholds for IP-based anomaly detection:

```python
@dataclass(frozen=True)
class IpAnomalyConfig:
    impossible_travel_window: float = 300.0   # Seconds, IP change within this window
    max_distinct_ips: int = 3                  # Hard limit on distinct IPs per session
```

### Checks

| Check | Severity | Description |
|-------|----------|-------------|
| `_impossible_travel_detected()` | MEDIUM | IP changed within `impossible_travel_window` seconds |
| `_ip_diversity_hard_limit()` | HIGH | Distinct IPs >= `max_distinct_ips` (3) |
| `_suspicious_asn_detected()` | - | **Always returns False**: ASN enrichment not yet wired |

## RiskMiddleware (`services/api/middleware/risk.py`)

FastMCP middleware that pushes `RiskContext` onto a ContextVar, records client IPs,
and evaluates signals after each tool call.

```python
class RiskMiddleware:
    def __init__(self, session_store: SessionStoreBase): ...

    async def _get_or_create_session(self, tool_name: str, arguments: dict) -> RiskContext
    async def _record_data_touch(self, context: RiskContext, records_returned: int) -> None
    async def _evaluate_signals(self, context: RiskContext) -> list[RiskSignal]
```

### Flow per tool call

1. Extract `session_handle` from tool arguments
2. Look up or create `RiskContext` from session store (via ContextVar)
3. Record client IP (`X-Forwarded-For` or `remote_addr`)
4. After tool call completes, record data touches (records returned)
5. Evaluate signals against `RiskConfig` thresholds
6. MEDIUM → escalate tier; HIGH → raise `RiskActionError` (block call)

## Session Store (`packages/postern-core/src/postern_core/risk/session.py`)

Pluggable per-session risk context store with in-memory and Redis backends.

| Backend | When used | Storage |
|---------|-----------|---------|
| `InMemorySessionStore` | Default (dev/test) | In-process dict with TTL expiry |
| `RedisSessionStore` | Production (`POSTERN_REDIS_URL`) | Redis with TTL-based expiry |

Factory: `create_session_store()` picks the backend based on environment.

### ContextVar pattern

```python
# Thread-local storage for per-call access
_current_session: ContextVar[RiskContext | None] = ContextVar("current_risk_context", default=None)

def get_current_session() -> RiskContext | None:
    return _current_session.get()

def set_current_session(session: RiskContext) -> None:
    _current_session.set(session)
```

The middleware sets the ContextVar at call start and clears it on completion.

## Source References

| Component | File |
|-----------|------|
| Risk engine + config | [`packages/postern-core/src/postern_core/risk/engine.py`](../../../packages/postern-core/src/postern_core/risk/engine.py) |
| Risk context + IP tracker | [`packages/postern-core/src/postern_core/risk/context.py`](../../../packages/postern-core/src/postern_core/risk/context.py) |
| Shared types (Severity, Signal) | [`packages/postern-core/src/postern_core/risk/types.py`](../../../packages/postern-core/src/postern_core/risk/types.py) |
| Session store (in-memory + Redis) | [`packages/postern-core/src/postern_core/risk/session.py`](../../../packages/postern-core/src/postern_core/risk/session.py) |
| IP anomaly detection | [`packages/postern-core/src/postern_core/risk/ip_anomaly.py`](../../../packages/postern-core/src/postern_core/risk/ip_anomaly.py) |
| Risk middleware (FastMCP) | [`services/api/middleware/risk.py`](../../../services/api/middleware/risk.py) |
| Verification tiers | [`packages/postern-core/src/postern_core/domain/verification.py`](../../../packages/postern-core/src/postern_core/domain/verification.py) |

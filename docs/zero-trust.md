# Zero Trust Architecture

Postern wraps the [Model Context Protocol](https://modelcontextprotocol.io/) in a
zero-trust security layer so the same tools work safely across machines. Every control
is enforced at infrastructure boundaries, not by code review promises.

## Controls in Place

### Continuous Authorization

Every token is checked against a revocation list at mint time. A JTI replay cache
prevents the same token from being used twice within its validity window. Revocation
supports three scopes: per-session, per-customer plus client, and a global kill switch.

### Workload Attestation

On startup each service mints a test token and verifies it against the JWKS it
publishes. If there is any drift between the signing key and what is published, the
service refuses to start.

### Approval Callbacks

Write operations are never executed from agent input. The model proposes a write,
a challenge record is stored server-side, and the customer approves on their own
device. The actual backend call is built from that stored record, not from anything
the agent can influence.

### Per-Session Anomaly Detection

Every session tracks records returned, accounts touched, session age, and IP
patterns. When thresholds are exceeded the system escalates verification tier or
blocks the call entirely.

### Key Split Architecture

Read and write keys are completely separate, published on different JWKS endpoints.
A compromised tool handler cannot mint a token the payments service will accept,
because it does not hold the key.

### Fail-Closed Auditing

Every tool call writes two audit rows — an entry row before the backend is reached
and a completion row after. If either write fails, the call itself fails. No data
is ever accessed without a record.

### Data Masking

Card numbers and IBANs are masked at the type level: `MaskedPan` and `MaskedIban`
reject raw values on construction. A handler that forgets to use the type fails
validation instead of leaking. Counterparty account numbers are omitted entirely.

## What Is Not Yet Implemented

- **Domain service scoping** — the operator's backend services must scope queries
  by the JWT subject claim. This lives in your infrastructure, not this repo.
- **Egress analysis** — outbound traffic monitoring for data exfiltration is planned.

## Cross-References

| Topic | Documentation |
|-------|---------------|
| Risk Engine (anomaly detection) | [Risk Engine](user-guide/components/risk-engine.md) |
| Audit System (two-row pattern) | [Audit System](user-guide/components/audit.md) |
| Masking (PAN/IBAN redaction) | [Masking](user-guide/components/masking.md) |
| Session Store (revocation, device codes) | [Session Store](user-guide/components/session-store.md) |
| API Service (token minting, key split) | [API Service](user-guide/components/api-service.md) |
| Confirm Service (approval callbacks) | [Confirm Service](user-guide/components/confirm-service.md) |

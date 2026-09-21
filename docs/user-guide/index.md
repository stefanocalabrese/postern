# Postern User Guide

> Zero-trust MCP server for banking: setup, components, and reference.

## Overview

Postern wraps [MCP](https://modelcontextprotocol.io/) in a zero-trust security layer so
the same tools work safely across machines. It exposes an operator's backend services to
AI clients as tools, with authentication, per-session anomaly detection, tiered
verification, and fail-closed auditing.

```
packages/postern-core/     shared library: domain types, façade, identity, masking
services/api/              read path: MCP tools, OAuth endpoints, consent checks
services/confirm/          write path: approval callback, payment execution, device auth
```

A compromised tool handler cannot mint a token the payments service will accept, because
it does not hold the key. That is an infrastructure property, not a code-review promise.

## Quick Links

| Chapter | Description |
|---------|-------------|
| [Getting Started](getting-started.md) | Prerequisites, installation, configuration, local development stack |
| [API Service](components/api-service.md) | Read path: MCP tools, OAuth endpoints, consent checks |
| [Confirm Service](components/confirm-service.md) | Write path: approval callback, device auth, payment execution |
| [Risk Engine](components/risk-engine.md) | Per-session anomaly detection, tier escalation, severity model |
| [Session Store](components/session-store.md) | In-memory and Redis backends, ContextVar pattern |
| [Masking](components/masking.md) | PAN/IBAN redaction layers, FreeText type, scan budgets |
| [Audit System](components/audit.md) | Two-row pattern, fail-closed writes, CHECK constraints |
| [Glossary](glossary.md) | Key terms and concepts across the platform |

## Architecture at a Glance

```
                    ┌──────────────┐
                    │   Mobile App │
                    │  (pairing +  │
                    │  approval)   │
                    └──────┬───────┘
                           │ RFC 8628 device grant
                    ┌──────▼───────┐
          QR scan  │ Confirm      │◄── POST /approve (signed)
   ┌─────────────►│  Service     │
   │              │ (write path) │
   │              └──────┬───────┘
   │                     │ read + write tokens (device grant)
   │              ┌──────▼───────┐
   │              │    API       │◄── MCP tools (tools/call)
   │              │  Service     │
   │              │ (read path)  │
   │              └──────┬───────┘
   │                     │ internal JWT (RS256)
   │              ┌──────▼───────┐
   │              │  Istio /     │◄── JWT validation (ZT-2)
   │              │  Gateway     │
   │              └──────┬───────┘
   │                     │ scoped query by JWT sub
   ▼              ┌──────▼───────┐
   └─────────────►│  Domain      │
                  │  Services    │
                  │ (accounts,   │
                  │  payments,   │
                  │  cards)      │
                  └──────────────┘

  Postgres: consents, audit_log, challenges tables
  Redis (optional): sessions, device codes, revocation lists
```

## Zero-Trust Controls

| Control | Status | Description |
|---------|--------|-------------|
| ZT-1 | ✅ Built | Continuous authorization: revocation list with O(1) lookups, JTI replay cache |
| ZT-2 | ⏳ Pending | Istio JWT validation; domain services must scope queries by token `sub` |
| ZT-3 | ✅ Built | Workload attestation: startup minter probe verifies token signing against published JWKS |
| ZT-4 | ✅ Built | Approval callback: signed approvals, backend execution from stored challenge row |
| ZT-5 | ✅ Built | Per-session anomaly detection: record budgets, account diversity, session age |
| ZT-6 | ✅ Built | Microsegmentation: read/write key split, separate JWKS endpoints |
| ZT-7 | ✅ Built | Revocation: three scopes (per-session, per-customer+client, kill switch) |
| ZT-8 | ⏳ Pending | Egress analysis: not yet implemented |

## Prerequisites

- **Python 3.12+** (pinned in `.python-version`)
- **uv**: project dependency manager and runner
- **PostgreSQL 15+**: for consents, audit_log, challenges tables
- **Redis** (optional), for sessions, device codes, revocation lists in production

## License

MIT. See the project root for license details.
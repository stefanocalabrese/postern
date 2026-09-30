# Postern User Guide

> Zero-trust MCP server for banking: setup, components, and reference.

## Overview

Postern wraps [MCP](https://modelcontextprotocol.io/) in a zero-trust security layer so
the same tools work safely across machines. It exposes an operator's backend services to
AI clients as tools, with authentication, per-session anomaly detection, tiered
verification, and fail-closed auditing.

```
packages/postern-core/     shared library: domain types, façade, identity, masking
packages/postern-cards/       a module's read half: the cards.list tool
packages/postern-cards-write/ a module's write half: three card write routes
services/api/              read path: MCP tools, OAuth endpoints, consent checks
services/confirm/          write path: approval callback, payment execution, device auth
```

Tool families are modules, discovered from installed distributions through Python
entry points rather than imported by name. See
[Writing a Module](writing-a-module.md).

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
| [Mobile App Pairing Contract](../integration/mobile-app-pairing-contract.md) | For the mobile team: the app link, `POST /scan`, the confirmation screen and `POST /approve` |
| [Operator App-Link Setup](../integration/operator-app-link-setup.md) | Choosing the app-link host, association files, proxy hops, rate limits and Redis for pairing |
| [Writing a Module](writing-a-module.md) | Adding tools through entry points: the two halves, what the host gives you, and what a module can break |
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
   │              │  Istio /     │◄── JWT validation
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

Continuous authorization, workload attestation, key split architecture, per-session
anomaly detection, fail-closed auditing, and data masking. See the [Zero Trust overview](../zero-trust.md)
for details on each control and what is still pending.

## Prerequisites

- **Python 3.12+** (pinned in `.python-version`)
- **uv**: project dependency manager and runner
- **PostgreSQL 15+**: for consents, audit_log, challenges tables
- **Redis** (optional), for sessions, device codes, revocation lists in production

## License

MIT. See the project root for license details.
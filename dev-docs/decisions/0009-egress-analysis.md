# 0009: Egress analysis and NAT Gateway decision

**Date:** 2026-09-20

## Summary

The zero-trust plan §5.3 justified a NAT Gateway + Elastic IP for ASPSP
whitelisting. **With own-backend-only scope, that justification is stale.**

This record enumerates what actually requires internet egress in this
repository's codebase and documents the decision.

## Egress enumeration

### What the application connects to

The codebase was scanned for hardcoded external URLs, OTel endpoints,
push notification providers, CRL/OCSP references, and any other outbound
connections.

**Finding: no hardcoded external endpoints.** Every URL in the codebase is
either an internal default or read from environment variables:

| Setting | Default / Source | Target | Internet? |
|---|---|---|---|
| `POSTERN_BACKEND_BASE_URL` | Required env var (no default) | Operator's backend | No — internal VPC via TGW/PrivateLink |
| `POSTERN_JWKS_URI` | Optional env var (`None`) | Customer auth provider | No — local dev uses `backend-stub` |
| `POSTERN_TOKEN_ISSUER` | Optional env var (`None`) | Customer auth provider | No — local dev uses `backend-stub` |
| `POSTERN_READ_TOKEN_ISSUER` | `"https://mcp-read.internal"` | Internal read token issuer | No — internal |
| `POSTERN_DATABASE_URL` | Required env var (no default) | RDS Postgres | No — same VPC |
| `POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS` | `"2.0"` | Backend connect timeout | N/A — not a URL |
| `POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS` | `"2.0"` | Backend write timeout | N/A — not a URL |
| `POSTERN_BACKEND_READ_TIMEOUT_SECONDS` | `"5.0"` | Backend read timeout | N/A — not a URL |
| `POSTERN_BACKEND_POOL_TIMEOUT_SECONDS` | `"1.0"` | Backend pool timeout | N/A — not a URL |
| `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` | `"2.0"` | DB connect timeout | N/A — not a URL |
| `POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS` | `"3.0"` | DB command timeout | N/A — not a URL |
| `POSTERN_DATABASE_POOL_TIMEOUT_SECONDS` | `"1.0"` | DB pool timeout | N/A — not a URL |
| `POSTERN_MAX_BODY_BYTES` | `"1048576"` | Max body size limit | N/A — not a URL |
| `POSTERN_REQUEST_DEADLINE_SECONDS` | `"101.0"` | Request deadline | N/A — not a URL |
| `POSTERN_CACHE_TTL_SECONDS` | `"60"` | Cache TTL | N/A — not a URL |
| `POSTERN_STRICT_HEADERS` | `"0"` | Header validation flag | N/A — not a URL |
| `POSTERN_AUDIENCE` | `"postern"` | JWT audience claim | N/A — not a URL |

### What the application does NOT connect to

The following potential egress targets were searched for and **not found**:

- **OTel / observability endpoints** — no `opentelemetry` import, no
  tracing configuration, no external metrics export.
- **Push notification providers** — no `boto3` SNS/SQS references, no
  push notification logic in the codebase. The confirmation callback is
  a synchronous HTTP call from the user's device, not server-initiated.
- **CRL / OCSP** — no certificate revocation checking in the codebase.
  The `cryptography` library is used for RSA key operations, not TLS
  certificate validation (that's handled by the OS / stdlib).
- **Third-party APIs** — no external API calls beyond the operator's own
  backend (which is internal).

### What the infrastructure layer connects to

The ECS/Fargate deployment (not in this repo) may need egress for:

- **ECR** — pull images at startup. Solved by VPC endpoint (`pl-xxxx`).
- **Secrets Manager** — fetch secrets at startup. Solved by VPC endpoint.
- **SSM** — parameter store access. Solved by VPC endpoint.
- **CloudWatch** — log export. Solved by VPC endpoint or IAM role with
  `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`.
- **ECR / Secrets Manager / SSM** — all have AWS VPC endpoints that keep
  traffic within the AWS network.

## Decision: no NAT Gateway needed for this scope

### Rationale

1. **Own-backend-only scope.** The zero-trust plan §5.3 justified NAT
   Gateway + Elastic IP for ASPSP whitelisting (the operator's backend
   requires the MCP server's public IP). This plan uses **own-backend-only**
   scope — the operator's own backend is in a separate VPC connected via
   Transit Gateway, not the public internet. No ASPSP whitelisting is needed.

2. **No external dependencies.** The codebase has zero hardcoded external
   URLs, no OTel, no push notifications, no CRL/OCSP. Every outbound
   connection is to an internal endpoint (backend, database) or reads its
   target from environment variables.

3. **Cost.** A NAT Gateway costs ~€35/month per AZ plus data processing
   charges. Removing it saves a significant fixed cost with no functional
   impact for this scope.

4. **VPC endpoints cover AWS services.** ECR, Secrets Manager, SSM, and
   CloudWatch all have VPC endpoints that keep traffic within the AWS
   network. No NAT Gateway is needed for these.

### What this means for Terraform

When the infrastructure is built (separate Terraform repo):

- **No NAT Gateway** in the MCP VPC public subnets.
- **VPC endpoints** for ECR, Secrets Manager, SSM, CloudWatch (all
  interface endpoints with private DNS enabled).
- **Security groups** on ECS tasks: allow inbound from the internet-facing
  ALB (port 8080), deny all outbound except to:
  - RDS Postgres (same VPC, security group)
  - VPC endpoint security groups (ECR, Secrets Manager, SSM, CloudWatch)
- **No Elastic IP** needed (no NAT Gateway).

### What would change this decision

This decision is scoped to the **own-backend-only** plan. If future work
adds:

- Third-party ASPSP adapters (requiring public internet egress for QWAC
  whitelisting)
- Push notification providers (SNS/SQS to external endpoints)
- OTel/observability with external backends

…then the NAT Gateway justification would need to be re-evaluated. In that
case, a default-deny egress with explicit allowlist via VPC endpoints or
an egress proxy would be preferred over an open NAT route.

## Verification

The test `tests/test_zt8_no_hardcoded_external_endpoints.py` verifies that
no hardcoded external URLs exist in the codebase. It scans all Python files
in `packages/` and `services/` for HTTP(S) URLs that are not internal
defaults or environment variable references.

See also: `dev-docs/decisions/0004-base-images.md` (base image pinning, ZT-3).


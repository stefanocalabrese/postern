# 0010: DPoP and sender-constrained tokens (ZT-6)

**Date:** 2026-09-20

## Question

Bearer tokens are the classic zero-trust weakness: possession is authorization.
A token exfiltrated from an AI vendor's infrastructure (threat A8) works from
anywhere. Should this repository implement DPoP (RFC 9449) for the
client→MCP-server layer, or accept the risk with compensating controls?

## DPoP investigation

### MCP 2026-07-28 spec

**Finding: DPoP / RFC 9449 appears nowhere in the MCP `2026-07-28` spec.**
Zero hits across the specification, changelog, and extension mechanisms. The
spec defines bearer-token authorization via the `Authorization: Bearer <token>`
header with no sender-constraint extension point.

### Client vendor support

Claude, ChatGPT (OpenAI), and Perplexity — the three reference clients cited
in §1 of the design handoff — do not implement DPoP. The zero-trust plan
§1 mandates "design for the weakest client, not for Claude." Unilateral DPoP
would break every non-DPoP client.

### FastMCP / MCP Python SDK

FastMCP 4.x (the server framework in use) has no DPoP middleware or built-in
support. The `AccessToken` object (from `fastmcp.server.dependencies`) carries
`.client_id`, `.scopes`, `.expires_at`, `.claims` — no DPoP proof key or
binding material.

### Verdict: DPoP is not viable for this deployment

DPoP cannot ship unilaterally. It requires:
1. MCP spec support (absent in 2026-07-28)
2. Client vendor implementation (absent from all reference clients)
3. Server framework support (absent in FastMCP 4.x)

Until at least one reference client implements DPoP and the MCP spec includes
an extension mechanism for it, this repository cannot adopt DPoP without
breaking the bootstrap tool (§4.2 of the handoff), which is the only
context-delivery mechanism that works everywhere.

## Compensating controls

The zero-trust plan §4 lists four compensating controls for the absence of
DPoP. Three are implemented; one is partially in place.

### Implemented controls

| Control | Status | Details |
|---|---|---|
| **Short token lifetime** (ZT-1) | ✅ Complete | Internal JWTs expire in 60 seconds (`_LIFETIME = timedelta(seconds=60)`). A stolen token has a 60-second window before it expires. |
| **Revocation on every mint** (ZT-1) | ✅ Complete | `ReadTokenMinter.__call__` checks the `RevocationList` before minting. A revoked session dies at next token request, not at next refresh. Kill-switch blocks all tokens from a client across all customers instantly. |
| **jti replay cache** (A10 / ZT-1) | ✅ Complete | `JtiReplayCache` tracks every minted jti and raises on duplicate within the token lifetime window. Prevents replay of a captured token even if it is still within its 60-second exp window. |
| **Audience scoping** (Vault key split) | ✅ Complete | `READ_SCOPES` restricts the read minter to three audiences (`accounts.svc`, `transactions.svc`, `cards.svc`). A write audience (`payments.svc`) raises `KeyError`. The read/write key split means even holding the right key, a token from this minter carries the wrong scope for write endpoints. Istio matches on claims as well as signature. |
| **Internal JWTs sender-constrained** (Vault key split) | ✅ Complete | Internal tokens (§7.2 of handoff) are signed with separate read/write keys. The MCP server process holds only the read key; the approval callback holds the write key. Istio enforces issuer-based routing — a read-signed token cannot reach write endpoints. |

### Partially in place

| Control | Status | Details |
|---|---|---|
| **Client IP/ASN anomaly detection** (ZT-5) | ⚠️ Framework exists, enforcement not wired | `RiskContext` tracks session age, record counts, distinct accounts touched. The risk engine (`RiskEngine`) evaluates thresholds and emits `RiskSignal` with severity levels (LOW/MEDIUM/HIGH). However, IP/ASN tracking is not yet implemented — no `client_ip` or `x-forwarded-for` extraction exists in the codebase. The framework is ready; the data collection layer needs to be added at the ASGI middleware level (D1 in the foundation plan). |

## Decision: accept the risk with compensating controls

### Rationale

1. **DPoP is not implementable today.** The MCP 2026-07-28 spec has no
   extension mechanism, reference clients do not support it, and FastMCP 4.x
   has no DPoP middleware. Unilateral adoption would break the bootstrap tool
   and all non-DPoP clients.

2. **Compensating controls cover the attack surface.** A stolen bearer token
   faces three independent barriers:
   - **60-second TTL** — the window of exploitation is narrow.
   - **jti replay cache** — even within 60 seconds, the same token cannot be
     used twice (the cache raises `ValueError` on duplicate jti).
   - **Revocation list** — if the token is detected as compromised, revoking
     the customer+client pair blocks all future mints instantly.

3. **Internal tokens are already sender-constrained.** The Vault key split
   (§7.2) means internal JWTs cannot be replayed across the read/write
   boundary, and Istio enforces issuer-based routing.

4. **The remaining gap (IP/ASN) is a known, scoped risk.** Without client IP
   tracking, an attacker who steals a token and replays it from different
   infrastructure within the 60-second window (before jti cache eviction) is
   not detected. This is a real gap, but:
   - The 60-second window makes this a narrow attack.
   - The risk engine framework is in place; adding IP/ASN tracking at the
     middleware layer (D1) is a small change.
   - This gap is documented and tracked as part of ZT-5's refresh evaluation
     domain.

### What this means for deployment

- **No DPoP implementation** — do not invest in DPoP until the MCP spec and
  reference clients support it.
- **Monitor for DPoP in future MCP revisions** — the next spec revision may
  add an extension mechanism. Re-evaluate when a reference client ships DPoP.
- **Add IP/ASN tracking to the risk engine** — this is a ZT-5 follow-up, not
  a ZT-6 blocker. The `RiskContext` and `RiskEngine` provide the evaluation
  framework; the data collection layer (ASGI middleware reading
  `X-Forwarded-For` / `remote_addr`) needs to be added.

### What would change this decision

This decision is scoped to the **MCP 2026-07-28 spec and current client
landscape**. It would need re-evaluation if:

- The MCP specification adds a DPoP extension mechanism or mandates sender
  constraints.
- A reference client (Claude, ChatGPT, Perplexity) implements DPoP and
  documents how to opt in.
- FastMCP adds native DPoP middleware support.

In any of those cases, the decision record would be superseded by a new one
documenting the DPoP implementation.

## Verification

The test `tests/test_zt1_continuous_auth.py` verifies the compensating controls:
- `test_revocation_list_blocks_mint_when_customer_client_revoked` — revocation
  blocks next mint.
- `test_revocation_list_blocks_mint_under_kill_switch` — kill-switch blocks all
  mints for a client.
- `test_jti_cache_detects_manual_replay` — duplicate jti raises.
- `test_revocation_checked_before_replay_cache` — revocation fires before jti
  cache, so a revoked customer is rejected even if their previous token's jti
  is still cached.

See also: `docs/postern-zero-trust-plan.md` §4 (ZT-6 work item),
`docs/superpowers/plans/postern-foundation-and-read-surface-2026-09-12.md`
(DPoP investigation, line 44).


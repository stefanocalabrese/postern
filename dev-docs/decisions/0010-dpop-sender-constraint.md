# 0010: DPoP and sender-constrained tokens (ZT-6)

**Date:** 2026-09-20

> **Corrected 2026-09-26 by decision record 0014, and the conclusion survives
> the correction.** Three passages below counted the jti cache as a
> compensating control against a stolen bearer token. It is not one: it holds
> only jtis this server minted, so it cannot observe a token arriving twice.
> Each is struck in place rather than rewritten, because a record of what was
> decided is worth more intact than tidy, and because the third of the three
> is where the error entered the zero-trust plan. **The decision to accept the
> risk stands** on the remaining controls, which are real, and the residual it
> accepts is wider than this document said: `dev-docs/postern-zero-trust-plan.md`
> 5.5 states it.

> **Amended with the layer-1 session token (`dev-docs/device-grant-session-token-spec.md`).**
> The table below counts a 60-second lifetime, and that describes the layer-2
> delegation token only. The token a client holds is now a layer-1 access
> token that lives **10 minutes** inside a refresh family that lives **1
> hour**, so the bearer-theft window is 10 minutes for a stolen access token
> and up to 1 hour for a stolen refresh token nobody has noticed. What
> replaces the short lifetime as a compensating control for those two:
>
> - **The per-call `jti` check.** `services/api/middleware/revocation.py`'s
>   `RevocationMiddleware` asks the ZT-7 store about the access token's `jti`
>   on every `tools/call` and `tools/list`, so a token is cut on its next call
>   once anything lists it. Recall at `POST /scan` and reuse detection both
>   list every live `jti` of the family they revoke.
> - **Refresh-token rotation with reuse detection** (RFC 9700 §4.14.2). A
>   rotated token presented again revokes the whole family. It detects, it
>   does not prevent: until both parties have presented, the thief refreshes
>   freely.
> - **The revocation checks at every refresh**: the customer, the
>   customer-client pair, the kill switch, every live access `jti`, and a
>   family created at or before a customer revocation is refused and revoked
>   for good.
>
> Not built, and needed before a revoked-`jti` set can be pruned: neither
> revocation store records when a revoked `jti` expires, so the set only grows.
> A companion sorted set scored by `exp` beside the `SADD` would let a sweep
> remove expired members.

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
| ~~**jti replay cache** (A10 / ZT-1)~~ | ❌ **Not a control** (entered 2026-09-20, struck 2026-09-26) | Original text: "`JtiReplayCache` tracks every minted jti and raises on duplicate within the token lifetime window. Prevents replay of a captured token even if it is still within its 60-second exp window." The first sentence is accurate and the second does not follow from it. Every jti it tracks was drawn from `uuid.uuid4()` by the same call that adds it, so the duplicate it raises on is a collision in this process's RNG. A captured token is presented to the gateway and the domain services, which this cache never hears from. Decision record 0014. |
| **Audience scoping** (Vault key split) | ✅ Complete | `READ_SCOPES` restricts the read minter to three audiences (`accounts.svc`, `transactions.svc`, `cards.svc`). A write audience (`payments.svc`) raises `KeyError`. The read/write key split means even holding the right key, a token from this minter carries the wrong scope for write endpoints. Istio matches on claims as well as signature. |
| **Internal JWTs sender-constrained** (Vault key split) | ✅ Complete | Internal tokens (§7.2 of handoff) are signed with separate read/write keys. The MCP server process holds only the read key; the approval callback holds the write key. Istio enforces issuer-based routing — a read-signed token cannot reach write endpoints. |

### Partially in place

| Control | Status | Details |
|---|---|---|
| **Client IP/ASN anomaly detection** (ZT-5) | ✅ Shipped (entered as "not wired" 2026-09-20, corrected 2026-09-26) | `IpTracker` in `postern_core.risk.context` and `IpAnomalyDetector` in `postern_core.risk.ip_anomaly` detect impossible travel and excessive IP diversity; `postern_core.net` does the extraction and `services/api/middleware/risk.py` wires it. The original entry read "IP/ASN tracking is not yet implemented — no `client_ip` or `x-forwarded-for` extraction exists in the codebase", which was true when written and false by the time this record was being cited for it. **This is the only compensating control on the read path that can separate an attacker's presentation of a stolen token from the customer's**, because that token is multi-use for its 60 seconds by design (record 0014). |

## Decision: accept the risk with compensating controls

### Rationale

1. **DPoP is not implementable today.** The MCP 2026-07-28 spec has no
   extension mechanism, reference clients do not support it, and FastMCP 4.x
   has no DPoP middleware. Unilateral adoption would break the bootstrap tool
   and all non-DPoP clients.

2. **Compensating controls cover the attack surface.** A stolen bearer token
   faces ~~three~~ **two** independent barriers:
   - **60-second TTL** — the window of exploitation is narrow.
   - ~~**jti replay cache** — even within 60 seconds, the same token cannot be
     used twice (the cache raises `ValueError` on duplicate jti).~~ **False,
     struck 2026-09-26.** Within 60 seconds the same token can be used as many
     times as its holder likes, by design: an MCP client presents one access
     token on every tool call in the window. Nothing counts presentations on
     this side. Decision record 0014.
   - **Revocation list** — if the token is detected as compromised, revoking
     the customer+client pair blocks all future mints instantly.

   Two barriers do not cover the attack surface; they narrow it. The heading
   above is left as written because it is what was argued at the time, and
   `dev-docs/postern-zero-trust-plan.md` 5.5 is what the residual actually is.

3. **Internal tokens are already sender-constrained.** The Vault key split
   (§7.2) means internal JWTs cannot be replayed across the read/write
   boundary, and Istio enforces issuer-based routing.

4. **The IP/ASN gap is closed; this entry is kept for the record.** ~~Without
   client IP tracking, an attacker who steals a token and replays it from
   different infrastructure within the 60-second window is not detected.~~
   Struck 2026-09-26: origin anomaly detection shipped, and the three bullets
   below describe a state that no longer holds. ~~(before jti
   cache eviction)~~ struck 2026-09-26: eviction has nothing to do with it,
   and origin is the only signal on this side that separates the attacker's
   presentation from the customer's. This is a real gap, but:
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
- `test_a_repeated_jti_raises_and_only_a_collision_could_repeat_one` — the
  raise exists, and the test name says what reaches it. Renamed 2026-09-26
  from `test_jti_cache_detects_manual_replay`, which named an event no input
  in this repository produces.
- `test_revocation_checked_before_replay_cache` — revocation fires before the
  jti cache, so a revoked customer is rejected even if their previous token's
  jti is still cached.
- `test_the_cache_never_fires_on_the_mint_path_it_guards` — two identical mint
  requests raise nothing. Renamed 2026-09-26 from
  `test_jti_cache_blocks_duplicate_token`, whose body had always asserted this
  and whose name had always said the opposite. That name is how the row above
  got its ✅.

See also: `dev-docs/postern-zero-trust-plan.md` §4 (ZT-6 work item),
`docs/superpowers/plans/postern-foundation-and-read-surface-2026-09-12.md`
(DPoP investigation, line 44).

> **Amended 3 October 2026.** Session-revocation pruning is now built, which
> corrects the "Not built" paragraph in the layer-1 amendment above: a companion
> sorted set `revoked:sessions:exp` (score: prune-after instant, ms) is written
> beside the `SADD`, entries are removed 930 s after the write, and
> `revoke.py prune-sessions` runs a batch on demand. Members written by a plain
> `SADD` have no index entry and are never pruned. See
> `dev-docs/device-grant-session-token-spec.md` section 11.

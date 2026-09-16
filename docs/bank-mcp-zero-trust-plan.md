# Bank MCP — Zero Trust Implementation and Mitigation Plan

**Companion to** `bank-mcp-design-handoff.md`. That document is the architecture; this one is the security posture, the threat model, and the work items needed to make zero trust real rather than claimed. Section references in the form §N.N point to the handoff document.

**Audience:** a Claude Code session implementing this, with access to the codebase and AWS accounts.

**Status:** assessment complete, work items defined, none implemented.

---

## 0. How to use this document

1. **§2 is the honest assessment.** The design is unusually well aligned with zero trust already. Do not rewrite what is working.
2. **§4 is the work list.** Each item has severity, acceptance criteria, and dependencies. ZT-2 blocks everything else — do it first.
3. **§5 covers risks that cannot be eliminated**, only bounded. Do not let anyone treat these as closed.
4. **§6 is how you prove it.** Controls without tests are claims. Every work item ends in a CI gate or a documented control.
5. **Do not let network isolation be cited as a zero trust control.** PrivateLink is blast-radius reduction (§5.2 of the handoff). The identity layer is the control.

---

## 1. What "zero trust" means for this system specifically

The system's defining property: **an LLM the bank does not control decides which tools to call, on behalf of a customer, against their real money.** Prompt injection is not a hypothetical — transaction descriptions, payee names and merchant strings are attacker-controllable text that lands in the model's context.

So the operating assumption is not "the network is hostile." It is stronger:

> **The caller is assumed to be under adversarial influence at all times, even when correctly authenticated.**

Every design decision follows from that. Authentication tells you *which vendor's client* is calling; it tells you nothing about what the model was instructed to do.

---

## 2. Posture assessment

### 2.1 Already zero-trust-native (do not regress these)

| Property | Where | Why it counts |
|---|---|---|
| No ambient authority | §7.2 | Per-request JWTs, 60s expiry, audience-scoped |
| No secret zero | §7.2 | Vault AWS IAM auth; the task role is the identity |
| Workload identity ≠ user identity | §7.2 | The distinction most designs collapse |
| Least privilege at the key layer | §7.2, §8.2 | Separate read/write Vault roles, separate deployables |
| Never trust the client for writes | §6.3 | Out-of-band confirmation on the user's own device |
| No trust accumulation in sessions | §3.2 | Protocol-mandated statelessness |
| Capability removal over capability control | §6.2 | No execute tool exists to misuse |
| Per-operation audit chain | §9 | Tool call → challenge → tier → device → execution |
| Minimization as privacy control | §6.5 | Masked types; data never returned cannot leak |

### 2.2 Gaps

Ranked by severity. Detail and acceptance criteria in §4.

| ID | Gap | Severity |
|---|---|---|
| **ZT-2** | Subject enforcement in domain services unverified | **Critical** |
| **ZT-1** | No continuous authorization or session revocation | **High** |
| **ZT-6** | Bearer tokens are not sender-constrained | **High** |
| **ZT-3** | No workload attestation (signing without verification) | Medium |
| **ZT-5** | No per-session anomaly detection | Medium |
| **ZT-4** | No microsegmentation inside the MCP VPC | Medium |
| **ZT-7** | Revocation exists as a concept, not a mechanism | Medium |
| **ZT-8** | Egress not default-deny; NAT justification is stale | Low |

---

## 3. Threat model

### 3.1 Actors

| Actor | Capability assumed |
|---|---|
| **Prompt injection** via attacker-controlled text in the model's context | Can cause any tool call the model is capable of making, with arbitrary arguments |
| **Compromised AI vendor** | Holds valid client credentials, customer tokens, and full chat history |
| **Compromised MCP server** (RCE in `bank-mcp-api`) | Read-path Vault key, database access, all in-flight sessions |
| **Stolen customer device** | App access if unlocked; cannot pass tier-2 identity verification |
| **Cross-device phishing attacker** | Can display our QR on their own page and harvest a session |
| **Malicious insider** with Vault access | Can mint tokens for any subject |
| **Compromised backend service** | Whatever that service can reach |

### 3.2 Attack scenarios and current coverage

| # | Scenario | Current mitigation | Residual |
|---|---|---|---|
| **A1** | Injected text in a transaction memo causes `create_payment` to an attacker IBAN | No execute tool (§6.2); push payload built server-side from the stored row (§6.3); `payee_ref` only, no raw IBAN from the agent (§6.5) | User approves a payment they did not intend but *can see correctly*. Social engineering remains. |
| **A2** | QR relayed to a phishing page; victim approves the attacker's session | Pairing code shown on both surfaces and confirmed **before** identity verification; rotating QR; short TTL (§7.3) | Depends on the app actually implementing the pairing screen — **open question 10** |
| **A3** | RCE in `bank-mcp-api` attempts a payment | Read-path Vault key only; Istio rejects write-audience claims; write path is a separate deployable (§7.2, §8.2) | Attacker can read everything the read role can read |
| **A4** | Valid token replayed from attacker infrastructure | **None — bearer tokens** | **ZT-6** |
| **A5** | Confused deputy: customer A's session reads customer B's accounts | JWT `sub` propagated (§7.2) — **enforcement unverified** | **ZT-2 — critical** |
| **A6** | Bulk exfiltration via many legitimate-looking reads | Bounded result sets, per-client rate limits (§6.5) | No per-customer behavioural baseline — **ZT-5** |
| **A7** | Malicious dependency in the Python image | ECR scan + Trivy + SBOM (§12.4) | Signing without deploy-time verification — **ZT-3** |
| **A8** | AI vendor breach exposes tokens and chat history | Masking (§6.5); per-client kill switch (§1) | Kill switch not built — **ZT-7**; long-lived tokens widen the window — **ZT-1** |
| **A9** | Insider mints a token for an arbitrary subject | Vault audit log | Writes still require a real device confirmation and a valid `challenge_id` — strong |
| **A10** | Replay of a captured signed approval | `jti`, short expiry | Needs an explicit replay cache — folded into **ZT-1** |
| **A11** | Risk signal appears mid-session (fraud report, SIM swap, impossible travel) | **None** | **ZT-1** |

---

## 4. Work items

### ZT-2 — Verify and enforce subject scoping in domain services
**Severity: critical. Do this before anything else.**

Istio *validates* the JWT; the domain services must *enforce* on it. If any service scopes a query by an account ID taken from the request body rather than by the token `sub`, the entire authorization layer is decorative and A5 is live.

**Do:**
- Audit every domain service handler reachable from the MCP façade. Produce a list: enforces on `sub` / does not.
- For each that does not, the fix is in that service, not in the MCP server. Raise with the owning team — this is likely the largest cross-team item in the programme.
- Add a contract test per domain service: a token for customer A requesting customer B's account returns 403, not 200.

**Acceptance:** an automated test suite, run in the backend services' CI, covering every MCP-reachable endpoint with a cross-customer request. Zero passes.

**Dependency:** backend service teams. **Start the conversation on day one.**

---

### ZT-1 — Continuous authorization and revocation
**Severity: high.**

Tokens are issued once at the QR flow and an agent session can run for hours. Zero trust requires continuous evaluation, not point-in-time.

**Do:**
- Short access-token lifetime (10–15 min) with refresh; **refresh re-evaluates risk** rather than rubber-stamping.
- Consume risk signals from the fraud platform on refresh: device flagged, fraud reported, SIM swap, impossible travel, consent revoked in-app.
- Implement **CAEP / Shared Signals Framework** receiver semantics if the fraud platform emits them — it likely already does for the mobile channel.
- Push-based revocation: a revoked session must die within seconds, not at next refresh. Revocation list checked on every token mint (§7.2) — cheap, since minting is local.
- `jti` replay cache covering the token lifetime (A10).
- Re-evaluate on **tier escalation**: moving from a read to a tier-2 write is a natural checkpoint.

**Acceptance:** revoking a session in the bank app terminates agent access within 30 seconds, proven by test. A fraud flag raised mid-session blocks the next tool call.

**Dependency:** fraud/risk platform team — what signals exist, in what form.

---

### ZT-6 — Sender-constrained tokens
**Severity: high.**

Bearer tokens are the classic zero-trust weakness: possession is authorization. A token exfiltrated from an AI vendor's infrastructure (A8) works from anywhere.

**Do:**
- Investigate **DPoP (RFC 9449)** for the client→MCP-server layer. Binds the token to a key the client holds, so a stolen token is useless without the key.
- **First: check whether the MCP authorization spec at `2026-07-28` supports or mandates DPoP, and which client vendors implement it.** If Claude, ChatGPT and Perplexity do not, this cannot ship unilaterally — we design for the weakest client (§1).
- If DPoP is not viable, compensate: shorter token lifetimes (ZT-1), client IP/ASN anomaly detection (ZT-5), and strict audience scoping.
- Internal JWTs (§7.2) are already effectively sender-constrained by the Vault key split — no change needed there.

**Acceptance:** either DPoP is implemented end-to-end with at least one client, or a written decision record stating why not and which compensating controls carry the risk.

---

### ZT-3 — Workload attestation
**Severity: medium.**

§12.4 signs images with cosign. Signing without verification is ceremony.

**Do:**
- Verify cosign signatures **at deploy time** as a hard gate — reject unsigned or mismatched images.
- Verify SBOM presence and scan results as part of the same gate.
- Pin base images by digest (already in §12.2) and fail the build on drift.
- Runtime threat detection on the Fargate tasks (GuardDuty Runtime Monitoring or equivalent) — the tasks are internet-facing.
- Confirm the read task role **cannot** assume the write role or read its Vault path; automated IAM policy test (§12.3).

**Acceptance:** a deliberately unsigned image fails deployment in a test run. The IAM policy test is in CI and passing.

---

### ZT-5 — Session and behavioural anomaly detection
**Severity: medium.**

Static tiers plus payment risk rules, but nothing watches the session. Forty calls pulling five years of transactions look identical to normal use at the per-request level (A6).

**Do:**
- Per-session budgets: total records returned, distinct accounts touched, time span requested. Exceeding a budget escalates the tier rather than hard-failing.
- Per-customer baselines: typical volume, typical hours, typical clients.
- Alert on: first use of a new client, geographic/ASN change mid-session, read volume far above baseline, repeated declined challenges.
- Feed these into ZT-1's refresh evaluation so anomalies shorten the session rather than merely logging.

**Acceptance:** a synthetic bulk-read session triggers an alert and a tier escalation in a test environment.

---

### ZT-4 — Microsegmentation inside the MCP VPC
**Severity: medium.**

The handoff specifies two deployables but not the network policy between them.

**Do:**
- Separate security groups per service. `bank-mcp-api` must **not** be able to reach `bank-mcp-confirm` directly — the confirmation callback arrives from the backend, not from the API service.
- Database-level separation: distinct Postgres roles per service, with `bank-mcp-api` holding no write grant on the challenges table beyond inserting pending rows.
- PrivateLink endpoint security groups scoped to the specific task security groups, not the VPC CIDR.
- Document explicitly that network isolation is **defence in depth, not the control**.

**Acceptance:** a connectivity test from an `api` task to a `confirm` task fails. Database grants reviewed and documented.

---

### ZT-7 — Revocation mechanism
**Severity: medium.**

Per-client kill switches and customer consent revocation are referenced but not designed.

**Do:**
- Per-client kill switch: disable one AI vendor without affecting others, effective within seconds.
- Per-customer, per-client revocation from inside the bank app — customers must be able to see and cut active agent sessions, same as any other connected-app list.
- Per-session revocation (one device, one client) without killing the customer's other sessions.
- Surface active sessions in the app: which client, since when, what it accessed.

**Acceptance:** each revocation scope demonstrably terminates access within 30 seconds without collateral effect.

---

### ZT-8 — Default-deny egress; re-examine the NAT Gateway
**Severity: low, but has a cost saving attached.**

§5.3 justifies NAT Gateway + Elastic IP by ASPSP whitelisting. **With own-backend-only scope, that justification is stale.**

**Do:**
- Enumerate what actually requires internet egress. Likely candidates: push notification providers, OTel/observability endpoints, CRL/OCSP. Possibly nothing.
- If egress is needed, default-deny with an explicit allowlist via VPC endpoints or an egress proxy — not an open NAT route.
- If not needed, **remove the NAT Gateway.** It is the single largest fixed cost in the stack (~€35/month per AZ).
- Use VPC endpoints for AWS services (ECR, Secrets Manager, SSM, CloudWatch) regardless.

**Acceptance:** a documented egress allowlist, and either a NAT Gateway with a written justification or no NAT Gateway.

---

## 5. Irreducible risks — bound, do not close

These cannot be engineered away. Document them, get them accepted explicitly, and revisit them.

### 5.1 Client runtime integrity cannot be attested
We authenticate *which vendor* is calling. We cannot verify the model was not prompt-injected, what system prompt wrapped our data, or how the response was rendered.

**Bounding:** out-of-band confirmation for every write (§6.3); reads cheap, money expensive — the correct asymmetry; capability removal rather than capability control (§6.2); strict `outputSchema` so figures are structured rather than paraphrasable (§6.5).

**Accepted residual:** a customer may be socially engineered into approving a payment they can see correctly. This is the same residual as any push-confirmation channel, and no worse.

### 5.2 Third-party retention is unrecallable
Tool results land in vendor chat histories under vendor retention policies. There is no MCP "do not persist" flag, and a note in a tool description is a prompt, not a control.

**Bounding:** minimization as the primary mechanism (§6.5); masked types; bounded result sets; consent screen naming the client and the disclosure; per-client kill switch (ZT-7).

**Accepted residual:** everything ever returned through this channel is permanently outside the bank's control. **This is a legitimate reason to scope this channel more tightly than the bank's own app.**

### 5.3 We do not control rendering
A client may paraphrase a balance incorrectly and a customer may act on it.

**Bounding:** structured amounts with explicit currency and `as_of`; account identifier alongside every balance; strict output schemas.

**Open:** conduct-risk position on erroneous rendering by a third-party client. **Needs a decision from the conduct/compliance function — this is not an engineering call.**

### 5.4 Regulatory treatment is unsettled
Whether consumer AI agents acting for a bank's own customers constitute an account information service has not been tested (handoff §1, open question 2).

**Bounding:** design as reading (a); do not market to third-party organizations; keep the dedicated-interface option open by using Open Banking-shaped contracts.

**Action:** compliance opinion on record. Do not let it block the build.

---

## 6. Proving it — controls and evidence

Controls without tests are claims. Every item above ends in one of these.

### 6.1 CI gates (blocking)

| Gate | Covers |
|---|---|
| Golden masking test — every tool vs PAN/IBAN regex | §6.5, A6, A8 |
| Header/body mismatch → 400 + `-32020` | §3.3 |
| Import-linter: `services/api` cannot import the write path | §8.2, A3 |
| IAM policy test: read role cannot assume write role or read its Vault path | ZT-3, A3 |
| Cross-customer contract tests per domain service | ZT-2, A5 |
| Cosign signature + SBOM verification at deploy | ZT-3, A7 |
| Backend OpenAPI contract tests | §8.5 |

### 6.2 Red team scenarios (run before production)

1. Injected instruction in a transaction memo attempting to initiate a payment (A1).
2. QR relay to a separate browser; confirm the pairing code mismatch blocks it (A2).
3. Token captured from one client, replayed from different infrastructure (A4, ZT-6).
4. Cross-customer account access with a valid token (A5, ZT-2).
5. Bulk transaction extraction across many calls; confirm alerting fires (A6, ZT-5).
6. Session revocation mid-conversation; confirm timing (ZT-1, ZT-7).

### 6.3 Evidence for auditors

The per-operation audit chain (§9) is the core artifact: tool call and arguments → challenge → verification tier required and satisfied → device → execution. Plus: the risk manifest declaring each tool's tier, the IAM policy test results, the egress allowlist, and the decision records from §5.

---

## 7. Sequencing

| Phase | Items | Gate |
|---|---|---|
| **Before writing code** | ZT-2 audit started; fraud-signal inventory for ZT-1; DPoP viability check for ZT-6 | Know whether ZT-2 is a small fix or a programme |
| **With the skeleton** | ZT-4 (security groups, DB roles), ZT-8 (egress enumeration), CI gates from §6.1 | These are cheap now, expensive later |
| **Before shipping reads** | ZT-2 complete, ZT-3 deploy gate, ZT-7 kill switches | Reads cannot ship with A5 open |
| **Before shipping writes** | ZT-1 complete, ZT-5 baseline alerting | Money cannot move without continuous authorization |
| **Before production** | §6.2 red team scenarios; §5 residuals formally accepted | |

**ZT-2 is the critical path.** If the domain services do not enforce on the token subject, nothing else in this plan matters — and finding out it is a large change six weeks in would be the worst outcome available. Answer it in week one.

---

## 8. Open dependencies on other teams

| Team | Question |
|---|---|
| Backend domain services | ZT-2: does every handler enforce on JWT `sub`? Do pre-masked agent-facing projections (handoff §10.17) decide PCI DSS scope? |
| Fraud / risk platform | ZT-1: what signals exist, in what form? CAEP/SSF available? |
| Mobile | Pairing-code screen (handoff Q10); session list and revocation UI (ZT-7) |
| Platform / Vault | Two signing roles, JWKS hosting, sidecar pattern (handoff Q22, Q27) |
| Platform / supply chain | Signing, SBOM format, deploy-time verification (ZT-3, handoff Q26) |
| Conduct / compliance | §5.3 rendering risk; §5.4 regulatory position |
| DPO | Art. 9 basis and DPIA (handoff Q9); third-party disclosure analysis (Q19) |

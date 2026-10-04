# Payments producer core: design

Date: 4 October 2026. Status: draft for capo review. Slice 1 of the payments producer.

## 1. Purpose

Everything downstream of a `challenges` row exists and is tested: the approval callback, the Ed25519 device-signature check, the single-use `pending -> approved` claim, the executor, the write token and the audit rows. Nothing upstream exists. No code outside tests calls `create_challenge`, and `payments.create_payment` and `payments.get_payment_status` are not registered. This slice adds the two tools, behind a flag that is off by default, together with the data and read-side pieces they need. After it, a client can propose a payment and read its status. Nothing can yet show the proposal to a phone, and nothing enforces the tier at approval, so the flag stays off in production (section 13).

## 2. Non-goals

Each of these is left out on purpose, with its blocker.

| Not in this slice | Why | Blocked by |
|---|---|---|
| Delivery of the challenge to the phone, and an endpoint the app can read it from | No push sender, no device registry, no read route exists; only `POST /challenges/{id}/approve` does | Handoff §10.4, another team |
| Tier-2 enforcement at approval | `services/confirm/callback.py` never reads `row.tier`, and stores `verification_result` unvalidated, so a tier-2 payment can be approved on a device signature alone | A separate slice in `services/confirm` |
| Consent-grant flow | Nothing writes `consents` rows (`sql/02-grants.sql` says so), so no client can be granted `payments` | A separate flow |
| New-payee entry | The IBAN is typed in the app, so the signed stored row cannot bind it (handoff §6.5, §10.18) | App team, §10.18 |
| Approval consulting `client_id` / `session_jti` | The columns are added so it can; making it do so is a separate change | A follow-up in `services/confirm` |
| A decline path | `declined` exists in the CHECK constraint, but no route sets it (handoff §10.15) | Handoff §10.15 |
| A write-count or amount budget in ZT-5 | The risk engine budgets reads only | A follow-up |
| Linking audit rows to `challenge_id` | `audit_log` has no such column on the api path | A follow-up |

## 3. Decisions taken

Four decisions were taken by capo, each from the options shown below.

| Decision | Chosen | Rejected, with the reason shown to capo |
|---|---|---|
| Registration | Built into the api composition; the tools are not a `ReadModule`. The A3 control gains an explicit allowlist for the flag-on surface | A new producer module kind with its own entry-point group and a database-carrying context: new public surface, new import-linter contracts and image wiring, before a second user exists. Renaming the tools to avoid "pay": departs from the names in CLAUDE.md and the handoff, and the test would hide the capability instead of guarding it |
| Payee lookup | A new read audience `payments.svc` with scope `payments:read`, distinct from `payments:execute`, and a decision record. `GET /payees/{ref}`, scoped by the token `sub` | No lookup in this slice: any well-formed `payee_ref` is accepted, the challenge has no payee name, and the first validation happens after the user approves (a 207) |
| Tier and gating | Tier 2, from one shared declaration. Tools registered only when `POSTERN_PAYMENTS_ENABLED=1`; the flag stays off in production until tier-2 enforcement lands | Tier 1 for now: contradicts `tool-surface.json` and the handoff row, and changes what existing pending rows mean later. Tier 2 always on: leaves a pay-named write tool visible to every client with an untested gap behind it |
| Idempotency | Fingerprint of customer, tool and canonical payload, plus a partial unique index on pending rows | A required client `idempotency_key` argument: asks an adversarially influenced model to manage a key. Both together: a second contract before any client needs it |

## 4. Architecture

| Component | File | Change |
|---|---|---|
| Shared declaration | `packages/postern-core/src/postern_core/payments.py` (new) | `PAYMENT_TIER = VerificationTier.APP_IDENTITY_VERIFICATION` and the two tool-name constants. Imported by `services/api` and `services/confirm`. Not part of `postern_core.modules.write`, so the api import rule is untouched |
| Confirm operation | `services/confirm/execute.py::BUILTIN_WRITE_OPERATIONS` | The `payments.create_payment` entry takes its name and tier from the shared declaration instead of the literal `VerificationTier.APP_IDENTITY_VERIFICATION`. Same values, so `tool-surface.json` is unchanged |
| Claims provider | `packages/postern-core/src/postern_core/identity.py` | `TokenClaims` (frozen: `client_id: str \| None`, `jti: str \| None`) and `TokenClaimsProvider` (zero-argument protocol), next to `CustomerResolver` |
| Production provider | `services/api/server.py` | `token_claims_provider()` beside `token_customer_resolver()`, built on `get_access_token()`; no model-settable input |
| Tools | `services/api/tools/payments.py` (new) | `register(server, resolver, backend, runtime)` registers the two tools. Not a `ReadModule` |
| Wiring | `services/api/server.py::build_server`, `services/api/main.py` | `build_server` gains `payments: PaymentsRuntime \| None`; `main.py` builds it from the existing `Database` and the claims provider when the flag is on |
| Flag | `services/api/settings.py`, `packages/postern-core/src/postern_core/env_inventory.py` | `payments_enabled: bool`, read with `bool_from_env("POSTERN_PAYMENTS_ENABLED", False, because=...)`; inventory row `EnvVar("POSTERN_PAYMENTS_ENABLED", "flag", ("api",))` |
| Read scope | `packages/postern-core/src/postern_core/auth/read_minter.py::READ_SCOPES` | Add `"payments.svc": "payments:read"` |
| Facade | `packages/postern-core/src/postern_core/facade/payments.py` (new) | `get_payee(backend, customer, payee_ref)` only; returns `Payee(payee_ref: Ref, display_name: FreeText)`. No IBAN field, no write helper, no store import |
| Domain model | `packages/postern-core/src/postern_core/domain/models.py` | New `Payee`. `FreeText` and `Ref` already exist |
| Store | `packages/postern-core/src/postern_core/store/challenges.py` | New `create_pending_challenge_once(...)` and `expire_stale_pending(...)`. `create_challenge` is unchanged, so existing callers and tests are untouched |
| Model and migration | `store/models.py::ChallengeRecord`, `migrations/versions/` | Three nullable columns and one partial unique index (section 5) |
| Stub | `stub/backend.py` | `GET /payees/{ref}` with subject scoping and fixtures for both customers |
| Start session | `services/api/tools/bootstrap.py` | With the flag on, the confirmation note says payments are proposals the customer approves in their banking app (section 10) |
| Docs | `CLAUDE.md`, `docs/user-guide/`, `docs/user-guide/writing-a-module.md` | State what the flag does; correct the "no payments tool is registered" sentences; fix the module example that names `payments.svc` for a read |
| Decision record | `dev-docs/decisions/0022-payments-read-audience.md` (new) | Why a read audience is added, the scope split, and the accepted ZT-4 deviation |

No `.importlinter` contract changes. `services.api` imports `postern_core.payments`, `postern_core.facade.payments` and `postern_core.store.challenges`, none of which is in the write half or in `services.confirm`.

## 5. Data model

Migration on head `e08757299819`, run as `postern_owner`. It adds to `challenges`:

| Column | Type | Source |
|---|---|---|
| `client_id` | `String(128)`, nullable | the verified token's `client_id` |
| `session_jti` | `String(128)`, nullable | the verified token's `jti` |
| `request_fingerprint` | `String(64)`, nullable | lowercase hex SHA-256 |

Index: `Index("ix_challenges_pending_fingerprint", "customer_ref", "request_fingerprint", unique=True, postgresql_where=sa.text("status = 'pending'"))`, in the model and the migration. The repository has no earlier partial index, so `tests/test_schema_drift.py` is the check that the two agree. Rows created by other callers leave `request_fingerprint` NULL, and NULLs do not collide in a unique index.

`sql/02-grants.sql` is expected to be unchanged: `postern_app` already holds `SELECT, INSERT, UPDATE` on `challenges`, and no column grant is used. `tests/test_application_role.py` derives the set from the store modules and must be re-run to confirm.

Fingerprint: SHA-256 of `json.dumps({"customer_ref": ..., "tool_name": ..., "payload": ...}, sort_keys=True, separators=(",", ":"))`, hex digest. JSON with sorted keys avoids the ambiguity of concatenating fields.

## 6. Tool contracts

Both tools are registered with `auth=consent_for("payments", db)` and are never given the `_no_consent_required` shortcut, even when the server has no real customer auth.

### 6.1 `payments.create_payment`

Annotations: `read_only_hint=False`, `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=False`.

Arguments, all agent-supplied text and none a user or customer identifier:

| Name | Type | Rule |
|---|---|---|
| `from_account_ref` | `Ref` | the payer account |
| `payee_ref` | `Ref` | a saved payee. `Ref` enforces a three-letter prefix and nothing else |
| `amount` | `str` | `^[0-9]{1,15}(\.[0-9]{1,4})?$`, greater than zero |
| `reference` | `str \| None` | printable characters only, at most 140 characters; both checked before scrubbing |

Flow. The cheap checks on the arguments run first, so a malformed amount or reference costs no backend read; the order of refusals is therefore amount, reference, payer account, payee.

1. Amount. Match `^[0-9]{1,15}(\.[0-9]{1,4})?$`, require greater than zero, and build the canonical string: at least 2 and at most 4 decimal places, no exponent, so `340.5` and `340.50` give one fingerprint.
2. Reference. Refuse any character whose `unicodedata.category` starts with `C` (Cc, Cf, Cs, Co, Cn) or is `Zl` or `Zp` (U+2028, U+2029), with the fixed message `reference may contain only printable characters`. The reference is the only agent-controlled text in the approval display the phone shows, so a newline or an escape sequence could fake a line the customer reads as the server's. Plain emoji are category So and are accepted; a zero-width joiner (U+200D) is Cf and is refused, so an emoji ZWJ sequence is refused as a whole. Then reject over 140 characters with a fixed message, then pass through `FreeText`. `FreeText` strips bidi and zero-width characters but not `\n`, `\r` or `\t`, has no length limit, and silently redacts PAN- and IBAN-shaped runs and masks long alphanumeric runs, so the stored text may differ from the input; the stored text is what the user later sees.
3. `resolver()` gives the customer from the token. A missing token fails closed.
4. Payer account. Read the balance through the existing accounts facade (`get_balance`), because `Account` carries no currency; the currency comes from `Balance.amount.currency`. A `BackendError` with status 404 becomes `ToolError("account not found")`, identical for a foreign and an invented ref (the stub returns one constant 404 body for both).
5. Payee. `facade.payments.get_payee`; a 404 becomes `ToolError("payee not found")`.
6. Currency. Build `Money(amount=..., currency=<account currency>)` so `domain/money.py` enforces finiteness and a three-letter currency; a failure is reported as the amount refusal.
7. Payload, all values strings, built only from server-resolved data:
   `{"from_account_ref", "payee_ref", "payee_name", "amount", "currency", "reference"}` (`reference` omitted when absent). Floats are never present, because `canonical_approval_message` raises `UncanonicalChallengeError` on them.
8. Fingerprint (section 5).
9. In one transaction, `create_pending_challenge_once`, which expires this customer's stale pending rows with this fingerprint inside each of its (at most two) passes, using `statement_timestamp()` as `_select_live_pending` does. The insert is an `INSERT ... ON CONFLICT (customer_ref, request_fingerprint) WHERE status = 'pending' DO NOTHING RETURNING`; on no row it selects the existing pending row. The challenge id is `uuid4().hex` (32 characters, fits `String(36)`), tier is `PAYMENT_TIER`, `client_id` and `session_jti` come from the claims provider. Commit.
10. Return `{challenge_id, status: "pending", expires_at, human_summary}` where `human_summary` is "Approve {currency} {amount} to {payee_name} in your banking app." The summary is relayed by the model and is not the authoritative display; the authoritative display is rendered from the stored row.

A repeat inside the pending window returns the same `challenge_id` and `expires_at`. Once the row is approved, executed or expired, an identical request creates a new challenge; the user still approves each one, and this consequence is intended.

### 6.2 `payments.get_payment_status`

Annotations: `read_only_hint=False` (it may expire a row), `destructive_hint=False`, `idempotent_hint=True`, `open_world_hint=False`.

Argument: `challenge_id`, a string matching `^[A-Za-z0-9_-]{1,36}$`. It is not a `Ref`: ids made by this slice are 32 hex characters, and other callers use ids such as `chal_int_001`. The pattern is enforced in the handler on purpose, not in the tool's input schema, so that a malformed id and an unknown id get the same refusal and FastMCP's input-echoing validation text is never produced.

Flow:

1. Resolve the customer.
2. `get_challenge`. If the row is missing, belongs to another customer, or has a `tool_name` other than `payments.create_payment`, raise `ToolError("challenge not found")`. The three cases are one code path and one message.
3. If `status == "pending"`, apply the existing conditional update `pending -> expired` with `expiry="expired"` (the database clock decides), and report the resulting status.
4. Fail closed on an unreadable payload: if it is not an object, or `amount`, `currency` or `payee_name` is missing or not a string, raise `ToolError("the payment status could not be read")` (`reference` stays optional).
5. Return `{challenge_id, status, expires_at, amount, currency, payee_name, reference}` from the stored payload. Never the signature, `confirming_device`, `verification_result`, the fingerprint, `client_id`, `session_jti` or the raw payload.

An approved row whose backend call failed (the callback answers 207) stays `approved`. No status is invented; the documentation says an `approved` payment may not have executed.

## 7. Token claims

`ReadContext` carries exactly `resolver` and `backend`, pinned by `tests/test_module_seam.py::test_a_read_context_carries_only_the_resolver_and_the_backend`, and `build_server` receives `db` only when real customer auth is configured. The producer therefore does not go through `ReadContext`:

- `CustomerResolver` stays the only source of the customer.
- `TokenClaimsProvider` (section 4) supplies `client_id` and `jti`. The production implementation calls `fastmcp.server.dependencies.get_access_token()` exactly as `RevocationMiddleware._claims` does: `client_id` from `token.client_id`, `jti` from `token.claims`. `client_id` is the value the verifier derives (the `client_id` claim, else `azp`, else `sub`), the same one `RevocationMiddleware` keys on, which is why it is stored; it is NULL only when the token is absent or the value exceeds 128 characters. `jti` is NULL when absent or over 128 characters.
- Under the in-process `Client(transport=server)` there is no token, so tests pass a provider such as `lambda: TokenClaims(client_id="claude-code", jti="j-1")`. Tests with a real token use `create_app(..., auth_override=<JWTVerifier>)`, as `tests/test_zt7_revocation_reachable.py` does.
- When a value is absent or too long the column is NULL and the tool does not fail; it is a record for later revocation matching, not a gate.

## 8. Audit

The api audit middleware wraps every registered tool. The account and payee reads go through `BackendClient`, so the `reaching` row is written once, on the first read (`_PendingEntry.record` is guarded to once per call), followed by one completion row, correlated by `call_id`. Both writes fail closed (decision 0006). The challenge insert and the status update are plain database writes by the tool and are not audit rows. `arguments` in both rows hold the tool arguments, scrubbed and clipped to 512 characters per value, so `reference` appears there. The returned `challenge_id` is not recorded; linking it is a non-goal.

## 9. Errors

Tool errors in this stack are `isError` results inside an HTTP 200. Messages are fixed strings raised as `ToolError`; no `ValidationError` text from this tool's own checks reaches the client (`errors(include_input=False)` wherever one is rendered). One exception: for a malformed `Ref` argument, FastMCP returns its own argument-validation text, which echoes the caller's own input and is logged at WARNING. That holds for every `Ref`-taking read tool as well, it never carries another customer's data, and the audit row stores it scrubbed.

| Failure | Client sees | Fails closed |
|---|---|---|
| Unknown or foreign payer account | `account not found` | yes |
| Unknown or foreign payee | `payee not found` | yes |
| Amount not a positive decimal with at most 4 places | `amount must be a positive decimal with at most 4 decimal places` | yes |
| Reference with a control, format, surrogate, private-use or unassigned character, or U+2028 or U+2029 | `reference may contain only printable characters` | yes |
| Reference over 140 characters | `reference is limited to 140 characters` | yes |
| Challenge unknown, foreign, or not a payment | `challenge not found` | yes |
| Database error on `create_payment`'s insert or its select | `the payment could not be recorded` | yes, nothing created |
| Database error on `get_payment_status`'s select or update | `the payment status could not be read` | yes |
| Stored row of the caller's own payment whose payload is not an object, or lacks a text `amount`, `currency` or `payee_name` | `the payment status could not be read`, logged at ERROR naming the tool only | yes |
| Any other `BackendError` (5xx, timeout) | the facade's existing text | yes |
| `payments` consent not granted | `Unknown tool: 'payments.create_payment'`, the existing consent behaviour; the tools are also absent from `tools/list` | yes |

## 10. Flag-on effects

Flag off (default): the registered tools, `tools/list`, `start_session` output and the first two sections of `tool-surface.json` are exactly as today. This is a tested property.

Flag on:

- The two tools are registered. A client sees them only if its customer has a `payments` consent row; nothing in the repository writes one.
- `start_session` still reports `payments` as `granted=False` and `write_enabled=[]`. Its `_CONFIRMATION_NOTE` ("It cannot move money or change anything") is replaced by a note that says, in substance: "If payment tools are listed for this customer, they only propose a payment. A proposal moves no money: the customer approves each one in their banking app, never in this conversation, and nothing here can approve or execute it." The note is static: whether the tools are listed depends on the customer's `payments` consent, which `start_session` does not report (the hard-coded `granted=False` stays and is a known limit until a consent flow exists). The note promises neither that the tools are available nor that a prompt reaches the phone.

## 11. Security properties

| Item | How this design meets it |
|---|---|
| A1, injected memo | The payload is built from server-resolved data. The agent supplies a payee reference and an amount, never a name or an account number, and `payee_name` comes from the backend. A wrong proposal is still possible; the user sees the stored row, not the agent's text |
| A3, RCE in the api | The api can insert and expire pending rows, which `postern_app` could already do. It cannot approve (needs an enrolled device signature and a banking-app assertion) or execute (no write key). With the flag off the tools do not exist |
| A5, cross-customer | The payer account, the payee and the challenge are each scoped by the token's customer; foreign and unknown are one refusal |
| A10, replay of an approval | Unchanged: the single-use conditional update in `services/confirm` |
| ZT-4 | Read audience only in the api process. Accepted deviation: the api issues an `UPDATE` on `challenges` (`pending -> expired`) where the plan expects insert-only. The shared `postern_app` role already holds `UPDATE`, and a pending-to-expired transition leaves no information the row did not hold. Recorded in decision 0022 |
| ZT-5 | Tier is stored on the row; nothing reads it yet (non-goal) |
| ZT-7 | `client_id` and `session_jti` are stored so the approval path can match all three revocation scopes later (non-goal) |

## 12. Tests

New and changed tests, with the file.

| Test | File |
|---|---|
| Default (flag-off) server: the existing blocklist, read-only and facade tests still pass unchanged | `tests/test_no_write_from_api.py` |
| Flag-on allowlist: registered names are the seven expected (5 read plus exactly `payments.create_payment`, `payments.get_payment_status`), annotations as in section 6, no other non-read tool, no other tool containing "pay", "execute", "submit" or "transfer" | `tests/test_no_write_from_api.py` |
| Flag-off surface is byte-identical: `tools/list`, `start_session`, `read_tools` and `write_operations` in `tool-surface.json` | `tests/test_tool_surface_golden.py` |
| New `producer_tools` section in `tool-surface.json`, generated from a flag-on server by `tests/tool_surface.py`; the 5-read and 6-write assertions are unchanged | `tests/test_tool_surface_golden.py`, `tests/tool_surface.py`, `tool-surface.json` |
| `PAYMENT_TIER` is what `services/confirm` registers and what the api uses | `tests/test_payments_tier.py` (new) |
| Masking golden cases for both tools, including `payee_name` and `reference` | `tests/test_masking_golden.py` |
| Cross-customer: payee and payer account against the stub; challenge ownership against Postgres, byte-identical for foreign, unknown and non-payment ids | `tests/test_stub_subject_scoping.py`, `tests/test_payments_producer.py` (new) |
| Idempotency: repeat returns the same id and `expires_at`; two concurrent calls make one row; a stale pending row is expired and a new one created; fingerprint stable and key-order independent and sensitive to every field | `tests/test_payments_producer.py` |
| `get_payment_status` expires a past-deadline pending row and reports `expired`; leaks none of the forbidden fields | `tests/test_payments_producer.py` |
| Payload is all strings and `canonical_approval_message` accepts it with a test Ed25519 key | `tests/test_payments_producer.py` |
| A produced row is approved through the real callback and the executor posts the stored payload (mock transport, as `tests/test_approval_integration.py` does) | `tests/test_payments_producer.py` |
| Audit: one `reaching` and one completion row for a successful call; one row for a call refused by consent | `tests/test_payments_producer.py` |
| `payments.svc` maps to `payments:read`, distinct from `payments:execute`; an audience not in `READ_SCOPES` still raises; the facade has no write helpers | `tests/test_read_minter.py`, `tests/test_no_write_from_api.py` |
| Flag parsing and inventory: accepted and refused spellings, unset is off; counts in `tests/test_settings_bounds.py` move by one (83 to 84 known variables, 5 to 6 flags, 51 to 52 bounded names, 39 to 40 api variables) | `tests/test_boolean_env_flags.py`, `tests/test_settings_bounds.py`, `tests/test_unknown_env_guard.py` |
| Schema drift, grants derivation, header/body mismatch, import-linter | `tests/test_schema_drift.py`, `tests/test_application_role.py`, `tests/test_header_body_mismatch.py`, `make imports` |

The consent-evaluation counts in `tests/test_consent_check_failure_mode.py` assume four gated tools and hold only with the flag off; the flag-on tests do not reuse them.

## 13. Rollout

The flag stays off in production until all three hold:

1. The approval path enforces the row's tier, including `verification_result` for tier 2.
2. A delivery path to the phone exists (handoff §10.4).
3. A consent-grant flow exists, so `payments` can be granted.

An RCE in the api with the flag on can insert arbitrary pending rows for any customer and expire them. That was already possible with the existing grant; the flag adds a tool surface that reaches the same writes. It cannot approve or execute.

## 14. Open dependencies

| Item | Owner |
|---|---|
| `GET /payees/{ref}` contract and response shape (`payee_ref`, `name`) | Backend teams |
| `POST /payments` accepting `payee_name`, and the stored payload as its body (`resolve_endpoint` forwards it unchanged) | Backend teams |
| Tier-2 enforcement at approval | `services/confirm` |
| Delivery to the phone, and what the app displays | Another team (§10.4); the app team |
| Consent-grant flow | Not assigned |
| Payments gateway enforces `payments:read` (read issuer) only on `GET /payees/*`, and requires `payments:execute` from the write issuer on write paths | Backend and platform teams |

## 15. Facts relied on

Verified by reading the code on 4 October 2026 at commit 4bb9162: the tier enum (`VerificationTier`, `APP_IDENTITY_VERIFICATION = 2`) and the literal in `BUILTIN_WRITE_OPERATIONS`; `create_challenge` and its tier-to-TTL map (30, 180, 300 seconds); the `ChallengeRecord` columns and CHECK constraints; the absence of any partial index in the repository; `CustomerResolver`, `token_customer_resolver` and `RevocationMiddleware._claims`; `ReadContext`'s two fields and `build_server`'s `db` handling; tool errors and the consent refusal text; `Money`, `FreeText` and `Ref`; `Account` having no currency; the stub's route table; `READ_SCOPES` and decision 0010's `KeyError` property; the boolean-flag mechanism and the env-count assertions; the `_PendingEntry` once-per-call guard.

Not verified: how fastmcp renders a `ToolError` on the wire (read from its source, not exercised), the `Database` session API the tool will use (to be taken from `services/api/consent.py` in the plan), and whether `tests/test_key_split_is_a_property.py`, `tests/test_read_minter.py` and `tests/test_startup_minter_probe.py` need edits when `READ_SCOPES` grows.

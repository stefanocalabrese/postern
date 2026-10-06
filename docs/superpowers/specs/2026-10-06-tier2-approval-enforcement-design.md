# Tier-2 enforcement at approval: design

Date: 6 October 2026. Status: Draft for capo review; no code. Slice 2 of the payments producer. Decision record: `dev-docs/decisions/0023-tier-2-proof-in-the-app-assertion.md`.

## 1. Purpose

`payments.create_payment` stores a tier-2 challenge row. The approval callback (`services/confirm/callback.py::_approve`) never reads the row's tier. It approves any row on a valid device signature plus a banking-app assertion, and stores whatever string the body carries as `verification_result` without validating it. A tier-2 payment can therefore be approved with no identity verification at all. `tests/test_payments_approval_path.py` approves exactly such a row today and says so.

This slice makes the callback require, for a tier-2 row, a proof that app identity verification happened for this challenge. After it, producer rollout gate 1 (spec `2026-10-04-payments-producer-core-design.md` section 13, "the approval path enforces the row's tier") is met. Gates 2 and 3 (delivery to the phone, a consent-grant flow) are not touched, so the flag stays off in production.

## 2. What the proof is, and what it is not

The tier-2 proof is a pair of claims in the banking-app assertion that already authenticates the call. The operator's app backend mints that assertion, `services/confirm/auth.py::AppAssertionMiddleware` verifies it against a configured JWKS, issuer and audience, and nothing but `sub` is read from it today. This slice reads three more claims from it for tier-2 rows.

The consequence is stated plainly because it is the limit of the control. The trust anchor is the operator's app backend saying "identity verification happened for this challenge". Nothing in this repository can check the selfie match, which the handoff (section 6.3, section 10.8) places in the operator's backend cluster. A compromised app backend, or a stolen app-assertion signing key, can mint the claims for any challenge. What the control does stop is the case today's code allows: an approval that carries no claim of verification at all, and the replay of one verification across challenges.

## 3. Non-goals

| Not in this slice | Why |
|---|---|
| A signed attestation from the identity-verification service | Needs an issuer and key from the backend team that the docs do not name (handoff section 10.13). Decision 0023 records it as the stronger alternative |
| Putting `tier` or the verification reference inside the device-signed bytes | Would change the encoding and bump `APPROVAL_DOMAIN` from `v1` to `v2`; the mobile app has no approval contract yet. Not chosen |
| An `acr`-style claim in the write token to the payments backend | Confirm enforces alone in this slice. The backend cannot consume it until its team says so (handoff section 10.23) |
| Per-device capability (a biometric-capable flag on `EnrolledDeviceKey`) | The docs do not require it |
| Any migration | The columns exist (section 8) |
| Delivery to the phone, a consent-grant flow, the app's approval-body contract beyond section 9 | Separate work, rollout gates 2 and 3 |

## 4. Decisions taken

Four decisions were taken by capo on 6 October 2026, each from the options shown.

| Decision | Chosen | Rejected |
|---|---|---|
| Proof | Claims in the existing app assertion | A signed attestation from the identity-verification service (no issuer or key defined); a lookup against the operator's backend (a new outbound dependency, no stub route); validating the free-text `verification_result` only (proves nothing) |
| Binding | The assertion carries `challenge_id`, checked equal to the URL's challenge | Adding tier and reference to the device-signed message (breaking encoding change, `v2`); no binding (replay across payments) |
| Failure | 403, the row stays `pending` | 403 and move the row to `declined` |
| Scope | Confirm only, enforced on the tier stored in the row; tier 1 rows unchanged; tier 0 refused for writes; write token unchanged | Also forwarding an `acr` claim to the backend |

## 5. The rule

For a challenge row with `tier == 2`, `_approve` requires all of the following in the verified assertion's claims, after the device signature has verified and before the claiming `UPDATE`:

| Claim | Requirement |
|---|---|
| `acr` | A string equal to the configured value `POSTERN_CONFIRM_IDV_ACR`. Exact comparison, no case folding or trimming |
| `challenge_id` | A string equal to the `challenge_id` in the request path |
| `jti` | A non-empty string, at most 128 characters. The assertion path does not require a `jti` today, so a tier-2 approval requires one explicitly |

`sub` equal to the row's `customer_ref` is already enforced by the ownership check and is not repeated. The assertion's `exp`, `iat` and `nbf` are already checked by `_lifetime_refusal` (default lifetime ceiling 300 seconds) and are not repeated.

Tier handling, by the row's stored `tier`:

| Row tier | Behaviour |
|---|---|
| 1 | Unchanged. The body's `verification_result` and `confirming_device` are stored as today |
| 2 | The rule above. The body's `verification_result` is ignored; the stored `verification_result` is the assertion's `jti` |
| 0 | Refused with 403, detail `tier_unsupported`, row stays `pending`. Tier 0 is a read tier and no producer creates a tier-0 write row. The column's CHECK allows 0, so the callback must say what it does with one |

If `POSTERN_CONFIRM_IDV_ACR` is unset, every tier-2 approval is refused with detail `verification_not_configured`. Confirm still starts, because it does not know whether the api runs with the payments flag, and tier-1 approvals do not need the setting.

## 6. Position in the flow

`_approve` in `services/confirm/callback.py`, in order: revocation check (444), signature presence (457), `get_challenge` (465), ownership check (495), signature verify (533 to 537), claiming `UPDATE` (550 to 562), commit (576), executor.

The tier check goes between the signature verify and the claim. Line 538 is blank and 539 begins the comment for the claim step; the new block takes that gap, inside the same `async with db.sessionmaker()`. This keeps three properties: an unauthenticated or wrongly-signed caller is refused by the existing 403 before learning anything about the row's tier, the existing byte-identical 404 for foreign or unknown challenges is untouched, and a refusal before the claim writes nothing, so the row stays `pending` and the customer can retry inside the tier's 300-second window.

`_approve` does not receive the claims today. `verified_claims(request)` is already imported in `callback.py` (line 134), so the block calls it, or `approve_challenge` passes the dict it already reads at line 293 into `_approve`. The plan picks one; both are equivalent.

## 7. Refusals

All three refuse before the claim, return HTTP 403 with `{"error": code, "error_description": text}` and a fixed description, and write one audit row on the existing path (`audit.raised(detail)`).

| Case | `error` | `detail` |
|---|---|---|
| Tier 2, a required claim missing, of the wrong type, not equal, or `jti` empty or over 128 characters | `verification_required` | `verification_required` |
| Tier 2, `POSTERN_CONFIRM_IDV_ACR` unset | `verification_required` | `verification_not_configured` |
| Tier 0 | `tier_unsupported` | `tier_unsupported` |

The `error_description` never echoes a claim value, the configured `acr`, or which of the three claims failed, so a caller cannot learn the expected `acr` by probing. The audit `detail` for a failed claim does not say which claim failed either; it is `verification_required`. Which claim failed is recoverable by a test, not by a caller.

`detail` is an unconstrained `Text` column and no test enumerates `DETAIL_*` against `__all__`, so adding three literals to `services/confirm/audit.py` (`DETAIL_VERIFICATION_REQUIRED`, `DETAIL_VERIFICATION_NOT_CONFIGURED`, `DETAIL_TIER_UNSUPPORTED`, each also in `__all__`) needs no migration.

## 8. Storage

No schema change. For tier 2 the claiming `UPDATE` at `callback.py` 557 passes `verification_result=<the assertion jti>` instead of the body value. `challenges.verification_result` is `Text` and nullable, so it holds the `jti`. `confirming_device` keeps the body behaviour for both tiers: it is caller-supplied and unvalidated today, and this slice does not change that. The audit rows keep recording the scrubbed body, including a body `verification_result`, as they do now.

What this makes true: for a tier-2 row that reached `approved`, `verification_result` is the `jti` of an assertion that carried the configured `acr` and this challenge's id, not a string a caller chose. It is evidence only to the extent section 2 allows.

## 9. The contract the operator's app backend must meet

Added to `docs/integration/mobile-app-pairing-contract.md` as a new section, replacing the "will get its own contract" line for the tier-2 part only: to approve a tier-2 challenge, the banking app's assertion for that request must carry `acr` (the value the operator configures in `POSTERN_CONFIRM_IDV_ACR`), `challenge_id` (the challenge being approved) and a unique `jti`, and must be minted after the identity verification for that challenge completed. Everything else about the challenge-approval body (the delivery of the challenge to the phone, the display) stays out of the contract, as it is today. The section states that nothing here verifies the match and that the operator's backend owns that.

## 10. Settings

One new optional string setting on `ConfirmSettings`, copied from `POSTERN_DEVICE_KEYS_PATH`'s shape (`device_keys_path: str | None = None`, read as `os.environ.get(...) or None`):

| Item | Value |
|---|---|
| Field | `idv_acr: str | None = None` in `services/confirm/settings.py` |
| Variable | `POSTERN_CONFIRM_IDV_ACR` |
| Validation | Non-empty after stripping when set; at most 128 characters; no control characters. A value that fails raises `ValueError` naming the variable, like `_check_app_link_uri` |
| Inventory | `EnvVar("POSTERN_CONFIRM_IDV_ACR", "string", ("confirm",))` in `postern_core/env_inventory.py`. The inventory prose and the counts in `tests/test_settings_bounds.py` move: rows 84 to 85, strings 32 to 33, confirm-read 63 to 64 |
| `not_numeric` set | The name is added to the hand-kept set in `tests/test_settings_bounds.py` (the producer plan missed the same step for its flag) |
| Compose | Set on `confirm` to a dev value, with a comment that it is a placeholder agreed with the app backend, not a standard value |
| Docs | A row in the Confirm Service table of `docs/user-guide/getting-started.md` and a note in `docs/user-guide/components/confirm-service.md` |

## 11. Tests

A new file `tests/test_tier2_approval.py`, plus changes to one existing test. All against the real confirm app and Postgres, like `tests/test_payments_approval_path.py`.

| Test | Asserts |
|---|---|
| Tier-2 row, assertion with all three claims | 200, executor reached once, stored `verification_result` equals the assertion `jti`, not a body value sent alongside |
| Each claim missing, wrong type, or wrong value, in turn (`acr`, `challenge_id`, `jti`; `jti` empty and 129 characters) | 403 `verification_required`, row still `pending`, executor never reached, audit row with the detail, `error_description` identical across all of them |
| Assertion minted for challenge A used on challenge B | 403, B stays `pending` |
| `POSTERN_CONFIRM_IDV_ACR` unset | 403 `verification_required`, detail `verification_not_configured`, tier-1 approval in the same app still 200 |
| Tier-1 row with extra claims, with none | 200 both, stored `verification_result` is the body value as today |
| Tier-0 row | 403 `tier_unsupported`, row stays `pending` |
| Wrong device signature with correct claims | 403 `invalid_signature` unchanged (the signature check still runs first) |
| Refusal then retry with the right claims inside the window | second attempt 200 |
| Foreign challenge with correct claims | byte-identical 404 as today |
| Mutations the review will run | skip the tier check; compare `acr` case-insensitively; compare `challenge_id` against the row instead of the path; store the body string for tier 2; accept a missing `jti` |
| Changed existing test | `tests/test_payments_approval_path.py` approves its tier-2 row with the new claims, and its comments that say tier 2 is not enforced are removed. One extra assertion there: the stored `verification_result` equals the `jti` |

Settings tests: unset, set, over-length, control character, whitespace only. The env-inventory and bounds counts move as in section 10. `verified_claims`' docstring says no claim is ever an authorization input; it is rewritten to say which three are.

## 12. Documentation changes

| File | Change |
|---|---|
| `CLAUDE.md` line 13 and line 128 | The statements that tier 2 is not enforced become the new behaviour and its limit (section 2). The flag item keeps gates 2 and 3 |
| `docs/user-guide/getting-started.md` line 100 | The flag warning drops "until approval enforces tier 2" and keeps delivery and consent |
| `docs/superpowers/specs/2026-10-04-payments-producer-core-design.md` lines 16, 32, 203, 215 | Point to this slice as done, with its date |
| `services/confirm/execute.py` 100 to 103, `callback.py` 21 and 55 to 77, `device_signature.py` 85 to 91 | Comments and docstrings that say nothing reads the tier |
| `docs/integration/mobile-app-pairing-contract.md` section 10 line 304 and a new section | Section 9 |
| `dev-docs/decisions/0023` | New, Proposed until this spec is approved |

## 13. What remains after this slice

The producer still stays off in production:

- No delivery of the challenge to the phone (handoff section 10.4).
- No consent-grant flow, and `start_session` still reports `granted=False`.
- The trust anchor for tier 2 is the app backend's word (section 2). A signed attestation from the identity-verification service is the stronger form, and needs that service's issuer and key.
- The payments backend does not see the proof (non-goals). Whether it should is handoff section 10.23.
- Compliance: Art. 9 basis, DPIA and the accessibility fallback for users who cannot complete verification (handoff sections 10.9 and 10.12) are operator sign-off items that no code here discharges.
- The zero-trust plan's claim that a stolen unlocked device cannot pass tier-2 verification holds only as far as the app backend refuses to mint the claims.

## 14. Rollout

A pure addition for tier-1 traffic, which is the only traffic today, since no production code creates a challenge with the flag off. With the flag on and `POSTERN_CONFIRM_IDV_ACR` unset, every payment approval is refused: that is the safe default and it is why the setting has no built-in value.

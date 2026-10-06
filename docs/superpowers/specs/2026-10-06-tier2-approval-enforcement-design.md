# Tier-2 enforcement at approval: design

Date: 6 October 2026. Status: Accepted 6 October 2026 (approved by capo, with the review's recommendations on the claim name and the time bound); revised after an independent review the same day; no code yet. Slice 2 of the payments producer. Decision record: `dev-docs/decisions/0023-tier-2-proof-in-the-app-assertion.md`.

## 1. Purpose

`payments.create_payment` stores a tier-2 challenge row. The approval callback (`services/confirm/callback.py::_approve`) never reads the row's tier. It approves any row on a valid device signature plus a banking-app assertion, and stores whatever string the body carries as `verification_result` without validating it. A tier-2 payment can therefore be approved with no identity verification at all. `tests/test_payments_approval_path.py` approves exactly such a row today and says so; it is the only test that approves a non-tier-1 row through the callback (measured by a mutation that refused every non-tier-1 approval: one test failed).

This slice makes the callback require, for a tier-2 row, a proof that app identity verification happened for this challenge. After it, producer rollout gate 1 (spec `2026-10-04-payments-producer-core-design.md` section 13, "the approval path enforces the row's tier") is met. Gates 2 and 3 (delivery to the phone, a consent-grant flow) are not touched, so the flag stays off in production.

## 2. What the proof is, and what it is not

The tier-2 proof is a set of claims in the banking-app assertion that already authenticates the call. The operator's app backend mints that assertion, `services/confirm/auth.py::AppAssertionMiddleware` verifies it against a configured JWKS, issuer and audience, and today `sub` is the only claim that decides anything: `client_id` or `azp` is recorded in the audit row, and `exp`, `iat` and `nbf` bound its lifetime. This slice reads four more claims from it for tier-2 rows.

The consequence is stated plainly because it is the limit of the control. The trust anchor is the operator's app backend saying "identity verification happened for this challenge". Nothing in this repository can check the selfie match, which the handoff (section 6.3, section 10.8) places in the operator's backend cluster. A compromised app backend, or a stolen assertion-signing key, can mint the claims for any challenge.

What the control stops: an approval that carries no claim of verification, and the reuse of one assertion across challenges. What it does not stop, and cannot detect: one verification backing assertions for several challenges, an `idv` value that the backend sets without a verification behind it, and an `auth_time` that the backend sets to whatever it likes. Whether any of those happens is decided by the app backend, and section 9 lists what it must do to avoid them. The `auth_time` bound only rejects an assertion that claims a verification from before the challenge existed. The proof uses a dedicated claim name, `idv`, and not the standard `acr`: RFC 9068 section 2.2.1 defines `acr` in an access token as the authentication enforced before the token was issued, constant across the tokens derived from one authorization, so a backend that copies its login session's `acr` into every assertion would satisfy an `acr` check with no verification per challenge, and nothing here could tell.

## 3. Non-goals

| Not in this slice | Why |
|---|---|
| A signed attestation from the identity-verification service | Needs an issuer and key from the backend team that the docs do not name (handoff section 10.13). Decision 0023 records it as the stronger alternative |
| Putting `tier` or the verification reference inside the device-signed bytes | Would change the encoding and bump `APPROVAL_DOMAIN` from `v1` to `v2`; the mobile app has no approval contract yet. Not chosen |
| An `acr`-style claim in the write token to the payments backend | Confirm enforces alone in this slice. The backend cannot consume it until its team says so (handoff section 10.23) |
| A uniqueness check on `jti` across assertions | Needs an index of seen values; a reused `jti` is a violation by the app backend that confirm cannot see. Stated as a limit in section 8 |
| Per-device capability (a biometric-capable flag on `EnrolledDeviceKey`) | The docs do not require it |
| Any migration | The columns exist (section 8) |
| Delivery to the phone, a consent-grant flow, the app's approval-body contract beyond section 9 | Separate work, rollout gates 2 and 3 |
| `postern_core.domain.verification.Challenge.approve` | A domain dataclass used only by `tests/test_verification_tiering.py`. It requires a non-empty `verification_result` for tier 2 and accepts tier 0, so it states a rule that differs from this one. It is not called by the callback and is left as it is; the plan records it as unused |

## 4. Decisions taken

Four decisions were taken by capo on 6 October 2026, each from the options shown.

| Decision | Chosen | Rejected |
|---|---|---|
| Proof | Claims in the existing app assertion | A signed attestation from the identity-verification service (no issuer or key defined); a lookup against the operator's backend (a new outbound dependency, no stub route); validating the free-text `verification_result` only (proves nothing) |
| Binding | The assertion carries `challenge_id`, checked equal to the URL's challenge | Adding tier and reference to the device-signed message (breaking encoding change, `v2`); no binding (replay across payments) |
| Failure | 403, the row stays `pending` | 403 and move the row to `declined` |
| Scope | Confirm only, enforced on the tier stored in the row; tier 1 rows unchanged; tier 0 refused for writes; write token unchanged | Also forwarding an `acr` claim to the backend |
| Claim name | A dedicated claim, `idv`, compared to a configured value (decided 6 October 2026, on the review's recommendation) | The standard `acr`, which RFC 9068 defines as a session-level value (section 2) |
| Time bound | A numeric `auth_time` in `[row.created_at - 30 s, now + 30 s]` is required (decided 6 October 2026, on the review's recommendation) | Leaving it out: nothing would reject an assertion that claims a verification from before the challenge existed |

Added after the independent review, not among capo's four choices, and flagged here for review:

| Addition | Reason |
|---|---|
| A row whose tier is below its operation's declared tier is refused (`tier_mismatch`) | `postern_app` holds `SELECT, INSERT, UPDATE` on `challenges` and the api connects as it, so an api compromise can insert or update a payment row to tier 1. The declared tier is static config in confirm's own process |
| `jti` is printable ASCII, 1 to 128 characters; `idv` setting validated as the same class | A NUL byte in `jti` passed "non-empty, at most 128" and then made the claiming `UPDATE` raise, producing a 500 whose description carried the SQL and its bound parameters (probed against Postgres 17) |
| The assertion `jti` is also recorded in the approval's audit row | `challenges` is not append-only for `postern_app`, so the audit row is the copy of record |
| A WARNING log naming the failed claim, and one at startup when the setting is unset | An operator otherwise cannot tell which claim failed, and with the flag on each refusal has already cost a customer a biometric verification |

## 5. The rule

For a challenge row, `_approve` decides the required tier, then checks the proof, after the device signature has verified and before the claiming `UPDATE`.

Required tier. `declared = WRITE_OPERATIONS[row.tool_name].tier` when the tool is known to confirm, otherwise none. If `declared` exists and `row.tier < declared`, the approval is refused with `tier_mismatch` (section 7). Otherwise the row's tier decides, as the table below says.

| Row tier | Behaviour |
|---|---|
| 1 | Unchanged. The body's `verification_result` and `confirming_device` are stored as today |
| 2 | The proof below. The body's `verification_result` is ignored; the stored `verification_result` is the assertion's `jti` |
| 0 | Refused with 403, `tier_unsupported`, row stays `pending`. Tier 0 is a read tier, no producer creates a tier-0 write row, and the column's CHECK allows 0, so the callback must say what it does with one. A `WriteOperation` that declared tier 0 would become unapprovable; none does (every declared tier is 1 or 2). Because the tier-mismatch check runs first, a tier-0 row is refused as `tier_mismatch` whenever its tool is declared, so `tier_unsupported` is reachable only for a tool confirm does not declare |

The proof for tier 2, with `claims = verified_claims(request)` and `expected = settings.idv_value`:

| Step | Requirement |
|---|---|
| 1 | If `expected` is `None`: refuse, detail `verification_not_configured` |
| 2 | `idv`: `isinstance(claims.get("idv"), str)` and `claims["idv"] == expected`. Exact comparison on the stored string, no case folding, trimming or normalisation |
| 3 | `challenge_id`: `isinstance(..., str)` and equal to the `challenge_id` in the request path |
| 4 | `jti`: `isinstance(..., str)`, length 1 to 128, every character in 0x21 to 0x7E |
| 5 | `auth_time`: an `int` or `float` that is not a `bool` and is finite, with `row.created_at.timestamp() - 30 <= auth_time <= time.time() + 30`. The 30 seconds is the skew `_lifetime_refusal` already allows. `row.created_at` is the stored creation time of the challenge, so an assertion that claims a verification completed before the challenge existed is refused |

Any failure of steps 2 to 5 refuses with `verification_required`. `expected` can never equal a missing or empty claim, because the setting is validated to be 1 to 128 printable ASCII characters in `__post_init__` as well as in `from_env` (section 10), and `isinstance` rejects a missing claim before the comparison.

`sub` equal to the row's `customer_ref` is already enforced by the ownership check and is not repeated. The assertion's `exp`, `iat` and `nbf` are already checked by `_lifetime_refusal` (default ceiling 300 seconds, configurable to 3600) and are not repeated.

Leak window. A leaked tier-2 assertion is usable for at most the smaller of its own `exp` and the row's `expires_at`, so at most 300 seconds from the row's creation whatever the assertion ceiling says. It also needs the device signature, and the claim is single-use: a replay of the same body on the same challenge gets 409, as `tests/test_payments_approval_path.py` pins. The assertion lifetime ceiling therefore does not matter for tier 2.

If `POSTERN_CONFIRM_IDV_VALUE` is unset, every tier-2 approval is refused with detail `verification_not_configured`. Confirm still starts, because it does not know whether the api runs with the payments flag, and tier-1 approvals do not need the setting.

## 6. Position in the flow

`_approve` in `services/confirm/callback.py`, in order: revocation check (444), signature presence (457), `get_challenge` (465), ownership check (495), signature verify (533 to 537), claiming `UPDATE` (550 to 562), commit (576), executor. All measured against 46cb87d.

The tier check goes between the signature verify and the claim. Line 538 is blank and 539 begins the comment for the claim step; the new block takes that gap, inside the same `async with db.sessionmaker()`. This keeps three properties:

- An unauthenticated or wrongly-signed caller is refused by the existing 403 before learning anything about the row's tier.
- The existing byte-identical 404 for foreign or unknown challenges is untouched.
- A refusal before the claim writes nothing to `challenges`: the `_approve` session has run only a plain `SELECT`, returning inside the `async with` closes it with a rollback, and `audit.raised` runs afterwards in `approve_challenge` on its own session and writes only `audit_log`. The row stays `pending` and the customer can retry inside the tier's 300-second window.

The tier check does not look at the row's status or deadline, so sections 6 and 7 hold for a `pending` row and the other cases are as measured in review: a tier-2 row that is expired or already terminal, presented with bad claims, gets 403 `verification_required` (not 410 or 409), and an expired row is not retired by that request. With good claims it reaches the claim and gets the existing 410 `expired` with the expiry transition, or 409 `already_terminal`.

`_approve` does not receive the claims. `verified_claims(request)` is already imported in `callback.py` (line 134) and `approve_challenge` reads the same dict at line 293, so the block calls it, or `approve_challenge` passes the dict in. The plan picks one; they are equivalent. `request` is in scope at the insertion point.

## 7. Refusals

All refuse before the claim, return HTTP 403 with `{"error": code, "error_description": text}` and a fixed description, and write one audit row on the existing path (`audit.raised(detail)`).

| Case | `error` | `detail` |
|---|---|---|
| Tier 2, step 2, 3, 4 or 5 failed | `verification_required` | `verification_required` |
| Tier 2, setting unset | `verification_required` | `verification_not_configured` |
| Row tier below the operation's declared tier | `tier_mismatch` | `tier_mismatch` |
| Tier 0 | `tier_unsupported` | `tier_unsupported` |

The `error_description` never echoes a claim value or the configured `idv` value, and does not say which claim failed. A caller cannot change the signed claims, so there is nothing for it to probe; the fixed text exists so that nothing about the expected value is ever in a response. For the operator, one WARNING log line per refusal names the failed claim (`idv`, `challenge_id`, `jti` or `auth_time`) and never a value, following `_lifetime_refusal`'s pattern in `services/confirm/auth.py`. The audit row's `detail` is the coarse value in the table; the audit `arguments` hold the scrubbed body and never the assertion's claims, except the recorded `jti` of section 8.

`detail` is an unconstrained `Text` column and no test enumerates `DETAIL_*` against `__all__`, so adding four literals to `services/confirm/audit.py` (`DETAIL_VERIFICATION_REQUIRED`, `DETAIL_VERIFICATION_NOT_CONFIGURED`, `DETAIL_TIER_MISMATCH`, `DETAIL_TIER_UNSUPPORTED`, each also in `__all__`) needs no migration.

## 8. Storage and the record

No schema change. For tier 2 the claiming `UPDATE` at `callback.py` 557 passes `verification_result=<the assertion jti>` instead of the body value. `challenges.verification_result` is `Text` and nullable, so it holds the `jti`. The `jti` character rule of section 5 is what keeps that `UPDATE` from raising: Postgres refuses a NUL in text. `confirming_device` keeps the body behaviour for both tiers: it is caller-supplied and unvalidated today, and this slice does not change that.

The `challenges` row is not append-only: `postern_app` holds `UPDATE` on it, so the stored `verification_result` is evidence only as long as that role is not abused. The copy of record is the audit row, so the approval's audit `arguments` gain `assertion_jti` (capped but not scrubbed: it is validated printable ASCII, signed by the app backend, and the audit row is the copy of record; the scrubber masked 12.9% of `uuid4().hex` values, which would break the join to the backend's issuance log) for a tier-2 approval, whether it succeeds or is refused after the `jti` passed. The existing audit rows keep recording the scrubbed body, including a body `verification_result`, which tier 2 ignores; the new field is what an investigator reads.

What this makes true: for a tier-2 row that reached `approved` through confirm, `verification_result` is the `jti` of an assertion that carried the configured `idv` value and this challenge's id, not a string a caller chose. What it does not: `jti` uniqueness is not checked. An app backend that reuses a `jti` across two assertions violates RFC 7519 and confirm cannot see it without an index.

## 9. The contract the operator's app backend must meet

Added to `docs/integration/mobile-app-pairing-contract.md` as a new section, replacing the "will get its own contract" line for the tier-2 part only. To approve a tier-2 challenge, the banking app's assertion for that request must carry `idv` (the value the operator configures in `POSTERN_CONFIRM_IDV_VALUE`), `challenge_id` (the challenge being approved), a `jti` and an `auth_time`. The backend must:

- Set `idv` only from its own record of an identity verification that completed for this `challenge_id` and this `sub`; never from a value the app supplies and never from the login session.
- Mint at most one tier-2 assertion per verification.
- Use a `jti` unique per issuer, 1 to 128 printable ASCII characters.
- Use an `idv` value that appears in no other claim and that it emits for nothing else.
- Set `auth_time` to the time the verification for this challenge completed, as a number of seconds since the epoch. Confirm refuses a value earlier than 30 seconds before the challenge was created or later than 30 seconds from now. It cannot check that the value is true.

The section states that nothing here verifies the match or the order of events and that the operator's backend owns both. How the app requests a tier-2 assertion, and what inputs the backend accepts, is not established in any doc and stays out of the contract. Everything else about the challenge-approval body (delivery of the challenge to the phone, the display) stays out, as it is today.

## 10. Settings

One new optional string setting on `ConfirmSettings`, shaped like `POSTERN_DEVICE_KEYS_PATH` (`device_keys_path: str | None = None`, read as `os.environ.get(...) or None`):

| Item | Value |
|---|---|
| Field | `idv_value: str | None = None` in `services/confirm/settings.py` |
| Variable | `POSTERN_CONFIRM_IDV_VALUE` |
| Validation | In `__post_init__` as well as in `from_env`, as `_check_app_link_uri` is. A set value is 1 to 128 characters of printable ASCII (0x21 to 0x7E): no whitespace anywhere, no control characters. It is stored exactly as given. Anything else raises `ValueError` naming the variable. `ConfirmSettings(idv_value="")` built in code is refused. From the environment an empty value means unset, as `or None` makes it |
| Startup | One WARNING log when the setting is unset, saying tier-2 approvals will be refused |
| Inventory | `EnvVar("POSTERN_CONFIRM_IDV_VALUE", "string", ("confirm",))` in `postern_core/env_inventory.py`. The inventory prose and the counts in `tests/test_settings_bounds.py` move: rows 84 to 85, strings 32 to 33, confirm-read 63 to 64, and the prose counts at lines 28 to 30, 2119 to 2122 and 2209 |
| `not_numeric` set | The name is added to the hand-kept set in `tests/test_settings_bounds.py` (the producer plan missed the same step for its flag) |
| Compose | Set on `confirm` to a dev value, with a comment that it is a placeholder agreed with the app backend, not a standard value |
| Docs | A row in the Confirm Service table of `docs/user-guide/getting-started.md`, a note in `docs/user-guide/components/confirm-service.md`, and an operator checklist line in `CLAUDE.md` |

## 11. Tests

A new file `tests/test_tier2_approval.py`, plus changes to one existing test, against the real confirm app and Postgres like `tests/test_payments_approval_path.py`.

| Test | Asserts |
|---|---|
| Tier-2 row, assertion with all four claims | 200, executor reached once, stored `verification_result` equals the assertion `jti` and not a body value sent alongside, the reaching and returned audit rows written, `assertion_jti` in the audit arguments |
| Each of `idv`, `challenge_id`, `jti`, `auth_time` missing, of a wrong type, or of a wrong value, in turn; `auth_time` a bool, a string, NaN, infinite, 31 seconds before `created_at`, 31 seconds ahead of now; `jti` empty, 129 characters, containing a NUL, containing a space | 403 `verification_required`, row still `pending`, executor never reached, `error_description` identical across all of them, no claim value in the body, the audit detail, or the log line's value |
| `jti` of exactly 128 characters; `auth_time` exactly at the lower and upper bounds | 200 (kills off-by-ones) |
| Assertion minted for challenge A used on challenge B | 403, B stays `pending` |
| Setting unset | 403, detail `verification_not_configured`; a tier-1 approval in the same app still 200 |
| `ConfirmSettings(idv_value="")`, whitespace, control character, 129 characters | `ValueError` naming the variable at construction |
| Assertion with `idv: ""` or `idv: null` | 403 (cannot equal the validated setting) |
| Tier-1 row with extra claims, with none | 200 both, stored `verification_result` is the body value as today |
| Tier-0 row | 403 `tier_unsupported`, row stays `pending` |
| A `payments.create_payment` row inserted with `tier=1` | 403 `tier_mismatch`, row stays `pending`, executor never reached |
| Signature first | A tier-2 row, a wrong device signature and the claims MISSING: 403 `invalid_signature`, not `verification_required` |
| Ownership first | A foreign tier-2 challenge with NO claims: the byte-identical 404, detail `challenge_not_owned` |
| Revoked customer with valid tier-2 claims | `revoked` as today |
| Retry | A refusal, then the right claims inside the window: second attempt 200 |
| Concurrency | Two simultaneous approvals of one tier-2 row, one with valid claims and one with missing claims: exactly one 200 and one 403 `verification_required`, the backend reached once. Two simultaneous approvals with valid claims and different `jti`s: exactly one 200 and one 409, the backend reached once, the stored `verification_result` is the winner's `jti`, and each audit row carries its own |
| Mutations the review will run | Skip the tier check; compare `idv` case-insensitively; skip the `challenge_id` comparison (not "compare against the row", which is byte-equivalent and cannot be killed); store the body string for tier 2; accept a missing `jti`; drop the `auth_time` lower bound; drop the upper bound; accept a bool `auth_time`; `< 128` for `<= 128`; move the tier check above the ownership check; move it above the signature check; drop the `tier_mismatch` check |
| Changed existing test | `tests/test_payments_approval_path.py` approves its tier-2 row with the new claims, its comments that say tier 2 is not enforced are removed, and it asserts the stored `verification_result` equals the `jti`. It is the only test that approves a tier-2 row. The `tier_mismatch` rule also breaks 56 tests in 9 other files that use `payments.create_payment`, stored at tier 1, as a generic approval fixture (measured by applying the rule to the suite: 57 failures in all); the plan moves those fixtures to `standing_orders.cancel`, a tier-1 built-in with the same audience and write scope, and none of those files checks the `/payments` path |

`verified_claims`' docstring says no claim is ever an authorization input; it is rewritten to say which four are, for tier-2 rows: `idv`, `challenge_id`, `jti` and `auth_time`.

## 12. Documentation changes

| File | Change |
|---|---|
| `CLAUDE.md` lines 13 and 128, and the operator checklist | The statements that tier 2 is not enforced become the new behaviour and its limit (section 2). The flag item keeps gates 2 and 3. A new operator line: set `POSTERN_CONFIRM_IDV_VALUE` and make the app backend meet section 9 |
| `docs/user-guide/getting-started.md` line 100 | The flag warning drops "until approval enforces tier 2" and keeps delivery and consent |
| `docs/superpowers/specs/2026-10-04-payments-producer-core-design.md` lines 16, 32, 203, 215 | Point to this slice as done, with its date. The producer plan `2026-10-04-payments-producer-core.md` (lines 4923, 5026, 5037, 5055) is a dated record and is left as it is |
| `services/confirm/execute.py` lines 101 to 103 | The comment that nothing in confirm reads the tier |
| `services/confirm/callback.py` lines 21, 150 to 151, 163 to 166, 296 to 298 | The request-format docstring and flow steps that name `verification_result` as a selfie-match reference or omit the tier step. (Lines 55 to 77 and `device_signature.py` 85 to 91 were named in an earlier draft and say nothing about the tier) |
| `packages/postern-core/src/postern_core/store/challenges.py` line 260, `store/models.py` lines 962 to 963, `domain/verification.py` lines 124 to 126 | Descriptions of `verification_result` as an opaque selfie-match reference: for tier 2 it is the assertion `jti` |
| `docs/user-guide/components/confirm-service.md` | A new step between steps c and d of the flow at lines 333 to 340, and the four refusal details |
| `docs/integration/mobile-app-pairing-contract.md` section 10 line 304 and a new section | Section 9 |
| `dev-docs/decisions/0023` | Accepted 6 October 2026, aligned with this revision |

## 13. What remains after this slice

The producer still stays off in production:

- No delivery of the challenge to the phone (handoff section 10.4).
- No consent-grant flow, and `start_session` still reports `granted=False`.
- The trust anchor for tier 2 is the app backend's word (section 2). A signed attestation from the identity-verification service is the stronger form, and needs that service's issuer and key.
- The payments backend does not see the proof. Whether it should is handoff section 10.23.
- Compliance: Art. 9 basis, DPIA and the accessibility fallback for users who cannot complete verification (handoff sections 10.9 and 10.12) are operator sign-off items that no code here discharges. A tier-2 refusal is otherwise a dead end for such a user.
- The zero-trust plan's claim that a stolen unlocked device cannot pass tier-2 verification holds only as far as the app backend refuses to mint the claims.
- Pre-existing and not changed here: a tier-1 body `verification_result` that is not a string, or that contains a NUL, already produces a 500 whose description carries the SQL and its bound parameters (`callback.py` lines 338 and 570).

## 14. Rollout

No production code creates tier-1 rows. With the flag off, nothing creates a challenge row at all. With the flag on, every row is tier 2, so with `POSTERN_CONFIRM_IDV_VALUE` unset every payment approval is refused. That is the safe default, and it is why the setting has no built-in value.

## 15. Questions put to capo

1. The claim name: decided on 6 October 2026, a dedicated `idv` claim (section 4).
2. The `auth_time` bound: decided on 6 October 2026, required (section 5, step 5).
3. What the app does on `verification_required`, and where the handoff section 7.4 and 10.12 accessibility fallback hooks in: deferred. It belongs to the mobile and backend teams, the docs do not establish it, and no code in this slice waits on it. It is an open dependency, and a tier-2 refusal is a dead end for a user who cannot complete verification until it is answered.

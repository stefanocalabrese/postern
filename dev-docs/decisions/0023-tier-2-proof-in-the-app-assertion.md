# 0023. Tier-2 proof as claims in the banking-app assertion

Date: 6 October 2026

## Status

Proposed, 6 October 2026: awaiting capo's review of the spec
(`docs/superpowers/specs/2026-10-06-tier2-approval-enforcement-design.md`).
The four choices below were taken by capo on 6 October 2026.

## Context

`payments.create_payment` stores a tier-2 challenge row, and tier 2 means
server-side identity verification in the operator's backend cluster (handoff
section 6.3 and section 10.8). The approval callback never reads the row's tier,
so a tier-2 payment is approved on a device signature and a banking-app assertion
alone, and `verification_result` is a free string that nothing validates.

The docs name no artefact that proves the verification happened. Handoff section
7.4 says a match result asserts who and not what, and offers two designs, a
device key signing the payload or a backend minting the authentication code, and
says to establish which exists before building. This repository committed to the
first for the signature. For the verification itself nothing is established, and
the mobile and backend teams have not confirmed anything.

Alternatives considered:

- A signed attestation from the identity-verification service, verified here
  against a configured key set. The strongest form, since the party that did the
  matching vouches for it. It needs an issuer and key that the docs do not name.
- A lookup from confirm to the operator's backend. A new outbound dependency, and
  the stub has no route for it.
- Validating the free string only. It proves nothing: any holder of an assertion
  can send any text.
- Putting the tier and a reference inside the device-signed bytes. A breaking
  change to the encoding (`APPROVAL_DOMAIN` `v1` to `v2`) for an app that has no
  approval contract yet.

## Decision

For a challenge row of tier 2, `services/confirm` requires three claims in the
verified banking-app assertion: `acr`, a string equal to the configured
`POSTERN_CONFIRM_IDV_ACR`; `challenge_id`, a string equal to the challenge in the
request path; and `jti`, a string of 1 to 128 printable ASCII characters. The
check runs after the device-signature check and before the claiming update, so a
refusal is a 403 and leaves the row `pending`. For tier 2 the stored
`verification_result` is the assertion's `jti`, not the caller's string, and the
`jti` is also recorded in the approval's audit row. Tier-1 rows behave as before.
A tier-0 row is refused for writes. A row whose tier is below its operation's
declared tier is refused (`tier_mismatch`), because `postern_app` can write the
`challenges` table and the declared tier is static configuration in confirm. An
unset `POSTERN_CONFIRM_IDV_ACR` refuses every tier-2 approval and does not stop
confirm from starting. The write token to the payments backend is unchanged.

What is lost, and accepted: the trust anchor is the operator's app backend saying
that identity verification happened for this challenge. Nothing in this repository
can check the match, or whether the assertion was minted after it. A compromised
app backend, or a stolen assertion-signing key, can mint the claims for any
challenge. The control stops an approval that carries no claim of verification,
and the reuse of one assertion across challenges, and nothing beyond that. Whether
one verification backs assertions for several challenges, or whether `acr` is
copied from a login session, is decided by the app backend and cannot be detected
here; the spec lists what the backend must do.

## Consequences

- The banking app's backend must mint, for a tier-2 approval, an assertion carrying
  the three claims after the verification for that challenge completed. This is
  written into `docs/integration/mobile-app-pairing-contract.md` and is a
  dependency on the app backend team that this repository does not discharge.
- `verified_claims`' docstring ("no claim it carries is ever an authorization
  input") is no longer true for `acr`, `challenge_id` and `jti` on tier-2
  approvals, and is rewritten.
- Three audit details are added (`verification_required`,
  `verification_not_configured`, `tier_unsupported`). `audit_log.detail` is
  unconstrained text, so there is no migration.
- A signed attestation from the identity-verification service remains the
  stronger design. Moving to it replaces where the three claims are read from and
  nothing else in this decision.
- The payments flag stays off in production. Delivery to the phone and a
  consent-grant flow are still missing, and the Art. 9 basis, the DPIA and the
  accessibility fallback (handoff sections 10.9 and 10.12) are compliance items
  that no code here discharges.

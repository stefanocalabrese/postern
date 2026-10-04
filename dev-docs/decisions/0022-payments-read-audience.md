# 0022. A read audience for payees, and an api-side expiry update

Date: 4 October 2026

## Status

Proposed. Becomes Accepted when capo approves the payments producer spec
(`docs/superpowers/specs/2026-10-04-payments-producer-core-design.md`).

## Context

`payments.create_payment` must check that a `payee_ref` belongs to the calling
customer and show the customer a real payee name, so it needs one read from the
payments service before it creates a challenge. Decision 0010 lists as a control
that the read minter's audiences are `accounts.svc`, `transactions.svc` and
`cards.svc`, and that a payments audience raises `KeyError` because
`payments.svc` is a write audience. That property stays true for writes:
`payments:execute` is minted only by `services/confirm`, with the write key.

The alternatives were to look up nothing (the first check then happens after the
user approves, as a 207 from the executor) or to put the payee name in the
agent's arguments, which handoff §6.5 rules out.

The producer also needs to expire a pending challenge it finds past its
deadline, an `UPDATE` on `challenges` from the api process. The zero-trust plan
(ZT-4) expects the api to insert pending rows only.

## Decision

Add `"payments.svc": "payments:read"` to `READ_SCOPES`. The scope is distinct
from `payments:execute`. The only call it enables is a single read-only
`GET /payees/{ref}`, scoped by the token `sub`, returning a display name and no
account number (handoff §6.5: omit counterparty account numbers entirely). The
facade for it has one function and no write helper, and the
no-write-helper test is extended to cover it.

The read minter signs `payments:read` only, with the read key, and
`payments:execute` is still minted by `services/confirm` alone. What no longer
holds is the invariant "no api-minted token names `aud` `payments.svc`": the
minter binds the scope to the audience, not to a path, so any GET the api makes
with that audience carries a read-signed `payments:read` token. The read/write
separation at `payments.svc` now depends on the gateway or backend checking the
signing key and the scope per path, `payments:read` from the read issuer on
`GET /payees/*` only and `payments:execute` from the write issuer on write paths.
That is a real loss of one layer, accepted, and it is stated as an open
dependency in the spec.

Accept one deviation from ZT-4: `payments.get_payment_status` may move a
`pending` row to `expired` once its database-clock deadline has passed. The
shared `postern_app` role already holds `UPDATE` on `challenges`
(`sql/02-grants.sql`), the transition is the same conditional update the
approval callback uses, and it records only a fact the row already implies.
Splitting the role to remove it would give the api a different role from
`services/confirm` and is not attempted here.

## Consequences

- The read minter now knows four audiences, so the sentence in decision 0010
  naming `payments.svc` as a `KeyError` is amended by this record.
- Any test that loops over `READ_SCOPES` covers the new entry. The
  `writing-a-module.md` example that reads `payments.svc` no longer raises
  `KeyError`; its text is reviewed in the same change.
- An RCE in the api with the payments flag on can insert and expire pending
  challenges for any customer. It could already do so through the grants. It
  still cannot approve or execute.

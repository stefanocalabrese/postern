# 0020. The signing key is never in the process

Date: 29 September 2026

## Status

Accepted.

## Context

`KeySource` had two implementations and both held an `RSAKey` with private
parameters on an instance attribute. The seam's method was
`signing_key() -> RSAKey`, so every caller above it reached private key material
by attribute access, and the only question a Vault answered was where that
material was STORED. `dev-docs/module-isolation-spec.md` concluded this key is
the asset worth removing.

## Decision

Vault's transit engine signs. The key is generated inside Vault, is not
exportable, and the application asks for a signature over a hash input.

The seam becomes a signing CAPABILITY rather than a key: `sign(claims) -> str`,
`public_jwks()`, `close()`. `signing_key()` leaves the Protocol and stays as a
concrete method on the two local implementations. `VaultTransitKeySource` does
not have one -- verified: its public methods are exactly `close`, `public_jwks`
and `sign`.

`InternalTokenMinter.mint_with_jti` changed by one line. `ReadTokenMinter`,
`WriteTokenMinter`, both JWKS routes, `refuse_unverifiable_minter` and every
key-split test are unchanged.

`choose_key_source` absorbs the three copies of the same branch and **refuses**
a Vault address together with a PEM path rather than ordering them: a PEM still
on disk is still what an RCE finds.

PEM and generated keys keep working. `POSTERN_VAULT_ADDR` unset is the absence
of a Vault, not a degraded mode.

### Details that are not free to change

`signature_algorithm: pkcs1v15`, named rather than defaulted -- transit's RSA
default is PSS, and a header claiming RS256 over a PSS signature verifies
nowhere. The published kid is `<kid>.v<version>` and every version Vault holds
is published: under one fixed kid a rotation makes new tokens fail at a cached
verifier as `BadSignatureError('bad_signature: ')`, an empty description that
reads like forgery, where versioned kids give `InvalidKeyIdError`, which names
the problem. `key_version` is pinned from the same read that produced the
published set, because Vault signs with the latest when it is omitted.

Raw HTTP over `httpx2`, not `hvac`: hvac 2.4.0 requires `requests`, a second
synchronous HTTP stack for two endpoints. `httpx2` is already a dependency.

## Consequences

**Measured**: a transit signature is 1777us against 926us in process, so ~+850us
per backend call; a key read is 464us, once per TTL. End to end over a container
network, `tools/call` p50 moved 4.3ms to 5.7ms.

**The request deadline grew** 101.0 to 105.0, because its derivation requires it
to sit above every individually-bounded wait and signing is now one. An operator
who raises `POSTERN_VAULT_TIMEOUT_SECONDS` owes this line four times the
increase.

**The mint blocks the event loop.** `TokenMinter` is synchronous, so the round
trip runs on the loop. The in-process signature it replaces also blocked, but on
CPU, which nothing can yield during. Making it yield means making four layers
above this seam async. Not done; written down.

**Fail closed, at startup.** An unreachable Vault is a container that never
becomes ready rather than one that passes readiness and 500s every call.
`minter_probe`'s docstring asked that this be taken deliberately; it is, and
there is no flag.

**The secret moved, it was not removed.** The process holds a Vault token
instead of a key. What changes is its properties: short-lived, renewable,
revocable from outside the process, scoped to `update` on one path -- where a
PEM is none of those, and a PEM stolen once is a signing key forever.

**The split gained a second half.** The cryptographic half holds however the key
is stored. The new half is a Vault ACL: the api's token carries `update` on the
read key's sign path and nothing on the write key, measured 403 in both
directions.

**What an RCE in the api container now gets** is a signing oracle rather than a
key. It cannot sign with the write key, cannot read its public half, and cannot
export private material -- `GET /v1/transit/export/signing-key/<name>` answers
HTTP 400, "private key material is not exportable", to the ROOT token. It still
mints read tokens for any customer while it holds the process, because `sub`
comes from the caller. That is ZT-2's problem, not this one's.

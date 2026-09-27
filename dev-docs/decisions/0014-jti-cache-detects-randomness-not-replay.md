# 0014: The jti cache detects a randomness failure, not a replay

**Date:** 2026-09-26

## Question

`JtiReplayCache` is an in-process `OrderedDict`. Every other store in this
repository grew a shared backend during September: the session store, the ZT-7
revocation list, the device-code store and the per-customer approval counter
all read `POSTERN_REDIS_URL` and all survive a restart. This one did not, its
own docstring said "Not safe across processes", and the `POSTERN_REQUIRE_REDIS`
refusal told operators it "has no shared backend at all and stays per replica,
and lost on restart". So: give it a Redis backend?

The prior question is what it detects, and the answer changes the first one
into a different question.

## What it detects

`postern_core.auth.read_minter`'s `ReadTokenMinter.__call__` runs the
revocation decision, calls `InternalTokenMinter.mint`, decodes the token it
just got back, and passes the `jti` out of it to `JtiReplayCache.add`. The
value that reaches `add` was produced inside that same `mint` call, by
`uuid.uuid4()`, three statements earlier. `add` is called from nowhere else in
this repository: one writer, one argument, one origin.

The cache arrived in `744e864` on 2026-09-20, the same day decision record
0010 listed it as a compensating control against a stolen bearer token.

So the duplicate the cache raises on is `uuid.uuid4()` returning a value it
already returned, inside one process, inside 60 seconds. That is a failure of
the RNG behind `os.urandom`, not a token arriving twice.

`tests/test_zt1_continuous_auth.py` had already measured this and named the
measurement wrongly. `test_jti_cache_blocks_duplicate_token` minted twice with
identical arguments, asserted the two tokens differ, and carried a comment
saying "it does NOT raise". The assertion was right and the title was the part
people read. It is now
`test_the_cache_never_fires_on_the_mint_path_it_guards`.

## Why the mint side cannot detect a replay, at any scale

Replay is an observation about arrival. A recipient holds a token twice and
recognizes the second one; that recognition needs a record of what the
recipient accepted. An issuer holds a token once, at the instant it creates
it, and has by construction no way to learn that something happened to it
afterwards. No amount of shared storage on the issuing side converts one into
the other, because the event never reaches that side.

The recipients of these tokens are the Istio gateway and the operator's domain
services. A `jti` cache there is a real control and is a real deliverable, in
repositories this one does not contain.

The tempting objection is that this server is itself a recipient: it validates
the customer's access token on every request, and
`services/api/middleware/revocation.py`'s `RevocationMiddleware` already pulls
that token's `jti` out for the per-session revocation scope, so the value is
in hand and a cache is cheap. It does not work, for a reason that has nothing
to do with storage. That token is a multi-use bearer credential for the 60
seconds it lives: the MCP client presents the same one on every tool call in
the window, and `services/confirm/device_auth.py`'s token endpoint hands out
exactly one per approved device code. A cache that refuses a second sighting
refuses the customer's second tool call. Presentation count is not the signal
here. Origin is, which is what ZT-5's IP and ASN anomaly detection reads.

## What a Redis backend would buy

Two replicas noticing that they generated the same UUID4. That is a
distributed health check on the RNG, and it is not nothing: the realistic way
it fires is a cloned VM or container image resuming from a snapshot with a
duplicated entropy state, which is a documented failure class and which a
per-process cache cannot see by definition.

It is still the wrong place to put that check, for three reasons that compound.

**The same failure already surfaces somewhere better.** Device codes come from
`_generate_device_code`, which draws `secrets.token_urlsafe(32)` from the same
`os.urandom`, and land in a store whose `consume_device_code` is single-use and
Redis-backed because correctness requires it to be. Duplicated entropy across
replicas produces a duplicate device code before it produces a duplicate `jti`,
and a duplicate device code is a duplicate credential that a second holder can
spend. A duplicate `jti` is a duplicate log line. The detector that already
exists watches the value that matters, in a store that had to be shared
anyway.

**The check sits on the hot path of every customer read.** Each backend call
already pays a full verifying decode here to recover a value `mint` held in a
local variable: `KeySet.import_key_set` reparses the JWKS and `jwt.decode`
runs an RSA verification. Adding a Redis round trip on top buys a new
fail-open-or-fail-closed question for a non-control. Answering it wrongly in
either direction is worse than the thing it protects.

**The failure it would catch is not fixed here.** A platform that clones
entropy state needs a kernel or hypervisor fix. What this repository can do
about it is notice, once, loudly, and it already does that in the place where
noticing has consequences.

## What A10 is actually mitigated by, which is not this

`dev-docs/postern-zero-trust-plan.md`'s A10 row is "Replay of a captured signed
approval", and it read "Needs an explicit replay cache, folded into ZT-1". The
cache was then built and credited to that row.

Approvals carry no `jti`. They are replay-protected, and well, by something
else: `services/confirm/callback.py`'s `_approve` claims the challenge with one
conditional `UPDATE` through `update_challenge_status`, `pending -> approved`,
with the status and the expiry both inside the `WHERE` that PostgreSQL
re-evaluates under the row lock. A captured signed approval presented a second
time matches no row. That is durable, cross-replica, and already shipped. A10
is closed, by a control nobody had written down, while an in-memory dictionary
held the credit.

## Decision

**Keep `JtiReplayCache` in process. Build no Redis backend. Correct every
claim that calls it replay protection.**

Keep the class rather than delete it: an RSA-signed token whose `jti` repeats
is a catastrophic signal, the check costs one dictionary lookup -- 0.2us
measured -- and a cheap canary in the wrong place
is still a canary. Delete it and nothing in the read path would notice at all.
What it may not do is appear on a list of controls under a name that promises
an attacker was stopped.

The name stays too, and the reason is not that renaming is expensive: five
files carry `JtiReplayCache` and one of them defines it. It is that the wrong
name is the finding. Decision records 0010 and 0014, the zero-trust plan and
the user guide all now quote it while explaining what it does not do, and a
rename would leave those sentences pointing at a symbol the tree no longer
has. The docstring carries the correction in its first line instead, which is
where a reader who greps for the class arrives.

## Rejected

**A Redis backend.** It buys cross-replica detection of a `uuid4` collision,
which is a real property and not a security control, on a value that matters
less than the one `consume_device_code` already guards, at the cost of a
network round trip per customer read and a fail-mode decision with no good
answer.

**Removing the control.** A control that detects a randomness failure is not
worthless. It is misfiled, and the fix for misfiling is the filing.

**Widening `InternalTokenMinter.mint` to return its `jti`** (IMPLEMENTED 2026-09-27, see the amendment at the end -- and it needed no signature change), which would delete
the verifying decode this path pays per call. Correct, and a signature change
to the minter both services depend on. Noted here so the next person finds the
reasoning rather than the decode.

## What changed with this record

| File | Claim struck |
|---|---|
| `packages/postern-core/src/postern_core/auth/read_minter.py` | Module docstring, `JtiReplayCache` docstring, `ReadTokenMinter` docstring, the `jti_cache` argument and the call-site comment |
| `packages/postern-core/src/postern_core/auth/__init__.py` | "reads this call's revocation decision and the jti replay cache on every mint" |
| `services/api/main.py` | The `POSTERN_REQUIRE_REDIS` refusal's consequence clause |
| `dev-docs/postern-zero-trust-plan.md` | A4 row, A10 row, ZT-1 work list, ZT-6 compensating controls, and new 5.5 |
| `dev-docs/decisions/0010-dpop-sender-constraint.md` | Three passages counting the cache as a compensating control, struck in place |
| `tests/test_zt1_continuous_auth.py` | Two test names and four docstrings |
| `docs/user-guide/components/api-service.md` | "In-memory replay cache (60s window)", and a `revocation_list=` argument the constructor has not taken since ZT-1 |

`CLAUDE.md` lists "jti replay cache for A10" among what exists, under ZT-1.
That file is the user's and is not edited from here; the phrase is wrong and
is reported separately.

## Verification

- `tests/test_zt1_continuous_auth.py`, 11 tests, unchanged in count and in
  behaviour. `test_the_cache_never_fires_on_the_mint_path_it_guards` is the
  one that carries the finding.
- `tests/test_require_redis_guard.py`, 66 tests. `API_MESSAGE` reproduces the
  read path's refusal verbatim, so the corrected wording is pinned there and a
  future drift fails the build rather than misleading an operator quietly.

## Where token replay protection lives after this

| Token | Recipient | Who owns the replay check |
|---|---|---|
| Customer access token (client to MCP server) | `services/api` | Nobody, and it cannot be owned here: the token is multi-use within its 60 seconds. Bounded by TTL, revocation on mint and ZT-5 origin anomaly detection. Zero-trust plan 5.5 |
| Internal delegation token (MCP server to backend) | Istio gateway, domain services | The operator, in the gateway or the services. Not in this repository, and not derivable from anything in it |
| Signed device approval | `services/confirm` | This repository, via the single-use `pending -> approved` claim. Built and durable |

---

## Amendment, 27 September 2026: the cost clause above was circular

It read "one dictionary lookup on a path that is already paying an RSA
verification". The path was paying that verification **only to feed this
cache**. The `KeySet.import_key_set` plus RS256 `jwt.decode` sat inside
`if self._jti_cache is not None`, so a minter built without a cache verified
nothing and shipped its tokens unchecked -- and it was not a self-check on the
signing key either, because `refuse_unverifiable_minter` already does that
once at startup and unconditionally. The cache was paying for its own
justification.

The clause also conflated two operations. This path pays an RSA **signature**
regardless: 910us, measured over 2000 calls at 2048 bits. It paid the
**verification** only for the cache: 42us, which is 181 times the 0.2us lookup
the sentence was excusing.

Resolved by widening the minter rather than by dropping the cache, which makes
the clause true instead of merely unsupported. `mint_with_jti` returns a
`MintedToken` carrying the token and the jti; `mint` delegates to it and
returns `.token`, so its signature and return type did not move and its other
callers -- `WriteTokenMinter` and the device grant's token endpoint -- were not
touched. A second method rather than a widened return, because a widened
return would have added a `.token` nobody reads to every call site in order to
serve the one that wanted the jti.

Measured effect: the cache's cost per backend call fell from 62.2us to 0.1us,
and 4.9% came off a ~970us path. The signature is 95% of that path and is the
work.

`tests/test_zt1_continuous_auth.py` is 13 tests now, not the 11 recorded
below, and
`tests/test_zt1_continuous_auth.py::test_feeding_the_cache_reads_no_public_key_and_verifies_nothing`
is what pins the circularity as a number: one public-key read per backend call
became zero.

**The decision itself is unchanged.** Keep the cache, build no Redis backend,
and let nothing call it replay protection. The reason that carries it never
depended on the cost clause: a control that detects a randomness failure is
not worthless, it is misfiled, and the fix for misfiling is the filing.

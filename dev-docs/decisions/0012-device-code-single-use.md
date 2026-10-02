# 0012: What a successful token exchange does to the device code

**Date:** 2026-09-26

> **Since the layer-1 session token** the exchange issues a session (an access
> token for the MCP server and a refresh token), not the read token this record
> argues about, and spends the code in the same compare-and-set that records the
> family's `session_id`. The single-use argument below is unchanged: one
> approved code is worth one grant. Between 30 September 2026 and the session
> token the exchange issued nothing and spent nothing.

## Question

`services/confirm/device_auth.py`'s `token_endpoint` minted a read token for an
approved device code and returned without touching the code. The three
`revoke_device_code` calls in that module were the expiry sweep, the
pairing-code attempt budget, and `_withdraw_pairing` on an audit-write failure.
None of them ran on the success path.

So an approved device code could be exchanged again, and again, for the rest of
its life. Should a successful exchange end the code's life, and if so, what
happens to the browser whose token response is lost in transit?

## What RFC 8628 actually says, which is less than "single-use"

The premise this work started from was that RFC 8628 treats the device code as
single-use. It does not. Checked against the RFC text (fetched from
rfc-editor.org on 2026-09-26): the words "single", "single-use", "one-time",
"reuse", "replay", "consume" and "invalid_grant" do not appear anywhere in the
document.

§3.5, "Device Access Token Response", is the section that would carry such a
rule. It says what a success is and lists four error codes, and the only one
that ends anything is:

> **expired_token**
>   The "device_code" has expired, and the device authorization session has
>   concluded. The client MAY commence a new device authorization request but
>   SHOULD wait for user interaction before restarting to avoid unnecessary
>   polling.

Expiry is therefore the one thing the RFC says concludes a device authorization
session. A successful token response appears in no such sentence, and no
sentence anywhere tells the authorization server to invalidate, revoke or
forget the `device_code` after issuing a token. The RFC is silent, not weak: it
neither requires single use nor permits reuse, it simply does not address it.

Two further readings were checked and neither closes the gap. OAuth 2.1
(draft-ietf-oauth-v2-1-15) §4.4 folds the device grant in as an extension grant
and says only that a valid, authorized request gets an access token; it adds no
rule about the grant afterwards. RFC 9700, the OAuth 2.0 security best current
practice, does not mention device codes at all.

What the RFC does give is an analogy it draws itself, in §5.2, "Device Code
Brute Forcing":

> An attacker who guesses the device code would be able to potentially obtain
> the authorization code once the user completes the flow. As the device code is
> not displayed to the user and thus there are no usability considerations on
> the length, a very high entropy code SHOULD be used.

The RFC calls what a device code redeems "the authorization code". For those,
RFC 6749 is explicit twice. §4.1.2:

> The client MUST NOT use the authorization code more than once. If an
> authorization code is used more than once, the authorization server MUST deny
> the request and SHOULD revoke (when possible) all tokens previously issued
> based on that authorization code.

And §10.5:

> Authorization codes MUST be short lived and single-use. If the authorization
> server observes multiple attempts to exchange an authorization code for an
> access token, the authorization server SHOULD attempt to revoke all access
> tokens already granted based on the compromised authorization code.

The device grant is an extension grant type under RFC 6749 §4.5, not the
authorization code grant, so §4.1.2 does not textually bind it. The argument
here is therefore not "the RFC requires this". It is that the RFC's own
security considerations treat the device code as standing in for an
authorization code, and the rule for authorization codes is a MUST.

## What the gap was worth, in this deployment's numbers

- `device_code_ttl_seconds` is 900 (`services/confirm/settings.py`).
- `device_poll_interval_seconds` is 5, and `token_endpoint` enforces it **only
  while the code is unapproved**. Once approved, `slow_down` is never returned.
- A read token lives 60 seconds (`postern_core.auth.internal_jwt`), carries
  `aud=accounts.svc scope=accounts:read`.
- `/token` is rate-limited at 300 requests per 60 seconds per address bucket
  (`services/confirm/rate_limit.py`).

So an approved code leaked with L seconds of life left, L up to 900, bought:

- **Uninterrupted account-read access for the whole of L.** Fifteen exchanges,
  one a minute, cover 900 seconds with no gap, because each 60-second token is
  refreshed before the last expires. Fifteen requests is 5% of one minute's
  rate-limit budget.
- **4,500 tokens** as the arithmetic ceiling from one address bucket (300/min ×
  15 min), and more from more buckets. The ceiling was never the constraint;
  fifteen was enough.

Since commit `3f8aa4f` each exchange writes an `audit_log` row, so the replay
was visible. Visible is not prevented.

After this change: **one token, 60 seconds.** A leaked approved code is worth a
single 60-second read token and nothing else, whatever L is and whatever the
rate limit permits. The 15-minute window is now a window in which the code can
be redeemed once, not a window of access.

## The three shapes, and the one taken

### 1. Strict single-use, and the shape taken

Revoke the grant on the first successful exchange. The browser that loses its
token response gets a refusal and starts over.

### 2. Single-use with an idempotency window, rejected

Serve the same response to a retry inside some seconds. The obvious
implementation stores the minted token so it can be replayed, and that is worse
than the defect being fixed: it puts a live bearer credential in the device-code
store, a store whose whole population is reachable through one unauthenticated
endpoint, for the benefit of a retry. CLAUDE.md's rule is that nothing of a
minted token is stored anywhere, and `device_code_handle` exists precisely
because even the device code is too sensitive to write into `audit_log`.

A variant that stores something which is *not* a usable credential, a flag
saying "this code minted successfully at T, so re-answer 200 with a **freshly
minted** token until T+n", was rejected too, and it is worth saying why,
because it stores nothing dangerous. It is not single-use. It is bounded reuse
with the bound expressed in seconds instead of in exchanges: at a 60-second
token life, a 30-second window is a leaked code worth 30 extra seconds of
access, and at any window long enough to help a lost response over a slow
connection the multiplier is back. It would also have to answer what happens
when the retry arrives from a different address than the original, and the only
honest answer available here is "nothing, because the browser holds no
credential to bind either request to".

### 3. Bounded reuse at N, rejected

A cap of N exchanges rather than one. It leaves a multiplier instead of removing
it, and no N is defensible: 2 helps exactly one lost response and no more, 5 is
five minutes of continuous access from a leaked code, and nothing in the flow
measures how many retries a legitimate browser needs. A number nobody can
derive is a number the next person will raise.

## What the customer experiences when the token response is genuinely lost

The cost is real and it is paid in full. Step by step, with what each step
knows:

1. The browser POSTs `/token` with the device code. The server spends the code,
   mints, commits the `audit_log` row, and answers 200. The response is lost:
   a dropped connection, a proxy timeout, a closed laptop lid.
2. The browser has no token, no credential of its own and no session. It
   retries, which is what RFC 8628 §3.4 tells it to do ("it is expected for the
   client to try the access token request repeatedly in a polling fashion").
3. The retry is answered `400 invalid_grant`, "device code cannot be redeemed".
   §3.5 makes every code other than `authorization_pending` and `slow_down`
   terminal, so a conforming client stops polling rather than looping.
4. The browser starts a new device authorization. The customer scans a fresh QR
   and reads a fresh six-character pairing code.
5. The customer approves again on their phone: the pairing-code comparison, and
   then app identity verification if the tier calls for it.

That is one restart of the pairing flow, unprompted by anything the customer
did wrong. It is the whole cost of this decision and there is no mitigation for
it in this shape. What makes it acceptable rather than merely tolerable:

- **The frequency is the frequency of a lost HTTP response on the last hop of a
  request the browser just made successfully in both directions.** The browser
  has already exchanged a `/device_authorization` request and response with this
  service, and polled it repeatedly while waiting for the approval.
- **The restart re-anchors the A2 control.** A fresh QR means a fresh pairing
  code, and the human comparison of that code against the one the app shows is
  the actual defence against a relayed QR. The recovery path is the control
  path.
- **This repository already chose this trade twice.** A single mistyped pairing
  code at the attempt-budget floor revoked the device code
  (`_record_user_code_failure`, removed on 30 September 2026 with the attempt
  budget, when the pairing code became the lookup key), and an audit write that
  fails after an approval withdraws the pairing outright (`_withdraw_pairing`),
  both on the reasoning that "the recovery the customer needs is a fresh QR
  anyway". A lost token
  response is a milder event than either and now gets the same answer.
- **The alternative is not a better customer experience, it is a worse
  attacker experience.** Every shape that helps the lost response helps a
  replay by construction, because the server cannot tell them apart: both are a
  second request presenting the same code, and the browser holds nothing else.

## Marked, not revoked

The code is marked `exchanged_at`, not deleted. `revoke_device_code` was the
obvious verb and is the wrong one, for one reason that decides it and one that
supports it.

**The audit row.** A replay against an approved-then-spent code is the most
interesting event this table can hold about the device grant, and
`services/confirm/audit.py`'s `PairingAudit` rule says a row is owed when the
server resolved an identity and then reached a conclusion about that identity's
authority. Both halves are met on a replay: `customer_ref` is read off the
stored code, written there by a verified assertion at `POST /approve`. Delete
the row and there is no `customer_ref` to read, so the replay is answered by
`token_endpoint`'s unknown-code branch, which runs before any identity exists
and therefore writes nothing. Revoking would have made the change invisible in
exactly the case worth seeing. The refusal is recorded as
`detail = 'device_code_spent'`, distinct from `device_code_not_found`, and
`WHERE detail = 'device_code_spent'` is the whole replay query.

**The handle joins to a live row.** `PairingAudit._arguments` records a
`device_code_handle` and states that the scopes a pairing granted are "on the
device code, which the handle joins to while it lives". Deleting a code on
exchange shortens that join to the instant of the exchange.

What marking costs, against the store cap: a spent code holds its slot against
`max_device_codes` (10,000) until its own expiry, where revoking would have
released it early. This is not a regression. An approved code that is never
exchanged already holds its slot for its whole life, and nothing about spending
a code creates one, so the standing cost the cap bounds is unchanged. What is
forgone is an early release the cap never counted on. The expiry sweep still
collects a spent code: in memory through the existing heap reaper, and in Redis
through the key's own TTL, which the claim preserves with `KEEPTTL` rather than
recomputing.

## Two checks for one property, and the order of the three steps

`_exchange` refuses a spent code twice: once on the `exchanged_at` it read with
the code, and once on the return value of the atomic claim. They are not
redundant.

- The **stored check** refuses a code an earlier request spent, needs no round
  trip, and (the reason it exists rather than being left to the claim) comes
  before the ZT-7 revocation check. Left to the claim, a replay arriving while
  the revocation store is unreachable would be answered `503
  temporarily_unavailable`, a retryable code for a grant no retry can ever
  redeem; the browser would poll a dead code until it expired.
- The **claim** refuses a code a concurrent request is spending, and is the only
  one of the two that can. It is atomic by contract:
  `InMemoryDeviceCodeStore.consume_device_code` never yields between its read
  and its write, and `RedisDeviceCodeStore.consume_device_code` uses
  `WATCH`/`MULTI`/`EXEC` so the server settles it, which is the only place it
  can be settled, since two replicas share one Redis and no lock either process
  holds binds the other.

The claim sits **after** the revocation check, the opposite ordering, for the
mirror-image reason: it is irreversible, and 503 means the server failed to
decide. Claiming first would spend a legitimate customer's code during a
revocation-store outage, so the retry the 503 invited would be refused, and it
would hand anyone holding a leaked code a way to destroy a pairing during an
outage. Nothing is spent on a question this service could not answer.

The claim sits **before** the mint, so nothing is signed that this request is
not entitled to sign. A claim lost after the mint would mean every racing
request signs a credential and all but one discards it.

A lost claim is not rolled back anywhere. If the mint raises, or the audit write
does, the code stays spent and the customer re-pairs, the direction
`_withdraw_pairing` already chose one endpoint earlier.

## The idempotency tension, and why it is a category error

CLAUDE.md's version traps say every handler must be safe to re-run, because MCP
`2026-07-28` removed SSE resumability and a dropped stream makes the client
re-issue the request with a new id. This change deliberately makes `/token`
non-idempotent.

The two do not meet. That rule is about MCP tool calls over the JSON-RPC
transport `services/api` serves; `/token` is an OAuth device grant endpoint on
`services/confirm`, reached by a browser over plain HTTP, and it is in
`PUBLIC_PATHS` precisely because it is not part of that surface. Nothing in
`services/api` calls `/token` or references a device code: checked on
2026-09-26, the only occurrence of the string anywhere under `services/api` is a
comment in `settings.py` pointing at the confirm service's TTL floor.

The deeper point is that "safe to re-run" was never a claim that a re-run
produces the same result. An idempotent handler may legitimately answer "no"
the second time; what it must not do is leave inconsistent state or perform the
side effect twice. Minting a second credential on a re-run is the side effect
performed twice. Refusing it is the rule, not an exception to it.

## Two tests asserted the old behaviour, and one of them explained it

Worth recording, because it is how the gap survived a suite of 2361 tests.

`tests/test_confirm_rate_limit.py`'s
`test_an_approved_code_is_bounded_by_being_spent_and_not_by_a_limit`, which
carried the name "test_an_approved_code_is_bounded_only_by_the_ip_limit" until
this change renamed it along with what it asserts,
exchanged one approved code twenty times and asserted `statuses == [200] * 20`.
Its docstring named the amplification and treated it as a property: the
per-code `slow_down` "is skipped entirely once a code is approved, so for an
approved code this limit is the only one, and at 300/min it is loose. Each poll
costs an RSA signature and a revocation lookup." It cost a read token as well,
which the sentence does not say. The test now asserts one 200 and nineteen
`invalid_grant`, and keeps both properties that were actually its subject: no
request is answered `slow_down`, and none is answered 429.

`tests/test_zt7_confirm_revocation.py`'s
`test_a_revoked_customers_device_code_exchange_mints_nothing` exchanged one code
before a revocation and the same code after it, expecting `access_denied` the
second time. With the code spent by the first exchange, the second is refused
`invalid_grant` before the ZT-7 check runs, so the test as written would have
passed against a build with no revocation check at all. It now pairs two codes
up front, serves one and holds the other back for after the revocation. Both
must be paired before the revocation, because `POST /approve` refuses a revoked
customer one step earlier. Verified by mutation: with the ZT-7 refusal deleted,
the repaired test mints a token for a revoked customer and fails.

## What this does not do

- **It does not bound what the one token can reach.** A 60-second
  `aud=accounts.svc scope=accounts:read` token is still a bearer credential and
  still works from anywhere inside its life. Decision 0010 records that ZT-6
  resolved to compensating controls rather than sender constraint, and this
  changes nothing about that.
- **It does not detect a relay.** A party that obtained the QR holds both codes
  and can exchange first, in which case the legitimate browser gets the refusal
  and restarts. That is the A2 shape `postern_core.auth.device_codes` already
  documents as undetectable here; what changed is that the attacker now gets one
  token instead of a stream.
- **It does not alert.** `detail = 'device_code_spent'` is a row, not a page.
  Nothing in this repository watches `audit_log` and raises anything; the
  zero-trust plan's §6.2 red-team scenario 5 is where alerting on this table is
  owed, and it is owed by the operator.

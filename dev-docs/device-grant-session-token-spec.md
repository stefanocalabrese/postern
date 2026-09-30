# Device grant: the layer-1 session token `POST /token` should issue

**Date:** 30 September 2026, revised the same day after a security review
**Status:** specification. The seven decisions it specifies were approved by the user on 30 September 2026, and three more were taken after the security review: the refresh family lives **1 hour**, not 12; removing the read key from `services/confirm` is approved; and this spec is written against the issuance hotfix below. Nothing here is built.
**Against:** `origin/main` at `b764f16` **plus the issuance hotfix**, which had not landed on `origin/main` when this revision was written. The hotfix, as described to the author and not yet read in code: `POST /token` no longer mints the layer-2 token; for an approved code it answers **503 `temporarily_unavailable`** ("session token issuance is not enabled") **without spending the code**, and writes its row with detail `issuance_disabled`. Every statement below about "today's `/token`" means that state. Statements about the code before the hotfix say so.
**Reviewed by:** a security review on 30 September 2026, folded in below.

---

## What this fixes

**Before the hotfix, `POST /token` returned a layer-2 token to a layer-1 client.** Handoff §7.1 separates two layers and says not to conflate them: layer 1 is the AI client talking to the MCP server under OAuth, layer 2 is the MCP server talking to the backend with a 60-second Vault-signed delegation token. `services/confirm/device_auth.py::_exchange` minted the second and handed it to the first: the confirm service's read minter, an `InternalTokenMinter` over the READ key, with `aud="accounts.svc"`, `scope="accounts:read"`, `iss` = `read_token_issuer` (default `https://mcp-read.internal`), `act: {"sub": "svc:postern"}` and a 60-second life. That is a token Istio accepts at a domain service. `tests/test_qr_pairing_end_to_end.py::test_a_browser_and_a_phone_complete_a_pairing_through_every_route` asserted exactly that shape.

**After the hotfix, `/token` issues nothing.** An approved pairing waits at a 503 until its code expires. The device grant is safe and useless.

This spec re-enables issuance with the right token and **removes the hotfix's 503 path**:

- `POST /token` with `grant_type=device_code` returns a layer-1 **access token** whose audience is the MCP server, signed by a third key that signs nothing else, plus a **refresh token**.
- `POST /token` with `grant_type=refresh_token` rotates that refresh token and issues a fresh access token.
- `services/api` verifies the access token through a `JWTVerifier` subclass with a bounded JWKS cache (§8), from settings it already reads.
- No client receives a layer-2 token from any endpoint.
- **The session-swap residual in `dev-docs/qr-page-spec.md` closes.** That spec says that when `/scan` detects a swap after the code was exchanged, "the token already issued is not recalled by this spec". This one recalls it (§7).

## What this does not fix

- **Classic device-code phishing, and it gets worse.** The attacker starts a pairing, sends the victim the genuine `verification_uri_complete`, and the victim scans and approves **the attacker's own pairing** with their own phone. Only one customer ever scans, so there is no second scan, `claim_scan` never answers a conflict, and **§7's recall never fires.** Before the hotfix the attacker's client got one 60-second token; after this spec it gets a session family for its whole lifetime, **1 hour**, refreshable without the victim doing anything. `dev-docs/qr-page-spec.md` already names the lure; this spec raises its payoff sixty-fold. **Red-team scenario 2 (operator checklist item 9) must measure this form**, not only the QR relay it names today: a victim approving a pairing someone else started, and how long the resulting session lasts. The missing control is an **app notification per family** ("a new session for client X was opened for your accounts, tap to end it"), which only the mobile team can build; it is listed under "Owed outside this repository". **The 12-hour lifetime originally approved requires that notification first**; until it ships the family lifetime is 1 hour.
- **Client authentication.** The client stays a public client. `client_id` is whatever the browser typed at `POST /device_authorization`, and nothing here verifies it. CIMD registration (handoff §7.1) is the fix and is out of scope. The access token carries `client_id` with a `client_id_verified: false` claim beside it (§3), the marking `/scan` already puts in its response.
- **A stolen access token works for up to 10 minutes.** It is a bearer credential with no sender constraint; decision record 0010 records why DPoP is not available. Recall, reuse detection and ZT-7 revocation cut it early only once something notices. §11 makes the amendment of 0010 a deliverable.
- **A stolen refresh token is detected, not prevented.** Rotation with reuse detection (§4) tells the server that two parties hold one family; it cannot tell which is the customer, and it fires only once both have presented. Until then the thief refreshes freely, for up to the 1-hour family lifetime.
- **The kill switch and the customer-plus-client revocation key on a value the caller chose.** `services/api/middleware/revocation.py`'s `RevocationMiddleware` reads `client_id` off the validated token, which after this spec is the pairing's caller-supplied `client_id`. A kill switch on `vendor-x` does not stop a pairing that declared itself `vendor-x2`. The customer-wide check at `/token` still refuses a revoked customer under any `client_id`. ZT-5's risk budget keys on the same pair, so a customer who re-pairs under a new `client_id` gets a fresh budget; re-pairing costs a scan and an approval on the customer's own phone.
- **A restored kill switch revives families.** §6 step 6 refuses families issued before a **customer** revocation even after that revocation is restored. It does not do the same for the kill switch or a per-`jti` session revocation: restoring either revives the families it had stopped. Both restores are explicit operator acts; this is recorded, not closed.
- **The `scope` claim is whatever the pairing asked for.** `POST /device_authorization` validates no scope vocabulary, and `services/api/server.py::build_server` builds its verifier with `required_scopes=None`; consent is enforced from Postgres. The claim records what the customer saw on the `/scan` screen and approved, and authorizes nothing by itself.
- **Recall reaches back only while the device-code row lives**, default 900 seconds, and only if the victim's app can complete `/scan` (§7's retry residual).
- **Redis failover can lose a rotation or a revocation.** ElastiCache and similar services replicate asynchronously; a primary that fails after acknowledging a write can lose it. A lost rotation leaves the client holding a refresh token the store never saw (answered `invalid_grant`, the customer re-pairs); a lost family revocation or `SADD` revives a session the server had cut. Accepted residual, shared with every Redis-backed control here.
- **No idle expiry.** RFC 9700 §4.14.2 says refresh tokens "SHOULD expire if the client has been inactive for some time". The family has an absolute lifetime only. At 1 hour the difference is small; at 12 it would not be.
- **Discovery.** Neither service serves OAuth protected resource metadata or authorization server metadata. Whether an MCP client under protocol `2026-07-28` needs either has not been checked against the spec text. Out of scope.
- **`POST /device_authorization` returns `device_code` without `Cache-Control: no-store`.** `device_code` is the credential `/token` asks for. Out of scope here; recorded so it is not lost.

## What does not change

- **Layer 2.** `services/api` keeps minting its own 60-second RFC 8693 delegation token per backend call through `ReadTokenMinter` over the READ key, and Istio keeps verifying it against the api's `/.well-known/jwks.json`. `InternalTokenMinter`, `ReadTokenMinter`, `WriteTokenMinter`, `READ_SCOPES` and `WRITE_SCOPES` are untouched.
- **The read/write key split,** which gets stronger: §1 removes the read key from confirm.
- **The device-code lifecycle up to the exchange**, as `dev-docs/qr-page-spec.md` built it. `/scan` changes only on `conflict_exchanged` (§7); `/device_authorization` gains one refusal (§6 step 1's `client_id` rule).
- **Decision 0006.** Every row this spec adds is fail-closed like the rows beside it.

---

## Design

### 1. Roles: confirm becomes the layer-1 authorization server, and gives up the read key

`services/confirm` is the authorization server for the device grant. It issues layer-1 tokens for exactly one resource, the MCP server `services/api` serves, and publishes the key that verifies them. `services/api` is the resource server: it verifies, and never signs, a layer-1 token.

**Confirm no longer holds the read key** (approved after review). Its only use was the pre-hotfix mint in `_exchange`. Removed from `services/confirm/main.py::create_confirm_app`: the `choose_key_source(role="READ (device grant)", ...)` call, `read_minter`, `app.state.read_minter` and `app.state.postern_read_key_source` (if the hotfix has not already removed them). Removed from `ConfirmSettings`: `read_key_pem_path`, `read_key_kid`, `read_token_issuer` and `vault_read_key_name`, with their `from_env` lines. In `packages/postern-core/src/postern_core/env_inventory.py`, `POSTERN_READ_KEY_KID`, `POSTERN_READ_KEY_PEM_PATH`, `POSTERN_READ_TOKEN_ISSUER` and `POSTERN_VAULT_READ_KEY_NAME` change from `BOTH` to `("api",)`; a confirm environment still setting one gets the "set but not read" warning `enforce_known_environment` already logs, not a refusal. `device_auth_routes` takes `session_minter` and `session_store`.

After this, no process holds READ and WRITE together: the api holds READ, confirm holds WRITE and the new SESSION key. `tests/test_confirm_service.py::test_the_confirm_settings_have_no_read_key_field` tightens to what its name says.

**What the session key is worth to an attacker.** A process holding it can mint an access token for any customer, and the api will serve that customer's masked reads to whoever presents it. That equals the pre-hotfix read-key exception in confirm, one hop further out. The api's read key now signs only inside the api, and confirm can no longer reach a domain service with any token.

### 2. The session key

A third signing key, used for layer-1 access tokens and nothing else, built by the same `packages/postern-core/src/postern_core/auth/keys.py::choose_key_source` call the other keys use, so it inherits every existing rule:

- `POSTERN_VAULT_ADDR` set: a `VaultTransitKeySource` over the transit key named by `vault_session_key_name`.
- `POSTERN_SESSION_KEY_PEM_PATH` set: a `FileKeySource`, which refuses a public-key PEM at startup.
- Neither: a `GeneratedKeySource`, with `warn_ephemeral_signing_key(role="SESSION", pem_env_var="POSTERN_SESSION_KEY_PEM_PATH")`.
- Both: `choose_key_source` raises `ValueError` at startup.

The call sits in a new `build_session_minter(settings)` in a new `services/confirm/session_token.py`, returning the minter and its `KeySource` as `services/confirm/minter.py::build_write_minter` does, called from `create_confirm_app` after `build_write_minter`.

**New settings** on `ConfirmSettings`, each with an `EnvVar(..., ("confirm",))` inventory entry unless noted:

| Field | Variable | Default | Notes |
|---|---|---|---|
| `session_key_pem_path` | `POSTERN_SESSION_KEY_PEM_PATH` | `None` | PEM branch. |
| `session_key_kid` | `POSTERN_SESSION_KEY_KID` | `session-1` | Kid, or under Vault the kid prefix. |
| `vault_session_key_name` | `POSTERN_VAULT_SESSION_KEY_NAME` | `postern-session` | Transit key. |
| `session_token_issuer` | `POSTERN_SESSION_TOKEN_ISSUER` | `https://auth.postern.internal` | This service's public issuer URL, the `iss` of every access token. |
| `session_token_audience` | `POSTERN_SESSION_TOKEN_AUDIENCE` | `postern` | The MCP server's resource URI, the `aud` of every access token. Must equal the api's `POSTERN_AUDIENCE`. The default is a local-only value that §2's refusal rejects without the dev flag. |
| `allow_non_uri_audience` | `POSTERN_ALLOW_NON_URI_AUDIENCE` | off | Dev flag, kind `flag`, read by **both** services (`BOTH`). §2, §8. |
| `allow_process_local_sessions` | `POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS` | off | Dev flag, kind `flag`. §4. |
| `max_refresh_sessions` | `POSTERN_MAX_REFRESH_SESSIONS` | `40000` | §4. |
| `rate_limit_session_jwks` | `POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS` | `300` | §10. |

**Startup refusals**, each a `ValueError` naming the offending values:

- `session_token_issuer` must parse with `urllib.parse.urlsplit` as `https`, with a hostname, no query and no fragment.
- `session_token_issuer` must differ from `write_token_issuer` and from `app_assertion_issuer`: one issuer string per token type.
- `session_token_audience` must be an **absolute `https` URI with a host and no fragment** (RFC 8707 §2: the resource value "MUST be an absolute URI" and "MUST NOT include a fragment component"), **and already in the normal form of §5**, so that the string an operator types into both services is the string compared. Refused otherwise, unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set, in which case the service starts and logs a warning naming the flag. `docker-compose.yml` and `ConfirmSettings.for_testing()` set the flag, because their audience is `postern`.
- `session_token_audience` must differ from `app_assertion_audience`. `ConfirmSettings`' docstring argues why the app assertion's audience must not collide with the api's; this is the same rule from the other side, checkable here because this process holds both.
- Equality with the api's `POSTERN_AUDIENCE` cannot be checked here (a different deployment; `.importlinter` forbids reading its settings). A mismatch fails closed: every access token is refused at the api.

**JWKS path.** The session key's public half is published at **`/session/jwks.json`**, by a new `session_jwks_route(source)` in `services/confirm/jwks.py` beside `jwks_route`, with its own `SESSION_JWKS_PATH`. Not a path parameter on `jwks_route`, whose body is a deliberate duplicate of the api's copy and must change in step with it. **`/.well-known/jwks.json` stays write-only**, and a test asserts the two sets share no kid and no modulus: a merged key set is exactly the hazard `services/confirm/jwks.py`'s docstring measured.

**Kid and rotation, mirroring decision 0020.** Under Vault the published kid is `<session_key_kid>.v<version>` (default `session-1.v1`), every version Vault holds is published, and the version is pinned on each signature from the same read that produced the published set; `VaultTransitKeySource` already does all of that for any key name. Under a PEM or a generated key the kid is `session_key_kid`. **Do not raise `min_available_version` past a version whose tokens may be in flight: 10 minutes for this key**, not the 60 seconds decision 0020's operator note assumes. How fast the api notices a rotation or a removed version is §8's bounded cache.

**Vault.** A third transit key, `rsa-2048` or `rsa-4096`, without `exportable=true`. Confirm's policy gains `update` on `transit/sign/postern-session` and `read` on `transit/keys/postern-session`, and loses both paths on `postern-read`. The api's policy gains nothing. `docker-compose.yml` creates the key and changes the policy.

### 3. The access token

Minted by a new `SessionTokenMinter` in `services/confirm/session_token.py`, not by `InternalTokenMinter`, whose delegation shape (`act`, fixed 60-second life, a domain-service audience) is the conflation this spec removes. Two steps, because §5 and §6 record the `jti` in the store **before** the token exists:

- `prepare(*, customer: CustomerRef, client_id: str, scope: str, sid: str) -> SessionClaims` draws the `jti` (`uuid.uuid4()`, never accepted from a caller, for the reason `InternalTokenMinter.mint_with_jti`'s docstring gives), reads the clock once for `iat`, returns frozen claims.
- `sign(claims: SessionClaims) -> str` calls `KeySource.sign`; under Vault it can raise `VaultTransitError` and never returns an unsigned token.

Claims, and nothing else:

| Claim | Value |
|---|---|
| `iss` | `session_token_issuer` |
| `aud` | `session_token_audience`, one string |
| `sub` | the customer reference, through `CustomerRef` |
| `client_id` | the pairing's `client_id`, verbatim |
| `client_id_verified` | `false`, always |
| `scope` | the granted scope in the canonical form of §6 step 5 |
| `sid` | the session family id (§4) |
| `jti` | drawn by `prepare` |
| `iat` | issue time, integer seconds |
| `exp` | `iat + 600` |

No `act`, no `nbf`, no PII. `ACCESS_TOKEN_LIFETIME_SECONDS = 600` is a code constant.

**Header.** `alg: RS256` and the kid, as the key source writes them; `typ` is whatever the key source writes. This spec does not set RFC 9068 §2.1's `at+jwt` and does not claim that profile. Token types are kept apart by issuer, audience and key, each checked by every verifier in this system.

### 4. The refresh token and the session family store

A **session family** is everything issued from one device-code exchange: one family id, a chain of refresh tokens of which one is current, and the access tokens minted alongside. It lives **at most 1 hour** from the exchange.

**Format.** `prt1.<sid>.<secret>`: `sid` is 16 random bytes from `secrets`, unpadded base64url, 22 characters, the family id, also in every access token and therefore **not a secret**; `secret` is `secrets.token_urlsafe(32)`, 256 bits, fresh per refresh token. The store keeps `SHA-256(whole refresh token)` as lowercase hex and never the token.

**Integrity** (RFC 9700 §4.14.2's implementation note: when the grant is encoded in the refresh token, the server "MUST ensure the integrity of the refresh token value"). `sid` only selects a record. Every action, and every audit row, requires the SHA-256 of the whole presented value to equal a hash that record stored (§6 step 3). A known `sid` with any other secret matches nothing, writes nothing and changes nothing.

**The record**, a frozen dataclass `RefreshSession` in a new `packages/postern-core/src/postern_core/auth/refresh_sessions.py`, JSON-serialized as `DeviceCode` is:

| Field | Type | Meaning |
|---|---|---|
| `sid` | `str` | Family id. |
| `customer_ref` | `str` | From the device code's `customer_ref` at exchange. Never from a request. |
| `client_id` | `str` | The pairing's `client_id`, caller-supplied. |
| `scopes` | `str` | The pairing's scopes, canonicalized (§6 step 5). Fixed for the family's life, in the sense of RFC 8707 §2.2's "bound to the full original grant". |
| `created_at` | `datetime` | Exchange time. |
| `expires_at` | `datetime` | `created_at + 1 h`. Absolute. |
| `generation` | `int` | 0 at exchange, +1 per rotation. |
| `current_hash` | `str` | Hash of the one refresh token that may be presented. |
| `retained_hashes` | `tuple[str, ...]` | Hashes of every earlier refresh token of this family. |
| `access_tokens` | `tuple[tuple[str, datetime], ...]` | `(jti, exp)` of unexpired access tokens, pruned on every write. |
| `revoked_at` | `datetime \| None` | Set once, never cleared. |
| `revoked_reason` | `str` | `""`, then one of `reuse`, `recall`, `issued_before_revocation`. First reason wins. |
| `device_code_handle` | `str` | `services/confirm/audit.py::device_code_handle` of the exchanged code. |

Code constants: `SESSION_ABSOLUTE_LIFETIME = timedelta(hours=1)`; `MAX_GENERATIONS = 64`. One hour at one refresh per 10-minute token is 6 rotations; 64 admits a client refreshing roughly every minute. Past it, refresh answers `invalid_grant` and the customer re-pairs. `retained_hashes` is then at most 64 hashes of 64 characters, about 4 KiB.

**Interface**, `RefreshSessionStoreBase`, with `InMemoryRefreshSessionStore` and `RedisRefreshSessionStore`, chosen by `create_refresh_session_store(max_sessions)` on `POSTERN_REDIS_URL` as `create_device_code_store` chooses:

- `create(session) -> None`. Raises `RefreshSessionStoreFull` at the cap after sweeping expired entries. An existing `sid` is a 128-bit collision and raises.
- `get(sid) -> RefreshSession | None`. `None` for missing, expired or undeserializable.
- `discard(sid) -> None`. Deletes a family nobody holds a token for (§5).
- `rotate(sid, *, presented_hash, new_hash, access_jti, access_expires_at) -> Rotation`. One compare-and-set, deciding from the record read inside the transaction with one pure function both backends share (the pattern `_scan_verdict` set):
  - `ROTATED`: unrevoked, unexpired, `presented_hash == current_hash`, `generation < MAX_GENERATIONS`. Retains the old hash, sets the new one, increments `generation`, records the new access `jti`, prunes.
  - `REUSED`: `presented_hash` is retained. Revokes with reason `reuse` in the same transaction; returns the unexpired jtis.
  - `REVOKED`: already revoked. Writes nothing; returns the unexpired jtis.
  - `UNKNOWN`: hash neither current nor retained. Writes nothing.
  - `EXHAUSTED`, `GONE`: write nothing.
- `revoke(sid, *, reason) -> tuple[str, ...] | None`. Idempotent; keeps the first reason; returns unexpired jtis, or `None` when no record exists.

The current-hash compare is `hmac.compare_digest`; retained membership is a scan of at most 64 fixed-length strings.

**Redis layout**, under `POSTERN_REDIS_KEY_PREFIX` (default `postern:`):

| Key | Type | TTL | Written by |
|---|---|---|---|
| `{prefix}refresh:session:<sid>` | string, JSON | `ceil(expires_at - now)` s, set by `create` with `SET NX EX`; `rotate` and `revoke` use `KEEPTTL` | `create`, `rotate`, `revoke`; `discard` deletes |
| `{prefix}refresh:index` | sorted set, member `sid`, score `expires_at` | none, swept | `create` (`ZREMRANGEBYSCORE -inf now`, `ZCARD`, `ZADD`), `discard` (`ZREM`) |

The TTL is rounded **up**: truncation shortened device codes by up to a second (bug B1, in `packages/postern-core/src/postern_core/auth/device_codes.py`'s `MIN_DEVICE_CODE_TTL_SECONDS` commentary). Every read re-checks `expires_at`.

**Atomicity.** `rotate` and `revoke` on Redis: `WATCH` the session key, `GET`, decide, `MULTI`, `SET ... KEEPTTL`, `EXEC`, retrying on `WatchError` up to `_CLAIM_ATTEMPTS` (3), then raising `RefreshSessionStoreContended`. Two concurrent presentations of one current token resolve as one `ROTATED` and one `REUSED`, which revokes the family: RFC 9700 §4.14.2's behaviour, with its stated cost ("forcing the legitimate client to obtain a fresh authorization grant"), which also falls on a client that retries a refresh whose response it lost. The in-memory backend is atomic by not yielding between read and write.

**The cap**, `max_refresh_sessions`, default **40,000**, derived: `max_device_codes` (10,000) times the lifetime ratio (3,600 s / 900 s = 4), so a store in which every live device code were exchanged as fast as codes can exist still fits. Orphans from §5's losing exchanges count against it until they expire or are discarded.

**Shared state is required, and enforced.** Without `POSTERN_REDIS_URL`, this store and confirm's ZT-7 store are per process: a refresh token from one replica is `invalid_grant` at another, and §7's recall writes the revoked `jti` into confirm's own memory, which the api never reads. So **`create_confirm_app` refuses to start when `POSTERN_REDIS_URL` is unset**, unless `POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS` is set, with a message naming both ways out. The check sits beside `enforce_redis_requirement` and after it, so an operator who also set `POSTERN_REQUIRE_REDIS` hears that message first. With the flag set, the service starts, logs a warning at startup, and every recall row records `DETAIL_RECALL_LOCAL_ONLY` (§9). `docker-compose.yml`, which runs no Redis, and `ConfirmSettings.for_testing()` set the flag. It is refuse-to-start rather than refuse-at-`/token` because the device grant is this service's function and a service that cannot recall should not look ready.

### 5. `POST /token`, `grant_type=device_code`

`token_endpoint` keeps its structure: the dispatch, the unrecorded unknown, expired, `slow_down` and `authorization_pending` exits, the approved-with-no-customer 500, then `PairingAudit` with `TOKEN_TOOL_NAME`, then `_exchange`, whose first three steps (spent check, `CustomerRef` parse, ZT-7) stay in order. **The hotfix's 503 `issuance_disabled` exit is removed**; its detail literal stays defined and documented as historical, because `audit_log` is append-only and rows carrying it exist (the precedent `dev-docs/qr-page-spec.md` §7 set for `DETAIL_USER_CODE_MISMATCH`).

Added ahead of the lookup, request shape only, **no row**: **`resource`**. If present it must occur once and, after §5's normalization, equal `session_token_audience`; otherwise 400 `invalid_target` (RFC 8707 §2 defines it: "The requested resource is invalid, missing, unknown, or malformed"). Absent is accepted.

**Normalization of `resource`**, per RFC 3986 §6.2.2.1 and §6.2.3, applied to the presented value only (the configured audience is required to be in normal form already, §2): lower-case the scheme and the host; remove an explicit port that is empty or the scheme's default (443 for `https`, 80 for `http`); an empty path becomes `/`. **No other change**: the path is case-sensitive, percent-encoding is compared as sent, and a trailing slash on a non-empty path is significant, so `https://mcp.example/mcp` and `https://mcp.example/mcp/` are different resources. A value with a fragment, a relative URI, or more than one `resource` parameter is `invalid_target`.

Then, replacing the hotfix's 503:

0. **Customer revoked since approval** (§6 step 6's timestamp): if `customer_revoked_at(customer)` is at or after `code.approved_at`, refuse as the ZT-7 branch does today (400 `access_denied`, `DETAIL_REVOKED`). The approval predates the revocation; a restore must not make it redeemable.
1. **Draw** `sid`, the first refresh token and its hash; `prepare(customer, code.client_id, canonical(code.scopes), sid)`.
2. **Create the family**, generation 0, with the access `jti` in `access_tokens`, **before the code is spent**: `RefreshSessionStoreFull` answers 503 `temporarily_unavailable` with `Retry-After`, the shape `_store_full_response` uses, and the code stays redeemable, the argument `_exchange`'s docstring makes for ZT-7 before the claim. Recorded under the exception's type name.
3. **Spend the code**, `consume_device_code(device_code, session_id=sid)`, which gains the argument and writes `session_id` in the compare-and-set that sets `exchanged_at`. `DeviceCode` gains `session_id: str = ""`; older records deserialize with `""`. A lost claim answers `_unredeemable_response()` with `DETAIL_DEVICE_CODE_SPENT` and **discards** the family from step 2. A failing `discard` is logged at warning level with the `sid` and tolerated: the orphan holds a hash nobody has, counts against the cap until it expires within the hour, and a burst of concurrent polls on one approved code can leave at most one orphan per losing request, each bounded by `/token`'s 300 per minute per address.
4. **Sign.** A raise leaves the code spent and a family holding a never-issued `jti`; harmless, and the customer re-pairs.
5. **Row**, `audit.minted()`, before returning, unchanged including "do not move this below the return".

Family before spend, because §7 finds the family through the `session_id` step 3 writes; created first, the record exists before any reader can learn its id.

**Response (200)**:

```json
{
  "access_token": "<session token>",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "prt1.<sid>.<secret>",
  "scope": "<canonical scopes>"
}
```

Headers `Cache-Control: no-store` and `Pragma: no-cache` on this and every other `/token` response. RFC 6749 §5.1: "The authorization server MUST include the HTTP "Cache-Control" response header field [RFC2616] with a value of "no-store" in any response containing tokens, credentials, or other sensitive information, as well as the "Pragma" response header field [RFC2616] with a value of "no-cache"." RFC 8628 §3.5 makes the device grant's success response RFC 6749 §5.1's. A test asserts the exact key set and the absence of any layer-2 token.

### 6. `POST /token`, `grant_type=refresh_token`

A new `_refresh` beside `_exchange`, returning `(response, detail)` so the row is written in one place. RFC 6749 §6 parameters: `grant_type=refresh_token`, `refresh_token`, optional `scope`; plus optional `resource` (RFC 8707) and optional `client_id`.

1. **Shape, no row.** `refresh_token` missing: 400 `invalid_request`. `resource` failing §5's rule: 400 `invalid_target`. A value not matching `prt1.<22 base64url>.<43 base64url>`: 400 `invalid_grant`.
   **And at `/device_authorization`**: `client_id` equal to `-` is refused 400 `invalid_request`. `services/api/middleware/risk.py`'s `NO_CLIENT` is `-`, the value the api uses for "no client on this token", and a pairing named `-` would share one risk budget and one revocation key with every token that carries none.
2. **Lookup, no row.** `session_store.get(sid)` is `None`: 400 `invalid_grant`.
3. **Proof of possession before anything is recorded.** `sid` is in every access token, so a caller naming a real `sid` has proved nothing. Compute the presented hash and compare it with the record read in step 2:
   - **Neither `current_hash` nor in `retained_hashes`**: 400 `invalid_grant`, **no row, no re-assertion, no revocation.** A warning is logged, rate-limited to one line per `sid` per 60 seconds per process (a bounded map, at most 4,096 entries, oldest evicted), carrying the `sid` and never the presented value. Writing a row here would let anyone who has seen one access token drive an INSERT per request against a named customer.
   - **Current or retained**: from here the caller has shown a refresh token this family issued, so **every exit writes one row** through `PairingAudit` with `subject=session.customer_ref`, `claims={}`, `tool_name=REFRESH_TOOL_NAME`, `route=TOKEN_ROUTE`, `names(session_id=sid, paired_client_id=session.client_id)`.
4. **Classify** (no write yet, except where noted):
   - Revoked: **re-assert** `revoke_session(jti=...)` for every unexpired jti, then 400 `invalid_grant`, `DETAIL_SESSION_REVOKED`. Re-asserting (an idempotent `SADD`) is what makes a failed ZT-7 write at reuse or recall converge. `RevocationStoreUnavailable`: 503 `temporarily_unavailable`, type name as detail.
   - Retained hash on an unrevoked family: `session_store.revoke(sid, reason="reuse")`, `revoke_session` for each returned jti, then 400 `invalid_grant`, `DETAIL_REFRESH_REUSED`, plus a warning log with `sid` and `device_code_handle`. A store raising: 503 with the type name; the next presentation of either token lands in the revoked branch and re-asserts.
   - `generation == MAX_GENERATIONS`: 400 `invalid_grant`, `DETAIL_SESSION_GENERATIONS_EXHAUSTED`.
   - Past `expires_at`: 400 `invalid_grant`, `DETAIL_SESSION_EXPIRED`.
   - A `client_id` parameter present and not byte-equal to `session.client_id`: 400 `invalid_grant`, `DETAIL_CLIENT_ID_MISMATCH`. This authenticates nothing (both values are caller-supplied); it is a transplant signal, a refresh token presented by a client that calls itself something other than the client it was issued to. Absent is accepted.
5. **Scope.** Canonical form, used for the family's `scopes`, for every `scope` claim and for this comparison: split on ASCII space, drop empty strings, remove duplicates, sort by code point, join with one space. A `scope` parameter that is absent **or canonicalizes to empty** is treated as omitted, which RFC 6749 §6 defines as "equal to the scope originally granted by the resource owner". Otherwise a requested scope outside the family's is 400 `invalid_scope`, `DETAIL_SCOPE_EXCEEDED` (RFC 6749 §6: "The requested scope MUST NOT include any scope not originally granted by the resource owner"). A narrower request narrows this access token only.
6. **ZT-7, before the rotation spends anything**, the ordering `_exchange` argues for its claim:
   - `is_customer_revoked(customer_ref)`, as `/token` asks today.
   - `is_revoked({"sub": customer_ref, "client_id": session.client_id, "jti": jti})` for each unexpired access jti: the session scope, the pair and the kill switch. **An operator who revokes a live access token's `jti` also stops the family refreshing past it.**
   - **Issued before a customer revocation**: `customer_revoked_at(customer_ref)` at or after `session.created_at` refuses, and **revokes the family** with reason `issued_before_revocation`, because no later restore should revive it. Detail `DETAIL_ISSUED_BEFORE_REVOCATION`.

   Revoked by either of the first two: 400 `invalid_grant`, `DETAIL_REVOKED` (RFC 6749 §5.2's `invalid_grant` covers a grant that is "revoked"; `access_denied` belongs to RFC 8628 §3.5 and the device grant). The family is not revoked by those two: while the revocation stands it is refused, and step 6's third check makes a later restore irrelevant to it. `RevocationStoreUnavailable`: 503, nothing rotated.

   **The store change behind the third check.** `RevocationStoreBase` gains `customer_revoked_at(customer_ref) -> datetime | None`: the latest instant at which any customer-plus-client revocation naming this customer was written, **kept after that revocation is restored.** `revoke_customer_client` records it in the same round trip as the pair: on Redis an `HSET {prefix}revoked:customer-at <customer_ref> <unix seconds>` in one `MULTI` with the pair's `SADD`, which today is a bare `SADD` through `_add`; in memory a dict beside the pair set. `restore_customer_client` does not touch it. No TTL: one field per customer ever revoked, bounded by the customer base. It is a concrete method on the base defaulting to `None`, as `is_customer_revoked` is concrete, so `UnreachableRevocationStore`-style test doubles keep working, and it raises `RevocationStoreUnavailable` when the store cannot answer. `revoke_cli` needs no change.
7. **Draw** the new refresh token and hash; `prepare` the access claims with the granted scope.
8. **Rotate** (§4). `ROTATED` continues. Any other result re-runs the matching branch of step 4 against what the transaction saw; a concurrent refresh that won turns this one into `REUSED`. `RefreshSessionStoreContended` propagates, recorded under its type name.
9. **Sign.** A raise leaves the family rotated and the client's token retained; its retry is reuse and revokes the family. Fail-closed; the customer re-pairs.
10. **Row**, `audit.minted()`, committed before the response is returned.

**Response (200)**: §5's five keys with the new refresh token and granted scope, and the same two headers. Any other `grant_type` still answers 404 `unsupported_grant_type` (Discrepancies).

### 7. Session-swap recall at `POST /scan`

The case, from `dev-docs/qr-page-spec.md`: customer B scans victim A's QR first and approves; A's AI client exchanges and receives a session for **B's** accounts; A's scan then arrives and `claim_scan` answers `CONFLICT_EXCHANGED`.

In `services/confirm/device_auth.py::_scan`'s conflict branch, on `ScanClaim.CONFLICT_EXCHANGED` only:

1. **Re-read the row**, `store.get_device_code(code.device_code)`: the `code` `_scan` holds was read before `claim_scan`, possibly before the exchange; `session_id` is written in the compare-and-set that sets `exchanged_at`. Row gone or `session_id == ""`: the recall row records `DETAIL_RECALL_NO_SESSION`, and `/scan` answers as today.
2. **Revoke the family**, `session_store.revoke(sid, reason="recall")`. It returns the unexpired access jtis; `None` records `DETAIL_RECALL_NO_SESSION`.
3. **Revoke each access token**, `revocation_store.revoke_session(jti=...)`. The api refuses it on the next `tools/call` or `tools/list` on every replica sharing `POSTERN_REDIS_URL`.
4. **Rows**: the recall row, then the scan row with `DETAIL_SCAN_CONFLICT`. Response unchanged: 400 `scan_conflict`.

**Order.** Family first: revoking access tokens first would leave a window in which the family refreshes into a `jti` step 3 never names. Revoked first, the jtis `revoke` returns are complete.

**Race with the exchange.** §5 creates the family, with its first `jti`, before spending the code, so once `claim_scan` sees `exchanged_at` the family and its `jti` exist. A token signed after the recall is already on the revocation list when it reaches the api.

**Failure: fail closed, and the retry window.** If step 2 or 3 raises, `/scan` answers **503 `temporarily_unavailable` with `Retry-After: 1`**, and both rows are still written (the recall row `raised` with the exception's type name). A retried `/scan` repeats the recall safely: `claim_scan` writes nothing on `CONFLICT_EXCHANGED`, `revoke` keeps the first reason and returns the same jtis, `revoke_session` is a set add. **But `/scan` checks the rotation MAC before `claim_scan`, and a token is valid for 10 to 12 seconds**, so a retry later than that answers `qr_stale` and recalls nothing. The mobile pairing contract must therefore say: on 503 from `/scan`, retry once immediately with the same body. If the recall still did not complete, the family is live (step 2 failed) or revoked with its access token still accepted for up to 10 minutes (step 3 failed; the next presentation of the family's refresh token re-asserts it). The recall row names B's customer and is the operator's signal to revoke B with `revoke-customer-client`. An audit write failure raises and answers 500; nothing is withdrawn, because a revocation that happened is the safe state.

**Not triggered** by `CONFLICT_REVOKED` (never exchanged, no family) or by any other exit, including `qr_stale`.

**Rows name different customers.** The recall row names the family's customer (B, from the re-read row), the scan row the scanner (A); one `call_id` joins them.

### 8. `services/api`: one verifier subclass, one startup refusal, three settings

`services/api/server.py::build_server` builds `JWTVerifier(jwks_uri=customer_jwks_uri, issuer=customer_token_issuer, audience=audience, required_scopes=None)` when `POSTERN_JWKS_URI` and `POSTERN_TOKEN_ISSUER` are both set. Read in the installed FastMCP 4.0.3, `fastmcp/server/auth/providers/jwt.py`: `load_access_token` checks the signature against the key the token's kid names, `exp` when present, `iss`, and `aud` by equality; it takes `client_id` from `client_id`, then `azp`, then `sub`; and exposes all claims. So the api accepts a session token and refuses a layer-2 token, an app assertion or a write token on issuer, audience or key.

**Code change 1: a bounded JWKS cache.** In the same file, `JWTVerifier.__init__` sets `self._cache_ttl = 3600`, and `_get_jwks_key` serves from the cache only while `time.time() - self._jwks_cache_time < self._cache_ttl` **and** the kid is cached; any other case calls `_fetch_jwks`, which opens a new `httpx2.AsyncClient` with a 10-second timeout unless one was injected. There is no floor on refetches and no negative cache, so **every token carrying an unseen kid causes one outbound fetch**, and an unauthenticated caller can send such tokens at the api's full request rate. And a removed key stays trusted for up to an hour. A new `SessionTokenVerifier(JWTVerifier)` in a new `services/api/session_verifier.py` overrides `_get_jwks_key`:

- cache TTL = `POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS` (default 300, `DEFAULT_PUBLIC_KEY_TTL_SECONDS`), read by the api's `Settings` into a new `customer_jwks_ttl_seconds` whether or not Vault is configured (today `vault_from_env` reads it only when `POSTERN_VAULT_ADDR` is set);
- a **minimum refetch interval of 30 seconds** for unknown kids, and a **negative cache**: a kid not found after a fetch is refused without fetching until that interval passes;
- one fetch at a time, under an `asyncio.Lock`, with concurrent callers waiting on its result.

It overrides a **private** method of a pinned dependency (`fastmcp>=4.0.3,<5`), so a test asserts `JWTVerifier._get_jwks_key` exists with signature `(self, kid: str | None) -> str` under the installed version and fails loudly when an upgrade changes it. `build_server` constructs `SessionTokenVerifier` in place of `JWTVerifier`.

**Code change 2: the audience must be a URI.** When `POSTERN_JWKS_URI` is set, the api refuses to start unless `POSTERN_AUDIENCE` is an absolute `https` URI in §5's normal form, unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set. **The api's default audience `postern` therefore stops working in any deployment with customer authentication**, which is the point: RFC 8707 §2 requires an absolute URI.

**Key-compromise runbook line.** If the session key is compromised: rotate the transit key, remove the compromised version from what Vault publishes, then **restart every api replica**, which empties the cache at once. Without a restart the api keeps trusting the removed version for up to `POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS` after confirm stops publishing it, and confirm's own published set lags Vault by the same TTL, so up to twice that in all. Revocation cannot help: forged tokens carry `jti` values nobody recorded. The exact Vault commands for removing a version from a transit key's published set were not verified here.

**`RevocationMiddleware` already checks `jti` on every data-returning call.** In `services/api/middleware/revocation.py`, `on_call_tool` and `on_list_tools` call `_claims()`, which reads `jti` from `get_access_token().claims`, and `_refuse_if_revoked` asks `is_revoked` before `call_next`; on Redis one `SISMEMBER` on `{prefix}revoked:sessions`. No other MCP method returns customer data today.

**What an operator sets on `services/api`:**

| Variable | Value |
|---|---|
| `POSTERN_JWKS_URI` | `https://<confirm's public host>/session/jwks.json`, reachable from the api |
| `POSTERN_TOKEN_ISSUER` | exactly confirm's `POSTERN_SESSION_TOKEN_ISSUER` |
| `POSTERN_AUDIENCE` | the MCP server's canonical resource URI in §5's normal form, for example `https://mcp.bank.example/mcp`, and exactly confirm's `POSTERN_SESSION_TOKEN_AUDIENCE` |

And `POSTERN_REDIS_URL` on both services, same instance, same `POSTERN_REDIS_KEY_PREFIX`.

A test beside `tests/test_confirm_service.py::test_the_api_settings_name_no_write_key` asserts the api's `Settings` has no field containing `session_key`.

### 9. Audit

All rows go through `services/confirm/audit.py::PairingAudit`, unchanged in shape, fail-closed, via `append_with_reserve`.

**`PairingAudit.names` gains `session_id`**, written raw under a new `session_id` key (not a credential; an operator needs it verbatim). Key order: `route`, `device_code_handle`, `session_id`, `client_ip`, `paired_client_id`. No token, segment or digest of one is ever written.

**New constants in `services/confirm/audit.py`:**

| Constant | Literal | Where |
|---|---|---|
| `REFRESH_TOOL_NAME` | `device_grant.refresh` | every recorded `refresh_token` row |
| `RECALL_TOOL_NAME` | `device_grant.recall` | the recall row; `route` stays `SCAN_ROUTE` |
| `DETAIL_REFRESH_REUSED` | `refresh_reused` | §6 steps 4 and 8 |
| `DETAIL_SESSION_REVOKED` | `session_revoked` | §6 step 4 |
| `DETAIL_SESSION_EXPIRED` | `session_expired` | §6 step 4 |
| `DETAIL_SESSION_GENERATIONS_EXHAUSTED` | `session_generations_exhausted` | §6 step 4 |
| `DETAIL_CLIENT_ID_MISMATCH` | `client_id_mismatch` | §6 step 4 |
| `DETAIL_SCOPE_EXCEEDED` | `scope_exceeded` | §6 step 5 |
| `DETAIL_ISSUED_BEFORE_REVOCATION` | `issued_before_revocation` | §6 step 6 |
| `DETAIL_RECALL_NO_SESSION` | `recall_no_session` | §7: nothing to recall |
| `DETAIL_RECALL_LOCAL_ONLY` | `recall_local_only` | §7 under `POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS`: the recall was written to process-local stores the api does not read |

An unknown refresh hash has no constant because it has no row (§6 step 3).

Rows by exit:

- **`device_code`**: `TOKEN_TOOL_NAME` on the recorded exits `token_endpoint`'s docstring counts, the hotfix's `issuance_disabled` exit removed, `session_id` added once drawn, `RefreshSessionStoreFull` recorded under its type name, §5 step 0 under `DETAIL_REVOKED`. The `resource` refusal writes nothing.
- **`refresh_token`**: `REFRESH_TOOL_NAME`, only past §6 step 3's proof.
- **Recall**: `RECALL_TOOL_NAME`, subject the recalled family's customer, `claims={}`. `returned` when the family was revoked and every jti written to a shared store; `raised` with `DETAIL_RECALL_LOCAL_ONLY`, `DETAIL_RECALL_NO_SESSION` or an exception type name otherwise.

No migration: `detail` is unconstrained `Text` and no constraint names `tool_name`.

### 10. Public paths, rate limits, body limit

`/session/jwks.json` joins `PUBLIC_PATHS` in `services/confirm/auth.py` with its reason (the api's verifier fetches it holding no assertion), making nine. A plain `Route`. `services/confirm/rate_limit.py` gains a row at 300 per minute per address bucket: §8 bounds each api replica to one fetch per 30 seconds on a miss plus one per TTL, and all replicas may share one NAT address. `/token` keeps its single 300-per-minute row for both grants. `BodySizeLimit` needs no change beyond the tests that list paths.

### 11. Deliverables in this repository besides the code

- **Amend decision record 0010.** Its compensating-control table counts a 60-second lifetime. After this spec the client-facing token lives 10 minutes inside a 1-hour family, and the compensating controls that replace the short lifetime are: the **per-call `jti` check** in `RevocationMiddleware`, which recall and reuse detection feed; **refresh-token rotation with reuse detection**; and §6 step 6's revocation checks at every refresh. The amendment states that, and that the bearer-theft window is 10 minutes for an access token and 1 hour for an undetected refresh token.
- **Pruning revoked jtis needs a `jti`-to-`exp` record.** `RedisRevocationStore.revoke_session` adds to a set with no TTL, and neither store records when a revoked `jti` expires, so nothing can prune safely. Recall and reuse add members. A companion sorted set (`{prefix}revoked:sessions-exp`, score `exp`) written beside the `SADD` would let a sweep remove members whose token has expired; this spec states the need and does not build it.
- **Update the mobile pairing contract** (`docs/integration/mobile-app-pairing-contract.md`): the token the AI client receives, the scopes-versus-token note, the `scan_conflict` row (a swap after exchange is now recalled), and a 503-on-`/scan` retry rule (retry once, immediately).
- **Red-team scenario 2** in CLAUDE.md's operator checklist gains the victim-approves-attacker's-pairing form (see "What this does not fix").

---

## Testing

Test-first. What must exist when this lands:

- **Session key**: all three `choose_key_source` branches with `role="SESSION"`; Vault plus PEM refused; the ephemeral warning names `POSTERN_SESSION_KEY_PEM_PATH`; each §2 refusal, including a non-URI audience with and without `POSTERN_ALLOW_NON_URI_AUDIENCE`, and an audience not in normal form. Against the live Vault: the confirm token signs with `postern-session` and cannot sign with `postern-read`; `/session/jwks.json` publishes `session-1.v<N>` kids.
- **JWKS**: each route serves exactly its source; no shared kid or modulus; no read key anywhere in confirm.
- **Access token**: exact claim set, `exp - iat == 600`, `client_id_verified is False`, no `act`, canonical `scope`.
- **Store, both backends** (Redis against the real container): every `Rotation`; `REUSED` revokes in the same transaction; two concurrent rotations with one token yield one `ROTATED` and one `REUSED`; `revoke` idempotent; pruning; the cap; TTL rounded up; undeserializable is `GONE`.
- **Startup**: refused without `POSTERN_REDIS_URL` and without `POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS`; starts and warns with the flag.
- **`device_code` exchange**: five keys and both headers; the token verifies against `/session/jwks.json`; `resource` normalization cases (host case, `:443`, empty path, trailing slash significant, fragment refused, duplicate refused) with no row; store full answers 503 and leaves the code redeemable; a lost claim discards its family and a failing discard is logged and tolerated; §5 step 0 refuses an approval older than a restored customer revocation; the hotfix's 503 path is gone.
- **Refresh**: every §6 branch with status, code and detail; **an unknown hash under a real `sid` writes no row and logs at most once per 60 seconds**; scope canonicalization (empty, duplicates, order); `client_id` mismatch; ZT-7 on the customer, the pair, the kill switch and a live `jti`; a family created before a since-restored customer revocation is refused and revoked; outage answers 503 and rotates nothing; reuse revokes and writes every live `jti`; convergence after a failed ZT-7 write.
- **Revocation store**: `customer_revoked_at` on both backends, surviving `restore_customer_client`, written atomically with the pair, raising when unreachable.
- **`/device_authorization`**: `client_id` `-` refused.
- **Recall**: B scans and approves, A's client exchanges, A scans: `scan_conflict`, B's family refuses refresh, and **A's client's next `tools/call` through the assembled `services/api` app is refused**, counted in backend touches as `tests/test_zt7_revocation_reachable.py` counts them. The recall-before-sign race. Store failure answers 503 with `Retry-After: 1` and both rows; an immediate retry completes the recall; a retry after the rotation window answers `qr_stale`. `recall_no_session` and `recall_local_only`.
- **api verifier**: TTL from `POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS`; a burst of tokens with one unknown kid causes one fetch per 30 seconds; concurrent misses coalesce into one fetch; the private-method signature pin; the audience-URI refusal with and without the flag.
- **End to end over ASGI**, extending `tests/test_qr_pairing_end_to_end.py::test_a_browser_and_a_phone_complete_a_pairing_through_every_route`: pairing, `/token`, `tools/list` on `services/api` configured per §8, a refresh, `tools/list` with the new token.
- **Audit**: one row per recorded exit with §9's literals; the recall's two rows share a `call_id` and name different customers; no token material in any row.

## Compatibility

**This is a breaking change to `/token`** relative to both the pre-hotfix response (a different token and two new keys) and the hotfix (200 where it answers 503). No client depends on either: nothing could verify the pre-hotfix token as a customer token, and the hotfix issues nothing.

Tests that change. Found by `grep` at `b764f16`, before the hotfix; **the hotfix will itself rewrite some of these and add tests pinning its 503 path, which this change deletes, and that list must be re-derived once it lands**:

- `tests/test_device_grant.py`: `test_approved_exchange_body_has_exactly_three_keys`, the approved-exchange test decoding against `app.state.postern_read_key_source`, and every other reference to that attribute, `app.state.read_minter` or `consume_device_code`.
- `tests/test_qr_pairing_end_to_end.py`: the read-kid, read-issuer, `accounts.svc`, `accounts:read` and `act` assertions.
- `tests/test_pairing_audit.py`: the test replacing `app.state.read_minter` with an unsignable minter targets the session minter.
- `tests/test_confirm_service.py::test_the_confirm_settings_have_no_read_key_field`: the allowed set becomes empty.
- `tests/test_ephemeral_key_warning.py`: the confirm cases passing `read_key_pem_path`; confirm now warns for write and session.
- `tests/test_device_code_pairing_store.py`, `tests/test_redis_backed_stores.py`: `consume_device_code` gains `session_id`; the record gains the field.
- `tests/test_zt7_confirm_revocation.py`, `tests/test_confirm_rate_limit.py`: assert only presence or absence of `access_token` and `token_type`; must be re-run.
- `tests/test_confirm_auth.py` (the `PUBLIC_PATHS` set), the confirm rate-limit and body-limit path tables, `tests/test_settings_bounds.py` (the environment inventory sweep), and every test that builds `create_confirm_app` without Redis (now needs the dev flag, which `ConfirmSettings.for_testing()` sets).
- api tests that build `build_server` with a JWKS URI and the default audience `postern` now need `POSTERN_ALLOW_NON_URI_AUDIENCE` or a URI audience.

Docs that go stale: `docs/user-guide/components/confirm-service.md`, `docs/user-guide/glossary.md`, `docs/user-guide/getting-started.md`, `docs/user-guide/components/audit.md`, `docs/integration/mobile-app-pairing-contract.md` (§11), `CLAUDE.md` (the `services/confirm` paragraph, operator item 6, red-team scenario 2), the `docker-compose.yml` comment on confirm's keys, `dev-docs/decisions/0010-dpop-sender-constraint.md` (§11), `dev-docs/decisions/0012-device-code-single-use.md`, and `dev-docs/qr-page-spec.md`. `tools/render_auth_flow.py` already says "customer access token".

## Size

About 18 production and config files: `services/confirm/session_token.py` (new, ~120 lines), `packages/postern-core/src/postern_core/auth/refresh_sessions.py` (new, ~450), `services/api/session_verifier.py` (new, ~90), `services/confirm/device_auth.py` (~300 changed: `_exchange`, `_refresh`, the recall, the `client_id` refusal), `services/confirm/audit.py` (~70), `services/confirm/settings.py` (~110 added, ~20 removed), `packages/postern-core/src/postern_core/auth/revocation.py` (~50, `customer_revoked_at` on both backends), `services/api/settings.py` and `services/api/server.py` (~40), `services/confirm/main.py`, `services/confirm/jwks.py`, `services/confirm/auth.py`, `services/confirm/rate_limit.py`, `packages/postern-core/src/postern_core/auth/device_codes.py`, `packages/postern-core/src/postern_core/env_inventory.py`, `docker-compose.yml`. Roughly 1,300 lines of production code and 2,000 to 2,500 of tests. No migration. Standing memory: at the 40,000 cap and the 4 KiB worst-case record, about 160 MiB of Redis; at the expected 7 generations per family, well under a fifth of that. Orphaned families from failed discards sit inside the cap.

## Discrepancies

1. **Stale "atomic step" claim, in four places.** `services/confirm/settings.py`'s module docstring, a comment in `create_confirm_app`, `CLAUDE.md` operator item 6 and `docker-compose.yml`'s confirm comment say the device grant mints read and write tokens in one atomic step. Audit finding C-01 removed the write token; the hotfix removes the read one.
2. **`RevocationMiddleware`'s docstring says `services/confirm` consults no revocation store** and that the device-grant exchange is uncovered. Stale: `services/confirm/revocation.py` checks on four paths.
3. **`/token` sends no `Cache-Control: no-store` or `Pragma: no-cache`**, which RFC 6749 §5.1 requires. §5 fixes it for `/token`; `/device_authorization` is recorded under "does not fix".
4. **An unsupported `grant_type` answers 404**; RFC 6749 §5.2 error responses are 400. Left as it is; not among the decisions.
5. **Decision 0010's 60-second compensating control** no longer describes the client-facing token. §11 makes the amendment a deliverable.
6. **The api's default audience `postern` is not an absolute URI**, which RFC 8707 §2 requires. §8 makes it refuse in any deployment with customer authentication, unless the dev flag is set.
7. **Before the hotfix, under Vault, the conflation was concrete.** Both services signed with `postern-read`, and the api publishes its public half, so an api configured with its own JWKS, issuer `https://mcp-read.internal` and audience `accounts.svc` would have accepted the pre-hotfix `/token` output as a customer token. Derived from code and configuration, not run.
8. **Pairing `scopes` are validated against no vocabulary**, and the api enforces no scope from the token. `docs/integration/mobile-app-pairing-contract.md` already says the scopes shown are not the scopes enforced.
9. **The first revision of this spec overstated recall's convergence.** It said a retried `/scan` completes a failed recall; it does only inside the 10-to-12-second rotation window, because the MAC check precedes `claim_scan`. §7 now says so.
10. **`dev-docs/qr-page-spec.md` §6 says "`/token` is unchanged"** and its session-swap residual says issued tokens are not recalled. Superseded.
11. **The issuance hotfix was not on `origin/main` when this revision was written.** Its behaviour is taken from the coordinator's description, not from code. Once it lands, re-verify §5's first paragraph and the Compatibility test list against it.

## RFC sections relied on

Each read from the RFC Editor's plain-text copy on 30 September 2026.

- RFC 3986 §6.2.2.1 (scheme and host are case-insensitive and "should be normalized to lowercase"; other components case-sensitive), §6.2.3 (an empty path normalizes to `/`; an empty or default port "should be removed").
- RFC 6749 §5.1 (response parameters; the `no-store` and `no-cache` MUST), §5.2 (`invalid_grant`, `invalid_scope`, `unsupported_grant_type`), §6 (refresh parameters, the scope rule, client authentication only for confidential clients, "MAY issue a new refresh token").
- RFC 8628 §3.5.
- RFC 8707 §2 (absolute URI, no fragment, `invalid_target`, "should reject"), §2.2 (a refresh token stays bound to the full original grant).
- RFC 9700 §2.2.2 ("Refresh tokens for public clients MUST be sender-constrained or use refresh token rotation"), §4.14.2 (rotation and reuse, the integrity note, the inactivity SHOULD).
- RFC 9068 §2.1, only to say `at+jwt` is not adopted.

FastMCP facts in §8 were read from the installed `fastmcp` 4.0.3 source on 30 September 2026, not recalled.

## Owed outside this repository

- **A per-family app notification**, "a new session for client X was opened, tap to end it", from the mobile team. It is the only control against a victim approving an attacker's pairing, and **the 12-hour family lifetime requires it first.** Until then the lifetime stays 1 hour.
- **The app's immediate retry of `/scan` on 503** (§7), in the mobile pairing contract.
- **MCP clients that store and use the refresh token.** Not checked; a client that does not re-pairs every 10 minutes.
- **The session transit key and the confirm policy change** in the operator's Vault (§2).
- **Reachability** from every api replica to `/session/jwks.json`.
- **A shared Redis** for both services, now enforced at confirm startup.
- **The api settings of §8**, and the audience equality no process can check.
- **Red-team scenario 2**, extended to the victim-approves-attacker's-pairing form and measured for session length.

## Out of scope

- CIMD client registration; discovery metadata; DPoP.
- A `revoke-family` command in `postern_core.auth.revoke_cli`. §6 step 6 makes a live `jti` stop its family; an operator holding only an expired `jti` revokes the customer.
- Per-customer caps on concurrent families.
- The creator-versus-scanner comparison `dev-docs/qr-page-spec.md` defers.
- `Cache-Control: no-store` on `/device_authorization`.

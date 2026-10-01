# Device grant: the layer-1 session token `POST /token` should issue

**Date:** 30 September 2026, revised the same day after a security review, a re-review, and the landing of the issuance hotfix
**Status:** specification. The seven decisions it specifies were approved by the user on 30 September 2026, and three more were taken after the security review: the refresh family lives **1 hour**, not 12; removing the read key from `services/confirm` is approved; and this spec is written against the issuance hotfix below. Nothing here is built.
**Against:** `origin/main` at `79edf65`, which carries the issuance hotfix (`e76ed4f` and `60161bf`) and the repeat-approval fix (`d0674e5`), read in code for this revision. Every statement below about "today's `/token`" means that state. Statements about the code before `e76ed4f` say "before the hotfix".
**Reviewed by:** a security review on 30 September 2026, folded in below.

---

## What this fixes

**Before the hotfix, `POST /token` returned a layer-2 token to a layer-1 client.** Handoff §7.1 separates two layers and says not to conflate them: layer 1 is the AI client talking to the MCP server under OAuth, layer 2 is the MCP server talking to the backend with a 60-second Vault-signed delegation token. `services/confirm/device_auth.py::_exchange` minted the second and handed it to the first: the confirm service's read minter, an `InternalTokenMinter` over the READ key, with `aud="accounts.svc"`, `scope="accounts:read"`, `iss` = `read_token_issuer` (default `https://mcp-read.internal`), `act: {"sub": "svc:postern"}` and a 60-second life. That is a token Istio accepts at a domain service. `tests/test_qr_pairing_end_to_end.py::test_a_browser_and_a_phone_complete_a_pairing_through_every_route` asserted exactly that shape.

**After the hotfix, `/token` issues nothing.** Read in `services/confirm/device_auth.py` at `60161bf`: for an approved, unexpired, unspent code whose customer passes the ZT-7 check, `_exchange` answers **503 `temporarily_unavailable`, "session token issuance is not enabled", with `Retry-After` set to `device_poll_interval_seconds`**, mints nothing, **does not spend the code** (`consume_device_code` has no caller on this path), and `token_endpoint` writes one row with `DETAIL_ISSUANCE_DISABLED` (`issuance_disabled`). Polls of an approved, unspent code are **paced** since `60161bf`: `token_endpoint` calls `_paced` on a second map, `app.state._approved_poll_times`, separate from the pending map so the last pending poll never paces the first poll after approval; a poll inside the interval answers `slow_down` with no row. The read minter is still built and wired on `app.state.read_minter`, unused, and `PairingAudit.minted()` is kept with a comment saying it has no caller until this change. An approved pairing waits at the 503 until its code expires. The device grant is safe and useless.

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

**Confirm no longer holds the read key** (approved after review). Its only use was the pre-hotfix mint in `_exchange`. Removed from `services/confirm/main.py::create_confirm_app`: the `choose_key_source(role="READ (device grant)", ...)` call, `read_minter`, `app.state.read_minter` and `app.state.postern_read_key_source`. The hotfix left all four wired and unused, and said their removal belongs to this change. Removed from `ConfirmSettings`: `read_key_pem_path`, `read_key_kid`, `read_token_issuer` and `vault_read_key_name`, with their `from_env` lines. In `packages/postern-core/src/postern_core/env_inventory.py`, `POSTERN_READ_KEY_KID`, `POSTERN_READ_KEY_PEM_PATH`, `POSTERN_READ_TOKEN_ISSUER` and `POSTERN_VAULT_READ_KEY_NAME` change from `BOTH` to `("api",)`; a confirm environment still setting one gets the "set but not read" warning `enforce_known_environment` already logs, not a refusal. `device_auth_routes` takes `session_minter` and `session_store`.

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
- `session_token_audience` must be an **absolute `https` URI with a host and no fragment** (RFC 8707 §2: the resource value "MUST be an absolute URI" and "MUST NOT include a fragment component"), **and already in the normal form of §5**, so that the string an operator types into both services is the string compared. Refused otherwise, unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set, in which case the service starts and logs a warning naming the flag. `ConfirmSettings.for_testing()` sets the flag, because its audience is `postern`. `docker-compose.yml` does not: it sets a URI audience on both services instead (§8, "Local stack").
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
  - `REVOKED`: already revoked, and the hash is current or retained. Writes nothing; returns the unexpired jtis.
  - `UNKNOWN`: hash neither current nor retained, **checked first, in every state including revoked**. Writes nothing, returns no jtis. (Amended 1 October 2026: the first implementation answered `REVOKED` to any hash on a revoked family, which told a caller with a guessed secret that the family was revoked and handed back its jtis. Possession now comes before every other verdict, as §6 step 3 already required of the handler.)
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

**Shared state is required, and enforced.** Without `POSTERN_REDIS_URL`, this store and confirm's ZT-7 store are per process: a refresh token from one replica is `invalid_grant` at another, and §7's recall writes the revoked `jti` into confirm's own memory, which the api never reads. So **`create_confirm_app` refuses to start when `POSTERN_REDIS_URL` is unset**, unless `POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS` is set, with a message naming both ways out. The check sits beside `enforce_redis_requirement` and after it, so an operator who also set `POSTERN_REQUIRE_REDIS` hears that message first. With the flag set, the service starts, logs a warning at startup, and every recall row records `DETAIL_RECALL_LOCAL_ONLY` (§9). `ConfirmSettings.for_testing()` sets the flag. `docker-compose.yml` runs no Redis today, so without a change it would have to set the flag too, and recall in the local stack would then be `recall_local_only` and untestable end to end; this spec therefore **adds a `redis` service to `docker-compose.yml`** (`redis:7-alpine`, the image `tests/conftest.py::redis_url` already runs) and sets `POSTERN_REDIS_URL` on both `api` and `confirm`, and compose does not set the flag. It is refuse-to-start rather than refuse-at-`/token` because the device grant is this service's function and a service that cannot recall should not look ready.

### 5. `POST /token`, `grant_type=device_code`

`token_endpoint` keeps its structure as `60161bf` left it: the grant-type dispatch; the unrecorded exits for a missing or unknown code and an expired one; pending polls paced by `_paced` on the pending map, then `authorization_pending`; the pending entry dropped once approved; **approved, unspent polls paced by `_paced` on `app.state._approved_poll_times`**; the approved-with-no-customer 500; then `PairingAudit` with `TOKEN_TOOL_NAME`, then `_exchange`, whose first three steps (spent check, `CustomerRef` parse, ZT-7) stay in order. **The 503 `issuance_disabled` return at the end of `_exchange` is removed** and replaced by the steps below; `DETAIL_ISSUANCE_DISABLED` stays defined and is documented as historical, because `audit_log` is append-only and rows carrying it exist (the precedent `dev-docs/qr-page-spec.md` §7 set for `DETAIL_USER_CODE_MISMATCH`). `PairingAudit.minted()` gets its caller back, loses its "no caller" comment, and its docstring's "a read token was signed" becomes "a session was issued". The sentence in `_exchange`'s docstring saying no build from 2026-09-30 on spends a code becomes false and is rewritten, and `token_endpoint`'s count of recorded and unrecorded exits (five and eight at `60161bf`) is recounted.

**The approved-poll pacing is kept, deliberately.** Once issuance returns, the first poll after approval is answered at once (its own map, never paced by the last pending poll) and on success spends the code, after which the spent code's `invalid_grant` is terminal, unpaced and recorded on every replay, exactly as `60161bf` treats spent codes. What the pacing still governs is an approved code that gets a **retryable** answer, and this spec keeps two: the revocation-store outage 503 and §5 step 2's store-full 503. Each costs a row and a store read, so a client honouring the retry is held to one attempt per interval instead of the address limiter's 300 a minute. Both 503s therefore carry `Retry-After: device_poll_interval_seconds`, as the hotfix's did, so a client honouring the header is never answered `slow_down`. The pacing has a second effect this spec relies on: a burst of concurrent polls on one approved code **within one process** is cut to one before §5 step 1 draws a family, so §5 step 3's orphans come only from polls that land on different replicas (the maps are per process).

Added ahead of the lookup, request shape only, **no row**: **`resource`**. If present it must occur once and, after §5's normalization, equal `session_token_audience`; otherwise 400 `invalid_target` (RFC 8707 §2 defines it: "The requested resource is invalid, missing, unknown, or malformed"). Absent is accepted.

**Normalization of `resource`**, per RFC 3986 §6.2.2.1 and §6.2.3, applied to the presented value only (the configured audience is required to be in normal form already, §2): lower-case the scheme and the host; remove an explicit port that is empty or the scheme's default (443 for `https`, 80 for `http`); an empty path becomes `/`. **No other change**: the path is case-sensitive, percent-encoding is compared as sent, and a trailing slash on a non-empty path is significant, so `https://mcp.example/mcp` and `https://mcp.example/mcp/` are different resources. A value with a fragment, a relative URI, or more than one `resource` parameter is `invalid_target`.

**Note, 1 October 2026: refusals added so one resource has one normal form.** The review of `241b7b5` found that `normalize_resource` merged different values: it lower-cased with Python's Unicode `str.lower()`, so `https://mcp.Key.example/mcp` (U+212A KELVIN SIGN) equalled `https://mcp.key.example/mcp`; `urlsplit` deletes tab, CR and LF and strips leading whitespace, so `https://mcp.exa\tmple/mcp` and ` https://mcp.example/mcp` equalled `https://mcp.example/mcp`; an IPvFuture host lost its brackets; and userinfo was kept. Each of these is now `invalid_target`: a value that is not pure ASCII, or that carries a control character (tab, CR, LF and NUL included), a space, a backslash or `%00`, checked on the raw string before parsing; any `@` in the authority (RFC 9110 §4.2.4: a sender "MUST NOT generate the userinfo subcomponent (and its "@" delimiter)" in an https URI); a bracketed host with no `:`; port 0; a `;` or a `%` in the host. The host is now read from the raw authority, not from `hostname`, and lower-cased only after the ASCII check. IPv6 spellings and a trailing dot on a host are not canonicalised: two spellings of one host compare unequal and are refused, so an operator configures the exact string the client sends. `POSTERN_SESSION_TOKEN_ISSUER` gets the same ASCII and control-character refusal at startup.

Then, replacing the hotfix's 503:

0. **Customer revoked since approval** (§6 step 6's timestamp): if `customer_revoked_at(customer)` is at or after `code.approved_at` less the 2-second cross-clock tolerance, both in milliseconds, refuse as the ZT-7 branch does today (400 `access_denied`, `DETAIL_REVOKED`). The approval predates the revocation; a restore must not make it redeemable.
1. **Draw** `sid`, the first refresh token and its hash; `prepare(customer, code.client_id, canonical(code.scopes), sid)`.
2. **Create the family**, generation 0, with the access `jti` in `access_tokens`, **before the code is spent**: `RefreshSessionStoreFull` answers 503 `temporarily_unavailable` with `Retry-After`, the shape `_store_full_response` uses but with `Retry-After` set to `device_poll_interval_seconds` rather than the device-code lifetime (the code is live and paced; see above), and the code stays redeemable, the argument `_exchange`'s docstring makes for ZT-7 before the claim. Recorded under the exception's type name.
3. **Spend the code**, `consume_device_code(device_code, session_id=sid)`, which gains the argument and writes `session_id` in the compare-and-set that sets `exchanged_at`. `DeviceCode` gains `session_id: str = ""`; older records deserialize with `""`. A lost claim answers `_unredeemable_response()` with `DETAIL_DEVICE_CODE_SPENT` and **discards** the family from step 2. A failing `discard` is logged at warning level with the `sid` and tolerated: the orphan holds a hash nobody has, counts against the cap until it expires within the hour, and orphans arise only from concurrent polls of one approved code that reach different replicas, because the approved-poll pacing cuts a same-process burst to one; the per-replica rate is bounded by `/token`'s 300 per minute per address.
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

   **The store change behind the third check.** `RevocationStoreBase` gains `customer_revoked_at(customer_ref) -> int | None`: the latest instant, **in milliseconds since the Unix epoch**, at which any customer-plus-client revocation naming this customer was written, **kept after that revocation is restored, and for a bounded time only.** It is a concrete method on the base defaulting to `None`, as `is_customer_revoked` is concrete, so `UnreachableRevocationStore`-style test doubles keep working, and it raises `RevocationStoreUnavailable` when the store cannot answer. `restore_customer_client` does not touch it. `revoke_cli` needs no change.

   - **Precision: milliseconds.** The earlier revision stored whole Unix seconds against a `created_at` held at full precision. A family created at 12:00:00.200 and a revocation at 12:00:00.900 then compare as 0 against 0.2, "revoked at or after created" is false, and a family created before the revocation escapes it. Both sides are now integer milliseconds, and every comparison in §5 step 0 and §6 step 6 is on them.
   - **Clock: Redis `TIME`.** On Redis the revocation is written by one server-side script (`EVAL`), which reads `TIME`, then performs the pair's `SADD` and `SET {prefix}revoked:customer-at:<customer_ref> <ms> EX <ttl>`, so the stamp and the revocation are one atomic step on one clock. Today `revoke_customer_client` is a bare `SADD` through `_add`; it becomes that script. `RedisRefreshSessionStore.create` stamps `created_at` from Redis `TIME` too, read on the same connection immediately before its `SET NX`, so the family comparison in §6 step 6 is one clock against itself. A script that calls `TIME` and then writes must be replicated by effects rather than by script body; whether the operator's Redis version does that by default was not verified for this revision, and the operator confirms it. The in-memory backends use `time.time_ns() // 1_000_000` for both, one process, one clock.
   - **The one comparison across two clocks** is §5 step 0: `code.approved_at` is written by the confirm process's clock, not Redis's. There the rule is "refuse when `revoked_at_ms >= approved_at_ms - 2000`": a 2-second tolerance that errs toward refusal, on the stated assumption that both hosts keep UTC under NTP. A customer whose approval lands within 2 seconds after a revocation re-pairs.
   - **Lifetime: bounded, one key per customer.** `{prefix}revoked:customer-at:<customer_ref>`, a string holding the milliseconds, `EX` = `CUSTOMER_REVOKED_AT_TTL_SECONDS` = **4,800 seconds**: the family lifetime (3,600) plus the default device-code lifetime (900), the longest a family or an approved-but-unexchanged code can outlive the revocation it must be compared with, plus a **300-second margin** for replication lag and the tolerance above. After that no family or code it could refuse still exists, so keeping it longer would retain a record that a named customer was cut off for no purpose, which GDPR Article 5(1)(e)'s storage-limitation principle forbids. A later revocation overwrites the value and restarts the expiry. The earlier revision's unbounded hash is dropped. In memory: a dict of `customer_ref -> (ms, expires_at)`, swept on read.
   - **The constant binds `device_code_ttl_seconds`.** The revoke writer (`revoke_cli`, or an operator's own backend) does not know confirm's settings, so the TTL is a constant in `packages/postern-core/src/postern_core/auth/revocation.py`, and `ConfirmSettings.from_env` refuses to start when `SESSION_ABSOLUTE_LIFETIME + device_code_ttl_seconds + 300` exceeds it, which today means a `POSTERN_DEVICE_CODE_TTL_SECONDS` above 900. That is a new ceiling on a variable that had none; the default is unaffected.
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

**Local stack (`docker-compose.yml`).** Today the `api` service trusts the backend stub as its customer-token issuer: `POSTERN_JWKS_URI: http://backend-stub:8081/.well-known/jwks.json`, `POSTERN_TOKEN_ISSUER: "https://postern-local-dev.invalid"`, `POSTERN_AUDIENCE: "postern"`, with local tokens minted by the stub's `/mint-token` route. This spec **repoints the `api` service at confirm**: `POSTERN_JWKS_URI: http://confirm:8080/session/jwks.json`, `POSTERN_TOKEN_ISSUER` equal to confirm's `POSTERN_SESSION_TOKEN_ISSUER`, and on both services the same URI audience, `https://mcp.postern.internal/mcp`, so neither container needs `POSTERN_ALLOW_NON_URI_AUDIENCE`. With the `redis` service of §4 on both, the whole device grant, refresh and recall run end to end in compose. The cost: a token from the stub's `/mint-token` no longer reaches the `api` container, because it names another issuer and another key. The route stays in `stub/backend.py`; the dated records under `docs/verification/` that used it stay as written, since they record what was observed on a date.

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

- **`device_code`**: `TOKEN_TOOL_NAME` on the recorded exits (five at `60161bf`: issuance disabled, ZT-7 refusal, malformed stored identity, revocation outage, spent code), the `issuance_disabled` exit replaced by the mint, `session_id` added once drawn, `RefreshSessionStoreFull` recorded under its type name, §5 step 0 under `DETAIL_REVOKED`. The `resource` refusal writes nothing.
- **`refresh_token`**: `REFRESH_TOOL_NAME`, only past §6 step 3's proof.
- **Recall**: `RECALL_TOOL_NAME`, subject the recalled family's customer, `claims={}`. `returned` when the family was revoked and every jti written to a shared store; `raised` with `DETAIL_RECALL_LOCAL_ONLY`, `DETAIL_RECALL_NO_SESSION` or an exception type name otherwise.

**Counts are per endpoint, and `tool_name` is what separates them.** Once `PairingAudit.minted()` is called again, several device-grant endpoints write `outcome='returned'` with a NULL `detail` on success: `/approve` (`PairingAudit.approved()`), `/scan` for first scans only (the same method, `dev-docs/qr-page-spec.md` §7), `/token` for both grants (`minted()`), and the recall. And since `d0674e5` a repeat `/approve` by the customer who already approved is answered 200 and recorded by `PairingAudit.approved_again()` as `outcome='returned'` with `detail = DETAIL_ALREADY_APPROVED` (`already_approved`), so on `/approve` rows "one pairing granted" is `outcome='returned' AND detail IS NULL`. A count that filters on outcome and detail alone therefore mixes pairings, scans, sessions, refreshes and recalls.

**Minted rows are told apart by `tool_name`, not by a detail of their own.** Every endpoint already writes its own `tool_name` (`device_grant.approve`, `device_grant.scan`, `device_grant.token`, `device_grant.refresh`, `device_grant.recall`), so the column that says which endpoint wrote a row is already there and already populated on every row, historical ones included. A success detail such as `minted` would be a second, redundant discriminator that only new rows carry, and it would break the reading "NULL `detail` on a `returned` row means plain success", which the approval fix keeps for every row except the repeat approval and the two `/scan` repeats (`already_scanned` before approving, `already_approved` after; `dev-docs/qr-page-spec.md` §5). So `minted()` keeps writing NULL, and the queries are:

| Question | Predicate |
|---|---|
| Pairings granted | `tool_name = 'device_grant.approve' AND outcome = 'returned' AND detail IS NULL` |
| Repeat approvals | `tool_name = 'device_grant.approve' AND outcome = 'returned' AND detail = 'already_approved'` |
| Pairings scanned (first scans only) | `tool_name = 'device_grant.scan' AND outcome = 'returned' AND detail IS NULL` |
| Repeat scans | `tool_name = 'device_grant.scan' AND outcome = 'returned' AND detail IN ('already_scanned','already_approved')` |
| Sessions issued | `tool_name = 'device_grant.token' AND outcome = 'returned' AND detail IS NULL` |
| Refreshes issued | `tool_name = 'device_grant.refresh' AND outcome = 'returned' AND detail IS NULL` |
| Recalls completed | `tool_name = 'device_grant.recall' AND outcome = 'returned'` |

`WHERE tool_name LIKE 'device_grant.%' AND outcome = 'returned' AND detail IS NULL` is the wrong query for any of them: it adds scans, approvals, sessions and refreshes together. Two tests pin the rule. One asserts that `minted()` is reached only from a `PairingAudit` built with `TOKEN_TOOL_NAME` or `REFRESH_TOOL_NAME`. The other drives one full pairing, one exchange and one refresh, then runs each predicate above against the table and asserts a count of exactly one for each (and zero repeat approvals). `docs/user-guide/components/audit.md`, which documents these rows for operators, carries the table.

No migration: `detail` is unconstrained `Text` and no constraint names `tool_name`.

### 10. Public paths, rate limits, body limit

`/session/jwks.json` joins `PUBLIC_PATHS` in `services/confirm/auth.py` with its reason (the api's verifier fetches it holding no assertion), making nine. A plain `Route`. `services/confirm/rate_limit.py` gains a row at 300 per minute per address bucket. §8's refetch floor, negative cache and coalescing live on one `SessionTokenVerifier` object, and that object is **per process**: "one fetch per 30 seconds on a miss plus one per TTL" is per api **worker process**, which equals per replica only with one worker per container. That holds today (the Dockerfile's `api` target runs `uvicorn services.api.main:app` with no `--workers`), and an operator who adds workers multiplies the fetch rate by their number. All replicas may also share one NAT address. `/token` keeps its single 300-per-minute row for both grants. `BodySizeLimit` needs no change beyond the tests that list paths.

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
- **Revocation store**: `customer_revoked_at` on both backends, in milliseconds, surviving `restore_customer_client`, written by the one script with the pair, stamped from Redis `TIME`, expiring after 4,800 seconds (Redis `TTL` read back), a second revocation overwriting the first; the 200 ms-before case of §6 step 6 refused; the 2-second tolerance of §5 step 0 at both edges; `ConfirmSettings.from_env` refusing a device-code TTL above 900.
- **`/device_authorization`**: `client_id` `-` refused.
- **Recall**: B scans and approves, A's client exchanges, A scans: `scan_conflict`, B's family refuses refresh, and **A's client's next `tools/call` through the assembled `services/api` app is refused**, counted in backend touches as `tests/test_zt7_revocation_reachable.py` counts them. The recall-before-sign race. Store failure answers 503 with `Retry-After: 1` and both rows; an immediate retry completes the recall; a retry after the rotation window answers `qr_stale`. `recall_no_session` and `recall_local_only`.
- **api verifier**: TTL from `POSTERN_VAULT_PUBLIC_KEY_TTL_SECONDS`; a burst of tokens with one unknown kid causes one fetch per 30 seconds; concurrent misses coalesce into one fetch; the private-method signature pin; the audience-URI refusal with and without the flag. **And a behavioural test, because a signature pin does not prove the override is called:** a token signed by a key whose kid is absent from the published JWKS, presented through the assembled `build_server` app, is refused, and the counting JWKS server behind it records exactly the fetches the override allows (one on the first miss, none on a second miss inside 30 seconds). If an upgrade stops routing through `_get_jwks_key`, this test sees FastMCP's unbounded refetch and fails. It must be re-run, not only kept green, on every `fastmcp` version bump.
- **End to end over ASGI**, extending `tests/test_qr_pairing_end_to_end.py::test_a_browser_and_a_phone_complete_a_pairing_through_every_route`: pairing, `/token`, `tools/list` on `services/api` configured per §8, a refresh, `tools/list` with the new token.
- **Audit**: one row per recorded exit with §9's literals; the recall's two rows share a `call_id` and name different customers; no token material in any row.

## Compatibility

**This is a breaking change to `/token`** relative to both the pre-hotfix response (a different token and two new keys) and the hotfix (200 where it answers 503). No client depends on either: nothing could verify the pre-hotfix token as a customer token, and the hotfix issues nothing.

Tests that change, re-derived by `grep` at `60161bf`, after the hotfix rewrote several of them:

- **The hotfix's own assertions, which this change inverts.** Every assertion on `ISSUANCE_DISABLED_BODY` (defined in `tests/device_grant_helpers.py` and imported by `tests/test_device_grant.py`, `tests/test_pairing_audit.py`, `tests/test_qr_pairing_end_to_end.py`, `tests/test_zt7_confirm_revocation.py` and `tests/test_confirm_rate_limit.py`) becomes the §5 success body, and every assertion that an approved code stays unspent becomes one that it is spent. By name: `tests/test_pairing_audit.py::test_an_approved_code_is_refused_503_unspent_and_recorded_as_issuance_disabled`; in `tests/test_device_grant.py`, `test_approved_exchange_is_refused_and_the_approval_names_the_bearer_subject`, `test_approved_exchange_body_has_exactly_the_two_error_keys`, `test_a_refused_exchange_leaves_the_code_unspent` and `test_two_concurrent_exchanges_issue_nothing_and_spend_nothing` (the last becomes: exactly one of two concurrent exchanges is issued a session); and the approved-exchange assertions in `tests/test_zt7_confirm_revocation.py` and `tests/test_confirm_rate_limit.py`, including the latter's comment that no exchange spends a code. The outage test in `tests/test_zt7_confirm_revocation.py`, which asserts the outage 503 is not the issuance body, keeps its point (the outage's own 503) with a new comparison.
- **The pacing tests stay**, re-pointed at the retryable answers that remain: `tests/test_pairing_audit.py::test_polls_of_an_approved_code_are_paced_at_the_interval` and `tests/test_pairing_audit.py::test_the_first_poll_after_approval_is_not_paced_by_the_last_pending_one` pace polls that answer the outage or store-full 503, and the first poll after approval now succeeds.
- **The regression helper narrows.** `assert_no_body_carries_a_token_the_api_trusts` in `tests/device_grant_helpers.py` asserts two things: no body string verifies against the api's read JWKS (kept; it is the property that matters, no layer-2 token reaches a client), and no body holds anything JWT-shaped at all, which a session token now is. The second half becomes: every JWT-shaped string verifies against `/session/jwks.json` only, with the session issuer and audience.
- **The read-minter control moves.** `tests/test_qr_pairing_end_to_end.py::test_a_browser_and_a_phone_complete_a_pairing_through_every_route` mints a backend token with `confirm.state.read_minter` to prove the regression can fail; with the read key gone from confirm, that control mints with a `services/api` app's read minter instead. Its `_approved_poll_times` rewind stays. `tests/test_pairing_audit.py` replaces `app.state.read_minter` twice (a must-not-be-called minter and an unsignable one); both target the session minter.
- `tests/test_confirm_service.py::test_the_confirm_settings_have_no_read_key_field`: the allowed set becomes empty.
- `tests/test_ephemeral_key_warning.py`: the confirm cases passing `read_key_pem_path`; confirm now warns for write and session.
- `tests/test_device_code_pairing_store.py`, `tests/test_redis_backed_stores.py`, and the `consume_device_code` calls in `tests/test_device_grant.py`, `tests/test_pairing_audit.py`, `tests/test_confirm_rate_limit.py` and `tests/test_scan.py` (which seed spent codes through the store): the method gains `session_id`; the record gains the field.
- `tests/test_confirm_auth.py` (the `PUBLIC_PATHS` set), the confirm rate-limit and body-limit path tables, and `tests/test_settings_bounds.py` (the environment inventory sweep, and the new device-code TTL ceiling).

**The dataclass defaults are chosen deliberately, and the choice has a cost in tests.** `ConfirmSettings`' field defaults are the safe values: `allow_process_local_sessions=False`, `allow_non_uri_audience=False`, `session_token_audience="postern"`. So a `ConfirmSettings(...)` built by hand and passed to `create_confirm_app` without `POSTERN_REDIS_URL` is refused at startup, twice over, exactly as a deployment would be; only `ConfirmSettings.for_testing()` sets the two flags. The alternative, permissive defaults, would make every hand-built settings object a configuration no deployment may run, silently. Every test that builds `ConfirmSettings(...)` directly and assembles an app must therefore pass the flags, or a URI audience and a Redis URL. Found by `grep -rl 'ConfirmSettings(' tests` at `60161bf`, 15 files, unchanged by the hotfix: `tests/test_approval_concurrency.py`, `tests/test_approval_integration.py`, `tests/test_audit_reserve.py`, `tests/test_confirm_app_link_setting.py`, `tests/test_confirm_auth.py`, `tests/test_confirm_body_limit.py`, `tests/test_device_grant.py`, `tests/test_device_signature.py`, `tests/test_ephemeral_key_warning.py`, `tests/test_pool_sizing.py`, `tests/test_settings_bounds.py`, `tests/test_vault_live.py`, `tests/test_write_audit_arguments_cap.py`, `tests/test_write_audit.py`, `tests/test_zt7_confirm_revocation.py`. Some of those build settings without building an app and are unaffected; which ones is re-derived at implementation. Files that call `ConfirmSettings.from_env` or `create_confirm_app` (`grep -rlE 'ConfirmSettings\.from_env|create_confirm_app' tests` at `60161bf`, 23 files): `tests/test_approval_concurrency.py`, `tests/test_approval_integration.py`, `tests/test_audit_reserve.py`, `tests/test_confirm_app_link_setting.py`, `tests/test_confirm_auth.py`, `tests/test_confirm_body_limit.py`, `tests/test_confirm_customer_rate_limit.py`, `tests/test_confirm_rate_limit.py`, `tests/test_confirm_service.py`, `tests/test_device_grant.py`, `tests/test_device_signature.py`, `tests/test_ephemeral_key_warning.py`, `tests/test_pairing_audit.py`, `tests/test_pool_sizing.py`, `tests/test_qr_pairing_end_to_end.py`, `tests/test_require_redis_guard.py`, `tests/test_scan.py`, `tests/test_settings_bounds.py`, `tests/test_unknown_env_guard.py`, `tests/test_verify_page.py`, `tests/test_write_audit_arguments_cap.py`, `tests/test_write_audit.py`, `tests/test_zt7_confirm_revocation.py`. Fourteen of them are also in the first list; `tests/test_vault_live.py` is in the first list only. Those that reach `create_confirm_app` through `for_testing()` are unaffected; those that go through `from_env` with a patched environment need `POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS` and `POSTERN_ALLOW_NON_URI_AUDIENCE` in it, or `POSTERN_REDIS_URL` against the suite's Redis container. `tests/test_require_redis_guard.py` gains the new refusal's ordering against `enforce_redis_requirement`.
- api tests that build `build_server` with a JWKS URI and the default audience `postern` now need `POSTERN_ALLOW_NON_URI_AUDIENCE` or a URI audience.

Docs that go stale, most of them already rewritten once by the hotfix to describe the 503: `docs/user-guide/components/confirm-service.md`, `docs/user-guide/glossary.md`, `docs/user-guide/getting-started.md`, `docs/user-guide/components/audit.md`, `docs/integration/mobile-app-pairing-contract.md` (§11), `CLAUDE.md` (the `services/confirm` paragraph, operator item 6, red-team scenario 2), the `docker-compose.yml` comment on confirm's keys, `dev-docs/decisions/0010-dpop-sender-constraint.md` (§11), `dev-docs/decisions/0012-device-code-single-use.md`, and `dev-docs/qr-page-spec.md`. `tools/render_auth_flow.py` already says "customer access token".

## Size

About 18 production and config files: `services/confirm/session_token.py` (new, ~120 lines), `packages/postern-core/src/postern_core/auth/refresh_sessions.py` (new, ~450), `services/api/session_verifier.py` (new, ~90), `services/confirm/device_auth.py` (~300 changed: `_exchange`, `_refresh`, the recall, the `client_id` refusal), `services/confirm/audit.py` (~70), `services/confirm/settings.py` (~110 added, ~20 removed), `packages/postern-core/src/postern_core/auth/revocation.py` (~80: `customer_revoked_at` on both backends, the Lua revoke script, the TTL constant), `services/api/settings.py` and `services/api/server.py` (~40), `services/confirm/main.py`, `services/confirm/jwks.py`, `services/confirm/auth.py`, `services/confirm/rate_limit.py`, `packages/postern-core/src/postern_core/auth/device_codes.py`, `packages/postern-core/src/postern_core/env_inventory.py`, `docker-compose.yml` (a `redis` service, the api repointed at confirm, URI audiences). Roughly 1,350 lines of production code and 2,000 to 2,500 of tests. No migration. Standing memory: at the 40,000 cap and the 4 KiB worst-case record, about 160 MiB of Redis; at the expected 7 generations per family, well under a fifth of that. Orphaned families from failed discards sit inside the cap. The customer revocation timestamps are one small key per customer revoked in the last 80 minutes.

## Discrepancies

1. **Stale "atomic step" claim, in three files at `60161bf`.** `services/confirm/settings.py`'s module docstring, a comment in `create_confirm_app` and two comments in `docker-compose.yml` still say (CLAUDE.md operator item 6 no longer does) the device grant mints read and write tokens in one atomic step. Audit finding C-01 removed the write token; the hotfix removes the read one.
2. **`RevocationMiddleware`'s docstring says `services/confirm` consults no revocation store** and that the device-grant exchange is uncovered. Stale: `services/confirm/revocation.py` checks on four paths.
3. **`/token` sends no `Cache-Control: no-store` or `Pragma: no-cache`**, which RFC 6749 §5.1 requires. §5 fixes it for `/token`; `/device_authorization` is recorded under "does not fix".
4. **An unsupported `grant_type` answers 404**; RFC 6749 §5.2 error responses are 400. Left as it is; not among the decisions.
5. **Decision 0010's 60-second compensating control** no longer describes the client-facing token. §11 makes the amendment a deliverable.
6. **The api's default audience `postern` is not an absolute URI**, which RFC 8707 §2 requires. §8 makes it refuse in any deployment with customer authentication, unless the dev flag is set.
7. **Before the hotfix, under Vault, the conflation was concrete.** Both services signed with `postern-read`, and the api publishes its public half, so an api configured with its own JWKS, issuer `https://mcp-read.internal` and audience `accounts.svc` would have accepted the pre-hotfix `/token` output as a customer token. Derived from code and configuration, not run.
8. **Pairing `scopes` are validated against no vocabulary**, and the api enforces no scope from the token. `docs/integration/mobile-app-pairing-contract.md` already says the scopes shown are not the scopes enforced.
9. **The first revision of this spec overstated recall's convergence.** It said a retried `/scan` completes a failed recall; it does only inside the 10-to-12-second rotation window, because the MAC check precedes `claim_scan`. §7 now says so.
10. **`dev-docs/qr-page-spec.md` §6 says "`/token` is unchanged"** and its session-swap residual says issued tokens are not recalled. Superseded.
11. **The hotfix, read in code, differs from how the previous revision described it** in three ways, all now folded in: it paces approved, unspent polls on a separate map (`app.state._approved_poll_times`, via `_paced`) and answers `slow_down` with no row inside the interval, with `Retry-After` on the 503 set to the poll interval; it leaves the read minter wired and unused rather than removing it; and it keeps `PairingAudit.minted()` with no caller. The previous revision also said the hotfix had not landed; it landed as `e76ed4f` and `60161bf`.

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

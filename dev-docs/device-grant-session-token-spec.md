# Device grant: the layer-1 session token `POST /token` should issue

**Date:** 30 September 2026
**Status:** specification. The seven decisions it specifies were approved by the user on 30 September 2026; this document states them precisely and does not reopen them. Nothing here is built.
**Against:** `services/confirm/device_auth.py`, `services/confirm/main.py`, `services/confirm/settings.py`, `services/confirm/jwks.py`, `services/confirm/audit.py`, `packages/postern-core/src/postern_core/auth/` and `services/api/` at `31103cf`.

---

## What this fixes

**`POST /token` returns a layer-2 token to a layer-1 client.** Handoff §7.1 separates two layers and says not to conflate them: layer 1 is the AI client talking to the MCP server under OAuth, layer 2 is the MCP server talking to the backend with a 60-second Vault-signed delegation token. `services/confirm/device_auth.py::_exchange` mints the second and hands it to the first. It calls the confirm service's read minter with `audience="accounts.svc"` and `scope="accounts:read"`, which is an `InternalTokenMinter` built over the READ key with `iss` set to `read_token_issuer` (default `https://mcp-read.internal`), and it carries `act: {"sub": "svc:postern"}` and a 60-second life. That is the token Istio accepts at a domain service. The AI client is not supposed to hold one: it is a credential for the hop behind the MCP server, and the whole point of the MCP server is that the client never talks to that hop. `tests/test_qr_pairing_end_to_end.py::test_a_browser_and_a_phone_complete_a_pairing_through_every_route` asserts exactly this shape today (`aud == "accounts.svc"`, `act == {"sub": "svc:postern"}`, the read kid, the read issuer).

The conflation also leaves the device grant unusable as a login. Nothing configures `services/api` to accept the token `/token` returns, because `services/confirm` publishes only its write key (`services/confirm/jwks.py`'s `jwks_route` over `write_key_source` in `services/confirm/main.py::create_confirm_app`). And a 60-second token with no refresh means the customer re-pairs with a QR scan every minute.

After this spec:

- `POST /token` with `grant_type=device_code` returns a layer-1 **access token** whose audience is the MCP server, signed by a third key that signs nothing else, plus a **refresh token**.
- `POST /token` with `grant_type=refresh_token` rotates that refresh token and issues a fresh access token.
- `services/api` verifies the access token through the `JWTVerifier` it already builds, from settings it already reads.
- No client receives a layer-2 token from any endpoint.
- **The session-swap residual in `dev-docs/qr-page-spec.md` closes.** That spec's "What this does not fix" says that when `/scan` detects a swap after the code was exchanged, "the token already issued is not recalled by this spec". This one recalls it (§7).

## What this does not fix

- **Client authentication.** The client stays a public client. `client_id` is whatever the browser typed at `POST /device_authorization`, and nothing here verifies it. CIMD registration (handoff §7.1) is the fix and is out of scope. The access token carries `client_id` with a `client_id_verified: false` claim beside it (§3), the same marking `/scan` already puts in its response.
- **A stolen access token works for up to 10 minutes.** The access token is a bearer credential with no sender constraint, and decision record 0010 records why DPoP is not available. Recall and ZT-7 revocation cut it early only when someone notices. That window is ten times the 60 seconds decision 0010 lists as a compensating control; see Discrepancies.
- **A stolen refresh token is detected, not prevented.** Rotation with reuse detection (§4) tells the server that two parties hold one family; it cannot tell which one is the customer, and it only fires once both have presented. Until the legitimate client refreshes, the thief refreshes freely, for up to the 12-hour family lifetime.
- **The kill switch and the customer-plus-client revocation key on a value the caller chose.** `services/api/middleware/revocation.py`'s `RevocationMiddleware` reads `client_id` off the validated token. After this spec that is the pairing's caller-supplied `client_id`, so a kill switch on `vendor-x` does not stop a pairing that declared itself `vendor-x2`. The customer-wide check at `/token` (below) still refuses a revoked customer under any `client_id`. ZT-5's risk budget in `services/api/middleware/risk.py` keys on the same pair, so a customer who re-pairs under a new `client_id` gets a fresh budget. Re-pairing costs a scan and an approval on the customer's own phone, which bounds it.
- **The `scope` claim is whatever the pairing asked for.** `POST /device_authorization` accepts any string of up to `max_scopes_length` characters as `scopes` and validates no vocabulary, and `services/api/server.py::build_server` builds its `JWTVerifier` with `required_scopes=None`; consent is enforced from Postgres, not from the token. The claim records what the customer was shown on the `/scan` screen and approved. It authorizes nothing by itself, today or after this spec.
- **Recall reaches back only while the device-code row lives.** `/scan` finds a pairing by `user_code`, and that lookup expires with the device code (default 900 seconds). A victim who scans later than that gets `invalid_grant` and nothing is recalled. In practice the victim scans within seconds of the attacker, which is the case §7 covers.
- **No idle expiry.** RFC 9700 §4.14.2 says refresh tokens "SHOULD expire if the client has been inactive for some time". This spec sets an absolute 12-hour lifetime only, per the approved decision. Recorded in Discrepancies.
- **Discovery.** Neither service serves OAuth protected resource metadata or authorization server metadata; `git grep` finds no `oauth-protected-resource` or `oauth-authorization-server` route under `services` or `packages`. Whether an MCP client under protocol `2026-07-28` needs either to find `/device_authorization` has not been checked against the spec text. Out of scope.

## What does not change

- **Layer 2.** `services/api` keeps minting its own 60-second RFC 8693 delegation token per backend call through `ReadTokenMinter` over the READ key, and Istio keeps verifying it against the api's `/.well-known/jwks.json`. Nothing in this spec touches `InternalTokenMinter`, `ReadTokenMinter`, `WriteTokenMinter`, `READ_SCOPES` or `WRITE_SCOPES`.
- **The read/write key split.** The api holds the read key and no other; confirm holds the write key; `/.well-known/jwks.json` on confirm stays write-only. The split gets stronger, not weaker: §1 removes the read key from confirm.
- **The device-code lifecycle up to the exchange.** `/device_authorization`, the page, `/scan`'s first five steps, `/approve` and `consume_device_code`'s single-use guarantee are as `dev-docs/qr-page-spec.md` built them. The only change to `/scan` is what it does on `conflict_exchanged` (§7).
- **Decision 0006.** Every row this spec adds is fail-closed like the rows it sits beside.

---

## Design

### 1. Roles: confirm becomes the layer-1 authorization server, and gives up the read key

`services/confirm` is the authorization server for the device grant. It issues layer-1 tokens for exactly one resource, the MCP server `services/api` serves, and publishes the key that verifies them. `services/api` is the resource server: it verifies, and never signs, a layer-1 token.

**Confirm no longer holds the read key.** Its only use of the read key is the mint in `_exchange`, which this spec deletes. With it go, from `services/confirm/main.py::create_confirm_app`, the `choose_key_source(role="READ (device grant)", ...)` call, `read_minter`, `app.state.read_minter` and `app.state.postern_read_key_source`; and from `ConfirmSettings`, the fields `read_key_pem_path`, `read_key_kid`, `read_token_issuer` and `vault_read_key_name` with their `from_env` lines. In `packages/postern-core/src/postern_core/env_inventory.py`, `POSTERN_READ_KEY_KID`, `POSTERN_READ_KEY_PEM_PATH`, `POSTERN_READ_TOKEN_ISSUER` and `POSTERN_VAULT_READ_KEY_NAME` change from `BOTH` to `("api",)`. A confirm environment that still sets one gets the "set but not read" warning `enforce_known_environment` already logs for that population, not a refusal. `device_auth_routes` loses its `read_minter` parameter and gains `session_minter` and `session_store`.

This is the device-grant exception `ConfirmSettings`' docstring records, and it ends. After this spec there is again one process per signing key in the read/write split: the api holds READ, confirm holds WRITE and the new SESSION key, and no process holds READ and WRITE together. `tests/test_confirm_service.py::test_the_confirm_settings_have_no_read_key_field` tightens to what its name says: no field of `ConfirmSettings` contains `read`.

**What the session key is worth to an attacker, stated plainly.** A process holding it can mint an access token for any customer, and `services/api` will serve that customer's masked reads to whoever presents it. That is the same power the read key in confirm gave before this spec, one hop further out: the old exception let confirm mint a token the backend accepted directly, and the session key lets confirm mint one the api accepts and then turns into a backend token under its own key. The blast radius is unchanged. The difference is that the api's read key now signs only inside the api, and the confirm process can no longer reach a domain service directly with any token.

### 2. The session key

A third signing key, used for layer-1 access tokens and for nothing else. It is built by the same `packages/postern-core/src/postern_core/auth/keys.py::choose_key_source` call the other two keys use, so it inherits every existing rule without new code in that module:

- `POSTERN_VAULT_ADDR` set: a `VaultTransitKeySource` over the transit key named by `vault_session_key_name`.
- `POSTERN_SESSION_KEY_PEM_PATH` set: a `FileKeySource`, which refuses a public-key PEM at startup.
- Neither: a `GeneratedKeySource`, and `warn_ephemeral_signing_key` fires with `role="SESSION"` and `pem_env_var="POSTERN_SESSION_KEY_PEM_PATH"`.
- Both a Vault address and a PEM path: `choose_key_source` raises `ValueError` at startup, as it does for the other two keys.

The call sits in a new `build_session_minter(settings)` in a new `services/confirm/session_token.py`, returning the minter and its `KeySource` the way `services/confirm/minter.py::build_write_minter` does. `create_confirm_app` calls it after `build_write_minter` and before the device-code store is built, so the startup-order tests that pin authentication-first and Redis-second keep holding.

**New settings** on `ConfirmSettings`, each with an `EnvVar(..., ("confirm",))` entry in `packages/postern-core/src/postern_core/env_inventory.py`:

| Field | Variable | Default | Notes |
|---|---|---|---|
| `session_key_pem_path` | `POSTERN_SESSION_KEY_PEM_PATH` | `None` | The PEM branch. |
| `session_key_kid` | `POSTERN_SESSION_KEY_KID` | `session-1` | The kid, or under Vault the kid prefix. |
| `vault_session_key_name` | `POSTERN_VAULT_SESSION_KEY_NAME` | `postern-session` | The transit key. |
| `session_token_issuer` | `POSTERN_SESSION_TOKEN_ISSUER` | `https://auth.postern.internal` | This service's public issuer URL, the `iss` of every access token. A placeholder host for local work, like `device_verification_uri`'s. |
| `session_token_audience` | `POSTERN_SESSION_TOKEN_AUDIENCE` | `postern` | The MCP server's resource identifier, the `aud` of every access token. Must equal `services/api`'s `POSTERN_AUDIENCE`, whose default is also `postern`. |
| `max_refresh_sessions` | `POSTERN_MAX_REFRESH_SESSIONS` | `100000` | The session store's cap (§4). |
| `rate_limit_session_jwks` | `POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS` | `300` | §10. |

**Startup refusals**, in `ConfirmSettings.from_env` for the ones that read one field and in `create_confirm_app` beside `_assertion_verifier` for the ones that compare fields, each raising `ValueError` with the offending values named:

- `session_token_issuer` must parse with `urllib.parse.urlsplit` as `https` with a hostname, no query and no fragment (the shape `_app_link_uri` already refuses for the app link).
- `session_token_issuer` must differ from `write_token_issuer` and from `app_assertion_issuer`. One issuer string per token type is what keeps a verifier configured for one from accepting another.
- `session_token_audience` must be non-empty and must differ from `app_assertion_audience`. `ConfirmSettings`' docstring already argues why the app assertion's audience must not collide with the api's; this is the same rule seen from the other side, and this process can check it because it holds both values.
- Nothing here can check that `session_token_audience` equals the api's `POSTERN_AUDIENCE`, for the reason `ConfirmSettings`' docstring gives: the other service is a different deployment and `.importlinter` forbids reading its settings. An operator owns that equality, and a mismatch fails closed: every access token is refused at the api.

**JWKS path.** The session key's public half is published at **`/session/jwks.json`** on `services/confirm`, by a new `session_jwks_route(source)` in `services/confirm/jwks.py` beside the existing `jwks_route`, with its own `SESSION_JWKS_PATH` constant. Not a path parameter on `jwks_route`: that module's docstring asks that its body stay the deliberate duplicate of `services/api/jwks.py` and change in step, and a second function in confirm alone changes nothing on the api side. Each route publishes one source's `public_jwks()` and nothing else. **`/.well-known/jwks.json` stays write-only**, and a test asserts the two key sets share no kid and no modulus: the combined-key-set hazard `services/confirm/jwks.py`'s docstring measured is exactly what a convenience merge of these two routes would reintroduce.

**Kid and rotation, mirroring decision 0020.** Under Vault the published kid is `<session_key_kid>.v<version>` (default `session-1.v1`), every version Vault still holds is published, and the version is pinned on every signature from the same read that produced the published set. None of that is new code: `VaultTransitKeySource` already behaves this way for any key name. Under a PEM or a generated key the kid is `session_key_kid` unchanged. Two facts specific to this key:

- The verifier picks a rotation up at once. `services/api` verifies through FastMCP 4.0.3's `JWTVerifier`, which caches the JWKS for 3600 seconds but, as read in the installed `fastmcp/server/auth/providers/jwt.py`, serves from the cache only when the presented kid is already in it and refetches otherwise. A token carrying a new version's kid therefore forces one fetch and verifies.
- **Do not raise `min_available_version` past a version whose tokens may still be in flight.** For the session key that is **10 minutes**, not the 60 seconds decision 0020's operator note is written around.

Vault: a third transit key, `rsa-2048` or `rsa-4096`, created without `exportable=true`. Confirm's policy gains `update` on `transit/sign/postern-session` and `read` on `transit/keys/postern-session`, and loses both paths on `postern-read` (§1). The api's policy gains nothing: it verifies session tokens from the JWKS and never signs one. `docker-compose.yml` creates the key and changes the confirm policy accordingly.

### 3. The access token

Minted by a new `SessionTokenMinter` in `services/confirm/session_token.py`. Not `InternalTokenMinter`: that class is the layer-2 delegation shape, with `act`, a fixed 60-second `_LIFETIME` and an audience that names a domain service, and bending it into a layer-1 token is the conflation this spec removes.

It has two steps, where `InternalTokenMinter` has one, because §5 and §6 must write the `jti` into the session store **before** the token exists:

- `prepare(*, customer: CustomerRef, client_id: str, scope: str, sid: str) -> SessionClaims` draws the `jti` (`uuid.uuid4()`, as `InternalTokenMinter.mint_with_jti` does, and never accepted from a caller, for the reason that method's docstring gives), reads the clock once for `iat`, and returns the claims as a frozen value.
- `sign(claims: SessionClaims) -> str` calls `KeySource.sign`. Under Vault it performs the transit round trip and can raise `VaultTransitError`; it never returns an unsigned token.

Claims, and nothing else:

| Claim | Value |
|---|---|
| `iss` | `session_token_issuer` |
| `aud` | `session_token_audience`, a single string |
| `sub` | the customer reference, from `CustomerRef` so its validation runs |
| `client_id` | the pairing's `client_id`, verbatim |
| `client_id_verified` | `false`, always. The caller-supplied marking the approved decision asks for, spelled the way `/scan`'s response spells it. |
| `scope` | the granted scope string: the pairing's `scopes` on a device-code exchange, the granted subset on a refresh (§6) |
| `sid` | the session family id (§4) |
| `jti` | drawn by `prepare` |
| `iat` | issue time, integer seconds |
| `exp` | `iat + 600` |

No `act`, because nothing is acting for anyone at layer 1: the client is the party the customer authorized. No `nbf`. No PII: `sub` is the opaque customer reference, the rule handoff §7.2 states for layer 2 and which holds here for the same reason.

`ACCESS_TOKEN_LIFETIME_SECONDS = 600` is a code constant in `services/confirm/session_token.py`, with no setting, the way `dev-docs/qr-page-spec.md` §2 fixed the rotation window.

**Header.** `alg: RS256` and the kid, as the key source writes them. The header's `typ` is whatever the key source writes (`JWT` under Vault, absent under the local sources); this spec does not set RFC 9068 §2.1's `at+jwt` and does not claim conformance with that profile. What keeps a session token from being accepted as another token type, and the reverse, is that each type has its own issuer, its own audience and its own key, and every verifier in this system checks all three: the api's `JWTVerifier` checks `iss` and `aud` and resolves the key from the session JWKS only; Istio resolves layer-2 tokens from the api's JWKS; `AppAssertionMiddleware` resolves app assertions from the operator's app JWKS.

### 4. The refresh token and the session family store

A **session family** is everything issued from one device-code exchange: one family id, a chain of refresh tokens of which exactly one is current, and the access tokens minted alongside them. It lives at most 12 hours from the exchange.

**Refresh token format.** `prt1.<sid>.<secret>`:

- `sid`: 16 random bytes from `secrets`, base64url without padding, 22 characters. The family id. It also appears in every access token as `sid`, so it is not a secret and is not treated as one.
- `secret`: `secrets.token_urlsafe(32)`, 256 bits, drawn fresh for every refresh token.

The refresh token is opaque to the client and is never stored. The store holds `SHA-256(refresh token)` as lowercase hex. A read of the store yields no usable refresh token.

**Why the family id is in the token, and why that is safe.** RFC 9700 §4.14.2's implementation note allows encoding the grant into the refresh token and then says authorization servers "MUST ensure the integrity of the refresh token value in this case". Here `sid` only selects which record to read. Every action (rotate, or revoke as reuse) requires the SHA-256 of the **whole** presented value to equal a hash that record stored. A value with a real `sid` and any other secret matches nothing and changes nothing: it is answered `invalid_grant` and revokes nothing. That matters because `sid` is readable in every access token; if a wrong secret under a known `sid` revoked the family, anyone who saw one access token could end the customer's session.

**The record**, a new frozen dataclass `RefreshSession` in a new `packages/postern-core/src/postern_core/auth/refresh_sessions.py`, serialized as JSON the way `DeviceCode` is:

| Field | Type | Meaning |
|---|---|---|
| `sid` | `str` | Family id. |
| `customer_ref` | `str` | The customer, copied from the device code's `customer_ref` at exchange. Never from a request. |
| `client_id` | `str` | The pairing's `client_id`, caller-supplied. |
| `scopes` | `str` | The pairing's granted scopes. Fixed for the family's life, in the sense of RFC 8707 §2.2's "bound to the full original grant": a refresh may narrow one access token, never the family. |
| `created_at` | `datetime` | Exchange time. |
| `expires_at` | `datetime` | `created_at + 12 h`. Absolute; no operation moves it. |
| `generation` | `int` | 0 at exchange, +1 per rotation. |
| `current_hash` | `str` | SHA-256 hex of the one refresh token that may be presented. |
| `retained_hashes` | `tuple[str, ...]` | Hashes of every earlier refresh token of this family, kept to recognize reuse. |
| `access_tokens` | `tuple[tuple[str, datetime], ...]` | `(jti, exp)` of the family's access tokens that have not expired, pruned on every write. Normally one or two entries. |
| `revoked_at` | `datetime \| None` | Set once and never cleared. |
| `revoked_reason` | `str` | `""` until revoked; then one of `reuse`, `recall`. The first reason wins. |
| `device_code_handle` | `str` | `services/confirm/audit.py::device_code_handle` of the code this family was exchanged from, so an operator can join a family to its pairing rows. |

`MAX_GENERATIONS = 256` is a code constant. Twelve hours at one refresh per 10-minute access token is 72 rotations; 256 leaves room for a client that refreshes every three minutes. A presentation that would rotate past it is refused `invalid_grant` and the customer re-pairs. It bounds `retained_hashes` at 256 hashes of 64 characters, about 16 KiB per record at worst and under 5 KiB at the expected cadence.

`SESSION_ABSOLUTE_LIFETIME = timedelta(hours=12)` is a code constant, with no setting.

**Store interface**, `RefreshSessionStoreBase`, with an in-memory backend for development and tests and a Redis backend for production, chosen by `create_refresh_session_store(max_sessions)` on `POSTERN_REDIS_URL` exactly as `create_device_code_store` chooses. Every method answers or raises; none returns a partial result.

- `create(session) -> None`. Writes a new family. Raises `RefreshSessionStoreFull` when the cap is reached after sweeping expired entries, the shape `DeviceCodeStoreFull` has. A `sid` that already exists is a 128-bit collision and raises; it is not retried silently.
- `get(sid) -> RefreshSession | None`. `None` for a missing, expired or undeserializable record.
- `discard(sid) -> None`. Deletes a family nobody holds a token for (§5's losing exchange).
- `rotate(sid, *, presented_hash, new_hash, access_jti, access_expires_at) -> Rotation`. One compare-and-set. Decides from the record read inside the transaction and writes only for `ROTATED` and `REUSED`:
  - `ROTATED`: unrevoked, unexpired, `presented_hash == current_hash`, `generation < MAX_GENERATIONS`. Moves `current_hash` into `retained_hashes`, sets `current_hash = new_hash`, increments `generation`, appends `(access_jti, access_expires_at)` to `access_tokens` and prunes expired entries.
  - `REUSED`: `presented_hash` is in `retained_hashes`. Sets `revoked_at` and `revoked_reason = "reuse"` in the same transaction, and returns the unexpired `access_tokens` jtis.
  - `REVOKED`: already revoked. Writes nothing; returns the unexpired jtis.
  - `UNKNOWN`: the hash is neither current nor retained. Writes nothing.
  - `EXHAUSTED`: `generation == MAX_GENERATIONS`. Writes nothing.
  - `GONE`: missing or expired.
- `revoke(sid, *, reason) -> tuple[str, ...] | None`. Idempotent. Sets `revoked_at` and `revoked_reason` if unset, keeps the first reason, and returns the unexpired access jtis; `None` when no record exists.

The compare is `hmac.compare_digest` on the hex strings, for the current hash; membership in `retained_hashes` is a tuple scan over at most 256 fixed-length strings.

**Redis layout**, under `POSTERN_REDIS_KEY_PREFIX` (default `postern:`), the prefix every other store here uses:

| Key | Type | TTL | Written by |
|---|---|---|---|
| `{prefix}refresh:session:<sid>` | string, the JSON record | `ceil(expires_at - now)` seconds, set by `create` with `SET NX EX`; `rotate` and `revoke` write with `KEEPTTL` | `create`, `rotate`, `revoke`; deleted by `discard` |
| `{prefix}refresh:index` | sorted set, member `sid`, score `expires_at` as a Unix timestamp | none; swept | `create` (`ZREMRANGEBYSCORE -inf now`, `ZCARD`, then `ZADD`), `discard` (`ZREM`) |

The TTL is rounded **up**, never truncated: `RedisDeviceCodeStore`'s TTL arithmetic truncated and shortened codes by up to a second (bug B1, recorded in `packages/postern-core/src/postern_core/auth/device_codes.py`'s `MIN_DEVICE_CODE_TTL_SECONDS` commentary). Rounding up lets the key outlive the record by under a second, and every read re-checks `expires_at` against the clock, as `get_device_code` re-checks `is_expired`.

**Atomicity.** `rotate` and `revoke` on Redis use `WATCH` on the session key, `GET`, decide in Python with one pure function both backends share (the pattern `_scan_verdict` set for `claim_scan`), then `MULTI`, `SET ... KEEPTTL`, `EXEC`, retrying on `WatchError` up to the existing `_CLAIM_ATTEMPTS` (3) and raising a new `RefreshSessionStoreContended` after that. Two concurrent presentations of the same current refresh token therefore resolve as one `ROTATED` and, on the loser's retry, one `REUSED`, which revokes the family. That is RFC 9700 §4.14.2's behaviour, including its stated cost ("forcing the legitimate client to obtain a fresh authorization grant"), and it applies equally to a client that retries a refresh whose response it lost. The in-memory backend is atomic by not yielding between the read and the write, the property `InMemoryDeviceCodeStore.consume_device_code`'s docstring states.

**The cap.** `max_refresh_sessions`, default 100,000. Chosen, not measured: ten times `max_device_codes`' default of 10,000, because a family outlives a device code 48 times over (12 hours against 900 seconds) but only an approved exchange creates one, and approvals are gated by an authenticated app scan and `/approve`'s per-customer limit. The number an operator should size against is peak approvals per 12 hours.

**Shared state is required for recall and for multi-replica refresh.** Without `POSTERN_REDIS_URL` both this store and confirm's ZT-7 revocation store are per process. A refresh token issued by one replica is then `invalid_grant` at another, and §7's recall writes the revoked `jti` into confirm's own memory, which the api never reads. `enforce_redis_requirement`'s message in `create_confirm_app` gains the refresh session store as a fourth store, with that consequence.

### 5. `POST /token`, `grant_type=device_code`

`services/confirm/device_auth.py::token_endpoint` keeps its structure: the grant-type dispatch, the unknown, expired, `slow_down` and `authorization_pending` exits that write no row, the approved-with-no-customer 500, then `PairingAudit` built with `TOKEN_TOOL_NAME` and `_exchange`. `_exchange` keeps its first three steps unchanged and in order: the spent check, the `CustomerRef` parse, the ZT-7 `customer_revoked` check.

One request-shape check is added ahead of the lookup, and writes no row, by `PairingAudit`'s rule: **`resource`**. If the form carries a `resource` parameter it must occur once and equal `session_token_audience` exactly; otherwise 400 `invalid_target`. RFC 8707 §2 defines `invalid_target` ("The requested resource is invalid, missing, unknown, or malformed") and says the server "should reject" a resource it does not consider acceptable. An absent `resource` is accepted: this server issues tokens for one resource only.

Then, replacing the read-token mint:

1. **Draw the family.** `sid`, the first refresh token and its hash; `SessionTokenMinter.prepare(customer, code.client_id, code.scopes, sid)` for the access claims and their `jti`.
2. **Create the family**, `session_store.create(...)`, generation 0, with the access `jti` already in `access_tokens`. **Before the code is spent**, so a full store (`RefreshSessionStoreFull`) is answered 503 `temporarily_unavailable` with `Retry-After`, the shape `_store_full_response` uses, and the code stays redeemable: the same argument `_exchange`'s docstring makes for putting the ZT-7 check before the claim. The row records the exception's type name.
3. **Spend the code**, `consume_device_code(device_code, session_id=sid)`. The method gains the `session_id` argument and writes it onto the row in the same compare-and-set that sets `exchanged_at`. `DeviceCode` gains `session_id: str = ""`; a record serialized before this change deserializes with `""`. A lost claim answers `_unredeemable_response()` with `DETAIL_DEVICE_CODE_SPENT`, as today, and **discards** the family created in step 2, which no client will ever hold a token for.
4. **Sign** the access token. A raise here leaves the code spent and the family holding a `jti` that was never issued; both are harmless, and the customer re-pairs, the direction `_exchange` already takes for a failed mint.
5. `token_endpoint` writes the row, `audit.minted()`, before returning. Unchanged from today, including "do not move this below the return".

Why step 2 comes before step 3 and not after: §7 finds the family through the `session_id` step 3 writes. If the family were created after the spend, a recall arriving between the two would find a `session_id` with no record behind it and could revoke nothing, while the exchange then created a live family. Created first, the record exists before any reader can learn its id.

**Response (200)**:

```json
{
  "access_token": "<session token>",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "prt1.<sid>.<secret>",
  "scope": "<the pairing's scopes>"
}
```

Headers `Cache-Control: no-store` and `Pragma: no-cache`, on this response and on every error response `/token` returns. RFC 6749 §5.1: "The authorization server MUST include the HTTP "Cache-Control" response header field [RFC2616] with a value of "no-store" in any response containing tokens, credentials, or other sensitive information, as well as the "Pragma" response header field [RFC2616] with a value of "no-cache"." RFC 8628 §3.5 makes the device grant's success response the one RFC 6749 §5.1 defines. `scope` is always present, although §5.1 makes it optional when identical to the request, because this grant's request carries no `scope` at `/token` at all.

There is no `write_token` and no layer-2 token in this body, and a test asserts the exact key set.

### 6. `POST /token`, `grant_type=refresh_token`

A new branch in `token_endpoint`'s dispatch, handled by a new `_refresh` beside `_exchange`, returning `(response, detail)` the same way so the row is written in one place. RFC 6749 §6 parameters: `grant_type=refresh_token` (required), `refresh_token` (required), `scope` (optional), plus `resource` (optional, RFC 8707). A `client_id` parameter, if sent, is ignored: RFC 6749 §6 requires client authentication only for confidential clients or clients issued credentials, this client is neither, and comparing a caller-supplied value to another caller-supplied value would authenticate nothing.

In this order:

1. **Shape.** `refresh_token` missing: 400 `invalid_request`. `resource` present and not exactly `session_token_audience`: 400 `invalid_target`. A value that does not parse as `prt1.<22 chars>.<43 chars>` of base64url: 400 `invalid_grant`. **No row** on any of these.
2. **Lookup**, `session_store.get(sid)`. `None`: 400 `invalid_grant`, **no row**, for the reason `token_endpoint` writes none for an unknown device code: no identity is resolved, and an unauthenticated caller must not be able to drive an INSERT per request.
3. **From here the family names a customer and every exit writes one row**, through `PairingAudit` with `subject=session.customer_ref`, `claims={}`, `tool_name=REFRESH_TOOL_NAME`, `route=TOKEN_ROUTE`, and `names(session_id=sid, paired_client_id=session.client_id)` (§9).
4. **Classify the presented hash against the record just read**, before anything else is spent: revoked, unknown, reused, exhausted and expired are all decided here without a write, and reuse is then confirmed by `rotate` or `revoke` inside a transaction:
   - Revoked: **re-assert** `revoke_session(jti=...)` for every unexpired jti the record lists, then 400 `invalid_grant`, `DETAIL_SESSION_REVOKED`. Re-asserting is an idempotent `SADD` and is what makes a failed ZT-7 write at reuse or recall converge on the next presentation. A `RevocationStoreUnavailable` answers 503 `temporarily_unavailable` with the exception's type name as the detail.
   - Hash matches neither current nor retained: 400 `invalid_grant`, `DETAIL_REFRESH_UNKNOWN`. Nothing revoked (§4).
   - Hash is retained: `session_store.revoke(sid, reason="reuse")`, then `revoke_session` for each returned jti, then 400 `invalid_grant`, `DETAIL_REFRESH_REUSED`. A log line at warning level with the `sid` and the `device_code_handle`, never the token, because this is an event an operator may alert on at the edge, as `/scan` logs `scan_conflict`. Either store raising answers 503 with the type name; the next presentation lands in the revoked branch and re-asserts.
   - `generation == MAX_GENERATIONS`: 400 `invalid_grant`, `DETAIL_SESSION_GENERATIONS_EXHAUSTED`.
   - Past `expires_at`: 400 `invalid_grant`, `DETAIL_SESSION_EXPIRED`.
5. **Scope.** If `scope` is present, split both it and `session.scopes` on spaces; a requested scope outside the family's is 400 `invalid_scope`, `DETAIL_SCOPE_EXCEEDED`. RFC 6749 §6: "The requested scope MUST NOT include any scope not originally granted by the resource owner, and if omitted is treated as equal to the scope originally granted by the resource owner." A narrower request narrows this access token only; the family keeps its scopes.
6. **ZT-7, before the rotation spends anything**, the ordering `_exchange` argues for its claim. Two questions, both on the store `services/confirm/revocation.py` already resolves:
   - `is_customer_revoked(customer_ref)`: any customer-plus-client revocation naming this customer, whatever the client. The check `/token` already makes at exchange.
   - `is_revoked({"sub": customer_ref, "client_id": session.client_id, "jti": jti})` for each unexpired access jti in the record: the session scope, this customer-and-client pair, and the kill switch on this `client_id`. This is the question `RevocationMiddleware` asks on every read, asked here so that **an operator who revokes a live access token's `jti` also stops the family refreshing past it.** Without it, refresh would turn the per-session scope into a 10-minute delay.

   Revoked: 400 `invalid_grant`, `DETAIL_REVOKED`. Not `access_denied`, which `_exchange` uses because RFC 8628 §3.5 defines it for the device grant; this is RFC 6749 §6, whose errors are §5.2's, and §5.2's `invalid_grant` covers a grant that is "revoked". The family is **not** revoked: a customer the operator restores keeps a session that has not expired. `RevocationStoreUnavailable`: 503, type name as detail, nothing rotated.
7. **Draw** the new refresh token and hash, and `prepare` the access claims with the granted scope.
8. **Rotate**, the compare-and-set of §4. `ROTATED` continues. Any other result re-runs the matching branch of step 4 against what the transaction saw: a concurrent refresh that won turns this one into `REUSED` and revokes the family. `RefreshSessionStoreContended` propagates and is recorded under its type name.
9. **Sign.** A raise leaves the family rotated and the client holding a refresh token that is now retained; its retry is reuse and revokes the family. That is the fail-closed direction, and the customer re-pairs.
10. **Row**, `audit.minted()`, committed before the response is returned, as at exchange. A raise drops the response, with the same consequence as step 9.

**Response (200)**: the five keys of §5, with a new `refresh_token` and the granted `scope`; the same two cache headers.

**Unchanged**: any other `grant_type` still answers `_error(404, "unsupported_grant_type", ...)` (see Discrepancies).

### 7. Session-swap recall at `POST /scan`

The case, from `dev-docs/qr-page-spec.md`: customer B scans victim A's QR first and approves; A's AI client polls `/token` and receives a session for **B's** accounts; A's own scan then arrives and `claim_scan` answers `CONFLICT_EXCHANGED`. Today `/scan` refuses with `scan_conflict` and recalls nothing.

After this spec, in `services/confirm/device_auth.py::_scan`'s conflict branch, when the claim is `ScanClaim.CONFLICT_EXCHANGED` and only then:

1. **Re-read the row**, `store.get_device_code(code.device_code)`. The `code` `_scan` holds was read by `_lookup_by_user_code` **before** `claim_scan`, and the exchange may have happened in between; `session_id` is written in the same compare-and-set as `exchanged_at` (§5 step 3), so any row on which `claim_scan` saw `exchanged_at` set carries it. If the row is gone (expired in between) or its `session_id` is `""` (a code exchanged before this change), nothing can be recalled: the recall row records `DETAIL_RECALL_NO_SESSION` and `/scan` answers as today.
2. **Revoke the family**, `session_store.revoke(sid, reason="recall")`. From this instant every refresh of the family is refused (§6 step 4). It returns the family's unexpired access jtis; `None` means the family already expired, and the recall row records `DETAIL_RECALL_NO_SESSION`.
3. **Revoke each access token**, `revocation_store.revoke_session(jti=...)` for each jti returned, through the same store `app.state.postern_revocation_store` holds. `services/api`'s `RevocationMiddleware` refuses that `jti` on the next `tools/call` or `tools/list` on every replica sharing `POSTERN_REDIS_URL` (§8).
4. **Rows**, the recall row first, then the existing scan row with `DETAIL_SCAN_CONFLICT`. The response is unchanged: 400 `scan_conflict`.

**Fail closed, and convergent.** If step 2 or step 3 raises (`RevocationStoreUnavailable`, a Redis error, `RefreshSessionStoreContended`), `/scan` answers **503 `temporarily_unavailable`** through `services/confirm/revocation.py`'s `store_unavailable_response`, and both rows are still written: the recall row with `outcome='raised'` and the exception's type name, the scan row with `DETAIL_SCAN_CONFLICT`. The app retries. The retry is safe because `claim_scan` writes nothing on `CONFLICT_EXCHANGED` and returns it again, `revoke` keeps the first reason and returns the same jtis, and `revoke_session` is a set add. A family revoked in step 2 whose step 3 failed also converges when anyone next presents its refresh token (§6 step 4). If a row cannot be written, the request raises and answers 500, the fail-closed direction of decision 0006; there is nothing to withdraw, because a revocation that happened is the safe state.

**Order, and why.** Refresh first, access second: revoking the access token first would leave a window in which the attacker-controlled family could refresh into a fresh `jti` that step 3 never names. With the family revoked first, the jtis `revoke` returns are the complete set of live tokens, because no later rotation can add one.

**Race with the exchange itself.** §5 creates the family, with its first access `jti` recorded, before it spends the code. So once `claim_scan` can see `exchanged_at`, the family exists and its first `jti` is known, even if the exchange has not yet signed or returned the token. A token the exchange signs after the recall is already on the revocation list when it reaches the api.

**Recall is not triggered by `CONFLICT_REVOKED`**: that code was never exchanged, `claim_scan` deleted it, and no family exists. It is not triggered by any other `/scan` exit, and in particular not by `qr_stale`: the MAC check in step 4 of `/scan` still runs before `claim_scan`, so only a scan inside the rotation window can recall anything.

**Who the recall row names.** The family's customer (`customer_ref` on the re-read row, which is the attacker B in the case above), not the scanner. The scan row names the scanner. An operator therefore reads both identities from one `call_id`.

### 8. `services/api`: no code change, three settings

`services/api/server.py::build_server` already builds `JWTVerifier(jwks_uri=customer_jwks_uri, issuer=customer_token_issuer, audience=audience, required_scopes=None)` when `POSTERN_JWKS_URI` and `POSTERN_TOKEN_ISSUER` are both set, and refuses to start when exactly one is. Verified against FastMCP 4.0.3's `load_access_token`: it checks the signature against the JWKS key named by the token's kid, `exp` when present, `iss` against the configured issuer, and `aud` by equality (or membership, for a list); it takes `client_id` from the `client_id` claim, then `azp`, then `sub`; and it exposes all claims. So the api accepts a session token with no change, and refuses a layer-2 token, an app assertion or a write token, each of which fails on issuer, audience or key.

**`RevocationMiddleware` already checks `jti` on every call that returns data.** Verified in `services/api/middleware/revocation.py`: `on_call_tool` and `on_list_tools` both call `_claims()`, which reads `jti` from `get_access_token().claims`, and `_refuse_if_revoked` asks `is_revoked` with it before `call_next`. On the Redis store that is one `SISMEMBER` on `{prefix}revoked:sessions`. The five registered tools and `tools/list` are the whole data surface, so a recalled `jti` is refused on the next request that could return customer data. `RevocationMiddleware` checks no other MCP method; none of the others returns customer data today.

**What an operator sets on `services/api`:**

| Variable | Value |
|---|---|
| `POSTERN_JWKS_URI` | `https://<confirm's public host>/session/jwks.json`, reachable from the api's network |
| `POSTERN_TOKEN_ISSUER` | exactly confirm's `POSTERN_SESSION_TOKEN_ISSUER` |
| `POSTERN_AUDIENCE` | exactly confirm's `POSTERN_SESSION_TOKEN_AUDIENCE`, which should be the MCP server's canonical resource URI; RFC 8707 §2 requires the `resource` value to be "an absolute URI" |

And `POSTERN_REDIS_URL` on both services, pointing at the same instance with the same `POSTERN_REDIS_KEY_PREFIX`, or recall and session revocation do not cross between them.

One test-only addition on the api side: `tests/test_confirm_service.py::test_the_api_settings_name_no_write_key` gains a sibling asserting `services.api.settings.Settings` has no field containing `session_key`. The api verifies session tokens and must never be able to sign one.

### 9. Audit

All rows go through `services/confirm/audit.py::PairingAudit`, unchanged in shape: one row per recorded request (two on a recall, correlated by `call_id`), `outcome='returned'` with NULL `detail` on success, `outcome='raised'` with a `DETAIL_*` literal or an exception type name otherwise, written through `append_with_reserve`, fail-closed.

**`PairingAudit.names` gains `session_id`.** The family id is written raw into `arguments` under a new `session_id` key: it is not a credential (it is in every access token) and an operator needs it verbatim to join rows to a family and to a token's `sid`. Key order in `_arguments`, server-chosen first and the one caller-supplied key last, as that method's docstring requires: `route`, `device_code_handle`, `session_id`, `client_ip`, `paired_client_id`. Neither refresh token nor access token, nor any part or digest of either, is ever written, the rule `token_endpoint`'s docstring states for today's token.

**New constants in `services/confirm/audit.py`:**

| Constant | Literal | Where |
|---|---|---|
| `REFRESH_TOOL_NAME` | `device_grant.refresh` | `tool_name` on every `grant_type=refresh_token` row. Its own literal for the reason `TOKEN_TOOL_NAME` has one: "which pairings produced a session" and "how often sessions were renewed" are different questions. Under `device_grant.*`, and not one of the five registered MCP tool names. |
| `RECALL_TOOL_NAME` | `device_grant.recall` | `tool_name` on the recall row `/scan` writes. `route` stays `SCAN_ROUTE`. |
| `DETAIL_REFRESH_REUSED` | `refresh_reused` | §6 step 4 and step 8: a retained refresh token was presented; the family is revoked. |
| `DETAIL_REFRESH_UNKNOWN` | `refresh_token_unknown` | §6 step 4: right `sid`, hash matches nothing. The trace of someone guessing under a `sid` they read off an access token. |
| `DETAIL_SESSION_REVOKED` | `session_revoked` | §6 step 4: a presentation to a family already revoked, for any reason. |
| `DETAIL_SESSION_EXPIRED` | `session_expired` | §6 step 4: past the 12-hour absolute lifetime. |
| `DETAIL_SESSION_GENERATIONS_EXHAUSTED` | `session_generations_exhausted` | §6 step 4. |
| `DETAIL_SCOPE_EXCEEDED` | `scope_exceeded` | §6 step 5. |
| `DETAIL_RECALL_NO_SESSION` | `recall_no_session` | §7: nothing to recall, either no `session_id` on the row or no live family. |

Rows by exit:

- **`device_code` grant**: `TOKEN_TOOL_NAME` as today, on the six exits `token_endpoint`'s docstring counts, with `session_id` added to `arguments` once §5 step 1 has drawn it. `RefreshSessionStoreFull` at §5 step 2 is a seventh recorded exit, under its type name. The `resource` refusal is a new unrecorded exit (request shape only).
- **`refresh_token` grant**: `REFRESH_TOOL_NAME`, from §6 step 3 on: the mint, and each refusal with the detail above, `DETAIL_REVOKED` for ZT-7, or an exception type name. Steps 1 and 2 write nothing.
- **Recall**: `RECALL_TOOL_NAME`, `subject` = the recalled family's customer, `claims={}` so `client_id` is NULL, `names(device_code=..., session_id=..., paired_client_id=...)`. `returned` when the family was revoked and every returned jti written to the revocation store, whether or not this request was the first to do it; `raised` with `DETAIL_RECALL_NO_SESSION` or an exception type name otherwise.

No migration: `detail` is unconstrained `Text` and no constraint names `tool_name`, the finding `dev-docs/qr-page-spec.md` §7 recorded and which still holds at `31103cf`.

### 10. Public paths, rate limits, body limit

`/session/jwks.json` joins `PUBLIC_PATHS` in `services/confirm/auth.py`, with its reason beside the others: the api's verifier fetches it holding no banking-app assertion. That makes nine public paths. It is a plain `Route`, for the reason `dev-docs/qr-page-spec.md` §4 gives.

`services/confirm/rate_limit.py` gains a `/session/jwks.json` row at 300 per minute per address bucket (`rate_limit_session_jwks`). Normal load is one fetch per api replica per hour, plus one per unseen kid; the ceiling is high because every api replica may sit behind one NAT address and because a stream of tokens carrying unknown kids makes FastMCP's verifier refetch on each one, which is a load on this route an attacker can drive through the api.

`/token` keeps its single row at 300 per minute: both grants share the endpoint, and the refresh grant's rate is a small fraction of the device-code poll rate it already absorbs. `BodySizeLimit` needs no change beyond the tests that list paths.

---

## Testing

Test-first. What must exist when this lands:

- **Session key**: `choose_key_source` called with `role="SESSION"` on all three branches; Vault plus `POSTERN_SESSION_KEY_PEM_PATH` refused; the ephemeral warning names `POSTERN_SESSION_KEY_PEM_PATH`; each startup refusal in §2, including issuer equal to the write issuer, equal to the app-assertion issuer, a non-`https` issuer, and audience equal to the app-assertion audience. Against the live Vault `make ci` already runs: the confirm token can sign with `postern-session` and cannot sign with `postern-read`, and `/session/jwks.json` publishes every version with `session-1.v<N>` kids.
- **JWKS**: `/session/jwks.json` serves exactly the session source's set; `/.well-known/jwks.json` serves exactly the write source's; the two share no kid and no modulus; confirm serves no read key anywhere.
- **Access token**: exact claim set of §3, `exp - iat == 600`, `client_id_verified is False`, no `act`; `prepare` never accepts a `jti`.
- **Store, both backends** (Redis against the real container): every `Rotation` result; `REUSED` revokes in the same transaction; two concurrent rotations with one token yield exactly one `ROTATED` and one `REUSED`; `revoke` idempotent with the first reason kept; `access_tokens` pruning; the cap with sweep-before-refuse; TTL rounded up; an undeserializable record is `GONE`; a record serialized without a field still loads.
- **`device_code` exchange**: the five-key body and both cache headers; no `write_token`; the token verifies against `/session/jwks.json` with the configured issuer and audience; `resource` accepted when equal and absent, `invalid_target` otherwise with no row; store full answers 503 and leaves the code redeemable; a lost `consume_device_code` discards its family; `session_id` lands on the device-code row.
- **Refresh**: every branch of §6 with its status, error code and row detail; no row for steps 1 and 2; scope narrowing and `invalid_scope`; ZT-7 on the customer, on the pair, on the kill switch and on a live `jti` each refuse without revoking the family; a revocation-store outage answers 503 and rotates nothing; reuse revokes the family and writes every live `jti` to the revocation store; a failed ZT-7 write at reuse converges on the next presentation.
- **Recall**: B scans, B approves, A's client exchanges, A scans: `/scan` answers `scan_conflict`, B's family refuses refresh, and **A's client's next `tools/call` through the assembled `services/api` app is refused** with a count of backend touches, the way `tests/test_zt7_revocation_reachable.py` measures. The recall-before-sign race (recall between §5 step 3 and step 4) leaves the signed token refused at the api. Store failure answers 503 with both rows, and a retry completes the recall. A pre-change row with no `session_id` records `recall_no_session`.
- **End to end over ASGI**, extending `tests/test_qr_pairing_end_to_end.py::test_a_browser_and_a_phone_complete_a_pairing_through_every_route`: pairing through `/token`, then `tools/list` on `services/api` configured with the three settings of §8, then a refresh, then `tools/list` again with the new token.
- **Audit**: one row per recorded exit with the §9 literals; the recall's two rows share a `call_id` and name different customers; no token, segment or digest in any row.

## Compatibility

**This is a breaking change to `/token`'s success response**: a different token (issuer, audience, key, lifetime and claims) and two new keys. No client depends on the old response, because nothing could verify the old token as a customer token (§1 of "What this fixes"), and the mobile app does not call `/token`.

Tests that pin the old response or the removed read key, found by `grep` at `31103cf`, and will change:

- `tests/test_device_grant.py`: `test_approved_exchange_body_has_exactly_three_keys` (the key set becomes five), the approved-exchange test that decodes against `app.state.postern_read_key_source`, and every other reference to `postern_read_key_source` or `app.state.read_minter` in the file (nine lines match those names or `consume_device_code`).
- `tests/test_qr_pairing_end_to_end.py`: the read-kid, read-issuer, `accounts.svc`, `accounts:read` and `act` assertions.
- `tests/test_pairing_audit.py`: the test that replaces `app.state.read_minter` with an unsignable minter targets the session minter instead.
- `tests/test_confirm_service.py::test_the_confirm_settings_have_no_read_key_field`: the allowed set becomes empty.
- `tests/test_ephemeral_key_warning.py`: the confirm cases that pass `read_key_pem_path` and the comment that says confirm warns "for both write and read keys"; it now warns for write and session.
- `tests/test_device_code_pairing_store.py` and `tests/test_redis_backed_stores.py`: every `consume_device_code` call gains `session_id`, and the device-code record shape gains the field.
- `tests/test_zt7_confirm_revocation.py` and `tests/test_confirm_rate_limit.py` assert only that `access_token` is present or absent and that `token_type` is `Bearer`; they should pass unchanged and must be re-run, not assumed.
- `tests/test_confirm_auth.py` (the exact `PUBLIC_PATHS` set), the confirm rate-limit and body-limit tests (their path tables), and `tests/test_settings_bounds.py` (the environment inventory sweep).

Docs that describe the old response or the read-key exception and would go stale (`make citations` catches only anchored citations): `docs/user-guide/components/confirm-service.md` (the `/token` row "Exchange device code for a read token" and the response `{ access_token, token_type, expires_in }`), `docs/user-guide/glossary.md` (the device-grant entry), `docs/user-guide/getting-started.md` (the `POSTERN_READ_*` rows, which stop applying to confirm), `docs/user-guide/components/audit.md` (the `/token` section), `CLAUDE.md` (the paragraph on `services/confirm` and operator item 6's "the write policy carries the read key too"), `docker-compose.yml`'s comment on the confirm service's two keys, `dev-docs/decisions/0012-device-code-single-use.md` (which reasons from "a single 60-second read token"), and `dev-docs/qr-page-spec.md` (§6's "`/token` is unchanged" and the session-swap residual this spec closes). `tools/render_auth_flow.py` already labels step 12 "customer access token" and needs no change.

## Size

About 14 production and config files: `services/confirm/session_token.py` (new, ~120 lines), `packages/postern-core/src/postern_core/auth/refresh_sessions.py` (new, ~450 lines across both backends, on the scale of `device_codes.py`'s compare-and-set methods), `services/confirm/device_auth.py` (~250 lines changed: `_exchange`, the new `_refresh`, the `/scan` recall), `services/confirm/audit.py` (~60), `services/confirm/settings.py` (~80 added, ~20 removed), `services/confirm/main.py`, `services/confirm/jwks.py`, `services/confirm/auth.py`, `services/confirm/rate_limit.py`, `packages/postern-core/src/postern_core/auth/device_codes.py` (the `session_id` field and argument), `packages/postern-core/src/postern_core/env_inventory.py`, `docker-compose.yml`. Roughly 1,000 lines of production code and 1,500 to 2,000 lines of new tests, besides the rewritten call sites. No migration.

## Discrepancies

Between this spec's approved decisions, the code at `31103cf` and the documents, found while writing it:

1. **Stale "atomic step" claim, in four places.** `services/confirm/settings.py`'s module docstring says the device grant "mints both read and write tokens in one atomic step", `create_confirm_app`'s comment says it "mints the browser's read token in the same atomic step as the write one", and `CLAUDE.md` operator item 6 and `docker-compose.yml`'s confirm-service comment repeat it. Audit finding C-01 removed the write token from `/token` before this spec; `device_auth_routes` takes no write minter. All four were already false and this spec makes the read half false too.
2. **`RevocationMiddleware`'s docstring says `services/confirm` consults no revocation store** and that "the RFC 8628 device-grant token exchange is uncovered". Both are stale: `services/confirm/revocation.py` checks on four paths, `/token` among them.
3. **`/token` sends no `Cache-Control: no-store` and no `Pragma: no-cache`.** `grep` finds `no-store` in `services/confirm` only in the page module. RFC 6749 §5.1 makes both a MUST for any response containing tokens. §5 fixes it.
4. **An unsupported `grant_type` answers 404.** RFC 6749 §5.2 error responses are 400, and `unsupported_grant_type` is one of its codes. This spec leaves the 404 as it is, because changing it is not among the approved decisions; it is one line.
5. **Decision record 0010 counts a 60-second lifetime as a compensating control** against a stolen bearer token (ZT-6). The client-facing token today is in fact 60 seconds; after this spec it is 600. The approved lifetime widens the residual 0010 accepts, and 0010 should be amended to say so.
6. **The api's default audience `postern` is not an absolute URI**, which RFC 8707 §2 requires of a resource value. Both defaults stay `postern` so the local stack pairs out of the box; a deployment sets both to the MCP server's URI.
7. **Under Vault, the conflation is concrete.** `services/api` and `services/confirm` both sign with transit key `postern-read`, and the api publishes its public half. An api configured with its own JWKS URL, issuer `https://mcp-read.internal` and audience `accounts.svc` would accept today's `/token` output as a customer token, and that same token is accepted by Istio at the accounts service. This follows from the code and configuration; it was not run.
8. **The pairing's `scopes` are not validated against any vocabulary**, and the api enforces no scope from the token. The `scope` claim this spec specifies is therefore descriptive. Not changed here.
9. **RFC 9700 §4.14.2's inactivity SHOULD is not met.** The approved decision is an absolute 12-hour lifetime with no idle expiry.
10. **`dev-docs/qr-page-spec.md` §6 says "`/token` is unchanged"** and its session-swap residual says the issued token "is not recalled". This spec supersedes both.
11. **Redis session revocations never expire.** `RedisRevocationStore.revoke_session` adds the `jti` to a set with no TTL, so every recall and every reuse adds members that outlive their tokens. At the expected rate (recalls are an attack signal) that is negligible; an operator can prune with `restore-session` once `exp` has passed.

## RFC sections relied on

Each read from the RFC Editor's plain-text copy on 30 September 2026.

- RFC 6749 §5.1 (success response parameters; `Cache-Control: no-store` and `Pragma: no-cache`), §5.2 (`invalid_grant`, `invalid_scope`, `unsupported_grant_type`), §6 (refresh request parameters, the scope rule quoted in §6 step 5, client authentication only for confidential clients, "The authorization server MAY issue a new refresh token").
- RFC 8628 §3.5 (the device access token response is RFC 6749 §5.1's; `access_denied` belongs to this grant).
- RFC 8707 §2 (`resource` is an absolute URI; `invalid_target`; the server should reject an unacceptable resource), §2.2 (a refresh token stays bound to the full original grant).
- RFC 9700 §2.2.2 ("Refresh tokens for public clients MUST be sender-constrained or use refresh token rotation"), §4.14.2 (rotation, reuse detection, the implementation note on encoding the grant with integrity, the inactivity SHOULD).
- RFC 9068 §2.1, cited only to say this spec does not adopt its `at+jwt` header.

## Owed outside this repository

- **MCP clients that store and use the refresh token.** Whether the clients named in the handoff implement `grant_type=refresh_token` against a device-grant session has not been checked. A client that does not re-pairs every 10 minutes.
- **The session transit key and the confirm policy change** in the operator's real Vault, per §2.
- **Network reachability** from every api replica to confirm's `/session/jwks.json`.
- **A shared Redis** for both services, per §4 and §8. Already required by `POSTERN_REQUIRE_REDIS` for the other stores.
- **The three api settings of §8**, and the equality of `POSTERN_AUDIENCE` with `POSTERN_SESSION_TOKEN_AUDIENCE`, which no process can check.
- **The app's handling of a 503 from `/scan`.** Recall converges only if the app retries; the mobile team owns that retry (handoff §10.10).

## Out of scope

- CIMD client registration and verification; discovery metadata; DPoP.
- A revocation scope that names a session family. The operator surface in `postern_core.auth.revoke_cli` revokes a `jti`, a customer-plus-client pair or a client; §6 step 6 makes a live `jti` stop its family, but there is no `revoke-family` command, and an operator who holds only an expired `jti` from an old log line must revoke the customer.
- Per-customer caps on concurrent families.
- The creator-versus-scanner comparison `dev-docs/qr-page-spec.md` defers.

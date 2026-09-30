# Mobile app pairing contract

**For:** the operator's mobile team, and whoever runs the app backend that mints the app's assertions.
**Against:** `services/confirm` as of commit `31103cf`, 30 September 2026.
**Status:** the server half is built. The app half (the `POST /scan` call and the confirmation screen) is not in this repository, and until it exists a pairing completes only in tests. Handoff §10.10 is the open question this answers from the server side.

Every statement below was checked against the code named beside it. Where the code does not decide something, this document says "not specified" instead of guessing.

---

## 1. What the app does, in order

1. The camera (or a tap on the page's "Open in your bank app" link) opens an app link. The app parses `user_code` and `qr` out of it (section 2).
2. The app immediately calls `POST /scan` with those two values and its assertion (section 4). Nothing is shown to the user before this call returns.
3. On 200, the app shows the pairing confirmation screen built from the `/scan` response (section 5). The user confirms the pairing code matches their computer and answers "Did you start this on your own computer just now?".
4. Only after that confirmation does the app run app identity verification, if the operator requires it for pairing.
5. The app calls `POST /approve` with the `user_code` (section 6).
6. The AI client's own poll of `POST /token` then receives no token: since 30 September 2026 it answers 503 `temporarily_unavailable` ("session token issuance is not enabled") until a layer-1 session token exists, because the read token it used to return was one the accounts backend accepts. The app plays no part in that step.

Steps 3 and 4 are the app's alone: the server cannot see whether either happened (section 9).

## 2. The app link

### Format

The QR on the pairing page encodes:

```
{POSTERN_DEVICE_APP_LINK_URI}?user_code=<user_code>&qr=<slot>.<mac>
```

built by `services/confirm/verify_page.py::app_link`. The configured base carries no query and no fragment: the service refuses both at startup, so the two parameters always follow a single `?`. Example, with a placeholder host:

```
https://app.bank.example/pair?user_code=K7M2QX&qr=893456712.q1Fz0bT7cN4pLm9wXy2VgA
```

- **`user_code`**: exactly six characters from `23456789ABCDEFGHJKLMNPQRSTUVWXYZ`, in the stored form with no hyphen. The page and the `/scan` response show the same code as `XXX-XXX`.
- **`qr`**: the rotation token, `<slot>.<mac>` (`services/confirm/qr_token.py::verify_token`). `slot` is decimal digits, no leading zero unless it is `0`, at most 19 digits. `mac` is exactly 22 characters of unpadded base64url. The server accepts one spelling of each token and compares the MAC as text, so the app must pass the value through byte for byte and never re-encode it.
- The host and path are whatever the operator configured (`docs/integration/operator-app-link-setup.md`). The server requires only that the base is `https`, has a hostname, and is on a different host from the pairing page.

### How long a `qr` value lives

A slot is two seconds of Unix time (`floor(unix_time / 2)`). `POST /scan` accepts a token whose slot is between five slots before the server's current slot and one slot after it. A token therefore stays valid for between 10 and 12 seconds after the page drew it, depending on where in its two-second slot it was drawn, measured on the clock of whichever server replica answers. The page redraws the QR every two seconds. These numbers are code constants with no setting.

That budget covers the camera, the app launch, fetching the assertion and the `/scan` request. Anything slow (a login, app identity verification, a network retry loop) placed before `/scan` will turn a genuine scan into `qr_stale`.

### Parsing rules

The app link is untrusted input. Anyone can put a link on the operator's app-link host into an email, a web page or a QR of their own, and the operating system will hand it to the app exactly as it hands over a genuine scan.

- Read `user_code` and `qr` by name with a standard URL query parser. Ignore every other parameter.
- If either is missing, empty or repeated, stop and show a generic "this link cannot be used" message. Do not call the server.
- An optional local shape check before the network call is safe: `user_code` matching `^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{6}$` and `qr` matching `^(0|[1-9][0-9]{0,18})\.[A-Za-z0-9_-]{22}$`. The app cannot check the MAC; only the server holds the per-pairing secret.
- Never take the confirm service's address from the link. The app sends `/scan` and `/approve` to a base URL built into the app or its configuration. A link that could redirect those calls would hand the app's assertion to whoever wrote the link.
- Never display anything from the link as confirmed. What the confirmation screen shows comes from the `/scan` response, which the server builds from its stored pairing and never from the link (`services/confirm/device_auth.py::_scan_context_response`).

## 3. Authentication: the app assertion

`POST /scan` and `POST /approve` are not in `services/confirm/auth.py::PUBLIC_PATHS`, so `services/confirm/auth.py::AppAssertionMiddleware` requires a verified assertion on both.

**Header:** `Authorization: Bearer <JWT>`. The scheme is matched case-insensitively. No other credential is read: there are no cookies on this service.

**Who mints it:** the operator's app backend, not the app and not this repository. The confirm service verifies it with FastMCP's `JWTVerifier`, configured from three settings that are all required at startup:

| Setting | What the assertion must satisfy |
|---|---|
| `POSTERN_APP_ASSERTION_JWKS_URI` | The signature verifies against a key published there. |
| `POSTERN_APP_ASSERTION_ISSUER` | `iss` equals this value exactly. |
| `POSTERN_APP_ASSERTION_AUDIENCE` | `aud` equals this value, or is a list containing it. |

What the installed verifier (fastmcp 4.0.3) does with the token, read from its source:

- **Algorithm:** `RS256` only. The confirm service does not pass an algorithm, and the verifier's default is `RS256`; an assertion signed with anything else is refused.
- **`kid`:** required in the header whenever the JWKS holds more than one usable key. With exactly one key it may be omitted. The JWKS is cached for one hour and refetched when a `kid` is not in the cache.
- **`exp`:** **required**, as a JSON number. The verifier checks it only when present, so since 30 September 2026 `services/confirm/auth.py::AppAssertionMiddleware` refuses, after the verifier accepts the token, an assertion with no numeric `exp`, and one whose `exp` is more than `POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS` (default 300, at most 3600) plus 30 seconds of clock skew ahead of the server's clock. An `exp` already past is refused by the verifier. Mint each assertion for one request, with `exp` a minute or two ahead.
- **`iat`:** optional. If present it must be a JSON number no more than 30 seconds ahead of the server's clock, or the assertion is refused.
- **`nbf`:** optional. If present it must be a JSON number no more than 30 seconds ahead of the server's clock, or the assertion is refused. A past `nbf` is accepted.
- **`crit`:** a token with critical header parameters the verifier does not support is refused.
- **`sub`:** required, and the only source of the customer's identity on this service. It must match `^cust[:_][A-Za-z0-9]{1,60}$` (`postern_core.identity`'s `CustomerRef`). A verified assertion whose `sub` does not match gets 403 `invalid_subject`, not 401.
- **`client_id` or `azp`:** optional. If present, the first of the two is written to `audit_log.client_id` on the pairing row (section 9). No decision is made on it.

**The audience must differ from the API service's.** `services/api` defaults its customer-token audience to `"postern"`. If the two services trusted the same issuer and audience, a token an AI client holds for reading balances would also authenticate here. Nothing in either service can detect that collision; it is the operator's configuration to get right.

Every failure (no header, wrong scheme, bad signature, wrong issuer, wrong audience, expired, no `exp`, `exp` too far ahead, `iat` in the future, no `sub`, JWKS fetch error) produces the same 401:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token"
Content-Type: application/json

{"error": "invalid_token", "error_description": "a verified app assertion is required"}
```

The body never says which check failed. The app backend's logs, not this response, are where to debug a rejected assertion.

Example assertion payload (all values fake):

```json
{
  "iss": "https://app-backend.bank.example",
  "aud": "postern-confirm-app",
  "sub": "cust_EXAMPLE0001",
  "exp": 1790000060,
  "iat": 1790000000,
  "azp": "bank-ios-app"
}
```

## 4. `POST /scan`

`services/confirm/device_auth.py::scan_callback` and `services/confirm/device_auth.py::_scan`.

**When:** immediately after parsing the link, before showing the user anything else. The first customer to present a valid token for a pairing becomes the only customer who can approve it. Calling late costs the 10-to-12-second window (section 2); showing the confirmation screen first would show it with nothing from the server behind it.

**Request:**

```
POST /scan HTTP/1.1
Host: <confirm service host>
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImFwcC0xIn0.FAKE.FAKE
Content-Type: application/json

{"user_code": "K7M2QX", "qr": "893456712.q1Fz0bT7cN4pLm9wXy2VgA"}
```

- Both fields are required strings. `user_code` may be sent bare or as `XXX-XXX`; the server strips surrounding whitespace, hyphens and spaces and uppercases it. Nothing else is normalised.
- The body is parsed as JSON whatever the `Content-Type` says. Send `application/json` anyway.
- Nothing in the body names the customer. The customer is the assertion's `sub`.

**Success:**

```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "client_id": "Claude",
  "client_id_verified": false,
  "scopes": "accounts:read transactions:read cards:read",
  "expires_at": "2026-09-30T10:15:00.123456+00:00",
  "user_code": "K7M-2QX"
}
```

| Field | What it is | What the app must do with it |
|---|---|---|
| `client_id` | Caller-supplied: the string the AI client sent, unauthenticated, when it started the pairing. It must be non-empty and at most 256 characters by default (`POSTERN_MAX_CLIENT_ID_LENGTH`), and is otherwise unconstrained. | Show it as text, escaped, never as markup or a link. It is attacker-chosen: anyone can start a pairing that says "Claude" or "Your bank". |
| `client_id_verified` | Always `false`. Nothing on this path verifies the client's identity; CIMD verification would, and is not built. | Label the client name as unverified on the screen (section 5). If a later server version ever returns `true`, that will be a contract change announced separately; until then treat any value as `false`. |
| `scopes` | A single space-separated string, as the AI client requested it. The server checks only that it is a string of at most 512 characters (`POSTERN_MAX_SCOPES_LENGTH`); it does not check the values against a list. The default, when the client asked for nothing, is `accounts:read transactions:read cards:read`. | Show the scopes. How to render a scope the app does not recognise is not specified by the server. See the note below the table. |
| `expires_at` | When the pairing expires, ISO 8601 with a UTC offset, possibly with fractional seconds. Set at creation, `POSTERN_DEVICE_CODE_TTL_SECONDS` after it (default 900 seconds). | Show the remaining time, and do not call `/approve` after it. |
| `user_code` | The stored pairing code in `XXX-XXX` form. | Show this one, not the one parsed from the link, as the code the user compares. |

**The scopes shown are not the scopes enforced.** Read from `services/confirm/device_auth.py`: `POST /token` issues no token after approval since 30 September 2026, and the one it issued before that was always `aud=accounts.svc`, `scope=accounts:read`, 60-second expiry, whatever the pairing's `scopes` string said. The string is what the client asked for, stored and echoed back, and no code path in this repository reads it after `/scan`. The app can show it faithfully; it cannot promise the user that it describes any token.

**Refusals.** Every error body is `{"error": ..., "error_description": ...}` except the 500. The `error_description` text is the server's English and may change; branch on `error` and on the status.

| Status | `error` | When | What the app shows |
|---|---|---|---|
| 400 | `invalid_request` | Body is not JSON, not an object, or `user_code`/`qr` missing, empty or not strings. | An app bug. A generic failure message; report it. |
| 400 | `invalid_grant` | One identical body (`"this pairing cannot be completed"`) for: an unknown or expired code, a code this customer already approved, a malformed or forged `qr`, a `qr` for a different pairing, or a slot more than one ahead of the server's clock. | "This code can no longer be used. Start again from your AI client." The server deliberately does not say which case it was. |
| 400 | `qr_stale` | A genuine token for this pairing, older than the window. | "The code on your screen has changed. Scan it again." The QR is still on the page if nobody has scanned it yet. |
| 400 | `scan_conflict` | Another customer's app scanned this pairing first. The server has now cancelled the pairing, including one already approved, because `/token` issues nothing and so spends no code. A code spent by an earlier build is the one case where nothing is cancelled. | "This pairing was cancelled because another device scanned the same code. Start again from your AI client, and do not share your screen while pairing." Both cases give the same body. |
| 401 | `invalid_token` | No valid assertion (section 3). | Refresh the assertion once and retry; if it fails again, a generic failure. |
| 403 | `invalid_subject` | The assertion verified but its `sub` is not a `cust_` / `cust:` reference. | An app-backend bug. A generic failure message; report it. |
| 403 | `access_revoked` | This customer's AI access is revoked (ZT-7). | "AI client access is turned off for your account." Do not retry. |
| 413 | `request_too_large` | Body over `POSTERN_CONFIRM_MAX_BODY_BYTES` (default 65,536 bytes). | An app bug. |
| 429 | `too_many_requests` | The per-address limit (section 7). Carries `Retry-After`. | "Too many attempts. Try again in a minute." |
| 429 | `customer_rate_limited` | The per-customer limit (section 7). Carries `Retry-After`. | As above. |
| 503 | `rate_limit_store_unavailable` | The shared per-customer counter cannot be reached. Carries `Retry-After`. | "Temporarily unavailable." |
| 500 | none: `text/plain`, `Internal Server Error` | The revocation store could not answer, the audit row could not be written, or the device-code store failed. No exception handler is registered, so this is Starlette's default body. | "Something went wrong. Start again from your AI client." See section 7 on why a retry rarely helps. |

**Repeating a successful scan.** A second `/scan` by the same customer with a token still inside its window returns the same 200 body and changes nothing. After the window, the same request answers `qr_stale`, even though the pairing is still claimed by this customer. Once scanned, the page removes the QR, so there is no fresh token to fetch. An app that loses the `/scan` response and cannot retry inside the window has no way back to the confirmation context; the recovery is a new pairing from the AI client. The spec (`dev-docs/qr-page-spec.md`, "Out of scope") records this as deliberate.

**Order of checks,** so the app team can reason about which failure it will see first: per-address rate limit, body size, assertion, per-customer rate limit, `sub` format, revocation, body shape, pairing lookup, rotation token, then the first-scan claim.

## 5. The confirmation screen

These requirements come from handoff §7.3 and `dev-docs/qr-page-spec.md`. The server cannot enforce any of them. They are the app's half of the A2 control (cross-device consent phishing).

1. **Pairing code, with an active confirmation.** Show the `user_code` from the `/scan` response and ask the user to confirm it matches the code on their computer. Handoff §7.3: "a required confirmation step, not a passive display". A relayed QR shows the victim a code from a pairing that is not theirs; this comparison is what exposes it.
2. **Ask the origin question.** "Did you start this on your own computer just now?" The pairing page itself says "only continue if you started this on your own computer just now". `dev-docs/qr-page-spec.md` ("What this does not fix") explains why the code comparison alone is not enough: an attacker can email the victim a genuine pairing page link, and then the codes on both screens match. The only thing that catches that form is the user noticing they did not start it.
3. **Client name, labelled unverified.** Show `client_id` with a visible statement that the bank has not verified which application this is. Handoff §7.3 asks for "rich context" (which client); the spec notes that this context is weaker than it reads, because the name is attacker-supplied.
4. **Scopes.** Show what the client requested, with the caveat in section 4.
5. **Expiry.** Show how long the user has, from `expires_at`.
6. **Confirmation before app identity verification.** Handoff §7.3: "The pairing-code confirmation must gate the identity verification, not follow it. The code check is what defeats a relayed QR; putting it after the expensive biometric step trains users to approve first and read second." If the user declines either question, do not run app identity verification and do not call `/approve`.

On decline: nothing needs to be sent to the server. The pairing stays scanned by this customer until it expires, the AI client keeps receiving `authorization_pending`, and no other customer can approve it. The server has no "decline" endpoint.

## 6. `POST /approve`

`services/confirm/device_auth.py::approve_callback` and `services/confirm/device_auth.py::_pair`.

**When:** after `/scan` returned 200 for this customer, after the user confirmed both questions and after any app identity verification, and before `expires_at`. The same `sub` must call both endpoints; the server approves only for the customer recorded by the first scan. There is no other deadline between scan and approve.

**Request:**

```
POST /approve HTTP/1.1
Host: <confirm service host>
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImFwcC0xIn0.FAKE.FAKE
Content-Type: application/json

{"user_code": "K7M-2QX"}
```

- `user_code` is the only field read. It is normalised as on `/scan`.
- **`device_code` is refused.** A body with a `device_code` key, whatever its value, gets 400 `invalid_request` (`"device_code is not accepted; send user_code only"`). This exists so an app built against the old contract fails loudly.
- The body does not carry a signature. Handoff §7.3 has the app's device-bound key sign the pairing approval; the current `/approve` checks only the bearer assertion, and the spec leaves the signature out of scope.

**Success:**

```
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "approved"}
```

The app can then tell the user to return to their computer, but the AI client gets nothing from its next poll yet: `POST /token` answers 503 `temporarily_unavailable` with a `Retry-After` header for an approved code and issues nothing, and does not spend the code. Issuance returns with the pending session-token change.

**Refusals:**

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_request` | Body not JSON or not an object, `user_code` missing, empty or not a string, or a `device_code` key present. |
| 400 | `invalid_grant` | One identical body (`"this pairing cannot be completed"`) for every refusal that concerns a pairing: unknown or expired code, nobody scanned it, another customer scanned it, or another customer approved it. |
| 401 | `invalid_token` | As on `/scan`. |
| 403 | `invalid_subject`, `access_revoked` | As on `/scan`. |
| 413, 429, 503, 500 | as on `/scan` | Same middleware, same bodies. A 500 after the store may have approved causes the server to withdraw the pairing before answering. |

**A retried approval answers 200 for the approver.** If the first `/approve` succeeded and its response was lost, a retry by the same customer before `expires_at` answers the same `200 {"status": "approved"}` and changes nothing on the server (recorded as `returned` with `detail` `already_approved`). So retrying `/approve` after a timeout or a dropped connection is safe, and its 200 means the approval stands. After `expires_at` the retry answers `invalid_grant`, as does a retry under a different `sub`. This is the behaviour since 30 September 2026; before it, the retry answered `invalid_grant`.

## 7. Rate limits and retries

Two limiters sit in front of both endpoints. Defaults, all per 60-second fixed window:

| Limiter | Key | `/scan` | `/approve` | Refusal |
|---|---|---|---|---|
| Per address (`services/confirm/rate_limit.py::DEFAULT_LIMITS`) | Client IPv4 address, or IPv6 /64, per server replica | 60 | 60 | 429 `too_many_requests` |
| Per customer (`services/confirm/customer_rate_limit.py::DEFAULT_CUSTOMER_LIMITS`) | Verified `sub`, shared across replicas when Redis is configured | 10 | 10 | 429 `customer_rate_limited` |

Every request counts, including refused ones. One pairing costs one `/scan` and one `/approve`, so a person never approaches either ceiling. If the app backend calls these endpoints on the phone's behalf, every customer shares the backend's few egress addresses, and the per-address 60 becomes a bank-wide ceiling. The operator raises it; see `docs/integration/operator-app-link-setup.md`.

Retry guidance:

- **400: never retry automatically.** Every 400 on these paths is a final answer about this request or this pairing. `qr_stale` is recovered by a new scan by the user, not by resending the same token.
- **429 and 503: honour `Retry-After`** (seconds). `Retry-After` is the seconds left in a fixed 60-second window, so it can be anything from 1 to 60, and a `/scan` retry after a 429 will usually answer `qr_stale` because the 10-to-12-second `qr` window has passed; tell the user to scan again instead of retrying silently.
- **401:** fetch a fresh assertion and retry once.
- **500:** the server may have withdrawn the pairing (it does so whenever a store write might have committed without its audit row). A retried `/scan` then answers `invalid_grant`. One retry is harmless; if it does not succeed, send the user back to the AI client.

## 8. Sequence

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (pairing page)
    participant P as Bank app
    participant AB as App backend
    participant C as services/confirm
    B->>P: QR or link: app link with user_code and qr
    P->>AB: Get assertion (sub = customer)
    AB-->>P: Assertion JWT
    P->>C: POST /scan {user_code, qr} + assertion
    C-->>P: 200 {client_id, client_id_verified:false, scopes, expires_at, user_code}
    Note over B: page stops showing the QR, shows "compare the code"
    P->>P: User confirms code matches AND that they started it
    P->>AB: App identity verification (if required)
    P->>C: POST /approve {user_code} + assertion
    C-->>P: 200 {status: approved}
    Note over B: page shows "This pairing is closed"
```

## 9. What the server records

Both endpoints write one `audit_log` row per recorded call through `services/confirm/audit.py::PairingAudit`, fail-closed: if the row cannot be written, the request fails with a 500 and a claim or approval it made is withdrawn.

| Column or key | Value |
|---|---|
| `tool_name` | `device_grant.scan` or `device_grant.approve` |
| `customer_ref` | The assertion's `sub` (NULL with a reason when it is not a customer reference) |
| `client_id` | The assertion's `client_id` claim, else `azp`, else NULL |
| `outcome`, `detail` | `returned` with NULL detail on success; `returned` with `already_approved` for the approver's repeated `/approve`; `raised` with a detail on refusal |
| `at`, `duration_ms` | Arrival time and handling time |
| `arguments.route` | `/scan` or `/approve` |
| `arguments.device_code_handle` | 16 hex characters of SHA-256 of the pairing's device code, never the code |
| `arguments.client_ip` | The caller's address, when one can be attributed |
| `arguments.paired_client_id` | The AI client's self-declared `client_id` |

Refusal `detail` values on `/scan`: `invalid_subject`, `revoked`, `user_code_not_found`, `qr_invalid`, `qr_stale`, `already_approved`, `scan_conflict`. On `/approve`: `invalid_subject`, `revoked`, `user_code_not_found`, `not_scanned`, `scanned_by_other`, and `already_approved` for a code approved for another customer. An exception is recorded under its class name.

**Not recorded, on purpose:** the `user_code`, the `qr` token, the scopes, and any request the server refused before reaching a pairing. A malformed body (400 `invalid_request`) leaves no row and no log line. A 401, 413, 429 or 503 leaves a log line and no row.

**What the app need not duplicate:** that a scan or an approval happened, for which customer, which pairing, from which address, and why it was refused.

**What only the app can record,** because the server never learns it: that the user confirmed the code match, their answer to the origin question, whether and how app identity verification ran, which device and app version made the call, and a user's decline. If the operator wants any of these in an investigation, the app or its backend must log them, keyed so they can be joined to the server's row (the time and the customer are the only keys both sides hold; the `client_id`/`azp` claim is another if the backend sets it).

## 10. Out of this contract

`POST /challenges/{challenge_id}/approve` is the payment approval callback. It is separate from pairing, requires an Ed25519 signature from an enrolled device on top of the assertion, and today has no production caller that creates a challenge. It will get its own contract.

## 11. What the server leaves unspecified

- How the app renders a scope string it does not recognise, and whether it should refuse one.
- Any device binding on `/approve`; handoff §7.3's device-bound signature on pairing is not implemented.
- Whether the operator requires app identity verification for pairing at all. The server does not know either way.
- The copy of every user-facing message. The suggestions above are suggestions.
- The confirm service's base URL. The app must be configured with it; nothing in the link or the server tells the app where to send `/scan`.

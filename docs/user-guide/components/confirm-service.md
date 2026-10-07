# Confirm Service (Write Path)

Device authorization, approval callbacks, and payment execution, the write-facing deployable.

## Overview

The confirm service is the **write path** of Postern. It holds the write signing key,
handles RFC 8628 device authorization (QR pairing codes), and processes verification
challenge approvals that trigger backend write endpoints server-side.

```
services/confirm/main.py                    Composition root (create_confirm_app)
services/confirm/device_auth.py             RFC 8628 device authorization endpoints
services/confirm/callback.py                Verification challenge approval handler
services/confirm/jwks.py                    Write JWKS endpoint (/.well-known/jwks.json)
services/confirm/settings.py                Runtime configuration
services/confirm/minter.py                  Write token minter wrapper
```

A compromised tool handler in the API service cannot mint a token the payments service
will accept, because it does not hold the write key. That is an infrastructure property,
not a code-review promise.

## Composition Root

The app is assembled by `create_confirm_app()` in [`services/confirm/main.py`](../../../services/confirm/main.py).
Like the API service, it uses PEP 562 lazy loading:

```python
def __getattr__(name: str) -> object:
    if name == "app":
        return create_confirm_app()
    raise AttributeError(...)
```

Production starts the process with: `uvicorn services.confirm.main:app`.

### Startup sequence

1. **Assertion verifier**, a `JWTVerifier` over `POSTERN_APP_ASSERTION_JWKS_URI`,
   `POSTERN_APP_ASSERTION_ISSUER` and `POSTERN_APP_ASSERTION_AUDIENCE`
2. **Write key source**, reads `POSTERN_WRITE_KEY_PEM_PATH` or generates ephemeral
3. **Write minter**, `build_write_minter()` wraps the write key for token minting
4. **Session key source and minter**, `build_session_minter()`: the SESSION key
   (`POSTERN_SESSION_KEY_PEM_PATH`, `POSTERN_VAULT_SESSION_KEY_NAME`, or generated
   with a warning), which signs the layer-1 access tokens `/token` issues and nothing else
5. **Device code store**, in-memory (dev) or Redis (production) via `create_device_code_store()`
6. **Refresh-family store**, in-memory or Redis via `create_refresh_session_store()`,
   capped at `POSTERN_MAX_REFRESH_SESSIONS`
7. **Database**, async SQLAlchemy engine for challenges table

The service **refuses to start without `POSTERN_REDIS_URL`** unless
`POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS` is set: without shared state a refresh token
from one replica is refused at another, and a recall at `/scan` never reaches
`services/api`. It also refuses a `POSTERN_SESSION_TOKEN_ISSUER` that is not an
`https` URL or that equals another issuer it knows, and a
`POSTERN_SESSION_TOKEN_AUDIENCE` that is not an absolute `https` URI in normal form
(unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set) or that equals
`POSTERN_APP_ASSERTION_AUDIENCE`.

Step 1 **raises `ValueError` and the process does not start** if any of the three
is unset. Unlike the API service, which may run with `auth=None` for local
development, this service has no unauthenticated mode: it holds the write
signing key and its endpoints approve money movement. See
[`services/confirm/auth.py`](../../../services/confirm/auth.py).

It starts without `POSTERN_CONFIRM_IDV_VALUE` and logs one warning: every tier-2
challenge approval is then refused with `verification_required`, and tier-1
approvals are unaffected. A set value that is not 1 to 128 printable ASCII
characters is refused at startup.

`POSTERN_APP_ASSERTION_AUDIENCE` must **not** equal the API service's
`POSTERN_AUDIENCE`. If both services accepted one audience from one issuer, a
customer token good enough to read a balance would be good enough to approve a
payment. Neither process can detect the collision, so it is an operator
requirement.

### Uncaught driver errors in the log

The approval callback re-raises its own exception after writing its audit row (decision 0006), so a driver
error can reach uvicorn's `Exception in ASGI application` line. Both database engines hide bound parameters,
and `create_confirm_app` calls `postern_core.log_safety.install_sql_safe_logging()`, which wraps the
process-wide log record factory: for such an error every log record, on any logger, keeps the traceback
frames and each exception's type and SQLSTATE (`client-side` for an error asyncpg raised without a server),
and withholds the driver's message, the SQL and the parameters. For an error Postgres raised, its own log has the message, the DETAIL and the statement at the same time (with `log_min_error_statement` at its default `error`; to match on a SQLSTATE put `%e` in `log_line_prefix`, the default `%m [%p] ` carries none). Errors asyncpg raises in the client while encoding a parameter (for example `DataError`, "invalid input for query argument") never reach the server and leave no record anywhere; the sanitised line says `client-side` for them. Postgres' log then holds the values these logs withhold (DETAIL `Failing row contains (...)`): treat it as customer data.

### Startup clock check

In its lifespan confirm runs one `SELECT statement_timestamp()` through its own
database engine, the clock that stamps a challenge's `created_at`, and compares the
answer with its own `time.time()` at the midpoint of the query's round trip. The query
has a 1.0 second timeout and the whole check, connect included, a 1.5 second bound.
If the skew exceeds 5.0 seconds either way it logs one WARNING on logger
`services.confirm.database_clock` with its direction. Database ahead of confirm:
legitimate tier-2 approvals may be refused as the skew nears the 30 second window.
Database behind confirm: the `auth_time` freshness window is widened by that much. A
check that cannot be measured (database unreachable, query timed out or stalled, answer
not a timezone-aware datetime) logs one WARNING saying so and carries on. It never
blocks startup, runs once per worker process, and happens at boot only, so drift after
boot is not detected. See
[`services/confirm/database_clock.py`](../../../services/confirm/database_clock.py).

### Keys

The confirm service holds the **write** key and the **session** key, and no read key.
Until the layer-1 session token it also held the read key, as a recorded exception,
because `/token` minted the browser a read token with it. No process holds READ and
WRITE together now: `services/api` holds READ, this service holds WRITE and SESSION.
The session key's public half is published at `/session/jwks.json`, and
`/.well-known/jwks.json` stays write-only; the two sets share no kid and no modulus.

The device grant does **not** touch the write key. `/token` used to return a
write-scoped token alongside the read one; that was audit finding C-01 and it is
gone, so `device_auth_routes()` is no longer passed a write minter at all.

## Device Authorization (`services/confirm/device_auth.py`)

Implements RFC 8628 Device Authorization Grant with QR pairing codes.

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/device_authorization` | public | Generate device code + user_code (pairing code) |
| `POST` | `/token` | public | `grant_type=device_code` or its RFC 8628 URN spelling: the browser's poll, an error until approved, then a layer-1 session. `grant_type=refresh_token`: rotate the refresh token for a fresh access token |
| `GET` | `/session/jwks.json` | public | The session key's public half, which `services/api` verifies access tokens against |
| `GET` | `/verify` | public | The browser's pairing page: pairing code, QR, app link |
| `GET` | `/verify/qr.svg` | public, same-origin only | The QR the page embeds, rotated every two seconds |
| `GET` | `/verify/state` | public, same-origin only | What the page's script polls: pending, scanned, or 404 |
| `GET` | `/verify.js`, `/verify.css` | public | The page's only script and stylesheet |
| `POST` | `/scan` | **app assertion** | Banking app scan of the QR; the first customer to scan holds the pairing |
| `POST` | `/approve` | **app assertion** | Banking app approval callback, for the customer who scanned |

`/device_authorization`, `/token` and the five `/verify` routes are public
because the caller is the **browser**, which holds no credential — that is the
premise of RFC 8628, not an oversight. The `device_code` (43 characters from
`secrets.token_urlsafe(32)`) is the authority at `/token` and never appears in
the page, the QR or the page URL. All seven are listed in `PUBLIC_PATHS`, alongside `/.well-known/jwks.json` and `/session/jwks.json` (nine entries in all), in
[`services/confirm/auth.py`](../../../services/confirm/auth.py); every other
route on this service is denied by default. Decision record 0021 is why the page
is served here rather than by `services/api`.

A JSON body on `/device_authorization`, `/scan`, `/approve` or the challenge
callback is read with `postern_core.json_strict.loads_finite`, so `NaN`,
`Infinity`, `-Infinity` and an overflowing literal such as `1e999` are refused
exactly as a body that is not JSON is (400 `invalid_request`, "body must be JSON",
on the three device-grant routes; the callback's `malformed_body` 400). So does a body nested past
the recursion limit. `/token` reads a form and has no JSON body.

### Flow

```
1. Browser → POST /device_authorization
   ← device_code + user_code (XXX-XXX) + verification_uri
     + verification_uri_complete = verification_uri?d=<display handle>

2. Browser opens verification_uri_complete (GET /verify?d=...)
   The page shows the pairing code and a QR encoding the app link:
     POSTERN_DEVICE_APP_LINK_URI?user_code=<code>&qr=<slot>.<mac>
   The QR's token rotates every two seconds.

3. Mobile app scans → POST /scan
     Authorization: Bearer <assertion from the operator's app backend>
     { "user_code": "ABC-DEF", "qr": "<slot>.<mac>" }
   ← 200 { client_id, client_id_verified: false, scopes, expires_at, user_code }

4. User compares the pairing codes and verifies identity → POST /approve
     Authorization: Bearer <assertion>
     { "user_code": "ABC-DEF" }
   ← 200 { "status": "approved" }
```

The customer is the assertion's verified `sub`. There is NO body field naming the
customer, and `/approve` refuses a body that still carries `device_code`
(`400 invalid_request`). A pairing can be approved only by the customer whose app
scanned it first; a second customer's scan of a pairing that has not been
exchanged revokes it (`400 scan_conflict`).

```
5. Browser → POST /token (grant_type=device_code, device_code=...)
   ← 400 authorization_pending (until approved)
   ← 200 { "access_token": "<session token>", "token_type": "Bearer",
           "expires_in": 600, "refresh_token": "prt1.<sid>.<secret>",
           "scope": "<canonical scopes>" }
     (after approval; Cache-Control: no-store, Pragma: no-cache)

6. Browser → POST /token (grant_type=refresh_token, refresh_token=prt1...)
   ← 200, the same five keys with a new refresh token
```

### The layer-1 session

`dev-docs/device-grant-session-token-spec.md` is the contract. The access token's
`aud` is `POSTERN_SESSION_TOKEN_AUDIENCE` (the MCP server's resource URI, equal to
`services/api`'s `POSTERN_AUDIENCE`), its `iss` is `POSTERN_SESSION_TOKEN_ISSUER`,
it lives 600 seconds, carries `sub`, `client_id` (with `client_id_verified: false`),
`scope`, `sid` and `jti`, and carries no `act`, so no domain service accepts it. The
refresh token belongs to a **family** that lives one hour from the exchange; each
refresh rotates it, and presenting a rotated one revokes the whole family and lists
every live access `jti` on the ZT-7 store. The exchange spends the device code; a
replay is `invalid_grant`.

A `resource` parameter (RFC 8707), if sent, must name the audience after RFC 3986
normalization, or the answer is `400 invalid_target`. The retryable answers, the
revocation store's outage and a family store that is full or unreachable, are 503 with
`Retry-After` set to the poll interval, and an approved code's polls are paced at that
interval.

**Two spellings of the device-code grant.** `/token` accepts RFC 8628 §3.4's
`grant_type=urn:ietf:params:oauth:grant-type:device_code` and the short literal
`grant_type=device_code`, with identical behaviour: the same response, the same audit
row, and one shared pacing budget per device code, so alternating spellings does not
buy extra polls. `grant_type=refresh_token` is already the RFC value. Matching is exact:
a different case, a trailing space, a different URN or an empty value is answered
`404 unsupported_grant_type` (`services/confirm/device_auth.py`, `token_endpoint`).

**Recall.** When a second customer's `/scan` finds a pairing already exchanged
(`conflict_exchanged`), the session that exchange issued is recalled: the family is
revoked and its access tokens listed, so `services/api` refuses the next call. If
a store needed for the recall is out or contended, `/scan` answers **503 with
`Retry-After: 1`**, writes both rows, and the app retries once, immediately. Any other
exception during the recall answers 500 and writes only the scan row.

`/scan` and `/approve` return **401** for a missing or unverifiable assertion and
**403** if the assertion's `sub` is not a `cust_...` reference or the customer is
revoked. Every refusal that could reveal whether a pairing exists -- unknown,
expired, unscanned, scanned by someone else, approved for someone else on
`/approve`, a forged rotation token -- is the same **400** `invalid_grant`;
`/scan` answers `qr_stale` for a
genuine token that has aged out (a token is accepted until 12 seconds after the start of its two-second slot, so 10 to 12 seconds after the page showed it) and `scan_conflict` as above. The
distinction lives in each request's `audit_log.detail`. The exceptions, since
30 September 2026, are the pairing's own customer repeating a request that
succeeded. On `/approve`, the customer who scanned and approved a code, repeating
the approval before it expires, gets the same `200 {"status": "approved"}` again,
so an app whose first response was lost can tell that its approval stands. On
`/scan`, that customer's repeat with a current rotation token gets the first
scan's 200 body again, before approving and after. Nothing is written to the
store by any repeat. The row is `returned` with `detail` `already_approved` for
a repeat after approving and `already_scanned` for a repeat scan before it, so
a NULL `detail` marks only a first scan or a first approval. Another customer's
scan of that code gets `scan_conflict`, and their `/approve` gets the 400.

Any store exception from the claim at `/scan` or the approval at `/approve`,
other than the contention error (every `WATCH` beaten, so nothing committed),
revokes the pairing before the exception propagates as a 500, because on Redis a
lost `EXEC` reply can hide a committed write. If that revoke also fails, an
ERROR line names the pairing's handle and says it may be claimed or approved
while its audit row records a refusal. The recovery either way is a fresh QR.

### Pairing network signal

Every successful `/scan`, the first scan and the same customer's repeat before
approving, records where the pairing was created against where it was scanned.
The creator's address is the one `/device_authorization` recorded on the device
code; the scanner's is the `/scan` request's own, also written on the code by
the claim. Both are taken through `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS`. The
row's `risk_signals` column carries one object, and no address, ASN number or
country code:

```json
[{"code": "PAIRING_NETWORK", "severity": "LOW",
  "description": "pairing creator and scanner network relation: different",
  "details": {"relation": "different", "proxy_hops": 2,
              "asn_match": false, "country_match": true}}]
```

`relation` is `same_ip`, `same_prefix` (one IPv4 /24 or one IPv6 /48),
`different` or `unknown`. `proxy_hops` is the hop count when the row was
written; `0` marks a row that compares a load balancer with itself. The two
match keys are `true`, `false` or `"unknown"`, and are absent when no enricher
is installed. It refuses nothing and changes no response, and `different` is
the normal case for a laptop on home Wi-Fi paired with a phone on mobile data.
Refusal rows and the approver's repeat after approving keep `risk_signals` NULL.

An enricher supplies ASN and country facts. None ships here. A distribution
declares one in the entry-point group `postern.pairing_network_enrichers`,
resolving to an instance with an `async def lookup(self, ip)` that returns
`NetworkFacts(asn, country)` or `None`. The service refuses to start with more
than one installed, or with one whose `lookup` is not async. Lookups share one
time budget (`POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS`) and at most 8
scans per process enrich at once; a timeout, a full cap, an exception (a
`CancelledError` raised by the provider itself included) or an
answer of the wrong type records `"unknown"` for both matches, and one WARNING
line that names neither address. An `asn` outside 0 to 4294967295 or a
`country` that is not two ASCII letters is dropped alone: that field's match is
`"unknown"` and the other is still compared.

An enricher runs inside the service that holds the write signing key and sees
every creator and scanner address. Installing one is as consequential as
merging a commit into this repository. A provider that calls an HTTP API needs
an egress exception, which ZT-8's default-deny egress exists to refuse, and
sends customers' addresses to a third party. It must read its own configuration
under its own prefix, because the service refuses unknown `POSTERN_` variables.

- **An enricher must do all I/O through async clients.** A `lookup` that never
  yields, or that calls blocking I/O inside `async def`, blocks every request
  on the replica, and the time budget cannot stop it.
- **Over-counting trusted hops is worse than under-counting.** With
  `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` larger than the number of proxies that
  really append to `X-Forwarded-For`, the address is read from an entry the
  caller wrote. In both phishing forms the pairing's creator is the attacker, so
  the attacker then chooses the creator's address and can forge the most
  benign-looking row available: `same_ip` if they have learned the victim's
  address (a tracking image in the lure email is enough), or `same_prefix` for a
  guessed carrier range. Under-counting only makes both addresses the proxy's,
  which `proxy_hops` already marks as noise.

### Device Code Model (`packages/postern-core/src/postern_core/auth/device_codes.py`)

```python
@dataclass(frozen=True)
class DeviceCode:
    device_code: str          # Opaque 40+ char code (secrets.token_urlsafe(32))
    user_code: str            # 6-char alphanumeric pairing code (no ambiguous chars)
    verification_uri: str     # Base URI of the browser's pairing page
    expires_at: datetime      # UTC expiry (default 900s = 15 min)
    interval: int             # Seconds between token polls (default 5)
    client_id: str            # OAuth client ID, caller-supplied, NEVER an identity
    scopes: str               # Space-separated scope list
    approved: bool            # Whether mobile app has approved
    approved_at: datetime | None  # Approval timestamp
    customer_ref: str         # Verified assertion `sub`, empty until approved
    exchanged_at: datetime | None  # When /token spent it
    display_handle: str       # 128 random bits; keys the page, useless at /token
    qr_secret: bytes          # Per-pairing HMAC key for the QR's rotation token
    creator_ip: str | None    # Where /device_authorization came from
    scanned_by: str           # Customer whose app scanned first, empty until scanned
    scanned_at: datetime | None  # When
    scanner_ip: str | None    # Where the claiming /scan came from, set only by the claim
    session_id: str           # The refresh family /token created, set with exchanged_at
```

`customer_ref` used to be `client_id`, reused for two purposes. That overload was
the enabling half of audit finding C-01: `/token` minted from a field the caller
of `/device_authorization` had populated. They are separate fields now, and
`/token` reads `customer_ref`, which only a verified approval ever writes, for
its ZT-7 check and its audit row.

The `user_code` uses an ambiguous-character-free alphabet:
`23456789ABCDEFGHJKLMNPQRSTUVWXYZ` (no I, L, O, 0, 1 to prevent confusion).

### Device Code Store Backends

| Backend | When used | Storage |
|---------|-----------|---------|
| `InMemoryDeviceCodeStore` | Default (dev/test) | In-process dict |
| `RedisDeviceCodeStore` | Production (`POSTERN_REDIS_URL` set) | Redis with TTL per code |

Factory: `create_device_code_store()` picks the backend based on environment.

## Approval Callback (`services/confirm/callback.py`)

Handles verification challenge approvals for write operations (payments, card writes).

### Endpoint

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/challenges/{challenge_id}/approve` | **app assertion** | Approve a verification challenge |

### Flow

```
1. Tool handler (API service) proposes write → creates ChallengeRecord in Postgres
   ← returns challenge_id to agent

2. Agent shows payload to user → user approves on mobile device
   Mobile app → POST /challenges/{challenge_id}/approve (signed)
```

3. Callback handler:

- a. Verifies the app assertion; the customer is its `sub` (401 if absent/invalid)
- b. Looks up challenge by ID
- c. Rejects with 404 unless `challenge.customer_ref` equals that `sub`
- c2. After the device signature verifies (below), checks the row's tier and
  refuses with 403, the row left `pending` (see "Tier enforcement" below)
- d. Validates state (must be "pending" + not expired)
- e. Marks challenge as "approved" in Postgres
- f. Executes backend write endpoint server-side (POST to payments.svc)
- g. Marks challenge as "executed". The backend has accepted the write by now, so this
  record is attempted up to 3 times, each on a fresh database session, with 0.1 s and
  0.3 s pauses between attempts. The backend is never called again. If all three fail,
  or the row is no longer `approved` on the first attempt, the answer is the 202 in
  "The 202 `accepted_unrecorded` response" below.

Step (c) returns the **same 404 body** as an unknown challenge id, deliberately:
a distinct 403 would be an existence oracle for ids that travel back through the
model's channel into a third-party AI vendor's chat history. It runs before the
expiry branch, which writes, so a stranger cannot drive a state transition on
another customer's challenge.

Since 2026-09-24 the `signature` field is verified, not merely recorded.
`services/confirm/device_signature.py` checks it against the Ed25519 public keys
the operator has enrolled for that customer (`postern_core.auth.device_keys`),
over bytes built entirely from the **stored challenge row** — challenge id,
customer, tool name, payload, and expiry (`postern_core.auth.approval_signature`).
Nothing the caller sends reaches the signed message except the signature itself.
The check runs after the ownership check and before the row is claimed, so a bad
signature leaves the challenge exactly `pending` rather than burning it into a
terminal state — the customer's own phone can still approve it.

A missing device enrollment, a malformed signature, and a well-formed signature
that verifies against none of the customer's enrolled keys all return **403**,
each recorded under its own `detail` in `audit_log` (`device_not_enrolled`,
`signature_malformed`, `signature_invalid`) so an operator can tell a support
issue from an attack. An unreachable device-key store is not treated as "no
device enrolled" — it raises, and the request fails with 500, challenge
untouched. `create_confirm_app` refuses to start without a device-key store
configured, the same way it refuses without the app-assertion verifier.

**Tier enforcement** (since 2026-10-06, decision record 0023). After the signature
verifies and before the row is claimed, the callback reads the row's tier, and
the tier its operation declares in `services/confirm/execute.py`:

| Case | `error` | `detail` in `audit_log` |
|---|---|---|
| Row tier below the operation's declared tier | `tier_mismatch` | `tier_mismatch` |
| Tier 0 (an operation confirm does not declare) | `tier_unsupported` | `tier_unsupported` |
| Tier 2, `POSTERN_CONFIRM_IDV_VALUE` unset | `verification_required` | `verification_not_configured` |
| Tier 2, a claim missing or wrong | `verification_required` | `verification_required` |

A tier-2 approval needs four claims in the banking-app assertion: `idv` equal to
`POSTERN_CONFIRM_IDV_VALUE`, `challenge_id` equal to the challenge in the path, a
`jti` of 1 to 128 printable ASCII characters, and a numeric `auth_time` no earlier
than 30 seconds before the challenge was created and no later than 30 seconds from
now. The row then stores that `jti` as `verification_result`, and every audit row
written after the check records it as `assertion_jti` (capped in size, not scrubbed, so it joins to the app
backend's issuance log). Every refusal is a 403 with a fixed description that
names no claim; one WARNING log line names the claim that failed, never its value.
The tier check does not look at the row's status or deadline: a tier-2 row that is
expired or already terminal, presented with bad claims, gets this 403 and not 410
or 409, and an expired row is not retired by that request.
Tier-1 rows are approved as before. What this cannot establish: that the
verification happened. The app backend that mints the assertion is the trust
anchor; [the pairing contract](../../integration/mobile-app-pairing-contract.md)
section 12 lists what it must do.

Clock caveat: the lower bound compares `auth_time`, which the app backend sets from
its own clock, with the challenge's `created_at`, which Postgres stamped; the upper
bound compares it with confirm's own clock. A startup check warns about skew between
confirm and Postgres (see "Startup clock check" above) and nothing detects drift after
boot. If confirm's clock lags the app backend's by more than about
30 seconds, or the database's clock leads the backend's by more than about 30
seconds, legitimate tier-2 approvals are refused, which is a liveness failure and
not a safety one. Keep the three clocks within a few seconds with NTP.

**Body checks and fixed error texts.** After the tier check and before the row is
claimed (step 2d), the callback validates the body fields the claim will write.
`confirming_device`, when present and not `null`, must be a string of 1 to 128
characters; for a tier-1 row `verification_result`, when present and not `null`, must
be a string (a tier-2 row ignores it and stores the assertion's `jti`). Neither may
contain a Unicode control, format or line-separator character (categories `C*`, `Zl`
and `Zp`). The refusals, with their `audit_log.detail`:

| Case | Response | `detail` |
|---|---|---|
| Body field malformed (step 2d) | 400 `invalid_request`, "`<field>` is not a well formed value", naming the field and never echoing the value | `body_field_invalid` |
| Body is not a JSON object, or holds JSON `NaN`, `Infinity` or `-Infinity` | 400 `invalid_request`, "body must be a JSON object" | `malformed_body` |
| `signature` missing, empty or not a string | 400 `invalid_request`, "signature is required" | `missing_signature` |
| Path challenge id outside `[A-Za-z0-9_-]{1,36}` | the same 404 `not_found` body as an unknown id, no database lookup | `challenge_not_found` |
| The claiming update raised | 500 `internal_error`, "the approval could not be recorded" | the exception type |
| `resolve_endpoint` refused the claimed row | 500 `internal_error`, "the approved operation could not be set up" | the exception type |

**The 207 response, when the backend answers anything but 200, 201 or 202.** The
approval is recorded and the write was not accepted (3xx, 4xx, 5xx and 204 all count):

```json
{"challenge_id": "<id>", "status": "approved",
 "message": "approval recorded, backend execution failed", "backend_status": 503}
```

`backend_status` is the integer from the backend's HTTP status line. The `message` is
a fixed text, and no text the backend sent appears in the response, in an audit row, in
an application log line or in an exception message: a backend response can carry a
connection string or a token, and scrubbing PAN and IBAN shapes out of it never made it
safe to forward. Three mechanisms hold that line:

- **Only the status line is read.** The request is sent as a stream and the client
  takes `status_code` and nothing else: not the body, not the headers, not the reason
  phrase. Leaving the block closes the connection with the body unread, so a body of
  any size, a corrupt gzip body or a short `Content-Length` changes nothing. An
  accepted status (200, 201, 202) with a garbled body is an accepted write and goes
  on to the `executed` record; a refused status with a garbled body is this 207.
- **Transport and protocol failures are reported by exception type only.** When no
  status arrives (connection refused, a timeout, a status line or header block the
  HTTP parser refuses) the client raises `BackendTransportError`, whose text is fixed
  and whose `kind` is the original exception's type name (`ConnectError`,
  `ReadTimeout`, `RemoteProtocolError`). The original is not chained, because `h11`
  and `httpcore2` quote the bytes they refused in their messages. Behaviour is as it
  was: the exception leaves the handler (a 500 under a server), the row stays
  `approved`, and the completion `audit_log` row is `raised` with `detail` set to
  the original type name.
- **`httpx2` and `httpcore2` are held at WARNING** by `create_confirm_app`. They log
  `HTTP Request: POST <url> "HTTP/1.1 500 <reason phrase>"` at INFO and every
  response header at DEBUG, which would start logging the backend's text the moment an
  operator lowers the root logger.

The one log line per refusal is a WARNING naming the challenge id, the operation and
the numeric status. The row stays `approved` and the completion `audit_log` row is
`raised` with `detail` `BackendWriteError`. To find out why the backend refused, look
in the payments backend's own logs, by the `Idempotency-Key`, which equals the
challenge id.

**The 202 `accepted_unrecorded` response.** Not a refusal: the backend accepted the
write (money may have moved) and recording `approved -> executed` failed on every
attempt:

```json
{"challenge_id": "<id>", "status": "approved", "execution": "accepted_unrecorded",
 "message": "the backend accepted the operation but recording it failed; do not retry, it will be reconciled"}
```

The row stays `approved`, which a 207 backend refusal also leaves, and the completion
`audit_log` row is `raised` with `detail` `executed_unrecorded`, paired with the
`reaching` row. **A caller must never retry a 202.** The repository documents no
backend dedupe behind the `Idempotency-Key` it sends, so a second approval attempt
(which would be refused 409 `already_terminal` anyway) or any re-drive risks paying
twice. What an operator does: find the challenge id in the ERROR log line "the backend
accepted ... and recording it as executed failed", join the two `audit_log` rows by
`call_id` for that challenge, ask the payments backend what it did for the
`Idempotency-Key` equal to the challenge id, then settle the `challenges` row by hand.
Nothing reconciles it automatically.

Who can settle it, and what is left behind: `postern_app` (what both services run as)
holds `UPDATE` on `challenges` and could write the row, but you should not run an
operator's hand-edit as the application role. `postern_owner` owns the tables and is the
role to use (`sql/02-grants.sql`, `sql/01-roles.sql`); the bootstrap superuser can do
anything and should do nothing here. **Either way the settling write leaves no
`audit_log` row**: nothing in this repository records a hand-made `challenges` update, so
keep your own record of it (an incident note with the challenge id, the old and new
status, who and when, and what the backend said). The `audit_log` rows stay as they are:
`reaching`, then `raised` / `executed_unrecorded`.

**Recording outlives the request.** The `executed` record runs in a background task
that a cancelled request (client disconnect, graceful shutdown) does not stop. If the
request is cancelled while it runs, the server logs one ERROR line,
`the backend accepted <tool> and the request was cancelled while recording it; the
record continues in the background and may need reconciliation`, with the challenge id,
and re-raises the cancellation. Grep for that line next to the
`the backend accepted <tool> and recording it as executed failed` line: the first means
the record may still land (check the row's status), the second means it did not. If the
event loop itself is closing (a process stop), the task is cancelled with it and nothing
can finish it: the row stays `approved` with no response and no line beyond the
cancellation one, which is a case this repository cannot test beyond cancellation. If the completion audit row also cannot be
written, the request fails with a bare 500 instead (decision 0006).

Ordering: step 2d runs after the revocation, ownership, signature and tier checks, so
a caller who fails any of those learns nothing from the 400, and it runs before the
claim's status and deadline test. A refused body leaves the row `pending`; an expired
row with a bad body gets this 400 and is not retired (with a good body it gets 410 and
the expiry transition), and an `executed` row with a bad body gets 400, not 409. No
exception's text reaches a response, an audit row or an application log line, only its
type. `NaN` and its two siblings are refused when the body is parsed, and an audit
row cannot fail on a non-finite number because the row's argument tree turns one into
a string.

What this does **not** establish: that a human looked at the payment, or that
the phone itself is uncompromised. Both depend on the device's secure element
and its own unlock step, which live on the phone, outside anything this
repository can attest.

```
4. Agent polls GET /challenges/{challenge_id}/status
   ← returns challenge status (pending/approved/executed/declined/expired)
```

### Challenge Model (`packages/postern-core/src/postern_core/store/challenges.py`)

Challenges are **append-only by construction**: `create_challenge` inserts a new row;
`update_challenge_status` transitions the status. There is no delete, expired rows
remain for audit trail.

```python
# Tier-based TTLs (challenge expiry)
ttl_seconds = {
    VerificationTier.SESSION_ONLY: 30,           # 30 seconds
    VerificationTier.APP_APPROVAL: 180,          # 3 minutes
    VerificationTier.APP_IDENTITY_VERIFICATION: 300,  # 5 minutes
}
```

### Challenge Status Machine

```
pending → approved → executed    (successful flow)
pending → declined               (user rejected)
pending → expired                (TTL elapsed without approval)
```

## Source References

| Component | File |
|-----------|------|
| Composition root | [`services/confirm/main.py`](../../../services/confirm/main.py) |
| Settings | [`services/confirm/settings.py`](../../../services/confirm/settings.py) |
| Device auth endpoints | [`services/confirm/device_auth.py`](../../../services/confirm/device_auth.py) |
| Approval callback | [`services/confirm/callback.py`](../../../services/confirm/callback.py) |
| Write JWKS endpoint | [`services/confirm/jwks.py`](../../../services/confirm/jwks.py) |
| Write minter wrapper | [`services/confirm/minter.py`](../../../services/confirm/minter.py) |
| Device code model | [`packages/postern-core/src/postern_core/auth/device_codes.py`](../../../packages/postern-core/src/postern_core/auth/device_codes.py) |
| Challenge store | [`packages/postern-core/src/postern_core/store/challenges.py`](../../../packages/postern-core/src/postern_core/store/challenges.py) |
| Verification tiers | [`packages/postern-core/src/postern_core/domain/verification.py`](../../../packages/postern-core/src/postern_core/domain/verification.py) |
| Internal JWT minter | [`packages/postern-core/src/postern_core/auth/internal_jwt.py`](../../../packages/postern-core/src/postern_core/auth/internal_jwt.py) |
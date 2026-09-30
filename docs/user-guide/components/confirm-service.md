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
4. **Read key source**, reads `POSTERN_READ_KEY_PEM_PATH` (needed for device grant)
5. **Read minter**, `InternalTokenMinter` with read key (device grant exception)
6. **Device code store**, in-memory (dev) or Redis (production) via `create_device_code_store()`
7. **Database**, async SQLAlchemy engine for challenges table

Step 1 **raises `ValueError` and the process does not start** if any of the three
is unset. Unlike the API service, which may run with `auth=None` for local
development, this service has no unauthenticated mode: it holds the write
signing key and its endpoints approve money movement. See
[`services/confirm/auth.py`](../../../services/confirm/auth.py).

`POSTERN_APP_ASSERTION_AUDIENCE` must **not** equal the API service's
`POSTERN_AUDIENCE`. If both services accepted one audience from one issuer, a
customer token good enough to read a balance would be good enough to approve a
payment. Neither process can detect the collision, so it is an operator
requirement.

### Key split exception

The confirm service holds **both** read and write keys. This is a deliberate, documented
exception: the device grant used the read key to mint the browser's token, and the key
stays wired while that issuance is disabled (see "Token issuance is disabled" below). No
other code path hands one process both keys for general use, the separation is preserved
at startup.

The device grant does **not** touch the write key. `/token` used to return a
write-scoped token alongside the read one; that was audit finding C-01 and it is
gone, so `device_auth_routes()` is no longer passed a write minter at all.

## Device Authorization (`services/confirm/device_auth.py`)

Implements RFC 8628 Device Authorization Grant with QR pairing codes.

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/device_authorization` | public | Generate device code + user_code (pairing code) |
| `POST` | `/token` | public | The browser's poll: an error until approved, then 503 (issuance disabled) |
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
the page, the QR or the page URL. All seven are listed in `PUBLIC_PATHS`, alongside `/.well-known/jwks.json` (eight entries in all), in
[`services/confirm/auth.py`](../../../services/confirm/auth.py); every other
route on this service is denied by default. Decision record 0021 is why the page
is served here rather than by `services/api`.

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
   ← 503 { "error": "temporarily_unavailable",
           "error_description": "session token issuance is not enabled" }
     (after approval)
```

### Token issuance is disabled

Since 30 September 2026 `/token` returns no token. For an approved, unexpired
code whose customer is not revoked it answers the 503 above with
`Retry-After` set to the poll interval (`POSTERN_DEVICE_POLL_INTERVAL_SECONDS`,
default 5), spends nothing, and writes one `audit_log` row with
`detail = 'issuance_disabled'`. The code stays unspent, so the next poll gets
the same answer; a poll that arrives inside the interval gets `400 slow_down`
and writes no row, as a pending code's does. A revoked customer still
gets `400 access_denied`, because the ZT-7 check runs first.

Until then it returned a read token: `aud=accounts.svc`, `scope=accounts:read`,
`act.sub=svc:postern`, 60 seconds, signed with the read key. That is a layer-2
backend token (handoff §7.1). Under Vault both services sign with transit key
`postern-read`, which `services/api` publishes at its JWKS and Istio trusts, so
any client that completed a pairing, a phishing client included, held a token
the accounts backend accepts. The browser should get a layer-1 session token
that only this deployment's MCP server accepts. That is a separate, later
change; until it lands, a completed pairing yields nothing the browser can use.

`/scan` and `/approve` return **401** for a missing or unverifiable assertion and
**403** if the assertion's `sub` is not a `cust_...` reference or the customer is
revoked. Every refusal that could reveal whether a pairing exists -- unknown,
expired, unscanned, scanned by someone else, already approved, a forged rotation
token -- is the same **400** `invalid_grant`; `/scan` answers `qr_stale` for a
genuine token that has aged out (a token is accepted until 12 seconds after the start of its two-second slot, so 10 to 12 seconds after the page showed it) and `scan_conflict` as above. The
distinction lives in each request's `audit_log.detail`. One exception on
`/approve` since 30 September 2026: the customer who scanned and approved a code,
repeating the approval before it expires, gets the same `200 {"status":
"approved"}` again, so an app whose first response was lost can tell that its
approval stands. Nothing is written to the store, and the row is `returned` with
`detail` `already_approved`. Anyone else sending that code still gets the 400.

Any store exception from the claim at `/scan` or the approval at `/approve`,
other than the contention error (every `WATCH` beaten, so nothing committed),
revokes the pairing before the exception propagates as a 500, because on Redis a
lost `EXEC` reply can hide a committed write. If that revoke also fails, an
ERROR line names the pairing's handle and says it may be claimed or approved
while its audit row records a refusal. The recovery either way is a fresh QR.

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
    exchanged_at: datetime | None  # When /token spent it (nothing spends it since 2026-09-30)
    display_handle: str       # 128 random bits; keys the page, useless at /token
    qr_secret: bytes          # Per-pairing HMAC key for the QR's rotation token
    creator_ip: str | None    # Where /device_authorization came from
    scanned_by: str           # Customer whose app scanned first, empty until scanned
    scanned_at: datetime | None  # When
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
- d. Validates state (must be "pending" + not expired)
- e. Marks challenge as "approved" in Postgres
- f. Executes backend write endpoint server-side (POST to payments.svc)
- g. Marks challenge as "executed"

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
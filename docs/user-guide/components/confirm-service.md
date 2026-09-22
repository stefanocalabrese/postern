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
exception: the device grant needs the read key to mint the browser's access token. No
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
| `POST` | `/token` | public | Exchange device code for a read token (polling; error until approved) |
| `POST` | `/approve` | **app assertion** | Banking app approval callback |

`/device_authorization` and `/token` are public because the caller is the
**browser**, which holds no credential — that is the premise of RFC 8628, not an
oversight. The `device_code` (43 characters from `secrets.token_urlsafe(32)`) is
the authority at `/token`. Both are listed in `PUBLIC_PATHS` in
[`services/confirm/auth.py`](../../../services/confirm/auth.py); every other
route on this service is denied by default.

### Flow

```
1. Browser → POST /device_authorization
   ← device_code + user_code (XXX-XXX format) + verification_uri

2. QR code encodes: verification_uri + user_code
   User scans with mobile app → bank app shows pairing code

3. Mobile app → POST /approve
     Authorization: Bearer <assertion from the operator's app backend>
     { "device_code": "...", "user_code": "ABC-DEF" }
   ← 200 OK
   The customer is the assertion's verified `sub`. There is NO body field
   naming the customer; `user_code` is required and compared in constant time.

4. Browser → POST /token (grant_type=device_code, device_code=...)
   ← 400 authorization_pending (until approved)
   ← 200 { access_token, token_type, expires_in } (after approval)
```

`/approve` returns **401** for a missing or unverifiable assertion, **403** if the
assertion's `sub` is not a `cust_...` reference, and **400** `invalid_user_code`
for a wrong pairing code. Three wrong pairing codes revoke the device code
(`POSTERN_USER_CODE_MAX_ATTEMPTS`, default 3) per RFC 8628 §5.2.

### Device Code Model (`packages/postern-core/src/postern_core/auth/device_codes.py`)

```python
@dataclass(frozen=True)
class DeviceCode:
    device_code: str          # Opaque 40+ char code (secrets.token_urlsafe(32))
    user_code: str            # 6-char alphanumeric pairing code (no ambiguous chars)
    verification_uri: str     # URI for mobile deep-linking
    expires_at: datetime      # UTC expiry (default 900s = 15 min)
    interval: int             # Seconds between token polls (default 5)
    client_id: str            # OAuth client ID, caller-supplied, NEVER an identity
    scopes: str               # Space-separated scope list
    approved: bool            # Whether mobile app has approved
    approved_at: datetime | None  # Approval timestamp
    customer_ref: str         # Verified assertion `sub`, empty until approved
    user_code_attempts: int   # Failed pairing-code comparisons at /approve
```

`customer_ref` used to be `client_id`, reused for two purposes. That overload was
the enabling half of audit finding C-01: `/token` minted from a field the caller
of `/device_authorization` had populated. They are separate fields now, and
`/token` reads `customer_ref`, which only a verified approval ever writes.

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

3. Callback handler:
   a. Verifies the app assertion; the customer is its `sub` (401 if absent/invalid)
   b. Looks up challenge by ID
   c. Rejects with 404 unless `challenge.customer_ref` equals that `sub`
   d. Validates state (must be "pending" + not expired)
   e. Marks challenge as "approved" in Postgres
   f. Executes backend write endpoint server-side (POST to payments.svc)
   g. Marks challenge as "executed"

Step (c) returns the **same 404 body** as an unknown challenge id, deliberately:
a distinct 403 would be an existence oracle for ids that travel back through the
model's channel into a third-party AI vendor's chat history. It runs before the
expiry branch, which writes, so a stranger cannot drive a state transition on
another customer's challenge.

The `signature` body field is **recorded, never verified** — presence is the whole
check. Verifying it needs a per-customer device public-key registry, which this
repository does not have. The local variable is named `unverified_signature` at
every use site, and `services/confirm/callback.py`'s module docstring states the
residual risk and what would close it.

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
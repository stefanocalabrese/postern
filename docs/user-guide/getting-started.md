# Getting Started

Prerequisites, installation, configuration, and local development stack.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.12+ | Pinned in `.python-version` |
| uv | Latest stable | Project dependency manager and runner |
| PostgreSQL | 15+ | For consents, audit_log, challenges tables |
| Docker / Podman | Any recent | For local development stack (optional) |
| Redis | 7+ | Required in production (`POSTERN_REQUIRE_REDIS=1`); optional locally |

## Installation

### Clone and sync dependencies

```bash
git clone https://github.com/YOUR_ORG/postern.git
cd postern
uv sync
```

### Verify the toolchain

```bash
make ci
```

This runs: `lint`, `fmt-check`, `type`, `imports`, `lock`, `citations`, `test`.
Run locally because GitHub Actions minutes are billed on private repos.

### Format code

```bash
make fmt        # format all Python files in packages, services, tests
```

> **Note:** `fmt-check` is scoped to `packages services tests`, not `.`, because
> `ruff format` on `.` also rewrites the Python code fences inside markdown design docs.

## Configuration

Both services read configuration from environment variables prefixed with `POSTERN_`.
The table below lists every variable, grouped by service.

### A `POSTERN_` variable nothing reads stops the service from starting

Both services check the whole `POSTERN_` namespace at startup, before reading any
value, and refuse to start on a name that neither service reads:

```
1 POSTERN_ variable(s) are set that no code in this deployment reads:
  POSTERN_REQUIRE_REDDIS Did you mean POSTERN_REQUIRE_REDIS?
```

This exists because a misspelt name is not detectable any other way. Every check on
a value — the bounds below, the four accepted spellings of a flag — needs the name to
be read first, and nothing reads `POSTERN_REQUIRE_REDDIS`, so the value behind it
never reaches a check and the variable is indistinguishable from one you never set.
You would have armed nothing and been told nothing. Three of these variables are
safety switches (`POSTERN_REQUIRE_REDIS`, `POSTERN_REQUIRE_PEM_KEY`,
`POSTERN_STRICT_HEADERS`), and a switch that silently fails to arm is worse than one
that does not exist.

Names are compared exactly, so `postern_require_redis` and `POSTERN_REQUIRE_REDIS `
(trailing space) are each a different variable from `POSTERN_REQUIRE_REDIS` and each
refused, with the name you meant in the message.

**A variable the *other* service reads is not refused.** Running one environment file
against both deployables is normal — `POSTERN_CONFIRM_RATE_LIMIT_TOKEN` in the API
service's environment configures nothing there and is logged, not fatal. Check the
log line when the variable is a switch: `POSTERN_REQUIRE_PEM_KEY` and
`POSTERN_STRICT_HEADERS` are read by the API service **only**, so setting either on
the confirm service arms nothing.

**If your deployment sets a `POSTERN_` variable for something else** — a sidecar, your
own tooling, a version you have not deployed yet — name it in
`POSTERN_ALLOWED_UNREAD_ENV` and the service starts. It takes exact names, comma
separated, and no wildcards: a `POSTERN_SIDECAR_*` pattern would hide a typo inside
that family, which is what this check is for. Misspelling `POSTERN_ALLOWED_UNREAD_ENV`
itself cannot switch the check off — the misspelling is an unread `POSTERN_` name, so
the service refuses and names this variable as the one you meant.

### API Service (`services/api/settings.py`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTERN_BACKEND_BASE_URL` | **Yes** | - | Base URL of the operator's backend (accounts.svc, payments.svc) |
| `POSTERN_DATABASE_URL` | No | `postgresql+asyncpg://postern:postern@localhost:5432/postern` | Postgres connection string for audit + consent tables |
| `POSTERN_READ_KEY_PEM_PATH` | No | - | Path to the PEM file for signing internal read tokens. If unset, an ephemeral key is generated in-process (not suitable for production) |
| `POSTERN_READ_KEY_KID` | No | `read-1` | Key ID published in the read JWKS |
| `POSTERN_READ_TOKEN_ISSUER` | No | `https://mcp-read.internal` | `iss` claim on internal read tokens |
| `POSTERN_JWKS_URI` | No | - | URL where customer JWTs were signed (for consent enforcement). Leave unset for no-auth mode |
| `POSTERN_TOKEN_ISSUER` | No | - | Expected issuer of customer JWTs. Leave unset for no-auth mode |
| `POSTERN_AUDIENCE` | No | `postern` | Expected `aud` claim on customer JWTs: the MCP server's resource URI, equal to the confirm service's `POSTERN_SESSION_TOKEN_AUDIENCE`. **Refused at startup** when `POSTERN_JWKS_URI` is set and this is not an absolute `https` URI in normal form, unless `POSTERN_ALLOW_NON_URI_AUDIENCE` is set; the default therefore works only without customer authentication |
| `POSTERN_ALLOW_NON_URI_AUDIENCE` | No | off | Local-stack flag: accept a non-URI `POSTERN_AUDIENCE`, with a warning. Read by both services |
| `POSTERN_STRICT_HEADERS` | No | `0` | Enable strict MCP Streamable HTTP header validation (Mcp-Method/Mcp-Name must match body) |
| `POSTERN_TRUSTED_PROXY_HOPS` | No | `0` | Proxies in front of this service that append to `X-Forwarded-For`; the risk engine reads the n-th entry from the right. **Zero or greater**; zero trusts the header for nothing and uses the socket peer |
| `POSTERN_CACHE_TTL_SECONDS` | No | `60` | Consent domain cache TTL per request. **At least 1**; FastMCP refuses a cache TTL of zero when the server is built |
| `POSTERN_BACKEND_CONNECT_TIMEOUT_SECONDS` | No | `2.0` | Backend connection timeout (seconds). **Greater than 0**; at zero every backend request fails `ConnectTimeout` |
| `POSTERN_BACKEND_WRITE_TIMEOUT_SECONDS` | No | `2.0` | Backend write timeout (seconds). **Greater than 0** |
| `POSTERN_BACKEND_READ_TIMEOUT_SECONDS` | No | `5.0` | Backend read timeout (seconds). **Greater than 0** |
| `POSTERN_BACKEND_POOL_TIMEOUT_SECONDS` | No | `1.0` | Backend connection pool timeout (seconds). **Zero or greater**; zero sheds rather than queueing when the pool is saturated |
| `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` | No | `2.0` | Database connection timeout (seconds). **Greater than 0**; at zero every connection raises `TimeoutError` |
| `POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS` | No | `3.0` | Database statement timeout (seconds). **Greater than 0**; asyncpg rejects zero itself, at the first connect |
| `POSTERN_DATABASE_POOL_TIMEOUT_SECONDS` | No | `1.0` | Database pool timeout (seconds). **Zero or greater**; zero sheds rather than queueing when the pool is saturated |
| `POSTERN_DATABASE_POOL_SIZE` | No | `5` | Connections this replica keeps open. **At least 1**; zero is SQLAlchemy's spelling of "unlimited", not of "small" |
| `POSTERN_DATABASE_MAX_OVERFLOW` | No | `10` | Connections this replica may open above `POSTERN_DATABASE_POOL_SIZE` and close again on return. **Zero or greater**; zero means no burst, and `-1` is the off switch |
| `POSTERN_DATABASE_AUDIT_RESERVE_SIZE` | No | `1` | Connections held back so an audit row can still be written when the pool above is at its ceiling. **At least 1** — there is no value that turns it off. Opened only once the pool has actually refused a checkout, so an unsaturated replica holds none of them |
| `POSTERN_MAX_BODY_BYTES` | No | `1048576` (1 MiB) | Maximum request body size in bytes. **At least 1**; at zero every request carrying a body is refused 413 |
| `POSTERN_REQUEST_DEADLINE_SECONDS` | No | `105.0` | Wall-clock bound on the whole HTTP request (see [Audit System](components/audit.md)). **Greater than 0**, and finite: there is no off switch, raise the number instead |
| `POSTERN_REQUIRE_PEM_KEY` | No | - | Set to `"1"` to refuse startup with an ephemeral read key. Read by `services/api` only |
| `POSTERN_REQUIRE_REDIS` | No | - | Refuses startup without `POSTERN_REDIS_URL`. Enforced by **both** services since 26 September 2026; `services/api` alone before that. `1`, `true`, `yes` and `on` arm it, case and surrounding whitespace ignored; `0`, `false`, `no`, `off`, empty and unset leave it off. Anything else refuses to start rather than guessing — this line said until 27 September 2026 that only `"1"` worked and that `true` was silently ignored, which was the defect `bool_from_env` fixed |
| `POSTERN_REDIS_URL` | No | - | Redis connection string (for sessions, device codes, revocation lists, per-customer approval counters). A blank or whitespace-only value is treated as unset; on `services/api` that now means per-replica in-memory stores unless `POSTERN_REQUIRE_REDIS=1` (previously a blank value crashed at startup). Unset, each is per-replica: a revocation cuts one replica, a spent device code stays redeemable on the others, and R replicas admit R times the per-customer ceilings below. Point **both** services at the same instance — nothing checks that they agree |
| `POSTERN_REDIS_SESSION_TTL` | No | `1800` (30 min) | How long a risk context accumulates its ZT-5 budget, on the Redis session store. **At least 1**; at zero every load answers `None`, so every call starts from an empty budget |

### Confirm Service (`services/confirm/settings.py`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTERN_APP_ASSERTION_JWKS_URI` | **Yes** | - | JWKS of the operator's banking-app backend, used to verify inbound assertions |
| `POSTERN_APP_ASSERTION_ISSUER` | **Yes** | - | Expected `iss` on inbound app assertions |
| `POSTERN_APP_ASSERTION_AUDIENCE` | **Yes** | - | Expected `aud` on inbound app assertions. Must **not** equal the API service's `POSTERN_AUDIENCE` |
| `POSTERN_CONFIRM_ASSERTION_MAX_LIFETIME_SECONDS` | No | `300` | How far ahead of now an app assertion's `exp` may sit, plus 30 seconds of clock skew. **From 1 to 3600**. An assertion with no `exp`, or with an `iat` more than 30 seconds in the future, is refused with the same 401 regardless of this value |
| `POSTERN_WRITE_KEY_PEM_PATH` | No | - | Path to the PEM file for signing internal write tokens |
| `POSTERN_WRITE_KEY_KID` | No | `write-1` | Key ID published in the write JWKS |
| `POSTERN_WRITE_TOKEN_ISSUER` | No | `https://mcp-write.internal` | `iss` claim on internal write tokens |
| `POSTERN_CONFIRM_MAX_BODY_BYTES` | No | `65536` (64 KiB) | Maximum request body size in bytes on the write path, separate from the API service's `POSTERN_MAX_BODY_BYTES`. **At least 1** |
| `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` | No | `0` | Proxies in front of this service that append to `X-Forwarded-For`. **Zero or greater**; zero trusts the header for nothing and uses the socket peer. The pairing network signal compares addresses taken through this setting, so under the default both are the load balancer's and the recorded relation means nothing |
| `POSTERN_CONFIRM_PAIRING_ENRICHER_TIMEOUT_SECONDS` | No | `0.25` | How long a successful `/scan` waits for an installed pairing network enricher before recording `"unknown"`. **Above 0 and at most 1.0**; the budget is added to the scan's latency. Unused when no enricher is installed |
| `POSTERN_MAX_DEVICE_CODES` | No | `10000` | Device codes the store will hold before refusing new pairings. **At least 1**; at zero the cap is met by an empty store |
| `POSTERN_MAX_SCOPES_LENGTH` | No | `512` | Ceiling on the `scopes` string at `/device_authorization`. **At least 42**, the length of the default this endpoint substitutes when a caller sends none |
| `POSTERN_MAX_CLIENT_ID_LENGTH` | No | `256` | Ceiling on the `client_id` string. **At least 1**; `client_id` is required and non-empty |
| `POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION` | No | `60` | Requests per minute per client address bucket. **At least 1**; there is no value that disables the limit |
| `POSTERN_CONFIRM_RATE_LIMIT_TOKEN` | No | `300` | As above, for `/token` |
| `POSTERN_CONFIRM_RATE_LIMIT_APPROVE` | No | `60` | As above, for `/approve`. Raise this if the banking app calls from its own backend rather than from the phone |
| `POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE` | No | `60` | As above, for the challenge approval callback |
| `POSTERN_CONFIRM_RATE_LIMIT_SCAN` | No | `60` | As above, for `/scan`. Raise it for the same reason as `/approve`'s |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY` | No | `60` | As above, for the pairing page `/verify`: page loads plus the 12 a minute its noscript refresh adds |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_QR` | No | `300` | As above, for `/verify/qr.svg`, which the page reloads every two seconds: 30 a minute per open tab, so 300 is ten tabs behind one address |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_STATE` | No | `300` | As above, for `/verify/state`, which the page polls every two seconds |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_JS` | No | `60` | As above, for `/verify.js`, loaded once per page |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS` | No | `60` | As above, for `/verify.css`, loaded once per page |
| `POSTERN_CONFIRM_RATE_LIMIT_DEFAULT` | No | `60` | As above, for every other path |
| `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_APPROVE` | No | `10` | Requests per minute per **customer** (the verified assertion `sub`), for `/approve`. A second limiter behind the assertion check; the address-keyed one above stays in front. **At least 1** |
| `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE` | No | `10` | As above, for the challenge approval callback. One payment approval is one tap on a phone, so ten a minute is already well above what a person does |
| `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN` | No | `10` | As above, for `/scan`, which precedes every pairing approval once. **At least 1** |
| `POSTERN_DEVICE_VERIFICATION_URI` | No | `https://auth.postern.internal/verify` | URI of the browser's pairing page, which `verification_uri_complete` extends with `?d=<handle>`. The QR does not encode this: it encodes `POSTERN_DEVICE_APP_LINK_URI`. **Refused at startup** unless its path is exactly `/verify` (`/verify/` does not match the route) and it carries no `?` and no `#` |
| `POSTERN_DEVICE_APP_LINK_URI` | **Yes, in any deployment** | `https://app.postern.internal/pair` | Base of the universal link / app link the pairing QR encodes, as `?user_code=...&qr=...`. The default is a local placeholder: a deployment must set its own host and publish the Apple associated-domains and Android asset-links files for it, or a phone camera will not open the bank app. **Refused at startup** when it contains `?` or `#` (the QR appends `?user_code=...&qr=...`, which a fragment would swallow), unless it is an `https` URL with a hostname, and when its host equals `POSTERN_DEVICE_VERIFICATION_URI`'s host (case-insensitive, port ignored) |
| `POSTERN_DEVICE_CODE_TTL_SECONDS` | No | `900` (15 min) | Lifetime of a device code. Refused at startup below 30 seconds, which the Redis store cannot represent, and above 900, the most the 4,800-second customer revocation stamp covers beside a one-hour session family |
| `POSTERN_REDIS_DEVICE_CODE_TTL` | No | `900` (15 min) | Lifetime a device code gets when the caller passes no `expires_in`, on the Redis store. Refused below the same 30 seconds, and for the same reason: it sets the lifetime of the same object |
| `POSTERN_DEVICE_POLL_INTERVAL_SECONDS` | No | `5` | Minimum seconds between token polls. **At least 1**; must also stay below `POSTERN_DEVICE_CODE_TTL_SECONDS`, which is not checked: an interval at or above the lifetime expires the code before the browser may poll once |
| `POSTERN_SESSION_KEY_PEM_PATH` | No | - | The SESSION key's PEM, which signs the layer-1 access tokens `/token` issues. Unset without Vault: an ephemeral key, with a warning. Refused together with `POSTERN_VAULT_ADDR` |
| `POSTERN_SESSION_KEY_KID` | No | `session-1` | Its kid, or under Vault the kid prefix (`session-1.v<N>`) |
| `POSTERN_VAULT_SESSION_KEY_NAME` | No | `postern-session` | The session transit key under Vault |
| `POSTERN_SESSION_TOKEN_ISSUER` | No | `https://auth.postern.internal` | `iss` of every access token, and what `services/api`'s `POSTERN_TOKEN_ISSUER` must equal. **Refused at startup** unless `https` with a host and no query or fragment, and when it equals `POSTERN_WRITE_TOKEN_ISSUER` or `POSTERN_APP_ASSERTION_ISSUER` |
| `POSTERN_SESSION_TOKEN_AUDIENCE` | **Yes, in any deployment** | `postern` | `aud` of every access token: the MCP server's resource URI, equal to `services/api`'s `POSTERN_AUDIENCE`. **Refused at startup** unless an absolute `https` URI in normal form (or `POSTERN_ALLOW_NON_URI_AUDIENCE` is set), and when it equals `POSTERN_APP_ASSERTION_AUDIENCE` |
| `POSTERN_ALLOW_PROCESS_LOCAL_SESSIONS` | No | off | Development flag: start without `POSTERN_REDIS_URL`, with refresh families and recalls in this process only. Without it the service **refuses to start** when `POSTERN_REDIS_URL` is unset |
| `POSTERN_MAX_REFRESH_SESSIONS` | No | `40000` | Ceiling on live refresh families: `POSTERN_MAX_DEVICE_CODES` times the lifetime ratio (3,600 s against 900 s). **At least 1** |
| `POSTERN_CONFIRM_RATE_LIMIT_SESSION_JWKS` | No | `300` | Per-address requests a minute to `/session/jwks.json`. **At least 1** |
| `POSTERN_BACKEND_BASE_URL` | No | `https://backend.internal` | Base URL for backend write endpoints (payments.svc, cards.svc) |
| `POSTERN_DATABASE_URL` | No | `postgresql+asyncpg://postern:postern@localhost:5432/postern` | Postgres connection string for challenges table |
| `POSTERN_DATABASE_CONNECT_TIMEOUT_SECONDS` | No | `2.0` | Database connection timeout (seconds). **Greater than 0**; at zero every connection raises `TimeoutError` |
| `POSTERN_DATABASE_COMMAND_TIMEOUT_SECONDS` | No | `3.0` | Database statement timeout (seconds). **Greater than 0**; asyncpg rejects zero itself, at the first connect |
| `POSTERN_DATABASE_POOL_TIMEOUT_SECONDS` | No | `1.0` | Database pool timeout (seconds). **Zero or greater**; zero sheds rather than queueing when the pool is saturated |
| `POSTERN_CONFIRM_DATABASE_POOL_SIZE` | No | `5` | Connections this replica keeps open, separate from the API service's `POSTERN_DATABASE_POOL_SIZE`. **At least 1** |
| `POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW` | No | `5` | Burst above `POSTERN_CONFIRM_DATABASE_POOL_SIZE`. **Zero or greater**. Lower than the API service's 10 because one approval is one person tapping a phone, and both services draw on one `max_connections` |
| `POSTERN_CONFIRM_DATABASE_AUDIT_RESERVE_SIZE` | No | `1` | Connections held back so an approval's **completion** row can still be written when the pool above is at its ceiling. **At least 1** — no value turns it off. Serves `ApprovalAudit`'s completion row and every `PairingAudit` row, and deliberately **not** the entry row: see the sizing section below |

### Naming the variables this deployment must provide

The check above fires on a name that is present and wrong. It cannot fire on one
that is absent and needed, because for `POSTERN_REQUIRE_REDIS`,
`POSTERN_REQUIRE_PEM_KEY` and `POSTERN_STRICT_HEADERS` "not set" and
"deliberately off" are the same thing. List what your deployment must provide in
`POSTERN_REQUIRED_ENV` and each service refuses to start without it:

```
POSTERN_REQUIRED_ENV=POSTERN_REQUIRE_REDIS,POSTERN_REDIS_URL,POSTERN_READ_KEY_PEM_PATH
```

```
1 POSTERN_ variable named in POSTERN_REQUIRED_ENV that nothing set:
  POSTERN_REQUIRE_REDIS
```

**What this is for, and what it is not.** If the whole ConfigMap is dropped then
`POSTERN_REQUIRED_ENV` goes with it and nothing is checked — a list that lives in
the environment cannot guard the environment's own existence. That case is
already fatal without it: the API service raises `KeyError` on
`POSTERN_BACKEND_BASE_URL` and the confirm service raises `ValueError` on the
three `POSTERN_APP_ASSERTION_*` settings, so neither starts on an empty
environment. What this list closes is **one key dropped or renamed** on a
variable that has a default, which is the remaining way a deployment starts
weaker than you think it is.

Worth listing, because each of these is silent today and each is a control:
`POSTERN_REQUIRE_REDIS`, `POSTERN_REQUIRE_PEM_KEY`, `POSTERN_STRICT_HEADERS`,
`POSTERN_REDIS_URL`, `POSTERN_READ_KEY_PEM_PATH`, `POSTERN_WRITE_KEY_PEM_PATH`,
`POSTERN_JWKS_URI`, `POSTERN_TOKEN_ISSUER`.

**Set but empty does not count.** A Helm template rendering nothing, an ECS task
definition carrying `"value": ""`, an `env_file` line left as `POSTERN_X=` — all
produce an empty string, and every reader in Postern takes its default for one.
An empty required variable gets its own message, because the fix is different:
something rendered here and produced nothing, so look at what feeds it rather
than at whether the key exists.

**A name in the list that Postern does not read is refused**, with the name you
probably meant. That catches a typo in the list itself even when the variable is
unset, which is exactly when the namespace check cannot see it.

**A name the *other* service reads is logged, not refused.** One list for both
deployables is normal; the API service will not fail because a confirm-only
variable is absent from its own environment. Write one list per service if you
want a dropped key caught by whichever image starts first.

### Migrations

`alembic upgrade` runs the same check, as `service=migrations`. It reads three
variables — `POSTERN_DATABASE_URL`, `POSTERN_ALLOWED_UNREAD_ENV` and
`POSTERN_REQUIRED_ENV` — and refuses on any other `POSTERN_` name:

```
$ POSTERN_DATABASE_UR=postgresql+asyncpg://... alembic upgrade head
RuntimeError: 1 POSTERN_ variable is set that no code in this deployment reads:
  POSTERN_DATABASE_UR -- Did you mean POSTERN_DATABASE_URL?
```

This is the most valuable place the check runs. `migrations/env.py` applies
`POSTERN_DATABASE_URL` over `alembic.ini`'s `sqlalchemy.url` **when it is set**,
so a misspelt name silently leaves the ini file's URL in place and the migration
applies DDL to whatever that names. The check runs before that read, so the typo
stops the task instead of altering the wrong schema.

When it refuses, `alembic upgrade` exits non-zero and your deploy stops before
the migration runs — and before the application rolls out behind it. That is the
direction you want. Put `POSTERN_DATABASE_URL` in `POSTERN_REQUIRED_ENV` for the
migration task as well, and a dropped key stops it too rather than falling back
to the ini file.

### Both services

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTERN_ALLOWED_UNREAD_ENV` | No | - | `POSTERN_` variable names this deployment sets that Postern does not read, comma separated, exact names, no wildcards. Without it, any such name refuses startup — see the section above |
| `POSTERN_REQUIRED_ENV` | No | - | `POSTERN_` variable names this deployment must provide, comma separated, exact names, no wildcards. Absent or empty refuses startup. Also read by `alembic upgrade` |

The three `POSTERN_APP_ASSERTION_*` variables are the only **required** settings on
either service. `create_confirm_app()` raises `ValueError` and the process does not
start without all three. The API service may run with no authentication for local
development; the confirm service may not, because it holds the write signing key and
its endpoints approve money movement.

Setting `POSTERN_APP_ASSERTION_AUDIENCE` to the same value as the API service's
`POSTERN_AUDIENCE` would mean a customer token good enough to list a balance is also
good enough to approve a payment. Neither process can detect that — they are separate
deployments reading separate environments — so keeping them distinct is an operator
requirement, not something a gate here will catch.

### Sizing the connection pools

The six pool variables above are the one set of numbers this repository cannot
pick for you, because the constraint involves your replica count and your
database's limit and neither is visible from here:

```
  api_replicas     x (POSTERN_DATABASE_POOL_SIZE + POSTERN_DATABASE_MAX_OVERFLOW
                      + POSTERN_DATABASE_AUDIT_RESERVE_SIZE)
+ confirm_replicas x (POSTERN_CONFIRM_DATABASE_POOL_SIZE + POSTERN_CONFIRM_DATABASE_MAX_OVERFLOW
                      + POSTERN_CONFIRM_DATABASE_AUDIT_RESERVE_SIZE)
+ migrations, psql, monitoring, backups
<= max_connections - superuser_reserved_connections
```

Both services connect to the same database, so both sides count against one
limit. On an unmodified PostgreSQL 17 those two server settings are 100 and 3
(measured); a managed instance sets its own, so read them with
`SHOW max_connections` against the instance you will actually deploy against.
Going over is not a slowdown, it is a refusal at connect:
`asyncpg.exceptions.TooManyConnectionsError: sorry, too many clients already`.

At the defaults a replica of `services/api` may hold `5 + 10 + 1 = 16`
connections and a replica of `services/confirm` `5 + 5 + 1 = 11`. Four API
replicas and two confirm replicas hold `4x16 + 2x11 = 86`, which leaves 11 of
the default 100 once the 3 reserved slots are taken.

**What still fits at `max_connections = 100`**, with the 3 reserved slots taken
and counting nothing for migrations, psql or monitoring:

| API replicas | confirm replicas | held | spare of 97 |
|---|---|---|---|
| 3 | 2 | 70 | 27 |
| 3 | 3 | 81 | 16 |
| 4 | 2 | 86 | 11 |
| 5 | 1 | 91 | 6 |
| 4 | 3 | 97 | **0 — does not fit** |
| 5 | 2 | 102 | **does not fit** |
| 6 | 3 | 129 | **does not fit** |

`4 x api + 2 x confirm` is the shape the repository's own test asserts, and at
the Postgres default it is one replica of either service away from not fitting.
If you need a fifth API replica, raise `max_connections` (the usual first move
on a managed instance), lower `POSTERN_DATABASE_POOL_SIZE`, or put a
transaction-mode pooler in front. Do not reach for the reserve: it is one
connection and it is the only thing that records the refusal.

**Both reserves are in the sum, and they do not serve the same rows.** The
reserve is the connection an audit row is written on when the pool is full —
without it, a pool at its ceiling fails the request *and* loses the row that
says why, because the application work and the audit write draw on the same
pool. On `services/api` the reserve serves both of a call's rows. On
`services/confirm` it serves the **completion** row of an approval and every
pairing row, and deliberately **not** the entry row that precedes the backend
write: that row keeps the pool's refusal, so a saturated replica stops *before*
money moves rather than being carried past it on a connection that cannot see
the `approved -> executed` transition through. The practical consequence is the
one to plan around — while a confirm replica is saturated, approvals are
refused and recorded, not performed.

Count a reserve as a ceiling rather than a standing cost: a replica opens it
only once its pool has actually refused a checkout. Budget it anyway, because
the moment one replica needs it is the moment they all do.

A pool holds one connection per in-flight *request*, not per request's worth of
work: a tool call costs two to seven checkouts one after another, and an
approval costs four. `dev-docs/decisions/0013-connection-pool-ceiling.md` has
the derivation, what a saturated pool looks like from the customer's side, and
when raising these is the right response.

### Environment variable conventions

- **Empty string = off**: For optional settings like `POSTERN_JWKS_URI`, setting the value
  to `""` is treated as unset (collapsed to `None`). This lets docker-compose use
  `POSTERN_JWKS_URI=""` to disable a feature. Numeric settings follow the same rule: an empty
  string means "keep the default", never "zero".
- **Numeric settings are bounded at startup**: every number above is checked when
  `from_env()` runs, and a value outside its stated range raises a `ValueError` naming the
  variable, the bound and the value that was set. The process then fails to start rather
  than serving requests on a setting that cannot work. A bound says what is
  *representable*, never what is *advisable*: `POSTERN_MAX_BODY_BYTES=1` is accepted and
  is still a service that refuses almost every request.
- **Production hardening flags**: `POSTERN_REQUIRE_PEM_KEY=1` and `POSTERN_REQUIRE_REDIS=1`
  cause the service to refuse startup if the required resource is not configured. These
  should be set in all production deployments.

## Local Development Stack

The project ships a `docker-compose.yml` that brings up:

| Service | Port | Purpose |
|---------|------|---------|
| `db` (PostgreSQL) | 5432 | Audit log, consents, challenges tables |
| `backend-stub` | 8081 | Stub operator backend with local IdP (JWKS + token minting) |
| `api` | 8080 | MCP read path: tools, OAuth endpoints |
| `confirm` | 8082 (mapped to 8080 inside container) | Write path: device auth, approval callback |

### Start the stack

```bash
docker compose up --build
```

The API service will be available at `http://localhost:8080/mcp`.

### Run migrations

```bash
uv run alembic upgrade head
```

Migrations live in `migrations/versions/`. Each migration adds or alters a table/column
used by the audit log, consent enforcement, risk signals, or challenges.

### Run tests

```bash
uv run pytest                    # all tests (requires Docker for DB-backed tests)
uv run pytest -m "not db"       # skip database-backed tests (no Docker needed)
```

### Run a single service directly

```bash
# API service (read path)
uv run uvicorn services.api.main:app --reload --port 8080

# Confirm service (write path) — the three assertion variables are REQUIRED;
# without them the process exits at startup instead of serving unauthenticated.
POSTERN_APP_ASSERTION_JWKS_URI=http://localhost:8081/.well-known/jwks.json \
POSTERN_APP_ASSERTION_ISSUER=https://postern-local-dev.invalid \
POSTERN_APP_ASSERTION_AUDIENCE=postern-confirm \
  uv run uvicorn services.confirm.main:app --reload --port 8082
```

`docker compose up` sets all three for the `confirm` container already; only the
bare `uvicorn` invocation above needs them spelled out.

## Production Deployment

Before deploying, ensure the following configuration items are set:

| Item | Variable(s) | Purpose |
|------|-------------|---------|
| Persisted read key | `POSTERN_READ_KEY_PEM_PATH` | Not ephemeral: survives restarts |
| Persisted write key | `POSTERN_WRITE_KEY_PEM_PATH` | Not ephemeral: survives restarts |
| Redis backend | `POSTERN_REDIS_URL`, `POSTERN_REQUIRE_REDIS` enabled | Session store, device code persistence, revocation list, and per-customer approval rate limits; without it, a spent device code stays redeemable on another replica |
| JWKS / issuer URIs | `POSTERN_JWKS_URI`, `POSTERN_TOKEN_ISSUER` | Customer JWT validation |
| Strict headers | `POSTERN_STRICT_HEADERS=1` | Enforce MCP Streamable HTTP header compliance |
| Require PEM key | `POSTERN_REQUIRE_PEM_KEY=1` | Refuse startup with ephemeral keys |
| Istio JWT validation | - | Domain services must scope queries by token `sub` |
| Database migrations | - | Run `alembic upgrade head` before first startup |

## Next Steps

- Read the [API Service](components/api-service.md) chapter for details on MCP tools,
  OAuth endpoints, and consent enforcement.
- Read the [Confirm Service](components/confirm-service.md) chapter for device auth,
  approval callbacks, and payment execution.
- Read the [Glossary](glossary.md) for key terms across the platform.
# QR page: the browser half of the device grant, and the scan that binds it

**Date:** 29 September 2026
**Status:** specification, approved in design review on 29 September 2026. Nothing here is built.
**Against:** `services/confirm/device_auth.py` and `packages/postern-core/src/postern_core/auth/device_codes.py` at `58ad120`.
**Reviewed by:** a security review and a code-fit review, both on 29 September 2026. Their findings are folded in below and credited where they changed the design.

---

## What this fixes, first

The device grant cannot complete today, and nothing in the test suite notices.

`POST /approve` requires the bank app to send `device_code` and `user_code` (`services/confirm/device_auth.py::_pair`). The only thing the app ever sees is the QR, and the QR encodes `verification_uri_complete`, which is `verification_uri?user_code=X` (`packages/postern-core/src/postern_core/auth/device_codes.py::verification_uri_complete`). The app has no way to learn `device_code`. The comment above `services/confirm/device_auth.py::approve_callback` says the app reads it "from the scanned QR"; it cannot. The tests pass because they hand both codes to the app directly.

`device_code` must not go into the QR. It is the only credential `POST /token` asks for, so anyone who photographs the QR over a shoulder or a screen share would collect the customer's read token.

Two more defects this spec removes on the way:

- **No HTML is served anywhere.** Handoff §7.3 requires a page showing a QR and the pairing code. There is none.
- **`/approve` races across replicas.** `_pair` reads the device code, checks `approved`, then writes the whole snapshot with a plain `SETEX` through `update_device_code`. Two replicas can both pass the check and the last writer's `customer_ref` wins. The only atomic claim in the store today is `consume_device_code` (`packages/postern-core/src/postern_core/auth/device_codes.py::consume_device_code` on the Redis store, `WATCH`/`MULTI`).

## What this does not fix, stated so nobody records it as fixed

**A live relay of the page defeats both the pairing code and the rotating QR.** In consent phishing the attacker starts the pairing, so to this server the attacker is the legitimate browser. A phishing page that fetches `GET /verify/qr.svg` for the attacker's own handle every two seconds shows the victim a fresh QR and the attacker's pairing code. The victim scans, the app shows the same code, the codes match. Handoff §7.3 says "the attacker's browser shows a different code than the victim's phone"; that holds only when the victim has a pairing of their own open at the same moment.

Rotation stops **static** relays: a screenshot in an email, a QR image on a forum, a photo passed along later. Those are cheap for an attacker and worth stopping. It does not stop the live form.

The one server-side signal against a live relay is comparing the network that created the pairing with the network the phone scanned from. That needs a policy (refuse, step up, or record) and ASN data, and it is **a separate spec after this one**. This spec records the creator's address on the pairing so that spec has something to compare.

The "rich context" mitigation in §7.3 is also weaker than it reads. `client_id` is supplied unauthenticated at `POST /device_authorization`, so an attacker can make the app's confirmation screen say "Claude". This spec marks it unverified in the `/scan` response; CIMD verification is what would fix it, and that is not in scope.

---

## Design

### 1. Store: three identifiers, two of them secret

`DeviceCode` gains:

| Field | Type | Purpose |
|---|---|---|
| `display_handle` | 128-bit random, base64url | Keys the browser page and the QR image. Useless at `/token`. |
| `qr_secret` | 32 random bytes, base64 in the serialized form | Per-pairing HMAC key for the rotation token. Never leaves the store. |
| `creator_ip` | `str \| None` | The address `POST /device_authorization` came from, via `pairing_client_ip` and `trusted_proxy_hops`. Recorded only; nothing reads it in this spec. |
| `scanned_by` | `str` (customer ref), empty until scanned | Which customer's app scanned first. |
| `scanned_at` | `datetime \| None` | When. |

A record serialized before this change deserializes with no `qr_secret` and is therefore unscannable. That is the safe direction, and with a 900-second TTL no such record outlives a deploy by long.

`user_code_attempts` is removed. A per-code attempt budget has no meaning once the guess is the lookup key.

New store methods, each on both backends:

- `get_by_display_handle(handle)` and `get_by_user_code(user_code)`. On Redis each is a secondary key pointing at the primary, created with `SET NX EX` at creation time (a collision retries generation; check-then-set is not used), deleted on revoke and consume. The lookup re-reads the primary and re-checks that its `user_code` or `display_handle` matches the presented value and that it has not expired, because the secondary key's TTL can differ from the primary's by up to one second under the existing truncation. In memory, two dicts that `_drop_expired` and `revoke_device_code` also clear.
- `claim_scan(device_code, customer_ref) -> ScanClaim`. Compare-and-set on the primary, modelled on `consume_device_code`: succeeds when `scanned_by` is empty or already equals `customer_ref` and the code is unexpired and unapproved. When `scanned_by` holds a **different** customer, the pairing is revoked in the same transaction and the result says so.
- `approve_scanned(device_code, customer_ref) -> bool`. Compare-and-set: sets `approved`, `approved_at` and `customer_ref` only when `approved` is false, `scanned_by == customer_ref` and the code is unexpired.

`update_device_code` stays for any caller that remains, but `/approve` no longer uses it.

### 2. Rotation token

- `slot = floor(unix_time / 2)`, a two-second slot matching the page's poll.
- `mac = HMAC-SHA256(qr_secret, user_code_bytes(6) || slot as 8-byte big-endian)`, truncated to 16 bytes, base64url. Fixed-width input, so no two `(user_code, slot)` pairs share an encoding.
- Accepted at `/scan` when `now_slot - 5 <= slot <= now_slot + 1`: ten seconds back for camera, app launch, assertion fetch and the request itself, one slot forward for clock skew between replicas. Anything further forward is refused as invalid, not stale.
- A token is replayable inside its window. That is harmless once the first scan wins (§1): a replay by the same customer is idempotent and a replay by a different one revokes the pairing.

These are constants in code, not settings. Nobody operates this knob.

### 3. What the QR encodes, and where the page lives

Two different URIs, where today there is one:

- **The page**, which the MCP client shows the user: `verification_uri_complete` becomes `{device_verification_uri}?d=<display_handle>`. This departs from RFC 8628 §3.3.1, where the complete URI carries `user_code`; it carries the handle instead, because a URL keyed by a 30-bit code on a public endpoint is an enumeration oracle (32⁶ codes, a 60/min per-address limiter, and an IPv6 /48 holds more /64 buckets than the limiter's 20,000-entry table). `verification_uri` and `user_code` are still returned unchanged.
- **The app link**, which only the QR carries: `{device_app_link_uri}?user_code=<user_code>&qr=<slot>.<mac>`. `device_app_link_uri` is a new setting, `POSTERN_DEVICE_APP_LINK_URI`, naming the operator's universal-link / app-link base. It is a different host from the page on purpose: today `device_verification_uri` defaults to `…/verify`, the same path the page will have, so a phone camera would open the browser page instead of the app. It gets an `env_inventory` entry and follows the required-in-deployment pattern from `467e5a4`.

Bare `GET /verify` with no handle shows one sentence: open the full link your AI client printed. There is no form to type a `user_code` into, because that form is the oracle again. This is a real limitation for a client that prints only `verification_uri` and `user_code`, and it is recorded, not solved.

The page is served by `services/confirm`, which holds the write key, not by `services/api` as the handoff's table says. The device-code store lives in `services/confirm`, and moving the grant is out of scope. Decision record **0021** records the choice: public, unauthenticated HTML on the write-key service, why it is acceptable here (bearer-only auth on every other path, no cookies, a CSP with no inline script), and what would change it.

### 4. Three public routes

All three go into `PUBLIC_PATHS` in `services/confirm/auth.py` with a reason each, like the existing three. All three are plain `Route`s, not a `Mount`: `AppAssertionMiddleware` matches paths exactly and the route-table test in `tests/test_confirm_auth.py` skips anything without `.methods`, so a `StaticFiles` mount would slip past both.

**`GET /verify?d=<handle>`**, the page. The pairing code as `XXX-XXX`, the QR as `<img src="/verify/qr.svg?d=…">`, an "Open in your bank app" link to the same app link for a phone that is itself the browser, and the instruction: check that the code in your app matches this one, and only continue if you started this on your own computer just now. Headers:

- `Content-Security-Policy: default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`
- `Referrer-Policy: no-referrer` (the handle is in the URL)
- `Cache-Control: no-store`
- `X-Content-Type-Options: nosniff`
- `<noscript><meta http-equiv="refresh" content="5"></noscript>` on a pending pairing only. Five seconds, not one: one second fails WCAG 2.2.1 and 2.2.2 and spends 60 requests a minute. A terminal page carries no refresh.

The page embeds the **stored** `user_code`, never anything taken from the query string.

**`GET /verify/qr.svg?d=<handle>`**, the QR, rendered by `segno` from the app link with the current slot's token. `404` when the handle is unknown, the pairing expired, or it is already approved or scanned by someone; the three are indistinguishable, so the image confirms nothing about approval. Headers: `Content-Type: image/svg+xml`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and `Content-Security-Policy: default-src 'none'`, because an SVG opened directly is a document.

**`GET /verify.js`**, a static same-origin file. Every two seconds it replaces the image `src` and the app link's `href` with a cache-busting query. On `404` it stops polling and removes the image, but **leaves the pairing code on the page**: a scan also turns the image into a `404`, and that is exactly the moment the user needs the code in front of them to compare with the app. The message reads "This QR is no longer active. If your bank app is showing a pairing code, it must match the one above; if it does not, cancel in the app." On `429` it backs off exponentially to a ceiling of 30 seconds.

**Dependency:** `segno` 1.6.6 (PyPI, 12 March 2025, BSD licence, no dependencies on Python 3.10+, checked 29 September 2026). It goes in the root `pyproject.toml`; `services/` is not a distribution, so it lands in the shared serving environment and therefore in the api image too.

### 5. `POST /scan`, the new app route

Requires the banking-app assertion, like `/approve`: it is **not** in `PUBLIC_PATHS`. Body `{user_code, qr}`.

1. Customer from the verified `sub`, refused if not a `CustomerRef` (`invalid_subject`, 403).
2. ZT-7 revocation check on that customer, before anything is read.
3. Look up by `user_code`. Unknown, expired or already approved: 400 `invalid_grant`.
4. Verify `qr`: a malformed or forged MAC, or a slot beyond `now + 1`, is `qr_invalid`; a correct MAC older than the window is `qr_stale`. Both 400.
5. `claim_scan`. A different customer already holds the scan: the pairing is revoked, 400 `scan_conflict`.
6. 200 with the stored row's context, never anything from the QR: `client_id` (with `client_id_verified: false`), `scopes`, `expires_at`, and the pairing code for the app to show beside the one the user sees.

### 6. `POST /approve`, the changed contract

Body `{user_code}`. `device_code` is removed from the request.

Lookup by `user_code`, then `approve_scanned(device_code, sub)`. Refused unless this customer scanned it, it is unexpired and it is unapproved. The ZT-7 check and the `invalid_subject` check stay where they are. Guessing is bounded by the per-customer limiter already on `/approve` (10/min) and by the scan requirement: a guessed `user_code` approves nothing that the same customer did not scan with a valid rotation token first, and a valid token needs the handle.

`/token` is unchanged.

### 7. Audit

`/scan` writes one `audit_log` row per call through `PairingAudit`, fail-closed per decision 0006: if the row cannot be written the scan is refused and, if it had claimed, the pairing is withdrawn exactly as `_withdraw_pairing` does for `/approve`. Details: success, `qr_stale`, `qr_invalid`, `scan_conflict`, plus the existing `revoked` and `invalid_subject`. A stale scan is the direct trace of a screenshot relay, and a conflict is the trace of a code seen by two phones.

No migration: `detail` is unconstrained `Text` (the comment above `services/confirm/audit.py`'s `DETAIL_USER_CODE_MISMATCH` says so) and no constraint on `tool_name` exists in `migrations/`. New `DETAIL_*` constants and a scan route/tool name go in `services/confirm/audit.py`.

### 8. Rate limits

Explicit entries in `services/confirm/rate_limit.py`'s table, each a setting with an `env_inventory` entry, so browsers behind one NAT are not cut off at the 60/min fallback:

| Path | Per address bucket, per minute | Why |
|---|---|---|
| `/verify` | 60 | page loads, plus the 12/min noscript refresh |
| `/verify/qr.svg` | 300 | 30/min per open tab at a two-second poll; ten tabs behind one address |
| `/verify.js` | 60 | loaded once per page |
| `/scan` | 60 outer, 10 per customer | same as `/approve` |

`BodySizeLimit` handles GET already and needs no change beyond the tests that list paths.

### 9. Removed configuration

`user_code_max_attempts` and `POSTERN_USER_CODE_MAX_ATTEMPTS` are removed, with their `env_inventory` entry. Under `c3aa67c`, an operator who still sets the variable is refused at startup, which is the intended signal that the control it named no longer exists.

---

## Testing

Test-first throughout. What must exist when this lands:

- Rotation token: slot boundaries, the window's both edges, a future slot, a tampered MAC, a MAC for a different `user_code`, fixed-width encoding.
- Store, on both backends (the Redis ones against the real container `make ci` already runs): handle and `user_code` lookups, secondary-key cleanup on revoke and consume, `SET NX` collision retry, `claim_scan` first-wins and conflict-revokes, `approve_scanned` refusing an unscanned code, a different scanner, an approved code, an expired code, and two concurrent approvals of which exactly one wins.
- `/scan`: every refusal branch, the success body's fields and that `client_id_verified` is false, and one audit row per branch including the fail-closed withdrawal.
- `/approve`: the new body, scanned-by-A-approved-by-B refused, the old `device_code` field ignored or refused (decided in the plan, tested either way).
- Page and image: every header above, the stored `user_code` rendered rather than a query value, `404` indistinguishable across unknown, expired, approved and scanned, no refresh on terminal pages.
- Wiring: the three new public paths and nothing else public, the route-table test still covering every route, the new limits in both limiter tables.
- End to end over ASGI: `device_authorization` → `/verify` → `qr.svg` → `/scan` → `/approve` → `/token` returns a read token.

Existing tests that pin the old behaviour and will change: `tests/test_confirm_auth.py` (the exact `PUBLIC_PATHS` set), `tests/test_confirm_rate_limit.py` and `tests/test_confirm_customer_rate_limit.py` (the limit tables), `tests/test_confirm_body_limit.py` (the path list), `tests/test_settings_bounds.py` (`user_code_max_attempts`), `tests/test_redis_backed_stores.py` (the device-code record shape), and roughly 65 `/approve` bodies across `tests/test_device_grant.py`, `tests/test_pairing_audit.py` and `tests/test_zt7_confirm_revocation.py`.

Docs that cite removed symbols and would fail `make citations`: `docs/user-guide/getting-started.md`, `docs/user-guide/components/confirm-service.md`, `dev-docs/decisions/0012-device-code-single-use.md`.

## Size

About 14 production and config files plus 3 docs and one new decision record. Roughly 700 lines of production code (store ~200, handlers and token ~350, page and script ~100) and 1,000 to 1,300 lines of new tests, besides the rewritten call sites.

## Owed outside this repository

- **The app's `/scan` call and confirmation screen.** Handoff §10.10. Until the mobile team builds it, the flow completes only in tests.
- **The universal-link domain.** Apple associated domains and Android asset links for `device_app_link_uri`'s host are the operator's and the mobile team's.
- **Clients that print only `verification_uri`.** They will land on a page that cannot show a QR. Whether the MCP clients named in the handoff show `verification_uri_complete` has not been checked.
- **The live-relay signal.** The next spec, using `creator_ip`.

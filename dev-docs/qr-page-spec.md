# QR page: the browser half of the device grant, and the scan that binds it

**Date:** 29 September 2026, revised 30 September 2026
**Status:** specification, approved in design review on 29 September 2026. Built on 30 September 2026, by `docs/superpowers/plans/postern-qr-page-and-scan-2026-09-30.md`. The sections below still read as the specification they were written as, so where they say "today" or describe the absent page, they describe `58ad120`.
**Against:** `services/confirm/device_auth.py` and `packages/postern-core/src/postern_core/auth/device_codes.py` at `58ad120`.
**Reviewed by:** a security review and a code-fit review, both on 29 September 2026, and a spec review on 30 September 2026, all folded in below.

---

## What this fixes, first

The device grant cannot complete today, and nothing in the test suite notices.

`POST /approve` requires the bank app to send `device_code` and `user_code` (`services/confirm/device_auth.py::_pair`). The only thing the app ever sees is the QR, and the QR encodes `verification_uri_complete`, which is `verification_uri?user_code=X` (`packages/postern-core/src/postern_core/auth/device_codes.py::verification_uri_complete`). The app has no way to learn `device_code`. The comment above `services/confirm/device_auth.py::approve_callback` says the app reads it "from the scanned QR"; it cannot. The tests pass because they hand both codes to the app directly.

`device_code` must not go into the QR. It is the only credential `POST /token` asks for, so anyone who photographs the QR over a shoulder or a screen share would collect the customer's read token.

Two more defects this spec removes on the way:

- **No HTML is served anywhere.** Handoff §7.3 requires a page showing a QR and the pairing code. There is none.
- **`/approve` races across replicas.** `_pair` reads the device code, checks `approved`, then writes the whole snapshot with a plain `SETEX` through `update_device_code`. Two replicas can both pass the check and the last writer's `customer_ref` wins. The only atomic claim in the store today is `consume_device_code` (`packages/postern-core/src/postern_core/auth/device_codes.py::consume_device_code` on the Redis store, `WATCH`/`MULTI`).

## What this does not fix

**The page URL is itself the lure, and nothing in this spec stops it.** The cheapest consent-phishing attack needs no infrastructure at all. The attacker calls `POST /device_authorization`, takes the `verification_uri_complete` it returns (`/verify?d=<handle>`), and emails it to the victim. The link is on the operator's own domain, the page it opens is the genuine page served by this repository, the pairing code on it is the one the victim's app will show, and it stays valid for the whole 900-second TTL. The victim scans, the codes match, the victim approves, and the attacker's AI client collects the read token at `/token`. Handoff §7.3 says "the attacker's browser shows a different code than the victim's phone"; that holds only when the victim has a pairing of their own open at the same moment. Neither the pairing code nor the rotating QR nor the hotlink refusal in §4 addresses this form. The only server-side signal against it is comparing the network that created the pairing with the network the phone scanned from. That needs a policy (refuse, step up, or record) and ASN data, and it is **a separate spec after this one**; this spec records the creator's address on the pairing (`creator_ip`, §1) so that spec has something to compare.

**A live relay is the same attack in a second form.** A phishing page on the attacker's domain that fetches `GET /verify/qr.svg` server-side for the attacker's own handle every two seconds shows the victim a fresh QR and the attacker's pairing code. A server-side fetch sets whatever `Sec-Fetch-Site` it likes, so the §4 refusal does not stop it. The same creator-versus-scanner comparison is the only signal against it.

Rotation stops **static** relays: a screenshot in an email, a QR image on a forum, a photo passed along later. §4's hotlink refusal stops the cheapest dynamic form of the same thing, an `<img>` pointing at this server from someone else's page. They do not stop the two forms above.

**Session swap is closed only until the victim's client has exchanged the code.** Attacker B, any customer of the operator, sees victim A's QR on a screen share or over a shoulder, scans it and approves first. Without §5's conflict rule, A's AI client would then receive a read token for B's accounts, and every transaction memo in it would be text B wrote, which is A1 delivered through A's own client. §5 revokes the pairing when A's scan arrives second and the code has not been exchanged. When A's client has already polled `/token` and exchanged it (a 5-second poll interval makes that window a few seconds wide), `/scan` refuses and records `scan_conflict`, and **the token already issued is not recalled by this spec.** A's client holds B's read token until it expires.

The "rich context" mitigation in §7.3 is also weaker than it reads. `client_id` is supplied unauthenticated at `POST /device_authorization`, so an attacker can make the app's confirmation screen say "Claude". This spec marks it unverified in the `/scan` response; CIMD verification is what would fix it, and that is not in scope.

---

## Design

### 1. Store: new fields and compare-and-set methods

`DeviceCode` gains:

| Field | Type | Purpose |
|---|---|---|
| `display_handle` | 128-bit random, base64url | Keys the browser page, the QR image and the state endpoint. Useless at `/token`. |
| `qr_secret` | 32 random bytes, base64 in the serialized form | Per-pairing HMAC key for the rotation token. Never leaves the store. |
| `creator_ip` | `str \| None` | The address `POST /device_authorization` came from, via `pairing_client_ip` and `trusted_proxy_hops`. Recorded only; nothing reads it in this spec. Under the default `trusted_proxy_hops = 0` it is the direct peer, which behind a load balancer is the load balancer's address, so an operator must set `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` for the next spec's comparison to mean anything. |
| `scanned_by` | `str` (customer ref), `""` (the empty string) until scanned | Which customer's app scanned first. |
| `scanned_at` | `datetime \| None` | When. |

`exchanged_at` is an existing field, set by `consume_device_code` when `/token` spends the code; that method keeps the row rather than deleting it, on both backends, so `/scan` can still read `exchanged_at` after an exchange.

A record serialized before this change deserializes with no `qr_secret` and is therefore unscannable. That is the safe direction, and with a 900-second TTL no such record outlives a deploy by long.

`user_code_attempts` is removed. A per-code attempt budget has no meaning once the guess is the lookup key.

New store methods, each on both backends:

- `get_by_display_handle(handle)` and `get_by_user_code(user_code)`. On Redis each is a secondary key pointing at the primary, created with `SET NX EX` at creation time (a collision retries generation; check-then-set is not used), deleted on revoke only. Consume leaves both in place, because `/scan` must still find an exchanged row to answer `conflict_exchanged`; they expire with the primary. The lookup re-reads the primary and re-checks that its `user_code` or `display_handle` matches the presented value and that it has not expired, because the secondary key's TTL can differ from the primary's by up to one second under the existing truncation. In memory, two dicts that `_drop_expired` and `revoke_device_code` also clear.
- `claim_scan(device_code, customer_ref) -> ScanClaim`. Compare-and-set on the primary, modelled on `consume_device_code`. One transaction reads the row and returns exactly one of:
  - `claimed`: `scanned_by` was empty and the code unexpired and unapproved; sets `scanned_by` and `scanned_at`.
  - `already_mine`: `scanned_by` already equals `customer_ref` and the code is unapproved; writes nothing. This serves only a retried `/scan` request (a dropped response, a client retry inside the token window (§2)), because the QR leaves the page at the first scan (§4) and nothing else can carry a second valid token to the app.
  - `approved_mine`: `scanned_by` equals `customer_ref` and the code is approved; writes nothing.
  - `conflict_revoked`: `scanned_by` holds a **different** customer and `exchanged_at` is `None`; the pairing is revoked in the same transaction.
  - `conflict_exchanged`: `scanned_by` holds a different customer and `exchanged_at` is set; writes nothing, because revoking a spent code recalls nothing.
  - `gone`: the row is missing or expired.

  A code can only be approved by the customer in `scanned_by` (`approve_scanned` below), so "scanned or approved by someone else" is the single test `scanned_by != customer_ref`.
- `approve_scanned(device_code, customer_ref) -> bool`. Compare-and-set: sets `approved`, `approved_at` and `customer_ref` only when `approved` is false, `scanned_by == customer_ref` and the code is unexpired.

**`update_device_code` and `approve_device_code` are removed** from `packages/postern-core/src/postern_core/auth/device_codes.py::DeviceCodeStoreBase` and from both backends. Each writes a whole snapshot: a snapshot read before a concurrent `claim_scan` or `approve_scanned` and written after it silently undoes that compare-and-set, and neither method touches the two secondary keys. Measured at `58ad120`, `update_device_code` has exactly two production callers, `services/confirm/device_auth.py::_pair` and `_record_user_code_failure` in the same file, both of which this spec rewrites or deletes, and `approve_device_code` has none (it is named only in a comment in `_pair` and a docstring in `device_codes.py`). The tests that call them are listed under Testing.

### 2. Rotation token

- `slot = floor(unix_time / 2)`, a two-second slot matching the page's poll.
- `mac = HMAC-SHA256(qr_secret, user_code_bytes(6) || slot as 8-byte big-endian)`, truncated to 16 bytes, base64url. Fixed-width input, so no two `(user_code, slot)` pairs share an encoding.
- Accepted at `/scan` when `now_slot - 5 <= slot <= now_slot + 1`: ten seconds back for camera, app launch, assertion fetch and the request itself, one slot forward for clock skew between replicas. Anything further forward is refused as invalid, not stale.
- A token is replayable inside its window; §1's first-scan-wins rule makes that harmless.

These are code constants, with no setting.

### 3. What the QR encodes, and where the page lives

Two different URIs, where today there is one:

- **The page**, which the MCP client shows the user: `verification_uri_complete` becomes `{device_verification_uri}?d=<display_handle>`. RFC 8628 §3.3.1 defines the complete URI as including the `user_code` "or other information with the same function as the user_code"; the handle is that other information. It is chosen over the `user_code` because a URL keyed by a 30-bit code on a public endpoint is an enumeration oracle (32⁶ codes, a 60/min per-address limiter, and an IPv6 /48 holds more /64 buckets than the limiter's 20,000-entry table). `verification_uri` and `user_code` are still returned unchanged.
- **The app link**, which only the QR, the page's "Open in your bank app" link and the state endpoint carry: `{device_app_link_uri}?user_code=<user_code>&qr=<slot>.<mac>`. `device_app_link_uri` is a new setting, `POSTERN_DEVICE_APP_LINK_URI`, naming the operator's universal-link / app-link base. It is declared the way `device_verification_uri` is: a `ConfirmSettings` field defaulting to `https://app.postern.internal/pair` for local work, the same default in `ConfirmSettings.from_env`'s `os.environ.get`, and an `EnvVar("POSTERN_DEVICE_APP_LINK_URI", "string", ("confirm",))` entry in `packages/postern-core/src/postern_core/env_inventory.py`, following the required-in-deployment pattern from `467e5a4`.

The app link must be a different host from the page: `device_verification_uri` defaults to `https://auth.postern.internal/verify`, the same path the page will have, and a phone camera handed a URL on the page's host would open the browser page instead of the app. **`ConfirmSettings.from_env` refuses to start** when the app link's host equals `device_verification_uri`'s host (hostnames compared after `urllib.parse.urlsplit`, case-folded), raising `ValueError` the way `_device_code_ttl` refuses an unrepresentable lifetime.

Bare `GET /verify` with no handle shows one sentence: open the full link your AI client printed. There is no form to type a `user_code` into, because that form is the oracle again. This is a real limitation for a client that prints only `verification_uri` and `user_code`.

The page is served by `services/confirm`, which holds the write key, not by `services/api` as the handoff's table says. The device-code store lives in `services/confirm`, and moving the grant is out of scope. Decision record **0021** records the choice: public, unauthenticated HTML on the write-key service, why it is acceptable here (bearer-only auth on every other path, no cookies, a CSP with no inline script), and what would change it.

### 4. Five public routes

All five go into `PUBLIC_PATHS` in `services/confirm/auth.py` with a reason each, like the existing three, which makes eight public paths in all:

| Path | Reason it is public |
|---|---|
| `/verify` | the page a browser opens from `verification_uri_complete`; the browser holds no assertion |
| `/verify/qr.svg` | the image the page embeds |
| `/verify/state` | the status the page's script polls |
| `/verify.js` | the page's only script, same-origin so the CSP needs no inline script |
| `/verify.css` | the page's only stylesheet, so `style-src 'self'` has a target |

All five are plain `Route`s, not a `Mount`: `AppAssertionMiddleware` matches paths exactly and the route-table test in `tests/test_confirm_auth.py` skips anything without `.methods`, so a `StaticFiles` mount would slip past both.

#### Page states

A pairing, as the page and the state endpoint see it, is in one of three states:

| State | Means | Shows pairing code? | Shows QR and app link? | Text | noscript refresh |
|---|---|---|---|---|---|
| pending | unexpired, unscanned | yes | yes | check that the code in your app matches this one, and only continue if you started this on your own computer just now | 5 s |
| scanned | unexpired, scanned, unapproved | yes | no | compare the code in your app with this one | 5 s |
| closed | unknown handle, expired, or approved (whether or not exchanged) | no | no | This pairing is closed. Return to your AI client. | none |

The three closed cases are indistinguishable on every route, so the page confirms nothing about approval. `GET /verify` answers 200 in all three states; `qr.svg` and `/verify/state` answer 404 for closed, and `qr.svg` answers 404 for scanned too.

**`GET /verify?d=<handle>`**, the page, rendered in the state above. In pending: the pairing code as `XXX-XXX`, the QR as `<img src="/verify/qr.svg?d=…">`, an "Open in your bank app" link to the app link for a phone that is itself the browser, and the instruction. The page embeds only the **stored** `display_handle` and the **stored** `user_code`, both read from the row the lookup returned, never a value taken from the query string. Headers:

- `Content-Security-Policy: default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`
- `Referrer-Policy: no-referrer` (the handle is in the URL)
- `Cache-Control: no-store`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security: max-age=31536000`
- `X-Frame-Options: DENY`, for browsers that predate `frame-ancestors`
- `<noscript><meta http-equiv="refresh" content="5"></noscript>` in pending and scanned only. Five seconds, not one: one second fails WCAG 2.2.1 and 2.2.2 and spends 60 requests a minute. A closed page carries no refresh.

**`GET /verify/state?d=<handle>`**, the status the script polls. `200 {"status": "pending", "app_link": "<app link signed for the current slot>"}` in pending, `200 {"status": "scanned"}` in scanned, `404` for closed. Headers: `Content-Type: application/json`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Resource-Policy: same-origin`. The same `Sec-Fetch-Site` refusal as `qr.svg` below.

**`GET /verify/qr.svg?d=<handle>`**, the QR, rendered by `segno` from the app link with the current slot's token. `404` for scanned and for closed. Headers: `Content-Type: image/svg+xml`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'` (because an SVG opened directly is a document), and `Cross-Origin-Resource-Policy: same-origin`.

**Hotlink refusal, on `qr.svg` and `/verify/state`.** Without it, `<img src="https://<operator>/verify/qr.svg?d=H">` in an HTML email or a forum post renders a fresh QR on every open and defeats rotation completely; `nosniff` and the SVG's own CSP do not stop a cross-origin image load. Both routes therefore answer the closed `404` to any request whose `Sec-Fetch-Site` header is not exactly `same-origin`, **including a request that carries no such header at all**. `Cross-Origin-Resource-Policy: same-origin` is the second, independent refusal in any browser that enforces CORP. Two consequences:

- Mail clients' image proxies fetch server-side and send no `Sec-Fetch-Site`, so they get the 404. That is intended.
- Browsers send `Sec-Fetch-Site` only to potentially trustworthy origins (HTTPS, or `localhost`). MDN's `Sec-Fetch-Site` reference, fetched 30 September 2026, marks the header Baseline widely available, "across browsers since March 2023"; per-browser version numbers were not verified. A browser older than that gets no QR and no state, only the pairing code and the noscript refresh.

**`GET /verify.js`**, a static same-origin file. Every two seconds it fetches `/verify/state?d=<handle>` with `fetch` (same-origin, so `Sec-Fetch-Site: same-origin`) and acts on the answer, matching the state table:

- `pending`: set the "Open in your bank app" link's `href` to `app_link`, and reload the QR by replacing the image `src` with a cache-busting query.
- `scanned`: remove the QR and the app link, keep the pairing code, show "compare the code in your app with this one", keep polling.
- `404`: stop polling, remove the pairing code, the QR and the app link, show "This pairing is closed. Return to your AI client."
- `429`: back off exponentially, doubling from two seconds to a ceiling of 30 seconds, and return to two seconds on the next 200.

**`GET /verify.css`**, a static same-origin stylesheet, a plain `Route` for the reason above. Headers: `Content-Type: text/css`, `X-Content-Type-Options: nosniff`.

**Dependency:** `segno` 1.6.6 (PyPI, 12 March 2025, BSD licence, no dependencies on Python 3.10+, checked 29 September 2026). It goes in the root `pyproject.toml`; `services/` is not a distribution, so it lands in the shared serving environment and therefore in the api image too.

### 5. `POST /scan`, the new app route

Requires the banking-app assertion, like `/approve`: it is **not** in `PUBLIC_PATHS`. Body `{user_code, qr}`.

1. Customer from the verified `sub`, refused if not a `CustomerRef` (`invalid_subject`, 403).
2. ZT-7 revocation check on that customer, before anything is read.
3. Look up by `user_code`. Unknown or expired: 400 `invalid_grant`.
4. Verify `qr`: a malformed or forged MAC, or a slot beyond `now + 1`, is 400 `invalid_grant` too. A correct MAC older than the window is 400 `qr_stale`.
5. `claim_scan`, and act on its result:
   - `claimed` or `already_mine`: continue to step 6.
   - `approved_mine`: 400 `invalid_grant`.
   - `conflict_revoked`: the pairing is already revoked; 400 `scan_conflict`. The AI client's next `/token` poll finds no code, and `/verify/state` answers 404, so the page shows closed.
   - `conflict_exchanged`: 400 `scan_conflict`. Nothing is revoked, and the read token already issued to the other customer's pairing stays valid until it expires; see "Session swap" above.
   - `gone`: 400 `invalid_grant`.

   A stale token from a different customer against a scanned code answers `qr_stale`, revokes nothing and is not recorded as `scan_conflict`, because the MAC check in step 4 runs before `claim_scan`. Only a scan inside the token window reaches session-swap detection.
6. 200 with the stored row's context, never anything from the QR: `client_id` (with `client_id_verified: false`), `scopes`, `expires_at`, and the pairing code for the app to show beside the one the user sees.

**One response for everything that leaks existence.** Unknown, expired, approved and a bad MAC or future slot all answer the identical 400 `invalid_grant` body; the audit `detail` alone separates them (§7): `qr_invalid` for a bad MAC or future slot, `already_approved` for an approved code, and `user_code_not_found` for an unknown or expired one. `qr_stale` and `scan_conflict` stay distinct responses because only a genuine MAC reaches them: a MAC that verifies proves the caller held a real QR for this `user_code`, and that caller already knows the pairing exists, so the distinct answer tells it nothing new. The app needs both to show a useful message ("scan again" and "this pairing was cancelled").

### 6. `POST /approve`, the changed contract

Body `{user_code}`. `device_code` is removed from the request, and a body that still carries it is refused 400 `invalid_request`, so an app on the old contract fails loudly. That refusal writes no audit row, like the existing malformed-body refusals in `services/confirm/device_auth.py::_pair`, which return with `recorded=False`.

Lookup by `user_code`, then `approve_scanned(device_code, sub)`. Refused unless this customer scanned it, it is unexpired and it is unapproved. After a refused `approve_scanned`, the audit `detail` is read from the row in this order: `user_code_not_found` when the row is gone (revoked) or expired by the time it is re-read, then `not_scanned` when `scanned_by` is empty, `scanned_by_other` when it names another customer, `already_approved` when the code is approved. That read labels the audit row only and decides nothing; the compare-and-set has already refused. Every one of those refusals, and the lookup miss before it, answers the identical 400 `invalid_grant` body, for the same existence-oracle reason as §5; the distinction lives only in the audit `detail`. The existing 401 for a missing or invalid assertion and 403 for `invalid_subject` and a ZT-7 revoked customer are unchanged, and both checks stay where they are, before the lookup. Guessing is bounded by the per-customer limiter already on `/approve` (10/min) and by the scan requirement: a guessed `user_code` approves nothing that the same customer did not scan with a valid rotation token first, and a valid token needs the handle.

The handoff's §7.3 steps 11 to 13 have the app's device-bound key sign the pairing approval. The device grant's `/approve` checks only the bearer assertion, and this spec leaves that out of scope.

`/token` is unchanged.

### 7. Audit

`/scan` writes one `audit_log` row per call through `services/confirm/audit.py::PairingAudit`, fail-closed per decision 0006: if the row cannot be written the scan is refused and, if it had claimed, the pairing is withdrawn exactly as `_withdraw_pairing` does for `/approve`. The rows are told apart from `/approve` rows by `tool_name` and route, following the existing pair `PAIRING_TOOL_NAME` / `PAIRING_ROUTE` and `TOKEN_TOOL_NAME` / `TOKEN_ROUTE`: two new constants, `SCAN_TOOL_NAME = "device_grant.scan"` and `SCAN_ROUTE = "/scan"`, keep `WHERE tool_name LIKE 'device_grant.%'` returning the whole flow.

**Success** on both routes is `outcome = 'returned'` with a NULL `detail`, as `PairingAudit.approved()` already writes it.

**`/scan` refusal details**, each a new or existing `DETAIL_*` constant in `services/confirm/audit.py`:

| Constant | Literal | When |
|---|---|---|
| `DETAIL_INVALID_SUBJECT` (existing) | `invalid_subject` | step 1 |
| `DETAIL_REVOKED` (existing) | `revoked` | step 2 |
| `DETAIL_USER_CODE_NOT_FOUND` (new) | `user_code_not_found` | step 3 unknown or expired, and step 5 `gone` |
| `DETAIL_ALREADY_APPROVED` (existing) | `already_approved` | step 5 `approved_mine`: this customer scanned and already approved the code |
| `DETAIL_QR_INVALID` (new) | `qr_invalid` | step 4, malformed or forged MAC, or a future slot |
| `DETAIL_QR_STALE` (new) | `qr_stale` | step 4, a genuine MAC older than the window. The direct trace of a screenshot relay. |
| `DETAIL_SCAN_CONFLICT` (new) | `scan_conflict` | step 5, both conflict results. The trace of a code seen by two phones, and of a session swap. |

**`DETAIL_USER_CODE_NOT_FOUND` is new rather than a reuse of `DETAIL_DEVICE_CODE_NOT_FOUND`.** That literal stays live at `/token`, where a lookup by `device_code` misses, and every `/approve` row written before this change carries it with the same meaning. A `device_code` miss is a guess at 256 bits of `secrets` entropy; a `user_code` miss is a guess at 30 bits, the enumeration signal the new keying opens. One literal for both would mix the cheap guess into the expensive one's history. `/approve` writes `DETAIL_USER_CODE_NOT_FOUND` for its own `user_code` lookup miss, and for a row revoked or expired between that lookup and the re-read after a refused `approve_scanned` (§6).

**`/approve` new details:** `DETAIL_NOT_SCANNED` (`not_scanned`, the code has no `scanned_by`) and `DETAIL_SCANNED_BY_OTHER` (`scanned_by_other`, `scanned_by` is a different customer). `DETAIL_ALREADY_APPROVED`, `DETAIL_REVOKED` and `DETAIL_INVALID_SUBJECT` stay in use there.

**`DETAIL_ALREADY_APPROVED`'s docstring is rewritten.** Its current rationale is a caller holding an assertion of their own swapping `customer_ref` to themselves in the window before the browser polls `/token`. That cannot happen once `approve_scanned` requires `scanned_by == sub`: only the scanner can approve, and approval is a compare-and-set. The literal now means a repeat approval by the customer who scanned, normally a retried request, on `/approve` and, through `approved_mine`, on `/scan`.

**`DETAIL_USER_CODE_MISMATCH` and `DETAIL_USER_CODE_BUDGET_EXHAUSTED` stay defined** in `services/confirm/audit.py`, documented as historical: `audit_log` is append-only, rows carrying them exist, and nothing writes them any more once `_record_user_code_failure` is deleted. Removing the constants would leave those rows carrying a literal no code names.

No migration: `detail` is unconstrained `Text` (the comment above `services/confirm/audit.py`'s `DETAIL_REVOKED` says so) and no constraint on `tool_name` exists in `migrations/`.

### 8. Rate limits

Explicit entries in `services/confirm/rate_limit.py`'s table, each a setting with an `env_inventory` entry, so browsers behind one NAT are not cut off at the 60/min fallback. One row per `PUBLIC_PATHS` addition, plus `/scan`:

| Path | Per address bucket, per minute | Why |
|---|---|---|
| `/verify` | 60 | page loads, plus the 12/min noscript refresh |
| `/verify/qr.svg` | 300 | 30/min per open tab at a two-second poll; ten tabs behind one address |
| `/verify/state` | 300 | the same poll, one request per image reload |
| `/verify.js` | 60 | loaded once per page |
| `/verify.css` | 60 | loaded once per page |
| `/scan` | 60 outer, 10 per customer | same as `/approve` |

`BodySizeLimit` handles GET already and needs no change beyond the tests that list paths.

### 9. Removed configuration

`user_code_max_attempts` and `POSTERN_USER_CODE_MAX_ATTEMPTS` are removed, with their `env_inventory` entry. The unknown-`POSTERN_`-variable startup check (`c3aa67c`) refuses to start a service whose environment still sets it.

---

## Testing

Test-first throughout. What must exist when this lands:

- Rotation token: slot boundaries, the window's both edges, a future slot, a tampered MAC, a MAC for a different `user_code`, fixed-width encoding.
- Store, on both backends (the Redis ones against the real container `make ci` already runs): handle and `user_code` lookups, secondary-key cleanup on revoke and both secondary keys still resolving after consume, `SET NX` collision retry, every `claim_scan` result (`claimed`, `already_mine`, `approved_mine`, `conflict_revoked` leaving no row, `conflict_exchanged` leaving the row unchanged, `gone`), `approve_scanned` refusing an unscanned code, a different scanner, an approved code, an expired code, and two concurrent approvals of which exactly one wins. That `DeviceCodeStoreBase` no longer has `update_device_code` or `approve_device_code`.
- `/scan`: every refusal branch, the identical `invalid_grant` body across unknown, expired, approved and bad-MAC, the distinct `qr_stale` and `scan_conflict` bodies, session swap (B scans first, A's scan revokes an unexchanged code, A's client's next `/token` fails; against an exchanged code, refused with nothing revoked), the success body's fields and that `client_id_verified` is false, and one audit row per branch with the `detail` in §7's table, including the fail-closed withdrawal.
- `/approve`: the new body, scanned-by-A-approved-by-B refused with `scanned_by_other`, an unscanned code refused with `not_scanned`, a code revoked or expired between the lookup and a refused `approve_scanned` labelled `user_code_not_found`, the identical `invalid_grant` body across every refusal, and a body still carrying `device_code` refused 400 `invalid_request` with no audit row written.
- Page, image and state: every header above on each route; the stored `user_code` and `display_handle` rendered rather than a query value; the three rows of the page-state table, each with its code, QR, text and refresh; `/verify/state` bodies for pending and scanned, the `app_link` changing across slots, and `404` indistinguishable across unknown, expired and approved; `qr.svg` `404` for scanned and all three closed cases; `qr.svg` and `/verify/state` answering `404` to `Sec-Fetch-Site: cross-site`, `same-site`, `none` and to a missing header, and carrying `Cross-Origin-Resource-Policy: same-origin` on every answer; `/verify.css` served as `text/css`.
- Settings: `POSTERN_DEVICE_APP_LINK_URI` defaulting to `https://app.postern.internal/pair`, its `env_inventory` entry, and `ConfirmSettings.from_env` refusing to start when its host equals `POSTERN_DEVICE_VERIFICATION_URI`'s, including a case-only difference.
- Wiring: exactly eight public paths, the five new ones and the existing three, and nothing else public; the route-table test still covering every route; the new limits in both limiter tables.
- End to end over ASGI: `device_authorization` → `/verify` → `/verify/state` → `qr.svg` → `/scan` → `/approve` → `/token` returns a read token, with `/verify/state` reading `scanned` after the scan and `404` after the approval.

Existing tests that pin the old behaviour and will change: `tests/test_confirm_auth.py` (the exact `PUBLIC_PATHS` set), `tests/test_confirm_rate_limit.py` and `tests/test_confirm_customer_rate_limit.py` (the limit tables), `tests/test_confirm_body_limit.py` (the path list), `tests/test_settings_bounds.py` (`user_code_max_attempts`), `tests/test_redis_backed_stores.py` (the device-code record shape, and six call sites of the removed `update_device_code` / `approve_device_code`), `tests/test_device_grant.py` (six call sites of the removed methods, four of `approve_device_code` and two of `update_device_code`) and `tests/test_pairing_audit.py` (two), and roughly 65 `/approve` bodies across `tests/test_device_grant.py`, `tests/test_pairing_audit.py` and `tests/test_zt7_confirm_revocation.py`.

Docs that describe removed symbols or settings and would go stale (`make citations` checks only anchored citations, so it would not catch them): `docs/user-guide/getting-started.md` (`POSTERN_USER_CODE_MAX_ATTEMPTS`), `docs/user-guide/components/confirm-service.md` (`POSTERN_USER_CODE_MAX_ATTEMPTS` and `user_code_attempts`), `docs/user-guide/components/session-store.md` (presents `approve_device_code` and `update_device_code` as abstract methods of `DeviceCodeStoreBase`), `dev-docs/decisions/0012-device-code-single-use.md` (`_record_user_code_failure`).

## Size

About 16 production and config files plus 3 docs and one new decision record. Roughly 800 lines of production code (store ~220, handlers and token ~380, page, state endpoint, script and stylesheet ~160, settings ~40) and 1,200 to 1,500 lines of new tests, besides the rewritten call sites.

## Owed outside this repository

- **The app's `/scan` call and confirmation screen.** Handoff §10.10. Until the mobile team builds it, the flow completes only in tests.
- **The universal-link domain.** Apple associated domains and Android asset links for `device_app_link_uri`'s host are the operator's and the mobile team's.
- **Clients that print only `verification_uri`.** They will land on a page that cannot show a QR. Whether the MCP clients named in the handoff show `verification_uri_complete` has not been checked.
- **The creator-versus-scanner signal and recalling a swapped session's token.** See "What this does not fix".

## Out of scope

- **An app that crashes after scanning.** Re-scan is unreachable by design: once a pairing is scanned the QR is gone (`qr.svg` 404, state `scanned`), so the app recovers only through a new pairing started from the AI client.

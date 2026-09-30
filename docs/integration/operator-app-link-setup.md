# Operator setup: the pairing app link

**For:** whoever deploys `services/confirm` and owns the domains the bank app is associated with.
**Against:** `services/confirm` as of commit `31103cf`, 30 September 2026.
**Companion:** `docs/integration/mobile-app-pairing-contract.md`, which is what the mobile team builds against the host you choose here.

The pairing page's QR encodes an app link, `{POSTERN_DEVICE_APP_LINK_URI}?user_code=...&qr=...`. For a phone camera to hand that link to the bank app rather than to a browser, the link's host must be associated with the app on both platforms. This repository configures the variable and refuses some bad values at startup. It publishes no association file and serves nothing on the app-link host. Everything on that host is yours.

---

## 1. Two hosts, and which one is which

| Variable | Default | What lives there | Served by |
|---|---|---|---|
| `POSTERN_DEVICE_VERIFICATION_URI` | `https://auth.postern.internal/verify` | The pairing page the AI client's user opens in a browser | `services/confirm` |
| `POSTERN_DEVICE_APP_LINK_URI` | `https://app.postern.internal/pair` | Nothing, from this repository's side. It exists so the operating system opens the bank app. | You: the association files and a fallback page |

Both defaults are placeholders on a `.internal` host for local work. A deployment owes real values for both.

The bank app sends `POST /scan` and `POST /approve` to the confirm service's own address, which the app is configured with. That address appears in neither variable.

## 2. Choosing the app-link host

`ConfirmSettings.from_env` in `services/confirm/settings.py` validates both values when the service starts and raises `ValueError`, so the container never becomes ready, for each of these:

**`POSTERN_DEVICE_APP_LINK_URI`** (`services/confirm/settings.py::_app_link_uri`):

- The scheme is not `https`.
- There is no hostname (a bare `/pair`, or `app.bank.example/pair` with the scheme missing).
- The hostname equals the pairing page's hostname. The comparison is case-folded and ignores the port, so `https://Auth.Bank.example:8443/pair` against a page on `auth.bank.example` is refused. A phone camera handed a URL on the page's own host opens the browser page, not the app, and no pairing could ever reach `/scan`.

**`POSTERN_DEVICE_VERIFICATION_URI`** (`services/confirm/settings.py::_verification_uri`):

- The path is anything other than `/verify` (including `/verify/`).
- The value contains `?` or `#` anywhere.

What the service does **not** check, so you must:

- **Unset is accepted.** An empty or unset `POSTERN_DEVICE_APP_LINK_URI` becomes the placeholder `https://app.postern.internal/pair`, with no warning. A deployment that forgets it starts normally and every QR it draws points at a host no phone can resolve.
- **The path is free.** `/pair` is only the default. Pick a path your association files cover.
- **A query in the base is allowed.** The two parameters are then appended with `&`.
- **Do not put a fragment in it.** Nothing refuses one, and `services/confirm/verify_page.py::app_link` decides between `?` and `&` by looking for a `?`, so a base ending in `#x` gets `?user_code=...&qr=...` appended after the fragment, where no server or app link handler receives it.
- **Reachability and association.** Nothing checks that the host resolves, serves TLS, or publishes the files below.

A separate subdomain, for example `app.bank.example` next to `auth.bank.example` for the page, meets every rule above.

## 3. Associating the host with the app

**Not verified.** The platform documentation was not fetched when this was written on 30 September 2026, so no URL is given and the details below are from general knowledge of both mechanisms. Check each against Apple's and Android's current documentation before relying on it.

**iOS universal links.** The app declares an Associated Domains entitlement naming the app-link host (`applinks:app.bank.example`). The host serves an `apple-app-site-association` JSON file over HTTPS, conventionally at `/.well-known/apple-app-site-association`, listing the app's identifier and the paths it handles. The path in `POSTERN_DEVICE_APP_LINK_URI` must be among them.

**Android App Links.** The app declares an intent filter for the host and path with automatic verification enabled. The host serves `/.well-known/assetlinks.json` over HTTPS, naming the app's package and the SHA-256 fingerprint of its signing certificate.

Two consequences that follow from this repository and not from the platforms:

- Handoff §7.3 requires universal links or app links, not a custom scheme: "`bankapp://` can be claimed by any installed app, a hijack vector in precisely the flow where it matters most". `_app_link_uri` enforces the `https` half of that.
- The page and the app link are on different hosts on purpose, so the association files go on the app-link host only. Do not associate the pairing page's host with the app.

## 4. When the app is not installed

The operating system then opens the app link in a browser, at your host, with `user_code` and `qr` in the query string. Nothing in this repository serves that path. Handoff §7.3's fallback is "app store, then web SCA flow"; this repository implements neither, so what the page says is yours to decide. At minimum it should tell the user to install the bank app and start the pairing again.

What is safe and unsafe about the parameters arriving there, from the code:

- The `qr` token expires 10 to 12 seconds after the page drew it (`services/confirm/qr_token.py::verify_token`), and `/scan` refuses it after that. A `user_code` without a current token cannot claim a pairing, and `/approve` approves only for a customer who already scanned. Access logs holding these values are therefore stale within seconds.
- The fallback page should still send `Referrer-Policy: no-referrer` and load no third-party scripts, because within those seconds the token is live and belongs to whoever reads it first.
- The fallback page must not try to complete the pairing itself. It has no assertion, and `/scan` and `/approve` require one.

## 5. The app's assertion settings

`services/confirm` refuses to start without all three:

| Variable | Set it to |
|---|---|
| `POSTERN_APP_ASSERTION_JWKS_URI` | Your app backend's JWKS URL |
| `POSTERN_APP_ASSERTION_ISSUER` | The exact `iss` your app backend writes |
| `POSTERN_APP_ASSERTION_AUDIENCE` | An audience used for nothing else. It must not be `services/api`'s customer-token audience (default `"postern"`), or a token an AI client holds for reads would authenticate here too. Neither service can detect the collision. |

The mobile contract, section 3, lists what the verifier accepts. One gap to close in the app backend: the verifier does not require `exp`, so your backend must always set a short one.

## 6. `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS`

How many proxies in front of `services/confirm` append to `X-Forwarded-For`. Default `0`, minimum `0`. It is a separate variable from `services/api`'s `POSTERN_TRUSTED_PROXY_HOPS`; set each for its own service.

It decides which address three things see:

- the per-address rate limiter's bucket (section 7);
- `arguments.client_ip` on the `/scan` and `/approve` audit rows;
- `creator_ip`, stored on every pairing at `POST /device_authorization`. Nothing reads it yet; a later spec will compare it with the scanner's address to catch the phishing-link form of consent phishing (`dev-docs/qr-page-spec.md`, "What this does not fix"). That comparison means nothing unless this variable is right.

How it resolves (`postern_core.net`'s `client_ip`):

- `0`: the TCP peer. Behind a load balancer that is the balancer, so every client shares one rate-limit bucket and every audit row carries the balancer's address.
- `N` greater than 0: the `N`th entry from the right of `X-Forwarded-For`. Behind exactly one proxy that appends the client's address, `1`.
- If the header is missing or has fewer than `N` entries, or the chosen entry does not parse as an IP, the request is attributed to nobody: it is recorded with no address and rate-limited in one shared bucket, `-`. A value set too high therefore puts all traffic in that bucket, and refusals start in the first minute.

## 7. Rate-limit variables

All are per-minute counts over a fixed 60-second window, read through `_positive_int`: `0`, negatives and non-integers refuse startup, and no value disables a limit.

**Per address bucket** (IPv4 address, or IPv6 /64), held in memory **per replica**, `services/confirm/rate_limit.py::DEFAULT_LIMITS`. Refusal: 429 `too_many_requests` with `Retry-After`, except `/token`, which gets 400 `slow_down`.

| Variable | Default | Path |
|---|---|---|
| `POSTERN_CONFIRM_RATE_LIMIT_SCAN` | 60 | `POST /scan` |
| `POSTERN_CONFIRM_RATE_LIMIT_APPROVE` | 60 | `POST /approve` |
| `POSTERN_CONFIRM_RATE_LIMIT_CHALLENGE_APPROVE` | 60 | `POST /challenges/{challenge_id}/approve` |
| `POSTERN_CONFIRM_RATE_LIMIT_DEVICE_AUTHORIZATION` | 60 | `POST /device_authorization` |
| `POSTERN_CONFIRM_RATE_LIMIT_TOKEN` | 300 | `POST /token` |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY` | 60 | `GET /verify` |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_QR` | 300 | `GET /verify/qr.svg` |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_STATE` | 300 | `GET /verify/state` |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_JS` | 60 | `GET /verify.js` |
| `POSTERN_CONFIRM_RATE_LIMIT_VERIFY_CSS` | 60 | `GET /verify.css` |
| `POSTERN_CONFIRM_RATE_LIMIT_DEFAULT` | 60 | Any other path |

`/device_authorization` also carries a second, fixed counter of 200 creations per bucket per 900 seconds, with no variable.

**Per customer** (the assertion's `sub`), `services/confirm/customer_rate_limit.py::DEFAULT_CUSTOMER_LIMITS`. Refusal: 429 `customer_rate_limited` with `Retry-After`; 503 `rate_limit_store_unavailable` if the shared counter cannot be reached.

| Variable | Default | Path |
|---|---|---|
| `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_SCAN` | 10 | `POST /scan` |
| `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_APPROVE` | 10 | `POST /approve` |
| `POSTERN_CONFIRM_CUSTOMER_RATE_LIMIT_CHALLENGE_APPROVE` | 10 | `POST /challenges/{challenge_id}/approve` |

Which way to move them:

- **Your app backend calls `/scan` and `/approve` for the phone.** Every approval in the bank then arrives from a few egress addresses and 60 per minute per address becomes a bank-wide ceiling. Raise `POSTERN_CONFIRM_RATE_LIMIT_SCAN` and `POSTERN_CONFIRM_RATE_LIMIT_APPROVE`; the per-customer limits still bound each customer.
- **Phones call directly.** The defaults assume this.
- **Browsers behind carrier-grade NAT** share an IPv4 address; the page's routes are set for about ten open tabs per address. Raise the `VERIFY_*` pair first if pages fail to refresh.
- **The per-customer limits** measure how fast one person can act. One pairing is one `/scan` and one `/approve`. If a customer hits 10 a minute, look for a retry loop in the app before raising them.

## 8. Redis

Set `POSTERN_REDIS_URL` for any deployment with more than one replica. Without it, the device-code store, the revocation list and the per-customer counters are per process: a pairing created on one replica is unknown to the next, and R replicas admit R times each customer limit. `POSTERN_REQUIRE_REDIS` makes a missing `POSTERN_REDIS_URL` a startup failure.

**The Redis must allow scripting.** `docs/user-guide/components/session-store.md` records that a device code's two lookup keys are deleted through a one-line Lua compare-and-delete sent with `EVAL`, and that "a managed Redis with `EVAL` disabled fails every revoke". On the pairing path that revoke runs when a second customer's `/scan` cancels a pairing, when a pairing is withdrawn after a failed audit write or an ambiguous store error, and when `/token` finds an expired code. On a Redis that refuses `EVAL`, a session-swap scan that should cancel the pairing answers 500 instead of `scan_conflict`, and the withdrawal that follows fails the same way, so whether the pairing is left cancelled is not something this document can promise. Confirm your managed Redis permits `EVAL` before going live.

The per-address limiter does not use Redis at all; it stays per replica whatever you set.

## 9. Checklist

- [ ] `POSTERN_DEVICE_VERIFICATION_URI` set to `https://<page host>/verify`.
- [ ] `POSTERN_DEVICE_APP_LINK_URI` set, `https`, on a different host, no fragment.
- [ ] `apple-app-site-association` and `assetlinks.json` published on the app-link host, covering its path, checked against current platform documentation.
- [ ] A fallback page on the app-link path for phones without the app.
- [ ] `POSTERN_APP_ASSERTION_JWKS_URI`, `_ISSUER` and `_AUDIENCE` set, with an audience distinct from `services/api`'s, and the app backend setting `exp`.
- [ ] `POSTERN_CONFIRM_TRUSTED_PROXY_HOPS` matching the proxies in front of the service.
- [ ] Rate limits reviewed against whether phones or the app backend call `/scan` and `/approve`.
- [ ] `POSTERN_REDIS_URL` set, `POSTERN_REQUIRE_REDIS` on, and `EVAL` allowed on that Redis.

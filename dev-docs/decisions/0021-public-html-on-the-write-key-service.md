# 0021. The pairing page is served by the service that holds the write key

Date: 30 September 2026

## Status

Accepted.

## Context

RFC 8628's browser needs a page: the one `verification_uri_complete` opens,
showing the pairing code and a QR the bank app scans. Handoff §7.3 requires it
and until this record nothing in the repository served any HTML at all.

The handoff's architecture table puts the device grant, and with it the QR
page, on `services/api`, the read path. The code does not: the grant lives in
`services/confirm`, because the grant mints the browser's read token and the
device-code store sits beside that mint (`ConfirmSettings`' docstring records
the read-key exception this already is). The page reads that same store on
every request -- by display handle, to draw the QR and answer the state poll --
so wherever the page is served, it needs the device-code store.

That makes the question concrete: five unauthenticated GET routes, one of them
HTML, on the one process that holds the WRITE signing key and reaches backend
write endpoints.

## Decision

Serve the page from `services/confirm`, as five plain Starlette routes added to
`services/confirm/auth.py::PUBLIC_PATHS` with a reason each: `/verify`,
`/verify/qr.svg`, `/verify/state`, `/verify.js`, `/verify.css`.
`dev-docs/qr-page-spec.md` section 4 is the contract.

It is acceptable here, and only because all of the following hold together:

- **No ambient credential exists on this origin.** Every other path authenticates
  with a bearer assertion the operator's app backend mints, checked by
  `AppAssertionMiddleware`; no path sets or reads a cookie. A page served here
  has nothing a cross-site request could borrow, so the usual reason to keep
  public HTML away from a privileged origin -- a script on it riding the
  origin's session -- has no session to ride.
- **No inline script and no third-party content.** The page's CSP is
  `default-src 'none'` with `'self'` only for the image, the one script, the one
  stylesheet and the state fetch, plus `frame-ancestors 'none'`,
  `base-uri 'none'` and `form-action 'none'`. The script and the stylesheet are
  two static files in the repository, served same-origin.
- **The page renders stored values only.** The `d` query parameter is a lookup
  key; the markup carries the `display_handle` and `user_code` read back from
  the row, escaped. A crafted URL can change which pairing is found and never
  what is written into the page.
- **Nothing on these routes reaches a key, a backend or the database.** They
  read the device-code store and draw an SVG. The write key is not in reach of
  any of their code paths, and they write no `audit_log` row.
- **The image and the state refuse other sites.** Both answer 404 unless
  `Sec-Fetch-Site` is exactly `same-origin`, and both carry
  `Cross-Origin-Resource-Policy: same-origin`.

## Alternatives rejected

**Serve the page from `services/api`.** That is where the handoff draws it, and
it would keep HTML off the write-key process. It needs the device-code store
there too, and there are two ways to get it. Move the whole grant to
`services/api`, which is a change of its own with its own review, out of scope
for a page. Or have `services/api` read the store `services/confirm` writes,
which puts one Redis keyspace under two deployables with nothing in the tree
saying which one owns it, and makes every change to the pairing's row shape a
two-service release.

**A third deployable for the page.** Operationally the cleanest isolation, and
the most expensive: a new image, a new task definition, and a Redis-sharing
contract between it and `services/confirm` identical to the one just rejected.

**A `StaticFiles` mount for the script and stylesheet.** `AppAssertionMiddleware`
matches `PUBLIC_PATHS` exactly and `tests/test_confirm_auth.py`'s route-table
test skips any route without `.methods`, so a mount would slip past both
controls silently. Two plain routes cost nothing and stay inside both.

## What would change this decision

- **A cookie or any session on this origin.** The first line of "acceptable
  here" stops holding the day one exists, and the page must move off the
  write-key origin before that ships.
- **Anything on the page other than the stored pairing.** Account data, a form,
  a login, a third-party script or font: each widens what an HTML response on
  this origin can do.
- **The grant moving to `services/api`.** Then the page moves with it, and this
  record is superseded.

## Consequences

The confirm service now answers unauthenticated GETs with HTML, eight public
paths where there were three. Each is rate-limited per address bucket
(`services/confirm/rate_limit.py`), bounded by `BodySizeLimit`, and listed in
`PUBLIC_PATHS` with its reason, so the exemption list is still the single place
to read what the write path serves anonymously.

The page does not stop consent phishing: the URL itself can be the lure, and a
live relay can proxy the QR. `dev-docs/qr-page-spec.md`'s "What this does not
fix" is the record of that, and `creator_ip` is recorded on every pairing for
the later spec that will compare it with the scanner's network.

"""The browser half of the device grant: the pairing page, its QR and its state.

Five public GET routes, and the only HTML this repository serves:

- ``/verify?d=<handle>`` -- the page the AI client's user opens from
  ``verification_uri_complete``.
- ``/verify/qr.svg?d=<handle>`` -- the QR the page embeds, drawn by ``segno``
  from the app link with the current slot's rotation token.
- ``/verify/state?d=<handle>`` -- what the page's script polls every two
  seconds.
- ``/verify.js`` and ``/verify.css`` -- the page's only script and only
  stylesheet, served same-origin so the CSP needs no inline anything.

``dev-docs/qr-page-spec.md`` section 4 is the contract, and
``dev-docs/decisions/0021-public-html-on-the-write-key-service.md`` is why
these live on the service that holds the write key.

THE PAGE RENDERS STORED VALUES ONLY. The handle in the query string is a
lookup key and nothing else: what the page, the image and the state show is
the ``display_handle`` and the ``user_code`` read from the row the lookup
returned, so a crafted ``d`` can change which pairing is found and never what
is written into the markup.

THREE STATES, AND THE CLOSED ONE HAS NO SUBSTATES. Pending (unexpired,
unscanned), scanned (unexpired, scanned, unapproved), closed (unknown handle,
expired, or approved whether or not exchanged). An unknown, an expired and an
approved pairing are indistinguishable on every route, so nothing here
confirms that an approval happened.

THE HOTLINK REFUSAL. ``qr.svg`` and ``/verify/state`` answer the closed 404
to any request whose ``Sec-Fetch-Site`` is not exactly ``same-origin``,
including one with no such header, and both carry
``Cross-Origin-Resource-Policy: same-origin`` as a second, independent
refusal. Without it an ``<img>`` pointing here from an email or a forum post
would draw a fresh QR on every open and defeat rotation outright. What it
does not stop -- a server-side relay fetching the image for the attacker's
own pairing -- is in the spec's "What this does not fix".

NO ``audit_log`` ROW ON ANY OF THE FIVE, by ``PairingAudit``'s rule: none of
them resolves an identity, and a row per poll would be an unauthenticated
INSERT every two seconds per open tab.
"""

from __future__ import annotations

import html
import io
import time
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlencode

import segno
from postern_core.auth.device_codes import DeviceCode, DeviceCodeStoreBase
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from services.confirm.qr_token import slot_at, token_for
from services.confirm.settings import ConfirmSettings

PairingState = Literal["pending", "scanned", "closed"]

#: The instruction under the pairing code, per state. Pending asks the user to
#: check the origin of the pairing as well as the code, because the page URL
#: itself can be the lure (the spec's "What this does not fix").
PENDING_TEXT = (
    "Check that the code in your app matches this one, and only continue if you "
    "started this on your own computer just now."
)
SCANNED_TEXT = "Compare the code in your app with this one."
CLOSED_TEXT = "This pairing is closed. Return to your AI client."
#: What a bare ``/verify`` says. There is no form to type a code into: that
#: form would be the ``user_code`` enumeration oracle the handle exists to
#: avoid.
NO_HANDLE_TEXT = "Open the full link your AI client printed."

#: The noscript refresh, in seconds, on a pending or scanned page. Five and
#: not one: one fails WCAG 2.2.1 and 2.2.2 and spends 60 requests a minute.
REFRESH_SECONDS = 5

#: Longer than any handle this service issues (22 characters). A longer value
#: names nothing, so it is answered as closed without a store round trip.
MAX_HANDLE_LENGTH = 64

PAGE_CSP = (
    "default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

#: Every header the page carries, in every state.
PAGE_HEADERS = {
    "Content-Security-Policy": PAGE_CSP,
    # The handle is in the URL, and the page's own requests must not carry it
    # off-origin in a Referer.
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000",
    # For browsers that predate `frame-ancestors`.
    "X-Frame-Options": "DENY",
}

#: The state endpoint's headers, on every answer including the 404.
STATE_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Resource-Policy": "same-origin",
}

#: The image's headers, on every answer including the 404. The CSP is there
#: because an SVG opened directly is a document.
QR_HEADERS = {**STATE_HEADERS, "Content-Security-Policy": "default-src 'none'"}

#: The script's and the stylesheet's.
ASSET_HEADERS = {"X-Content-Type-Options": "nosniff"}

_STATIC = Path(__file__).resolve().parent / "static"
VERIFY_JS = (_STATIC / "verify.js").read_bytes()
VERIFY_CSS = (_STATIC / "verify.css").read_bytes()


def _now() -> float:
    """The clock the rotation token is cut from. A function so a test can
    move it across a slot boundary."""
    return time.time()


def pairing_state(code: DeviceCode | None) -> PairingState:
    """Which of the three states a looked-up row is in."""
    if code is None or code.is_expired or code.approved:
        return "closed"
    if code.scanned_by:
        return "scanned"
    return "pending"


def app_link(settings: ConfirmSettings, code: DeviceCode, now: float) -> str:
    """The app link for ``code`` with the rotation token for ``now``'s slot.

    ``{device_app_link_uri}?user_code=<user_code>&qr=<slot>.<mac>``. The
    ``user_code`` is the stored six-character form; the token is
    ``services/confirm/qr_token.py``'s, keyed by the row's own secret.
    The base carries no ``?`` or ``#``:
    ``settings.py::_app_link_uri`` refuses both at startup.
    """
    token = token_for(code.qr_secret, code.user_code, slot_at(now))
    query = urlencode({"user_code": code.user_code, "qr": token})
    return f"{settings.device_app_link_uri}?{query}"


def render_qr_svg(link: str) -> bytes:
    """The QR for ``link`` as an SVG document, with no XML declaration.

    ``segno`` 1.6.6's ``make_qr`` and ``save(kind="svg")``. The output holds
    path data and nothing of the encoded text.
    """
    qr = segno.make_qr(link, error="m")
    buffer = io.BytesIO()
    qr.save(buffer, kind="svg", scale=6, border=4, dark="#000", light="#fff", xmldecl=False)
    return buffer.getvalue()


def render_page(state: PairingState | None, code: DeviceCode | None, link: str | None) -> str:
    """The page's HTML. ``state`` ``None`` is a bare ``/verify`` with no handle.

    Every interpolated value is ``html.escape``-d, including the ones that
    come from the store and could not carry markup today, so that stays true
    if the alphabet or the handle format ever changes.
    """
    live = state in ("pending", "scanned") and code is not None
    head_extra = ""
    body_attributes = ""
    parts: list[str] = []
    if live and code is not None:
        head_extra = (
            f'<noscript><meta http-equiv="refresh" content="{REFRESH_SECONDS}"></noscript>\n'
            '<script src="/verify.js" defer></script>\n'
        )
        body_attributes = f' data-handle="{html.escape(code.display_handle, quote=True)}"'
        parts.append(
            f'<p id="pairing-code" class="pairing-code">{html.escape(code.user_code_display)}</p>'
        )
        if state == "pending" and link is not None:
            image_src = f"/verify/qr.svg?d={quote(code.display_handle, safe='')}"
            parts.append(
                f'<img id="qr" src="{html.escape(image_src, quote=True)}" '
                'alt="QR code to scan with your bank app" width="246" height="246">'
            )
            parts.append(
                f'<a id="app-link" href="{html.escape(link, quote=True)}">Open in your bank app</a>'
            )
            parts.append(f'<p id="instruction">{html.escape(PENDING_TEXT)}</p>')
        else:
            parts.append(f'<p id="instruction">{html.escape(SCANNED_TEXT)}</p>')
    elif state is None:
        parts.append(f'<p id="instruction">{html.escape(NO_HANDLE_TEXT)}</p>')
    else:
        parts.append(f'<p id="instruction">{html.escape(CLOSED_TEXT)}</p>')
    body = "\n".join(parts)
    return (
        "<!doctype html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        "<title>Pair your AI client</title>\n"
        '<link rel="stylesheet" href="/verify.css">\n'
        f"{head_extra}"
        "</head>\n"
        f"<body{body_attributes}>\n"
        "<main>\n"
        "<h1>Pair your AI client</h1>\n"
        f"{body}\n"
        "</main>\n"
        "</body>\n"
        "</html>\n"
    )


async def _lookup(request: Request) -> DeviceCode | None:
    """The row the ``d`` parameter names, or ``None``. Expired rows come back
    ``None`` from the store's lookup already."""
    handle = request.query_params.get("d", "")
    if not handle or len(handle) > MAX_HANDLE_LENGTH:
        return None
    store: DeviceCodeStoreBase = request.app.state.device_code_store
    return await store.get_by_display_handle(handle)


def _same_origin(request: Request) -> bool:
    """Exactly ``Sec-Fetch-Site: same-origin``. Anything else -- another
    value, or no header at all -- is refused."""
    return request.headers.get("sec-fetch-site") == "same-origin"


def _closed_state() -> JSONResponse:
    """The one answer for every closed pairing and every refused fetch."""
    return JSONResponse({"status": "closed"}, status_code=404, headers=STATE_HEADERS)


def _no_qr() -> Response:
    """The one 404 the image answers, for every state but pending and every
    refused fetch. Empty, with the image's headers."""
    return Response(status_code=404, headers=QR_HEADERS)


async def verify_page(request: Request) -> HTMLResponse:
    """``GET /verify``: 200 in every state, rendered from the stored row."""
    if not request.query_params.get("d"):
        return HTMLResponse(render_page(None, None, None), headers=PAGE_HEADERS)
    code = await _lookup(request)
    state = pairing_state(code)
    if state == "closed" or code is None:
        return HTMLResponse(render_page("closed", None, None), headers=PAGE_HEADERS)
    link = None
    if state == "pending":
        settings: ConfirmSettings = request.app.state.settings
        link = app_link(settings, code, _now())
    return HTMLResponse(render_page(state, code, link), headers=PAGE_HEADERS)


async def verify_state(request: Request) -> JSONResponse:
    """``GET /verify/state``: pending with the current app link, scanned, or 404."""
    if not _same_origin(request):
        return _closed_state()
    code = await _lookup(request)
    state = pairing_state(code)
    if state == "closed" or code is None:
        return _closed_state()
    if state == "scanned":
        return JSONResponse({"status": "scanned"}, headers=STATE_HEADERS)
    settings: ConfirmSettings = request.app.state.settings
    return JSONResponse(
        {"status": "pending", "app_link": app_link(settings, code, _now())},
        headers=STATE_HEADERS,
    )


async def verify_qr(request: Request) -> Response:
    """``GET /verify/qr.svg``: the QR while pending, 404 otherwise."""
    if not _same_origin(request):
        return _no_qr()
    code = await _lookup(request)
    if code is None or pairing_state(code) != "pending":
        return _no_qr()
    settings: ConfirmSettings = request.app.state.settings
    svg = render_qr_svg(app_link(settings, code, _now()))
    return Response(svg, media_type="image/svg+xml", headers=QR_HEADERS)


async def verify_js(request: Request) -> Response:
    """``GET /verify.js``, the page's only script."""
    return Response(VERIFY_JS, media_type="text/javascript", headers=ASSET_HEADERS)


async def verify_css(request: Request) -> Response:
    """``GET /verify.css``, the page's only stylesheet."""
    return Response(VERIFY_CSS, media_type="text/css", headers=ASSET_HEADERS)


def verify_page_routes() -> list[Route]:
    """The five public routes, each a plain ``Route``.

    NOT A ``StaticFiles`` MOUNT, even for the script and the stylesheet.
    ``AppAssertionMiddleware`` matches ``PUBLIC_PATHS`` exactly, and
    ``tests/test_confirm_auth.py``'s route-table test skips anything without
    ``.methods``, so a mount would slip past both.
    """
    return [
        Route("/verify", verify_page, methods=["GET"]),
        Route("/verify/qr.svg", verify_qr, methods=["GET"]),
        Route("/verify/state", verify_state, methods=["GET"]),
        Route("/verify.js", verify_js, methods=["GET"]),
        Route("/verify.css", verify_css, methods=["GET"]),
    ]

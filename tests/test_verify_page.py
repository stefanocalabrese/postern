"""The five public pairing-page routes, over the assembled app.

Section 4 of ``dev-docs/qr-page-spec.md``: every header on every route, the
three rows of the page-state table, the stored values rendered instead of the
query's, the state endpoint's bodies, the image's 404s, and the hotlink
refusal on the image and the state. No Postgres: none of these routes reads or
writes ``audit_log``, and the app builds without connecting.
"""

from __future__ import annotations

import re
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Literal
from urllib.parse import parse_qs, quote, urlsplit

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_codes import DeviceCode
from postern_core.auth.device_keys import no_enrolled_devices
from starlette.applications import Starlette

from services.confirm import verify_page
from services.confirm.main import create_confirm_app
from services.confirm.qr_token import SLOT_SECONDS, SLOTS_BACK, QrVerdict, slot_at, verify_token
from services.confirm.settings import ConfirmSettings
from services.confirm.verify_page import (
    CLOSED_TEXT,
    NO_HANDLE_TEXT,
    PAGE_CSP,
    PENDING_TEXT,
    SCANNED_TEXT,
)
from tests.device_grant_helpers import device_store_of, overwrite_in_memory

SAME_ORIGIN = {"Sec-Fetch-Site": "same-origin"}
CUSTOMER = "cust_7f3a"
CLOSED_STATES = ["unknown", "expired", "approved"]


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture()
def app(key_pair: RSAKeyPair) -> Starlette:
    return create_confirm_app(
        ConfirmSettings.for_testing(),
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer="https://i.test", audience="a"
        ),
        device_key_store=no_enrolled_devices(),
    )


async def get(app: Starlette, path: str, headers: dict[str, str] | None = None) -> httpx2.Response:
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://test"
    ) as client:
        return await client.get(path, headers=headers or {})


async def pairing(app: Starlette, state: str) -> DeviceCode:
    """A stored pairing in ``state``: pending, scanned, expired or approved."""
    store = device_store_of(app)
    code = await store.create_device_code(
        client_id="browser-1", scopes="accounts:read", verification_uri="https://a.test/verify"
    )
    if state in ("scanned", "approved"):
        await store.claim_scan(code.device_code, CUSTOMER)
    if state == "approved":
        assert await store.approve_scanned(code.device_code, CUSTOMER) is True
    if state == "expired":
        overwrite_in_memory(app, replace(code, expires_at=datetime.now(UTC) - timedelta(seconds=1)))
    return code


async def handle_for(app: Starlette, state: str) -> str:
    """The ``d`` value for a pairing in ``state``; ``unknown`` names none."""
    if state == "unknown":
        return "no-such-handle-0000000"
    return (await pairing(app, state)).display_handle


def page_url(handle: str) -> str:
    return f"/verify?d={quote(handle, safe='')}"


# ---------------------------------------------------------------------------
# GET /verify
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["bare", "pending", "scanned", *CLOSED_STATES])
async def test_the_page_carries_every_header_in_every_state(app: Starlette, state: str) -> None:
    url = "/verify" if state == "bare" else page_url(await handle_for(app, state))

    resp = await get(app, url)

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/html")
    assert resp.headers["content-security-policy"] == PAGE_CSP
    assert resp.headers["referrer-policy"] == "no-referrer"
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["strict-transport-security"] == "max-age=31536000"
    assert resp.headers["x-frame-options"] == "DENY"


def test_the_csp_is_the_specs_to_the_character() -> None:
    assert PAGE_CSP == (
        "default-src 'none'; img-src 'self'; script-src 'self'; style-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )


async def test_a_pending_page_shows_the_code_the_qr_the_link_and_the_instruction(
    app: Starlette,
) -> None:
    code = await pairing(app, "pending")

    page = (await get(app, page_url(code.display_handle))).text

    assert code.user_code_display in page
    assert f'<img id="qr" src="/verify/qr.svg?d={code.display_handle}"' in page
    assert 'id="app-link" href="https://app.postern.internal/pair?user_code=' in page
    assert PENDING_TEXT in page
    assert '<meta http-equiv="refresh" content="5">' in page
    assert '<script src="/verify.js" defer></script>' in page
    assert '<link rel="stylesheet" href="/verify.css">' in page
    assert "<script>" not in page, "no inline script: the CSP would refuse it anyway"


async def test_a_scanned_page_shows_the_code_and_nothing_to_scan(app: Starlette) -> None:
    code = await pairing(app, "scanned")

    page = (await get(app, page_url(code.display_handle))).text

    assert code.user_code_display in page
    assert 'id="qr"' not in page
    assert 'id="app-link"' not in page
    assert SCANNED_TEXT in page
    assert '<meta http-equiv="refresh" content="5">' in page


async def test_every_closed_page_is_the_same_page(app: Starlette) -> None:
    """Unknown, expired and approved are indistinguishable, so the page
    confirms nothing about an approval."""
    pages = [(await get(app, page_url(await handle_for(app, s)))).text for s in CLOSED_STATES]

    assert pages[0] == pages[1] == pages[2]
    assert CLOSED_TEXT in pages[0]
    assert 'id="pairing-code"' not in pages[0]
    assert 'id="qr"' not in pages[0]
    assert 'http-equiv="refresh"' not in pages[0]
    assert "/verify.js" not in pages[0]


async def test_a_bare_page_says_one_sentence_and_offers_no_form(app: Starlette) -> None:
    page = (await get(app, "/verify")).text

    assert NO_HANDLE_TEXT in page
    assert "<form" not in page
    assert "<input" not in page
    assert 'http-equiv="refresh"' not in page


async def test_the_page_renders_the_stored_values_and_not_the_query(
    app: Starlette, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lookup is replaced by one that ignores its argument, so the only
    way the probe string could reach the page is from the query."""
    stored = replace(await pairing(app, "pending"), display_handle="stored-handle-00000000")

    async def found_regardless(display_handle: str) -> DeviceCode:
        return stored

    monkeypatch.setattr(device_store_of(app), "get_by_display_handle", found_regardless)

    page = (await get(app, "/verify?d=probe-from-the-query")).text

    assert "stored-handle-00000000" in page
    assert stored.user_code_display in page
    assert "probe-from-the-query" not in page


async def test_markup_in_the_query_never_reaches_the_page(app: Starlette) -> None:
    page = (await get(app, "/verify?d=%3Cscript%3Ealert(1)%3C%2Fscript%3E")).text

    assert "alert(1)" not in page
    assert CLOSED_TEXT in page


# ---------------------------------------------------------------------------
# GET /verify/state
# ---------------------------------------------------------------------------


def assert_state_headers(resp: httpx2.Response) -> None:
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["cross-origin-resource-policy"] == "same-origin"


async def test_a_pending_state_carries_a_current_app_link(app: Starlette) -> None:
    code = await pairing(app, "pending")

    resp = await get(app, f"/verify/state?d={code.display_handle}", SAME_ORIGIN)

    assert resp.status_code == 200
    assert_state_headers(resp)
    body = resp.json()
    assert set(body) == {"status", "app_link"}
    assert body["status"] == "pending"
    link = urlsplit(body["app_link"])
    assert f"{link.scheme}://{link.netloc}{link.path}" == "https://app.postern.internal/pair"
    query = parse_qs(link.query)
    assert query["user_code"] == [code.user_code]
    verdict = verify_token(code.qr_secret, code.user_code, query["qr"][0], slot_at(time.time()))
    assert verdict is QrVerdict.VALID


async def test_the_app_link_changes_from_one_slot_to_the_next(
    app: Starlette, monkeypatch: pytest.MonkeyPatch
) -> None:
    code = await pairing(app, "pending")
    url = f"/verify/state?d={code.display_handle}"

    monkeypatch.setattr(verify_page, "_now", lambda: 1_790_000_000.0)
    first = (await get(app, url, SAME_ORIGIN)).json()["app_link"]
    monkeypatch.setattr(verify_page, "_now", lambda: 1_790_000_002.0)
    second = (await get(app, url, SAME_ORIGIN)).json()["app_link"]

    assert first != second
    assert parse_qs(urlsplit(first).query)["qr"][0].startswith("895000000.")
    assert parse_qs(urlsplit(second).query)["qr"][0].startswith("895000001.")


async def test_a_scanned_state_says_scanned_and_nothing_else(app: Starlette) -> None:
    code = await pairing(app, "scanned")

    resp = await get(app, f"/verify/state?d={code.display_handle}", SAME_ORIGIN)

    assert resp.status_code == 200
    assert_state_headers(resp)
    assert resp.json() == {"status": "scanned"}


async def test_every_closed_state_is_the_same_404(app: Starlette) -> None:
    answers = [
        await get(app, f"/verify/state?d={await handle_for(app, s)}", SAME_ORIGIN)
        for s in CLOSED_STATES
    ]

    assert [r.status_code for r in answers] == [404, 404, 404]
    assert answers[0].json() == answers[1].json() == answers[2].json() == {"status": "closed"}
    for resp in answers:
        assert_state_headers(resp)


# ---------------------------------------------------------------------------
# GET /verify/qr.svg
# ---------------------------------------------------------------------------


def assert_qr_headers(resp: httpx2.Response) -> None:
    assert resp.headers["cache-control"] == "no-store"
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert resp.headers["content-security-policy"] == "default-src 'none'"
    assert resp.headers["cross-origin-resource-policy"] == "same-origin"


async def test_a_pending_pairing_gets_an_svg(app: Starlette) -> None:
    code = await pairing(app, "pending")

    resp = await get(app, f"/verify/qr.svg?d={code.display_handle}", SAME_ORIGIN)

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "image/svg+xml"
    assert_qr_headers(resp)
    assert resp.content.startswith(b"<svg")
    assert code.user_code.encode() not in resp.content, "the SVG is path data, not text"


async def test_the_qr_encodes_the_app_link_for_the_current_slot(
    app: Starlette, monkeypatch: pytest.MonkeyPatch
) -> None:
    code = await pairing(app, "pending")
    drawn: list[str] = []
    real = verify_page.render_qr_svg

    def spy(link: str) -> bytes:
        drawn.append(link)
        return real(link)

    monkeypatch.setattr(verify_page, "render_qr_svg", spy)
    monkeypatch.setattr(verify_page, "_now", lambda: 1_790_000_000.0)

    await get(app, f"/verify/qr.svg?d={code.display_handle}", SAME_ORIGIN)
    state = (await get(app, f"/verify/state?d={code.display_handle}", SAME_ORIGIN)).json()

    assert drawn == [state["app_link"]]


@pytest.mark.parametrize("state", ["scanned", *CLOSED_STATES])
async def test_every_other_state_gets_the_same_empty_404(app: Starlette, state: str) -> None:
    resp = await get(app, f"/verify/qr.svg?d={await handle_for(app, state)}", SAME_ORIGIN)

    assert resp.status_code == 404
    assert resp.content == b""
    assert_qr_headers(resp)


# ---------------------------------------------------------------------------
# The hotlink refusal, on the image and the state.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({"Sec-Fetch-Site": "cross-site"}, id="cross-site"),
        pytest.param({"Sec-Fetch-Site": "same-site"}, id="same-site"),
        pytest.param({"Sec-Fetch-Site": "none"}, id="none"),
        pytest.param({}, id="no header at all"),
    ],
)
async def test_anything_but_same_origin_gets_the_closed_answer(
    app: Starlette, headers: dict[str, str]
) -> None:
    code = await pairing(app, "pending")

    image = await get(app, f"/verify/qr.svg?d={code.display_handle}", headers)
    state = await get(app, f"/verify/state?d={code.display_handle}", headers)

    assert image.status_code == 404
    assert image.content == b""
    assert_qr_headers(image)
    assert state.status_code == 404
    assert state.json() == {"status": "closed"}
    assert_state_headers(state)


async def test_the_page_itself_is_not_refused_for_a_cross_site_navigation(
    app: Starlette,
) -> None:
    """The page is opened from a link in the AI client, which is exactly a
    cross-site navigation; only the image and the state are refused."""
    code = await pairing(app, "pending")

    resp = await get(app, page_url(code.display_handle), {"Sec-Fetch-Site": "cross-site"})

    assert resp.status_code == 200
    assert code.user_code_display in resp.text


HOSTILE_HANDLE = '"><script>x</script>'
HOSTILE_CODE = "<b>ABC"


async def _hostile(app: Starlette, state: str) -> DeviceCode:
    """A stored pairing whose handle and code carry markup.

    The render function is called directly by the callers: no route would
    find a handle like this, and the point is that a stored value is escaped
    on its own merits, not that the alphabet happens to keep markup out.
    """
    code = await pairing(app, state)
    return replace(code, display_handle=HOSTILE_HANDLE, user_code=HOSTILE_CODE)


@pytest.mark.parametrize("state", ["pending", "scanned"])
async def test_stored_markup_in_the_handle_and_code_is_escaped(
    app: Starlette, state: Literal["pending", "scanned"]
) -> None:
    """The handle lands in ``data-handle`` and, while pending, in the image
    ``src``; the code lands in the pairing paragraph and in the app link."""
    code = await _hostile(app, state)
    link = verify_page.app_link(ConfirmSettings.for_testing(), code, time.time())

    page = verify_page.render_page(state, code, link if state == "pending" else None)

    assert "<script>x" not in page
    assert HOSTILE_HANDLE not in page
    assert '"><script' not in page
    assert "<b>" not in page
    assert "&quot;&gt;&lt;script&gt;x&lt;/script&gt;" in page
    assert "&lt;b&gt;-ABC" in page
    assert page.count("<script") == 1, "only the page's own /verify.js tag"


async def test_a_pending_pages_image_and_link_escape_stored_markup(app: Starlette) -> None:
    code = await _hostile(app, "pending")
    link = verify_page.app_link(ConfirmSettings.for_testing(), code, time.time())

    page = verify_page.render_page("pending", code, link)

    assert f'src="/verify/qr.svg?d={quote(HOSTILE_HANDLE, safe="")}"' in page
    assert "user_code=%3Cb%3EABC" in page
    # Percent-encoding does not touch the `&` between the link's parameters;
    # only html.escape turns it into `&amp;` inside the href attribute.
    assert "&amp;qr=" in page
    assert "&qr=" not in page.replace("&amp;qr=", "")


NOSCRIPT_REFRESH = '<noscript><meta http-equiv="refresh" content="5"></noscript>'


@pytest.mark.parametrize("state", ["pending", "scanned"])
async def test_a_live_page_carries_the_five_second_noscript_refresh(
    app: Starlette, state: str
) -> None:
    resp = await get(app, page_url(await handle_for(app, state)))

    assert resp.text.count(NOSCRIPT_REFRESH) == 1


@pytest.mark.parametrize("state", CLOSED_STATES)
async def test_a_closed_page_carries_no_refresh(app: Starlette, state: str) -> None:
    resp = await get(app, page_url(await handle_for(app, state)))

    assert NOSCRIPT_REFRESH not in resp.text
    assert "http-equiv" not in resp.text


async def test_the_script_names_exactly_the_two_endpoints(app: Starlette) -> None:
    """Every absolute path the script can request. A third URL would be a
    route the page reaches that the spec's hotlink and audit rules never saw."""
    script = (await get(app, "/verify.js")).text

    paths = set(re.findall(r"[\"\'](/[A-Za-z0-9_./-]+)", script))
    assert paths == {"/verify/state", "/verify/qr.svg"}
    assert not re.search(r"https?://", script)


# ---------------------------------------------------------------------------
# GET /verify.js and /verify.css
# ---------------------------------------------------------------------------


async def test_the_script_is_served_as_javascript(app: Starlette) -> None:
    resp = await get(app, "/verify.js")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/javascript")
    assert resp.headers["x-content-type-options"] == "nosniff"
    assert "/verify/state?" in resp.text
    assert "30000" in resp.text, "the 429 back-off ceiling"


def _js_constant(script: str, name: str) -> int:
    """The integer ``var NAME = <n>;`` in the served script."""
    found = re.search(rf"var {name} = (\d+);", script)
    assert found is not None, f"{name} is not declared in verify.js"
    return int(found.group(1))


# NO TEST HERE RUNS THE SCRIPT. There is no JavaScript runtime in the
# toolchain, so the eight below read the served text: the constants, the
# strings and the branches are present, and no HTML sink is. What the browser
# does with them is not executed anywhere in this suite.


async def test_the_script_takes_the_qr_down_before_a_back_off_outlives_its_token(
    app: Starlette,
) -> None:
    """A token is accepted for at least ``SLOTS_BACK`` slots after its own, so
    a wait longer than that leaves a QR on screen that ``POST /scan`` refuses."""
    script = (await get(app, "/verify.js")).text

    assert _js_constant(script, "QR_STALE_AFTER_MS") == SLOTS_BACK * SLOT_SECONDS * 1000
    assert "Too many requests. Retrying..." in script
    assert _js_constant(script, "MAX_DELAY_MS") == 30000


async def test_the_script_ages_the_qr_from_when_it_was_shown(app: Starlette) -> None:
    """The next delay alone undercounts: a QR shown 6 s ago and a 8 s wait is
    already past the window. The age is measured from the last refresh, on the
    429 path and on the failure path alike."""
    script = (await get(app, "/verify.js")).text

    assert "freshAt = Date.now()" in script
    assert "Date.now() - freshAt + delay > QR_STALE_AFTER_MS" in script
    assert script.count("isStale()") >= 3, "declared, and checked on 429 and on failure"


async def test_the_script_hides_the_app_link_with_the_qr(app: Starlette) -> None:
    """The link carries the same rotation token as the QR, so it goes stale at
    the same moment and is held, detached and re-inserted with it."""
    script = (await get(app, "/verify.js")).text

    assert 'var linkNode = document.getElementById("app-link");' in script
    assert "linkNode.parentNode.removeChild(linkNode)" in script
    assert "insertBefore(linkNode" in script
    assert "linkNode = null" in script


async def test_the_script_says_what_the_page_says(app: Starlette) -> None:
    """The pending text is restored after a back-off, so it must be the
    page's own, character for character, as the other two already are."""
    script = (await get(app, "/verify.js")).text

    for text in (PENDING_TEXT, SCANNED_TEXT, CLOSED_TEXT):
        assert f'"{text}"' in script


async def test_the_script_stops_after_five_consecutive_failures(app: Starlette) -> None:
    script = (await get(app, "/verify.js")).text

    assert _js_constant(script, "MAX_FAILURES") == 5
    assert "failures >= MAX_FAILURES" in script
    assert "reload" in script.casefold()


async def test_the_script_counts_every_unexpected_answer_as_a_failure(app: Starlette) -> None:
    """Anything but 200, 404 and 429 is a failure, and the count is reset only
    by a 200 whose body parses as a pending or scanned answer, so a malformed
    or unrecognised body still reaches give-up.
    ``tests/test_verify_js_behaviour.py`` runs the script and checks that an
    unrecognised 200 is counted too, which reading the text cannot."""
    script = (await get(app, "/verify.js")).text

    assert "response.status >= 500" not in script
    assert "if (response.status !== 200) {\n          fail();" in script
    parsed = script.index("response.json().then(function (body) {")
    resets = [m.start() for m in re.finditer(r"(?<!var )failures = 0;", script)]
    assert resets, "a parsed 200 resets the count"
    assert all(at > parsed for at in resets), "every reset sits after the parse"


async def test_the_script_times_out_each_fetch(app: Starlette) -> None:
    script = (await get(app, "/verify.js")).text

    assert _js_constant(script, "FETCH_TIMEOUT_MS") == 8000
    assert "new AbortController()" in script
    assert "signal: controller.signal" in script
    assert "controller.abort()" in script


async def test_the_script_pauses_while_the_tab_is_hidden(app: Starlette) -> None:
    script = (await get(app, "/verify.js")).text

    assert '"visibilitychange"' in script
    assert 'document.visibilityState === "hidden"' in script
    assert "window.clearTimeout(" in script


async def test_the_script_writes_no_markup(app: Starlette) -> None:
    script = (await get(app, "/verify.js")).text

    for sink in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "eval(",
        "document.write",
        "Function(",
    ):
        assert sink not in script


async def test_the_stylesheet_is_served_as_css(app: Starlette) -> None:
    resp = await get(app, "/verify.css")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/css")
    assert resp.headers["x-content-type-options"] == "nosniff"


async def test_the_script_keeps_the_compare_instruction_after_a_scan(
    app: Starlette,
) -> None:
    script = (await get(app, "/verify.js")).text

    # Once scanned, showScanned nulls qrNode, and freshAt is never refreshed
    # again, so isStale() is true forever. Without a guard, a 429 or a failure
    # would replace the compare instruction with a retry message.
    body = script.split("function takeDown(text) {", 1)[1].split("\n  }\n", 1)[0]

    guard = "if (qrNode === null) {\n      return;\n    }"
    assert guard in body, (
        "takeDown must return before touching the instruction when no token is on the page"
    )
    assert body.index(guard) < body.index("degraded = true;")
    assert body.index(guard) < body.index("say(text)")

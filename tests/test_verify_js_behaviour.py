"""The pairing page's script, executed.

``tests/test_verify_page.py`` reads ``verify.js`` as text and checks what it
declares. This file runs it: the bytes ``services/confirm/verify_page.py``'s
``verify_js`` route serves are evaluated in a V8 isolate (``mini-racer``)
against the fake browser in ``tests/js/verify_harness.js``, on a page parsed
out of the HTML ``render_page`` produces, and each test drives the virtual
clock and the scripted ``/verify/state`` answers and asserts the resulting
DOM, timers and requests.

WHAT IS FAKED. The DOM is the ``<body>`` attributes and the direct children
of ``<main>``, nothing else: no layout, no image loads, no ``<head>``.
``fetch`` answers from a queue in order, resolving in the microtask queue
where a browser would take at least one task. Time moves only when a test
moves it. The harness header lists the rest.

WHAT IS REAL. The script, its constants and texts, the markup the server
renders, V8's promise machinery, and the ordering: each timer fires in its
own ``eval`` and V8 drains the microtask queue when an ``eval`` returns, so a
poll's whole promise chain settles before the next timer runs, as it would in
a browser. Measured on mini-racer 0.14.1 (V8 14.4) before this file was
written, not read from its documentation, which does not say.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Protocol

import pytest
from postern_core.auth.device_codes import DeviceCode
from py_mini_racer import MiniRacer

from services.confirm.settings import ConfirmSettings
from services.confirm.verify_page import (
    CLOSED_TEXT,
    PENDING_TEXT,
    SCANNED_TEXT,
    VERIFY_JS,
    app_link,
    render_page,
)

HARNESS = (Path(__file__).resolve().parent / "js" / "verify_harness.js").read_text()

#: The harness clock's reading when the page loads. Every time below is an
#: offset from it.
START = 1_000_000

#: The script's own texts that the server does not also render. Copied, not
#: imported: ``verify.js`` is the only place they live, and a test that read
#: them out of the script would agree with whatever the script said.
BACKING_OFF_TEXT = "Too many requests. Retrying..."
RETRYING_TEXT = "Trouble reaching the server. Retrying..."
GAVE_UP_TEXT = "This page lost contact with the server. Reload the page to try again."

SETTINGS = ConfirmSettings.for_testing()
HANDLE = "q3Vd9Zk1-mXo_2bT7wLr4A"
CODE = DeviceCode(
    device_code="dc-" + "x" * 40,
    user_code="K7MPQR",
    verification_uri="https://a.test/verify",
    expires_at=datetime.now(UTC) + timedelta(minutes=15),
    display_handle=HANDLE,
    qr_secret=b"\x07" * 32,
)
STATE_URL = f"/verify/state?d={HANDLE}"
SERVER_QR_SRC = f"/verify/qr.svg?d={HANDLE}"


def link_at(offset_seconds: float) -> str:
    """A real app link, cut for the slot ``offset_seconds`` after a fixed epoch."""
    return app_link(SETTINGS, CODE, 1_790_000_000.0 + offset_seconds)


def pending_page() -> str:
    return render_page("pending", CODE, link_at(0))


def scanned_page() -> str:
    return render_page("scanned", CODE, None)


# The /verify/state answers a test can script, as the harness reads them.


def pending(link: str) -> dict[str, Any]:
    return {"status": 200, "body": {"status": "pending", "app_link": link}}


SCANNED: dict[str, Any] = {"status": 200, "body": {"status": "scanned"}}
CLOSED: dict[str, Any] = {"status": 404, "body": {"status": "closed"}}
TOO_MANY: dict[str, Any] = {"status": 429, "body": {"error": "rate_limited"}}
HANG: dict[str, Any] = {"hang": True}
FAILURES: dict[str, dict[str, Any]] = {
    "500": {"status": 500, "raw": "Internal Server Error"},
    "503": {"status": 503, "raw": ""},
    "network error": {"network": True},
    "malformed 200": {"status": 200, "raw": '{"status": "pend'},
    "unexpected 403": {"status": 403, "body": {"status": "closed"}},
    "unknown status 200": {"status": 200, "body": {"status": "weird"}},
    "null body 200": {"status": 200, "body": None},
}


class _Page(HTMLParser):
    """The ``<body>`` attributes and the direct children of ``<main>``.

    Refuses anything nested inside those children, because the harness would
    silently drop it.
    """

    VOID = frozenset({"img", "br", "hr", "input", "meta", "link"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.body: dict[str, str] = {}
        self.main: list[dict[str, Any]] = []
        self.scripts: list[str] = []
        self._in_main = False
        self._open: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        if tag == "script":
            self.scripts.append(attributes.get("src", ""))
        elif tag == "body":
            self.body = attributes
        elif tag == "main":
            self._in_main = True
        elif self._in_main:
            if self._open is not None:
                raise AssertionError(f"<{tag}> nested in a <main> child: not modelled")
            element: dict[str, Any] = {"tag": tag, "attributes": attributes, "text": ""}
            self.main.append(element)
            if tag not in self.VOID:
                self._open = element

    def handle_endtag(self, tag: str) -> None:
        if tag == "main":
            self._in_main = False
        elif self._open is not None and tag == self._open["tag"]:
            self._open = None

    def handle_data(self, data: str) -> None:
        if self._open is not None:
            self._open["text"] += data


class Browser:
    """One page in one V8 isolate, driven from the test."""

    def __init__(self, racer: MiniRacer) -> None:
        self._racer = racer
        self._racer.eval(HARNESS)

    def load(self, html: str, *, force_script: bool = False) -> None:
        """Build the DOM from ``html`` and run ``verify.js`` if the page asks for it."""
        page = _Page()
        page.feed(html)
        page.close()
        payload = json.dumps({"body": {"attributes": page.body}, "main": page.main})
        self._racer.eval(f"__harness.load({payload})")
        # Runs the script after the DOM is built, which is what `defer` gives;
        # tests/test_verify_page.py asserts the page's script tag carries it.
        if "/verify.js" in page.scripts or force_script:
            self._racer.eval(VERIFY_JS.decode("utf-8"))

    def script(self, *entries: dict[str, Any]) -> None:
        self._racer.eval(f"__harness.script({json.dumps(list(entries))})")

    def now(self) -> int:
        return int(self._call("now"))

    def at(self) -> int:
        """The clock as an offset from page load."""
        return self.now() - START

    def advance(self, ms: int) -> None:
        """Move the clock ``ms`` forward, firing each timer due on the way as its
        own task."""
        target = self.now() + ms
        for _ in range(10_000):
            if not self._racer.eval(f"__harness.runNextDue({target})"):
                return
        raise AssertionError("more than 10000 timers fired in one advance")

    def advance_to_next_fetch(self, limit_ms: int = 120_000) -> dict[str, Any]:
        """Fire timers one at a time until the script starts a fetch."""
        before = len(self.fetches())
        target = self.now() + limit_ms
        while len(self.fetches()) == before:
            if not self._racer.eval(f"__harness.runNextDue({target})"):
                raise AssertionError(f"no fetch within {limit_ms} ms")
        return self.fetches()[-1]

    def set_visibility(self, state: str) -> None:
        self._racer.eval(f"__harness.setVisibility({json.dumps(state)})")

    def fetches(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = self._call("fetches")
        return result

    def fetch_times(self) -> list[int]:
        return [int(f["at"]) - START for f in self.fetches()]

    def timers(self) -> list[int]:
        """Each pending timer's remaining wait, in ms."""
        return sorted(int(t["in"]) for t in self._call("timers"))

    def main_ids(self) -> list[str]:
        """The ids of ``<main>``'s children, in document order; ``""`` for the h1."""
        dom = self._call("dom")
        main = dom["children"][0]
        return [str(child["id"]) for child in main["children"]]

    def element(self, element_id: str) -> dict[str, Any] | None:
        dom = self._call("dom")
        for child in dom["children"][0]["children"]:
            if child["id"] == element_id:
                found: dict[str, Any] = child
                return found
        return None

    def text(self, element_id: str) -> str:
        element = self.element(element_id)
        assert element is not None, f"#{element_id} is not in the document"
        return str(element["text"])

    def attribute(self, element_id: str, name: str) -> str:
        element = self.element(element_id)
        assert element is not None, f"#{element_id} is not in the document"
        return str(element["attributes"][name])

    def listeners(self, event_type: str) -> int:
        return int(self._racer.execute(f"__harness.listenerCount({json.dumps(event_type)})"))

    def unscripted(self) -> int:
        return int(self._call("unscripted"))

    def remaining(self) -> int:
        return int(self._call("remaining"))

    def real_timers(self) -> int:
        """Timers set on mini-racer's own wall-clock ``setTimeout``, which the
        harness replaces. Anything here escaped the virtual clock."""
        return int(self._racer.execute("__timer_manager.pending.size"))

    def _call(self, name: str) -> Any:
        return self._racer.execute(f"__harness.{name}()")


class OpenPage(Protocol):
    def __call__(self, html: str, *, force_script: bool = False) -> Browser: ...


@pytest.fixture()
def open_page() -> Iterator[OpenPage]:
    """Open a page in a fresh isolate. On teardown, every fetch the script
    made had a scripted answer and nothing used a real timer."""
    opened: list[Browser] = []
    with MiniRacer() as racer:

        def open_(html: str, *, force_script: bool = False) -> Browser:
            assert not opened, "one page per test"
            browser = Browser(racer)
            browser.load(html, force_script=force_script)
            opened.append(browser)
            return browser

        yield open_
        for browser in opened:
            assert browser.unscripted() == 0, "the script fetched more than was scripted"
            assert browser.remaining() == 0, "the script fetched less than was scripted"
            assert browser.real_timers() == 0


def assert_token_shown(browser: Browser) -> None:
    assert browser.main_ids() == ["", "pairing-code", "qr", "app-link", "instruction"]


def assert_token_gone(browser: Browser) -> None:
    ids = browser.main_ids()
    assert "qr" not in ids
    assert "app-link" not in ids


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def test_the_harness_builds_the_page_the_server_renders(open_page: OpenPage) -> None:
    browser = open_page(pending_page())

    assert_token_shown(browser)
    assert browser.text("pairing-code") == "K7M-PQR"
    assert browser.attribute("qr", "src") == SERVER_QR_SRC
    assert browser.attribute("app-link", "href") == link_at(0)
    assert browser.text("instruction") == PENDING_TEXT


def test_the_first_poll_is_two_seconds_after_load(open_page: OpenPage) -> None:
    browser = open_page(pending_page())

    assert browser.timers() == [2000]
    browser.advance(1999)
    assert browser.fetches() == []

    browser.script(pending(link_at(2)))
    browser.advance(1)
    assert browser.fetch_times() == [2000]


def test_a_page_with_no_handle_runs_nothing(open_page: OpenPage) -> None:
    """The closed page carries no script tag; forced to run anyway, the script
    finds no ``data-handle`` and returns before it schedules or listens."""
    browser = open_page(render_page("closed", None, None), force_script=True)

    assert browser.timers() == []
    assert browser.listeners("visibilitychange") == 0
    browser.advance(60_000)
    assert browser.fetches() == []


# ---------------------------------------------------------------------------
# pending 200
# ---------------------------------------------------------------------------


def test_a_pending_answer_refreshes_the_qr_and_the_app_link(open_page: OpenPage) -> None:
    browser = open_page(pending_page())
    browser.script(pending(link_at(2)), pending(link_at(4)))

    browser.advance(2000)

    (first,) = browser.fetches()
    assert first["url"] == STATE_URL
    assert first["cache"] == "no-store"
    assert first["credentials"] == "same-origin"
    assert first["hasSignal"] is True
    assert first["aborted"] is False
    assert browser.attribute("qr", "src") == f"{SERVER_QR_SRC}&t={START + 2000}"
    assert browser.attribute("app-link", "href") == link_at(2)
    assert browser.text("instruction") == PENDING_TEXT
    assert browser.timers() == [2000], "the next poll, and no deadline left behind"

    browser.advance(2000)

    assert browser.attribute("qr", "src") == f"{SERVER_QR_SRC}&t={START + 4000}"
    assert browser.attribute("app-link", "href") == link_at(4)
    assert_token_shown(browser)


# ---------------------------------------------------------------------------
# 429
# ---------------------------------------------------------------------------


def test_429_doubles_the_delay_up_to_thirty_seconds_and_a_200_resets_it(
    open_page: OpenPage,
) -> None:
    browser = open_page(pending_page())
    browser.script(*[TOO_MANY] * 6, pending(link_at(120)), pending(link_at(122)))

    browser.advance(122_000)

    times = browser.fetch_times()
    assert times == [2000, 6000, 14000, 30000, 60000, 90000, 120000, 122000]
    gaps = [b - a for a, b in zip(times, times[1:], strict=False)]
    assert gaps == [4000, 8000, 16000, 30000, 30000, 30000, 2000]


def test_a_429_takes_the_token_down_once_it_would_be_stale_and_a_200_restores_it(
    open_page: OpenPage,
) -> None:
    """Age from the last pending 200 plus the next wait: 2000 + 4000 is not
    past 10000, 6000 + 8000 is."""
    browser = open_page(pending_page())
    browser.script(TOO_MANY, TOO_MANY, pending(link_at(14)))

    browser.advance_to_next_fetch()
    assert browser.at() == 2000
    assert_token_shown(browser)
    assert browser.text("instruction") == PENDING_TEXT
    assert browser.timers() == [4000]

    browser.advance_to_next_fetch()
    assert browser.at() == 6000
    assert_token_gone(browser)
    assert browser.text("instruction") == BACKING_OFF_TEXT
    assert browser.element("pairing-code") is not None
    assert browser.timers() == [8000]

    browser.advance_to_next_fetch()
    assert browser.at() == 14000
    assert_token_shown(browser)
    assert browser.text("instruction") == PENDING_TEXT
    assert browser.attribute("qr", "src") == f"{SERVER_QR_SRC}&t={START + 14000}"
    assert browser.attribute("app-link", "href") == link_at(14)


def test_a_failure_takes_the_token_down_with_the_retrying_text_and_a_200_restores_it(
    open_page: OpenPage,
) -> None:
    """The 429 stretches the delay to 4000. The first 500 lands at age 6000,
    and 6000 + 4000 is not past 10000; the second at 10000 is."""
    browser = open_page(pending_page())
    browser.script(TOO_MANY, FAILURES["500"], FAILURES["500"], pending(link_at(14)))

    browser.advance_to_next_fetch()
    browser.advance_to_next_fetch()
    assert browser.at() == 6000
    assert_token_shown(browser)
    assert browser.text("instruction") == PENDING_TEXT

    browser.advance_to_next_fetch()
    assert browser.at() == 10000
    assert_token_gone(browser)
    assert browser.text("instruction") == RETRYING_TEXT
    assert browser.timers() == [4000], "a failure keeps the current delay"

    browser.advance_to_next_fetch()
    assert browser.at() == 14000
    assert_token_shown(browser)
    assert browser.text("instruction") == PENDING_TEXT
    assert browser.attribute("app-link", "href") == link_at(14)


# ---------------------------------------------------------------------------
# scanned 200
# ---------------------------------------------------------------------------


def test_a_scanned_answer_removes_the_token_and_shows_the_compare_instruction(
    open_page: OpenPage,
) -> None:
    browser = open_page(pending_page())
    browser.script(SCANNED)

    browser.advance(2000)

    assert browser.main_ids() == ["", "pairing-code", "instruction"]
    assert browser.text("instruction") == SCANNED_TEXT
    assert browser.text("pairing-code") == "K7M-PQR"
    assert browser.timers() == [2000], "scanned keeps polling"


def test_after_a_scan_429s_and_failures_leave_the_compare_instruction(
    open_page: OpenPage,
) -> None:
    """Delays grow to 30 s, far past the stale threshold, and there is still
    nothing to take down."""
    browser = open_page(pending_page())
    browser.script(SCANNED, *[TOO_MANY] * 4, FAILURES["500"], FAILURES["network error"])

    browser.advance_to_next_fetch()
    for _ in range(6):
        browser.advance_to_next_fetch()
        assert browser.text("instruction") == SCANNED_TEXT
        assert browser.main_ids() == ["", "pairing-code", "instruction"]

    assert browser.fetch_times() == [2000, 4000, 8000, 16000, 32000, 62000, 92000]
    assert browser.timers() == [30000]


def test_a_page_rendered_scanned_keeps_its_instruction_through_429s_and_failures(
    open_page: OpenPage,
) -> None:
    browser = open_page(scanned_page())
    assert browser.main_ids() == ["", "pairing-code", "instruction"]
    browser.script(*[TOO_MANY] * 3, FAILURES["503"])

    for _ in range(4):
        browser.advance_to_next_fetch()
        assert browser.text("instruction") == SCANNED_TEXT

    assert browser.main_ids() == ["", "pairing-code", "instruction"]
    assert browser.timers() == [16000]


# ---------------------------------------------------------------------------
# Failures and giving up
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", list(FAILURES))
def test_five_consecutive_failures_give_up_and_leave_no_timers(
    open_page: OpenPage, kind: str
) -> None:
    browser = open_page(pending_page())
    browser.script(*[FAILURES[kind]] * 5)

    for _ in range(4):
        browser.advance_to_next_fetch()
    assert browser.at() == 8000
    assert browser.text("instruction") == PENDING_TEXT
    assert_token_shown(browser)  # 8000 + 2000 is not past 10000
    assert browser.timers() == [2000]

    browser.advance_to_next_fetch()

    assert browser.at() == 10000
    assert browser.text("instruction") == GAVE_UP_TEXT
    assert_token_gone(browser)
    assert browser.element("pairing-code") is not None
    assert browser.timers() == []
    browser.advance(600_000)
    browser.set_visibility("hidden")
    browser.set_visibility("visible")
    assert len(browser.fetches()) == 5, "stopped for good, visibility included"


def test_five_different_failures_in_a_row_give_up(open_page: OpenPage) -> None:
    browser = open_page(pending_page())
    kinds = ["500", "network error", "malformed 200", "unexpected 403", "unknown status 200"]
    browser.script(*(FAILURES[kind] for kind in kinds))

    browser.advance(10_000)

    assert len(browser.fetches()) == 5
    assert browser.text("instruction") == GAVE_UP_TEXT
    assert browser.timers() == []


def test_unrecognised_200s_take_a_stale_token_down_and_give_up(open_page: OpenPage) -> None:
    """A 200 that is neither pending nor scanned refreshes nothing, so it must
    count as a failure: otherwise a run of them keeps a token on the page past
    the 10 s every token is guaranteed. The 429 stretches the first wait so the
    token goes stale before the fifth failure."""
    browser = open_page(pending_page())
    browser.script(TOO_MANY, *[FAILURES["unknown status 200"]] * 5)

    browser.advance(8000)
    assert browser.fetch_times() == [2000, 6000, 8000]
    assert_token_shown(browser)
    assert browser.text("instruction") == PENDING_TEXT

    browser.advance(2000)
    assert_token_gone(browser)
    assert browser.text("instruction") == RETRYING_TEXT, "10000 + 2000 is past 10000"

    browser.advance(4000)
    assert browser.fetch_times() == [2000, 6000, 8000, 10000, 12000, 14000]
    assert browser.text("instruction") == GAVE_UP_TEXT
    assert browser.timers() == []


def test_five_hung_fetches_are_each_aborted_at_eight_seconds_and_give_up(
    open_page: OpenPage,
) -> None:
    browser = open_page(pending_page())
    browser.script(*[HANG] * 5)

    browser.advance(2000)
    assert browser.timers() == [8000], "only the deadline while a fetch is in flight"
    browser.advance(7999)
    assert browser.fetches()[0]["aborted"] is False

    browser.advance(1)
    assert browser.fetches()[0]["aborted"] is True
    assert browser.text("instruction") == RETRYING_TEXT, "10000 + 2000 is past 10000"
    assert_token_gone(browser)
    assert browser.timers() == [2000]

    browser.advance(39_999)
    assert browser.fetch_times() == [2000, 12000, 22000, 32000, 42000]
    assert browser.text("instruction") == RETRYING_TEXT

    browser.advance(1)
    assert browser.at() == 50000
    assert [f["aborted"] for f in browser.fetches()] == [True] * 5
    assert browser.text("instruction") == GAVE_UP_TEXT
    assert browser.timers() == []


def test_a_parsed_200_resets_the_failure_count(open_page: OpenPage) -> None:
    browser = open_page(pending_page())
    browser.script(*[FAILURES["500"]] * 4, pending(link_at(10)), *[FAILURES["500"]] * 5)

    for _ in range(9):
        browser.advance_to_next_fetch()
    assert browser.text("instruction") == PENDING_TEXT, "four, a 200, then four more"
    assert browser.timers() == [2000]

    browser.advance_to_next_fetch()
    assert browser.text("instruction") == GAVE_UP_TEXT
    assert browser.timers() == []


def test_a_malformed_200_does_not_reset_the_failure_count(open_page: OpenPage) -> None:
    browser = open_page(pending_page())
    browser.script(*[FAILURES["500"]] * 4, FAILURES["malformed 200"])

    browser.advance(10_000)

    assert browser.text("instruction") == GAVE_UP_TEXT


def test_a_429_neither_adds_to_nor_resets_the_failure_count(open_page: OpenPage) -> None:
    browser = open_page(pending_page())
    browser.script(*[FAILURES["500"]] * 4, TOO_MANY, FAILURES["500"])

    for _ in range(5):
        browser.advance_to_next_fetch()
    assert browser.text("instruction") == BACKING_OFF_TEXT, "the 429 counted nothing"
    assert browser.timers() == [4000]

    browser.advance_to_next_fetch()
    assert browser.text("instruction") == GAVE_UP_TEXT
    assert browser.timers() == []


# ---------------------------------------------------------------------------
# Visibility
# ---------------------------------------------------------------------------


def test_a_hidden_tab_clears_the_timer_and_does_not_poll(open_page: OpenPage) -> None:
    browser = open_page(pending_page())

    browser.set_visibility("hidden")

    assert browser.timers() == []
    browser.advance(120_000)
    assert browser.fetches() == []


def test_becoming_visible_polls_once_at_once_and_starts_one_loop(open_page: OpenPage) -> None:
    browser = open_page(pending_page())
    browser.script(pending(link_at(120)), pending(link_at(122)))
    browser.set_visibility("hidden")
    browser.advance(120_000)

    browser.set_visibility("visible")

    assert browser.fetch_times() == [120_000]
    assert browser.attribute("app-link", "href") == link_at(120)
    assert browser.timers() == [2000], "one loop"

    browser.set_visibility("visible")
    assert browser.fetch_times() == [120_000], "a timer is pending: no second poll"
    assert browser.timers() == [2000]

    browser.advance(2000)
    assert browser.fetch_times() == [120_000, 122_000]
    assert browser.timers() == [2000]


def test_visibility_changes_during_a_fetch_do_not_start_a_second_loop(
    open_page: OpenPage,
) -> None:
    browser = open_page(pending_page())
    browser.script(HANG, pending(link_at(10)), pending(link_at(12)))
    browser.advance(3000)
    assert browser.fetch_times() == [2000]

    browser.set_visibility("hidden")
    browser.set_visibility("visible")
    assert browser.fetch_times() == [2000], "the fetch is in flight"
    browser.set_visibility("hidden")

    browser.advance(7000)
    assert browser.fetches()[0]["aborted"] is True
    assert browser.timers() == [], "hidden: the failure schedules nothing"

    browser.set_visibility("visible")
    assert browser.fetch_times() == [2000, 10000]
    assert browser.timers() == [2000]
    browser.advance(2000)
    assert browser.fetch_times() == [2000, 10000, 12000]
    assert browser.timers() == [2000]


# ---------------------------------------------------------------------------
# 404
# ---------------------------------------------------------------------------


def test_a_404_shows_closed_and_stops(open_page: OpenPage) -> None:
    browser = open_page(pending_page())
    browser.script(CLOSED)

    browser.advance(2000)

    assert browser.main_ids() == ["", "instruction"]
    assert browser.text("instruction") == CLOSED_TEXT
    assert browser.timers() == []
    browser.advance(600_000)
    browser.set_visibility("hidden")
    browser.set_visibility("visible")
    assert len(browser.fetches()) == 1
    assert browser.remaining() == 0

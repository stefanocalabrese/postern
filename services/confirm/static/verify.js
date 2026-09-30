// The pairing page's only script. Served same-origin from /verify.js so the
// page's Content-Security-Policy needs no inline script.
//
// Every two seconds it asks /verify/state what the pairing is doing, and acts
// on the answer exactly as the page-state table in dev-docs/qr-page-spec.md
// section 4 says:
//   pending -> point the app link at the current token and reload the QR
//   scanned -> remove the QR and the app link, keep the code, keep polling
//   404     -> stop, remove the code, the QR and the link, say it is closed
//   429     -> back off, doubling from 2 s to at most 30 s, until the next 200
// fetch() of a same-origin URL sends Sec-Fetch-Site: same-origin, which is
// what the state endpoint and the image require.
//
// THREE THINGS THE TABLE DOES NOT SAY, each so the page never shows a QR that
// POST /scan would refuse:
//   - A wait longer than QR_STALE_AFTER_MS takes the QR off the page and says
//     so. A token is accepted for SLOTS_BACK slots after its own
//     (services/confirm/qr_token.py), 10 s at the least, and the back-off
//     reaches 16 s on its fourth step. The next pending 200 puts it back.
//   - MAX_FAILURES network errors or 5xx answers in a row stop polling and
//     ask for a reload. A 200 resets the count; a 429 neither adds nor resets.
//   - A hidden tab does not poll. Becoming visible polls at once, which also
//     replaces whatever token went stale while it was hidden.
(function () {
  "use strict";

  var BASE_DELAY_MS = 2000;
  var MAX_DELAY_MS = 30000;
  var QR_STALE_AFTER_MS = 10000;
  var MAX_FAILURES = 5;
  // The page's own three texts, character for character: PENDING_TEXT is put
  // back after a back-off replaced it.
  var PENDING_TEXT = "Check that the code in your app matches this one, and only continue if you started this on your own computer just now.";
  var CLOSED_TEXT = "This pairing is closed. Return to your AI client.";
  var SCANNED_TEXT = "Compare the code in your app with this one.";
  var BACKING_OFF_TEXT = "Too many requests. Retrying...";
  var GAVE_UP_TEXT = "This page lost contact with the server. Reload the page to try again.";

  var handle = document.body.getAttribute("data-handle");
  if (!handle) {
    return;
  }
  var query = "d=" + encodeURIComponent(handle);
  var delay = BASE_DELAY_MS;
  var failures = 0;
  var stopped = false;
  // True while the instruction says something other than PENDING_TEXT
  // because of a back-off, so the next pending answer knows to restore it.
  var degraded = false;
  var timer = null;
  var inFlight = false;
  // Held so a back-off can take the QR off the page and put the same element
  // back. Dropped for good once the pairing is scanned or closed.
  var qrNode = document.getElementById("qr");

  function byId(id) {
    return document.getElementById(id);
  }

  function remove(id) {
    var element = byId(id);
    if (element && element.parentNode) {
      element.parentNode.removeChild(element);
    }
  }

  function say(text) {
    var instruction = byId("instruction");
    if (instruction) {
      instruction.textContent = text;
    }
  }

  function hideQr() {
    if (qrNode && qrNode.parentNode) {
      qrNode.parentNode.removeChild(qrNode);
    }
  }

  function restoreQr() {
    if (!qrNode || qrNode.parentNode) {
      return;
    }
    var before = byId("app-link") || byId("instruction");
    if (before && before.parentNode) {
      before.parentNode.insertBefore(qrNode, before);
    }
  }

  function showPending(appLink) {
    var link = byId("app-link");
    if (link && typeof appLink === "string") {
      link.setAttribute("href", appLink);
    }
    if (qrNode) {
      qrNode.setAttribute("src", "/verify/qr.svg?" + query + "&t=" + Date.now());
      restoreQr();
    }
    if (degraded) {
      degraded = false;
      say(PENDING_TEXT);
    }
  }

  function showBackingOff() {
    degraded = true;
    hideQr();
    say(BACKING_OFF_TEXT);
  }

  function showGaveUp() {
    stopped = true;
    hideQr();
    say(GAVE_UP_TEXT);
  }

  function showScanned() {
    qrNode = null;
    remove("qr");
    remove("app-link");
    say(SCANNED_TEXT);
  }

  function showClosed() {
    stopped = true;
    qrNode = null;
    remove("qr");
    remove("app-link");
    remove("pairing-code");
    say(CLOSED_TEXT);
  }

  function schedule() {
    if (stopped || document.visibilityState === "hidden") {
      return;
    }
    timer = window.setTimeout(poll, delay);
  }

  function fail() {
    failures += 1;
    if (failures >= MAX_FAILURES) {
      showGaveUp();
    }
  }

  function poll() {
    timer = null;
    inFlight = true;
    fetch("/verify/state?" + query, { cache: "no-store", credentials: "same-origin" })
      .then(function (response) {
        if (response.status === 404) {
          showClosed();
          return null;
        }
        if (response.status === 429) {
          delay = Math.min(delay * 2, MAX_DELAY_MS);
          if (delay > QR_STALE_AFTER_MS) {
            showBackingOff();
          }
          return null;
        }
        if (response.status >= 500) {
          fail();
          return null;
        }
        if (response.status !== 200) {
          return null;
        }
        delay = BASE_DELAY_MS;
        failures = 0;
        return response.json();
      })
      .then(function (body) {
        if (!body) {
          return;
        }
        if (body.status === "pending") {
          showPending(body.app_link);
        } else if (body.status === "scanned") {
          showScanned();
        }
      })
      .catch(function () {
        // A network error or an unreadable body: neither a 404 nor a 429, so
        // keep the current delay and count it.
        fail();
      })
      .then(function () {
        inFlight = false;
        schedule();
      });
  }

  document.addEventListener("visibilitychange", function () {
    if (document.visibilityState === "hidden") {
      if (timer !== null) {
        window.clearTimeout(timer);
        timer = null;
      }
      return;
    }
    if (!stopped && timer === null && !inFlight) {
      poll();
    }
  });

  schedule();
})();

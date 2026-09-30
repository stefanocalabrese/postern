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
// WHAT THE TABLE DOES NOT SAY, each so the page never shows a token that
// POST /scan would refuse:
//   - The QR and the app link carry the same rotation token, so they are
//     shown and hidden together. A token is accepted for SLOTS_BACK slots
//     after its own (services/confirm/qr_token.py), and SLOTS_BACK *
//     SLOT_SECONDS = 5 * 2 s = 10 s is the least any token gets, so
//     QR_STALE_AFTER_MS is that 10 s and must move if either constant does.
//     Age is counted from freshAt, the last pending 200, plus the wait before
//     the next poll: when that sum passes QR_STALE_AFTER_MS on a 429 or a
//     failure, both come off the page with a message saying why. The next
//     pending 200 puts both back and restores the pending text. Once scanned
//     there is no token to take down, so a 429 or a failure leaves the compare
//     instruction alone and only reschedules; failures still count toward
//     MAX_FAILURES.
//   - Any answer but 200, 404 and 429, a network error, a body that does not
//     parse, and a fetch still unanswered after FETCH_TIMEOUT_MS are all
//     failures. MAX_FAILURES in a row stop polling and ask for a reload. Only
//     a 200 whose body parsed resets the count; a 429 neither adds nor resets.
//   - A hidden tab does not poll. Becoming visible polls at once, which also
//     replaces whatever token went stale while it was hidden.
(function () {
  "use strict";

  var BASE_DELAY_MS = 2000;
  var MAX_DELAY_MS = 30000;
  var QR_STALE_AFTER_MS = 10000;
  var MAX_FAILURES = 5;
  var FETCH_TIMEOUT_MS = 8000;
  // The page's own three texts, character for character: PENDING_TEXT is put
  // back after a back-off replaced it.
  var PENDING_TEXT = "Check that the code in your app matches this one, and only continue if you started this on your own computer just now.";
  var CLOSED_TEXT = "This pairing is closed. Return to your AI client.";
  var SCANNED_TEXT = "Compare the code in your app with this one.";
  var BACKING_OFF_TEXT = "Too many requests. Retrying...";
  var RETRYING_TEXT = "Trouble reaching the server. Retrying...";
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
  // because the token was taken down, so the next pending answer restores it.
  var degraded = false;
  var timer = null;
  var inFlight = false;
  // The page was rendered with a token cut for this moment.
  var freshAt = Date.now();
  // Held so a stale token can be taken off the page and the same two elements
  // put back. Dropped for good once the pairing is scanned or closed.
  var qrNode = document.getElementById("qr");
  var linkNode = document.getElementById("app-link");

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

  function isStale() {
    return Date.now() - freshAt + delay > QR_STALE_AFTER_MS;
  }

  function hideToken() {
    if (qrNode && qrNode.parentNode) {
      qrNode.parentNode.removeChild(qrNode);
    }
    if (linkNode && linkNode.parentNode) {
      linkNode.parentNode.removeChild(linkNode);
    }
  }

  function restoreToken() {
    var instruction = byId("instruction");
    if (!instruction || !instruction.parentNode) {
      return;
    }
    var parent = instruction.parentNode;
    if (linkNode && !linkNode.parentNode) {
      parent.insertBefore(linkNode, instruction);
    }
    if (qrNode && !qrNode.parentNode) {
      parent.insertBefore(qrNode, linkNode && linkNode.parentNode ? linkNode : instruction);
    }
  }

  function showPending(appLink) {
    if (linkNode && typeof appLink === "string") {
      linkNode.setAttribute("href", appLink);
    }
    if (qrNode) {
      qrNode.setAttribute("src", "/verify/qr.svg?" + query + "&t=" + Date.now());
    }
    freshAt = Date.now();
    restoreToken();
    if (degraded) {
      degraded = false;
      say(PENDING_TEXT);
    }
  }

  function takeDown(text) {
    // Scanned: no token is on the page, so there is nothing to take down, and
    // the compare instruction is what the user needs in front of them.
    if (qrNode === null) {
      return;
    }
    degraded = true;
    hideToken();
    say(text);
  }

  function showGaveUp() {
    stopped = true;
    hideToken();
    say(GAVE_UP_TEXT);
  }

  function showScanned() {
    qrNode = null;
    linkNode = null;
    remove("qr");
    remove("app-link");
    say(SCANNED_TEXT);
  }

  function showClosed() {
    stopped = true;
    qrNode = null;
    linkNode = null;
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
    } else if (isStale()) {
      takeDown(RETRYING_TEXT);
    }
  }

  function poll() {
    timer = null;
    inFlight = true;
    var controller = new AbortController();
    var deadline = window.setTimeout(function () {
      controller.abort();
    }, FETCH_TIMEOUT_MS);
    fetch("/verify/state?" + query, {
      cache: "no-store",
      credentials: "same-origin",
      signal: controller.signal
    })
      .then(function (response) {
        if (response.status === 404) {
          showClosed();
          return null;
        }
        if (response.status === 429) {
          delay = Math.min(delay * 2, MAX_DELAY_MS);
          if (isStale()) {
            takeDown(BACKING_OFF_TEXT);
          }
          return null;
        }
        if (response.status !== 200) {
          fail();
          return null;
        }
        delay = BASE_DELAY_MS;
        return response.json();
      })
      .then(function (body) {
        if (!body) {
          return;
        }
        failures = 0;
        if (body.status === "pending") {
          showPending(body.app_link);
        } else if (body.status === "scanned") {
          showScanned();
        }
      })
      .catch(function () {
        // A network error, the deadline's abort, or a 200 whose body did not
        // parse: neither a 404 nor a 429, so keep the current delay and count
        // it.
        fail();
      })
      .then(function () {
        window.clearTimeout(deadline);
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

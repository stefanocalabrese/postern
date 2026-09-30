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
(function () {
  "use strict";

  var BASE_DELAY_MS = 2000;
  var MAX_DELAY_MS = 30000;
  var CLOSED_TEXT = "This pairing is closed. Return to your AI client.";
  var SCANNED_TEXT = "Compare the code in your app with this one.";

  var handle = document.body.getAttribute("data-handle");
  if (!handle) {
    return;
  }
  var query = "d=" + encodeURIComponent(handle);
  var delay = BASE_DELAY_MS;
  var stopped = false;

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

  function showPending(appLink) {
    var link = byId("app-link");
    if (link && typeof appLink === "string") {
      link.setAttribute("href", appLink);
    }
    var qr = byId("qr");
    if (qr) {
      qr.setAttribute("src", "/verify/qr.svg?" + query + "&t=" + Date.now());
    }
  }

  function showScanned() {
    remove("qr");
    remove("app-link");
    say(SCANNED_TEXT);
  }

  function showClosed() {
    stopped = true;
    remove("qr");
    remove("app-link");
    remove("pairing-code");
    say(CLOSED_TEXT);
  }

  function poll() {
    fetch("/verify/state?" + query, { cache: "no-store", credentials: "same-origin" })
      .then(function (response) {
        if (response.status === 404) {
          showClosed();
          return null;
        }
        if (response.status === 429) {
          delay = Math.min(delay * 2, MAX_DELAY_MS);
          return null;
        }
        if (response.status !== 200) {
          return null;
        }
        delay = BASE_DELAY_MS;
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
        // A network error is neither a 404 nor a 429: keep the current delay
        // and try again.
      })
      .then(function () {
        if (!stopped) {
          window.setTimeout(poll, delay);
        }
      });
  }

  window.setTimeout(poll, delay);
})();

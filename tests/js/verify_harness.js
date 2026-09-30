// A fake browser for services/confirm/static/verify.js and for nothing else.
//
// tests/test_verify_js_behaviour.py evaluates this file in a bare V8 isolate
// (mini-racer), then calls __harness.load() with the page structure it parsed
// out of the HTML verify_page.render_page produced, then evaluates the real
// verify.js. Everything verify.js touches outside the language is defined
// here, and each is a stand-in, not an implementation:
//
//   document      getElementById over connected elements, body.getAttribute,
//                 visibilityState, addEventListener("visibilitychange").
//   elements      tag, id, attributes, textContent, parentNode, and the three
//                 tree operations the script calls: removeChild, insertBefore
//                 and (for building) appendChild. No layout, no events, no
//                 image loading: an <img> src change is an attribute write.
//   the clock     Date.now() and window.setTimeout/clearTimeout read a
//                 virtual time that moves only when the test calls
//                 __harness.runNextDue(). The Date constructor stays real and
//                 the script never calls it.
//   fetch         Answers from a queue the test scripts, in order, and
//                 records every call. A response is resolved at once, in the
//                 microtask queue, where a browser would take at least a task.
//   AbortController  abort() flags the signal and fires its listeners
//                 synchronously; a hung fetch rejects with an AbortError on it.
//
// THE TEST DRIVES THE EVENT LOOP. runNextDue fires at most one timer per call,
// and each call is one mini-racer eval, after which V8 drains the microtask
// queue. So each timer callback is a task and every promise chain it starts
// settles before the next timer fires, which is the ordering a browser gives
// the script. Firing several timers inside one eval would not.
var __harness = (function (global) {
  "use strict";

  var now = 1000000;
  var timers = [];
  var nextTimerId = 1;
  var nextSeq = 0;
  var responses = [];
  var fetches = [];
  var unscripted = 0;
  var listeners = {};

  // ---- elements -----------------------------------------------------------

  function Element(tag, attributes, text) {
    this.tagName = tag.toUpperCase();
    this.attributes = {};
    this.textContent = text || "";
    this.parentNode = null;
    this.children = [];
    var names = Object.keys(attributes || {});
    for (var i = 0; i < names.length; i++) {
      this.attributes[names[i]] = String(attributes[names[i]]);
    }
  }

  Element.prototype.getAttribute = function (name) {
    return Object.prototype.hasOwnProperty.call(this.attributes, name)
      ? this.attributes[name]
      : null;
  };

  Element.prototype.setAttribute = function (name, value) {
    this.attributes[name] = String(value);
  };

  Element.prototype.appendChild = function (child) {
    return this.insertBefore(child, null);
  };

  Element.prototype.removeChild = function (child) {
    var index = this.children.indexOf(child);
    if (index < 0) {
      throw new Error("NotFoundError: removeChild of a node that is not a child");
    }
    this.children.splice(index, 1);
    child.parentNode = null;
    return child;
  };

  Element.prototype.insertBefore = function (child, reference) {
    if (reference !== null && reference.parentNode !== this) {
      throw new Error("NotFoundError: insertBefore a node that is not a child");
    }
    if (child.parentNode) {
      child.parentNode.removeChild(child);
    }
    var index = reference === null ? this.children.length : this.children.indexOf(reference);
    this.children.splice(index, 0, child);
    child.parentNode = this;
    return child;
  };

  Object.defineProperty(Element.prototype, "id", {
    get: function () {
      return this.getAttribute("id") || "";
    }
  });

  function findById(element, id) {
    if (element.id === id) {
      return element;
    }
    for (var i = 0; i < element.children.length; i++) {
      var found = findById(element.children[i], id);
      if (found) {
        return found;
      }
    }
    return null;
  }

  var document = {
    body: null,
    visibilityState: "visible",
    getElementById: function (id) {
      return document.body ? findById(document.body, id) : null;
    },
    addEventListener: function (type, listener) {
      (listeners[type] = listeners[type] || []).push(listener);
    }
  };

  // ---- the clock ----------------------------------------------------------

  global.Date.now = function () {
    return now;
  };

  function setTimeoutFake(callback, delay) {
    var id = nextTimerId++;
    timers.push({ id: id, due: now + Math.max(0, Number(delay) || 0), seq: nextSeq++, fn: callback });
    return id;
  }

  function clearTimeoutFake(id) {
    timers = timers.filter(function (timer) {
      return timer.id !== id;
    });
  }

  // ---- fetch and AbortController -------------------------------------------

  function AbortSignalFake() {
    this.aborted = false;
    this._listeners = [];
  }

  AbortSignalFake.prototype.addEventListener = function (type, listener) {
    if (type === "abort") {
      this._listeners.push(listener);
    }
  };

  function AbortControllerFake() {
    this.signal = new AbortSignalFake();
  }

  AbortControllerFake.prototype.abort = function () {
    var signal = this.signal;
    if (signal.aborted) {
      return;
    }
    signal.aborted = true;
    for (var i = 0; i < signal._listeners.length; i++) {
      signal._listeners[i]();
    }
  };

  function abortError() {
    var error = new Error("The operation was aborted.");
    error.name = "AbortError";
    return error;
  }

  function responseFor(entry) {
    var text = "raw" in entry ? entry.raw : JSON.stringify(entry.body === undefined ? null : entry.body);
    return {
      status: entry.status,
      ok: entry.status >= 200 && entry.status < 300,
      json: function () {
        try {
          return Promise.resolve(JSON.parse(text));
        } catch (error) {
          return Promise.reject(error);
        }
      }
    };
  }

  function fetchFake(url, init) {
    var signal = init && init.signal;
    var record = {
      url: String(url),
      at: now,
      cache: init ? init.cache : undefined,
      credentials: init ? init.credentials : undefined,
      hasSignal: !!signal,
      signal: signal || null
    };
    fetches.push(record);
    var entry = responses.shift();
    if (entry === undefined) {
      unscripted += 1;
      entry = { hang: true };
    }
    if (entry.network) {
      return Promise.reject(new TypeError("Failed to fetch"));
    }
    if (entry.hang) {
      return new Promise(function (resolve, reject) {
        if (signal) {
          signal.addEventListener("abort", function () {
            reject(abortError());
          });
        }
      });
    }
    return Promise.resolve(responseFor(entry));
  }

  // ---- the globals the script sees ----------------------------------------

  global.window = global;
  global.document = document;
  global.setTimeout = setTimeoutFake;
  global.clearTimeout = clearTimeoutFake;
  global.fetch = fetchFake;
  global.AbortController = AbortControllerFake;

  // ---- what the test calls ------------------------------------------------

  function describe(element) {
    return {
      tag: element.tagName.toLowerCase(),
      id: element.id,
      attributes: element.attributes,
      text: element.textContent,
      children: element.children.map(describe)
    };
  }

  return {
    // page: {body: {attributes}, main: [{tag, attributes, text}, ...]}
    load: function (page) {
      var body = new Element("body", page.body.attributes, "");
      var main = new Element("main", {}, "");
      body.appendChild(main);
      for (var i = 0; i < page.main.length; i++) {
        var child = page.main[i];
        main.appendChild(new Element(child.tag, child.attributes, child.text));
      }
      document.body = body;
    },
    script: function (entries) {
      for (var i = 0; i < entries.length; i++) {
        responses.push(entries[i]);
      }
    },
    // Fire the earliest timer due at or before `until`, moving the clock to
    // it, and return true; with none due, move the clock to `until` and
    // return false. Ties fire in the order they were set.
    runNextDue: function (until) {
      var next = null;
      for (var i = 0; i < timers.length; i++) {
        var timer = timers[i];
        if (timer.due <= until && (next === null || timer.due < next.due || (timer.due === next.due && timer.seq < next.seq))) {
          next = timer;
        }
      }
      if (next === null) {
        if (until > now) {
          now = until;
        }
        return false;
      }
      clearTimeoutFake(next.id);
      if (next.due > now) {
        now = next.due;
      }
      next.fn();
      return true;
    },
    setVisibility: function (state) {
      document.visibilityState = state;
      var handlers = (listeners.visibilitychange || []).slice();
      for (var i = 0; i < handlers.length; i++) {
        handlers[i].call(document, { type: "visibilitychange" });
      }
    },
    now: function () {
      return now;
    },
    timers: function () {
      return timers.map(function (timer) {
        return { id: timer.id, in: timer.due - now };
      });
    },
    fetches: function () {
      return fetches.map(function (record) {
        return {
          url: record.url,
          at: record.at,
          cache: record.cache,
          credentials: record.credentials,
          hasSignal: record.hasSignal,
          aborted: record.signal ? record.signal.aborted : null
        };
      });
    },
    unscripted: function () {
      return unscripted;
    },
    remaining: function () {
      return responses.length;
    },
    listenerCount: function (type) {
      return (listeners[type] || []).length;
    },
    dom: function () {
      return document.body ? describe(document.body) : null;
    }
  };
})(globalThis);

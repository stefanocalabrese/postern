# 0002: Header/body validation middleware -- known deviations and adversarial findings

**Date:** 2026-09-12

## Question

Task 5 implements the spec's mandatory control: "Servers that process the
request body MUST reject requests where the values specified in the headers
do not match the corresponding values in the request body", HTTP 400,
JSON-RPC `-32020`. This runs as ASGI middleware, not FastMCP middleware
(`docs/decisions/` has no separate record for that half of the decision; it is
the "Version traps" entry in `CLAUDE.md` and the plan's Task 5 preamble).
`services/api/asgi/header_validation.py` implements it. This record covers two
kinds of gap: known deviations from the spec's full scope, and findings from
an adversarial pass run against the implementation before it was committed.

## Known deviations from spec scope

- **Base64 sentinel header values are not decoded.** The spec allows a client
  to send certain header values Base64-encoded as a "sentinel" to avoid
  leaking the real value to intermediaries. This implementation compares raw
  values only, so a client using sentinel encoding would be rejected as a
  mismatch. Close it in Plan 4 alongside the client allowlist, when the set of
  clients is known.
- **`Mcp-Param-{Name}` headers are not validated.** The spec defines these,
  projected from a tool's `inputSchema` via `x-mcp-header`. No tool in this
  plan uses `x-mcp-header`, so there is nothing to validate yet. Revisit if a
  tool adopts it.

## Adversarial pass

Run against the plan's own code before it was committed, per the instruction
that passing the plan's ten tests is not sufficient for a request-smuggling
control. Every finding below has a regression test in
`tests/test_header_body_mismatch.py`. Fixed and reported-only findings are
both listed; fixing was explicitly optional per finding, verification was not.

### Fixed

1. **Duplicate `Mcp-Method`/`Mcp-Name` headers were silently resolved to the
   last occurrence, which is the exact smuggling shape this control exists to
   close.** `scope["headers"]` is a list; the plan's `_headers` built a
   `dict`, which keeps the last of a repeated key. A request with
   `Mcp-Method: tools/list` followed by `Mcp-Method: tools/call` -- where an
   upstream load balancer routes on the first occurrence and this middleware
   validated the last -- passed as a match under the plan's code, because the
   surviving value happened to agree with the body. Reproduced against the
   plan's implementation before the fix (`test_duplicate_mcp_method_header_is_rejected_even_if_last_value_matches`
   failed with `assert 200 == 400`). Fixed: `_headers` now groups every
   occurrence per lower-cased name into a list; `_single` returns
   `(value, is_duplicate)`, and any duplicate of `Mcp-Method` or `Mcp-Name` is
   rejected outright with `-32020`, regardless of whether any individual
   occurrence would have matched the body. Header NAME matching stays
   case-insensitive per RFC 9110 5.1 (`MCP-METHOD` and `Mcp-Method` are the
   same header, and a repeat under a different casing is still a repeat, not
   two independent headers).

2. **A header value containing an invalid UTF-8 byte crashed the middleware.**
   The plan's `_headers` decoded header bytes with the default UTF-8 codec.
   `scope["headers"]` values carry no encoding guarantee -- Starlette's own
   `Headers` datastructure decodes them as latin-1 for exactly this reason
   (`starlette/datastructures.py`, every `.decode("latin-1")` call on header
   bytes). A value such as `b"\xff\xfe"` raised `UnicodeDecodeError` under
   UTF-8 decoding, an unhandled exception inside a control whose entire job is
   to reject cleanly with 400; an unhandled exception is not a documented
   spec-compliant response and turns an availability property of the control
   into an attacker-triggerable failure. Confirmed directly:
   `b"\xff\xfe".decode()` raises `UnicodeDecodeError: 'utf-8' codec can't
   decode byte 0xff in position 0: invalid start byte`;
   `b"\xff\xfe".decode("latin-1")` succeeds for any byte 0-255. Fixed: both
   header names and values now decode as latin-1, matching Starlette's own
   convention.

3. **Nothing upstream of this middleware bounds request body size.** The
   drain buffers the entire body into memory before any check runs. Neither
   uvicorn, Starlette, nor FastMCP imposes a body size limit by default; this
   is a real denial-of-service surface on what may be an internet-facing
   edge, not a theoretical one. This project has no basis for choosing the
   number a given deployment's edge should own -- that depends on
   infrastructure (WAF, load balancer, CDN limits) not specified anywhere in
   this repository, and guessing one would violate this project's own rule
   against asserting unverified external facts. Implemented the mechanism
   without guessing the number: `HeaderBodyValidation(app, max_body_bytes=...)`
   is opt-in and defaults to `None` (unbounded, i.e. unchanged from the
   plan's behaviour). When set, `_drain` raises as soon as the running total
   crosses the cap -- it does not finish buffering an oversized body first --
   and the middleware responds `413` without invoking the downstream app.
   **Recommendation:** the deployment (or a future task that owns edge
   configuration) must set `max_body_bytes` to a value derived from the
   actual tool surface's largest legitimate request body, not left at the
   unbounded default, once that number is known.

### Reported, not fixed

4. **A JSON object with a duplicate top-level key (e.g. two `"method"`
   fields) is resolved by Python's parser to the last occurrence.** RFC 8259
   4: "the behaviour of software that receives JSON text containing duplicate
   [object member] names is unpredictable." A component elsewhere in the
   request path that parses the same body with a first-wins JSON parser would
   validate a different `method` (or a different `params.name` /
   `params.uri`, since the same ambiguity applies inside nested objects) than
   this middleware did -- the same desynchronisation class as finding 1, one
   level deeper, inside the body rather than between header and body. Not
   fixed: there was no instruction to reject it (unlike the header case), and
   a fix raises a question this task does not have the information to answer
   -- whether a duplicate key inside an arbitrary tool's own `arguments`
   object (unrelated to the two fields this control validates) should also
   fail closed. That is a broader JSON-parsing-strictness decision, not a
   header/body consistency one. `test_duplicate_method_key_in_json_body_is_resolved_to_the_last_occurrence`
   pins the current behaviour so a future change is deliberate, not silent.

5. **This middleware does not strip whitespace from header values itself.**
   A header value with leading whitespace (`" tools/call"`) compares unequal
   to the clean body value and is rejected as a mismatch. In production this
   input should not occur: RFC 9110 5.5 requires a compliant HTTP/1.1 parser
   (h11, underlying uvicorn) to strip leading/trailing OWS around a header
   field value before it ever reaches `scope["headers"]`. Not fixed, because
   this middleware only controls its own input, not the ASGI server's
   conformance, and adding independent stripping would be defending against
   an input the transport layer is already responsible for normalizing --
   this record exists so that assumption is written down rather than
   implicit.

6. **A NUL byte or an embedded newline in a header value does not crash the
   middleware and fails closed.** Both decode cleanly (as latin-1, and as
   UTF-8 too, since both are single-byte ASCII code points) and simply fail
   to equal the clean body value, producing the ordinary mismatch rejection.
   No fix needed; recorded as a confirmed-safe finding, not a silent gap.

7. **A JSON body that is a top-level array is not a legitimate batch under
   2026-07-28, but does not crash this middleware.** `_parse` only accepts a
   JSON object; an array returns `None` from `_parse`, so `_check` returns
   `None` (no problem found) and the array is passed through unvalidated to
   the MCP layer, which is responsible for rejecting a batch shape it does
   not support. This middleware's job is header/body consistency, not
   request-shape validation, so passing an unvalidatable body through is the
   same behaviour as the plan's own `test_unparseable_body_is_left_to_the_mcp_layer`.

8. **The rejection response's `error.data` field does not leak anything
   beyond the two values it compares.** That field contains attacker-supplied
   input on both sides -- the header value and the body value it was
   compared against -- reflected back to the same caller that sent them, so
   this is not a disclosure of anything the server holds. Confirmed with a
   regression test that embeds an unrelated, secret-shaped value inside
   `params.arguments` in the body and asserts it is absent from the 400
   response body: `test_rejection_response_leaks_nothing_but_the_two_compared_values`.
   No other field of the request (the tool name is not in this control's
   comparison unless it is the specific `Mcp-Name`/`params.name` pair being
   checked; `arguments` is never read by this middleware) can reach the
   response, because `_check` only ever returns a string built from
   `header_method`, `method`, `header_name`, `expected` and the two literal
   header names -- nothing else from the parsed payload is referenced.

9. **Wiring through the real stack.** The plan's own tests exercise
   `HeaderBodyValidation` directly against a fake downstream ASGI app.
   Verified separately, through the actual installation path: `build_server`
   (Task 4) produces a `FastMCP` instance, `server.http_app(path="/mcp",
   middleware=[Middleware(HeaderBodyValidation, strict=...)])` wraps it, and a
   real request against that stack gets a real `400` with `-32020` --
   `test_real_stack_returns_a_genuine_400_through_build_server_and_http_app`.
   `httpx` is not installed in this project (`docs/decisions/0001-facade-http-client.md`);
   this test uses `httpx2.ASGITransport`, which mirrors `httpx.ASGITransport`'s
   API and is already this project's HTTP stack, so no new dependency was
   added for it.

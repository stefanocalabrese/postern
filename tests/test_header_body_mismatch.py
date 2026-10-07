import json
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from services.api.asgi.header_validation import HeaderBodyValidation


async def _call(app: ASGIApp, headers: dict[str, str], body: bytes) -> list[Message]:
    scope: Scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "server": ("test", 80),
        "client": ("test", 1234),
    }
    pending: list[Message] = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[Message] = []

    async def receive() -> Message:
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


def _downstream(seen: list[bytes]) -> ASGIApp:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        body = b""
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        seen.append(body)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    return app


def _status(sent: list[Message]) -> int:
    return int(next(m["status"] for m in sent if m["type"] == "http.response.start"))


def _json(sent: list[Message]) -> dict[str, Any]:
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    result: dict[str, Any] = json.loads(raw)
    return result


CALL = json.dumps(
    {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {"name": "accounts.list", "arguments": {}},
    }
).encode()


async def test_matching_headers_pass_through_with_body_intact() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, CALL)
    assert _status(sent) == 200
    assert seen == [CALL]


async def test_method_mismatch_is_rejected_with_400_and_32020() -> None:
    app = HeaderBodyValidation(_downstream([]))
    sent = await _call(app, {"Mcp-Method": "tools/list", "Mcp-Name": "accounts.list"}, CALL)
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020


async def test_name_mismatch_is_rejected_with_400_and_32020() -> None:
    app = HeaderBodyValidation(_downstream([]))
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "payments.create"}, CALL)
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020


async def test_rejection_echoes_the_request_id() -> None:
    app = HeaderBodyValidation(_downstream([]))
    sent = await _call(app, {"Mcp-Method": "tools/list", "Mcp-Name": "accounts.list"}, CALL)
    assert _json(sent)["id"] == 7


async def test_downstream_never_runs_on_mismatch() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    await _call(app, {"Mcp-Method": "tools/list", "Mcp-Name": "accounts.list"}, CALL)
    assert seen == []


async def test_missing_headers_pass_when_not_strict() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen), strict=False)
    sent = await _call(app, {}, CALL)
    assert _status(sent) == 200
    assert seen == [CALL]


async def test_missing_headers_are_rejected_when_strict() -> None:
    app = HeaderBodyValidation(_downstream([]), strict=True)
    sent = await _call(app, {}, CALL)
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020


async def test_resources_read_matches_on_uri_not_name() -> None:
    seen: list[bytes] = []
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "resources/read",
            "params": {"uri": "postern://errors"},
        }
    ).encode()
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "resources/read", "Mcp-Name": "postern://errors"}, body)
    assert _status(sent) == 200


async def test_unparseable_body_is_refused_with_a_parse_error() -> None:
    """Refused HERE, not left to FastMCP: a second parser that reads a body this
    one cannot is a parser difference, and a parser difference is what a
    request-smuggling shape needs. HTTP 400 with JSON-RPC -32700, id null."""
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "tools/call"}, b"not json")
    assert _status(sent) == 400
    assert _json(sent) == {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": -32700, "message": "Parse error"},
    }
    assert seen == []


async def test_non_post_requests_are_ignored() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    scope_get: Scope = {"type": "http", "method": "GET", "path": "/health", "headers": []}
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    async def receive() -> Message:
        return {"type": "http.request", "body": b"", "more_body": False}

    await app(scope_get, receive, send)
    assert _status(sent) == 200


# --- Adversarial pass ------------------------------------------------------


async def _call_raw(
    app: ASGIApp, header_pairs: list[tuple[str, str]], body: bytes
) -> list[Message]:
    """Like `_call`, but takes a raw list of (name, value) pairs so a header
    can be repeated -- a plain `dict[str, str]` cannot represent that.
    """
    scope: Scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(k.encode(), v.encode()) for k, v in header_pairs],
        "server": ("test", 80),
        "client": ("test", 1234),
    }
    pending: list[Message] = [{"type": "http.request", "body": body, "more_body": False}]
    sent: list[Message] = []

    async def receive() -> Message:
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


async def test_non_utf8_body_does_not_crash_and_is_refused_with_a_parse_error() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    body = b"\xff\xfe\x00\x01not-utf8"
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, body)
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32700
    assert seen == []


async def test_json_array_body_is_not_a_batch_and_does_not_crash() -> None:
    """2026-07-28 sends one message per POST, so a top-level array is not a
    legitimate batch; `_parse` only accepts a dict and returns `None`
    otherwise, so this is left to the MCP layer, same as any other JSON body
    this middleware has no `method` to compare in. It must not crash on the way there.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    body = json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "tools/call"}]).encode()
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, body)
    assert _status(sent) == 200
    assert seen == [body]


async def test_duplicate_method_key_in_json_body_is_resolved_to_the_last_occurrence() -> None:
    """Documents current behaviour, does not change it. `json.loads` silently
    keeps the LAST of a repeated top-level key (RFC 8259 4: "the behaviour of
    software that receives JSON text containing duplicate names is
    unpredictable"). A component elsewhere in the chain that parses the same
    body with a first-wins JSON parser would validate a different `method`
    than this middleware did -- the same desynchronisation class as the
    duplicate-header finding above, but one nesting level down, inside the
    body rather than between header and body. Not fixed here: unlike the
    header case, there is no explicit instruction to reject it, and doing so
    would need a decision about what counts as a legitimate duplicate inside
    an arbitrary tool's own `arguments` object, which is out of scope for a
    header/body consistency check. Recorded as a finding in
    dev-docs/decisions/0002-header-validation.md.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    body = (
        b'{"jsonrpc":"2.0","id":1,"method":"tools/list",'
        b'"method":"tools/call","params":{"name":"accounts.list"}}'
    )
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, body)
    assert _status(sent) == 200
    assert seen == [body]


async def test_duplicate_mcp_method_header_is_rejected_even_if_last_value_matches() -> None:
    """`scope["headers"]` is a list; an upstream load balancer may route on the
    FIRST occurrence of a repeated header while a dict-based validator (the
    plan's `_headers` keeps the LAST) validates a different one. That
    divergence is exactly the request-smuggling shape -32020 exists to close,
    so any repeat of Mcp-Method must be rejected outright, regardless of
    whether the surviving value happens to match the body.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call_raw(
        app,
        [
            ("mcp-method", "tools/list"),
            ("mcp-method", "tools/call"),
            ("mcp-name", "accounts.list"),
        ],
        CALL,
    )
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020
    assert seen == []


async def test_duplicate_mcp_name_header_is_rejected() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call_raw(
        app,
        [
            ("mcp-method", "tools/call"),
            ("mcp-name", "payments.create"),
            ("mcp-name", "accounts.list"),
        ],
        CALL,
    )
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020
    assert seen == []


async def _call_chunks(app: ASGIApp, headers: dict[str, str], chunks: list[bytes]) -> list[Message]:
    """Like `_call`, but delivers the body across several `http.request`
    messages, `more_body=True` on all but the last -- how a real ASGI server
    delivers a body too large for one read.
    """
    scope: Scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "server": ("test", 80),
        "client": ("test", 1234),
    }
    pending: list[Message] = [
        {"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1}
        for i, chunk in enumerate(chunks)
    ]
    sent: list[Message] = []

    async def receive() -> Message:
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent


async def test_real_stack_returns_a_genuine_400_through_build_server_and_http_app() -> None:
    """Verifies the middleware wired the way it will actually be installed:
    `mcp.http_app(path="/mcp", middleware=[Middleware(HeaderBodyValidation, ...)])`
    on top of Task 4's `build_server`, driven through a real ASGI transport
    rather than the fake downstream app the rest of this file uses. `httpx`
    is not installed in this project (see dev-docs/decisions/0001-facade-http-client.md);
    this uses `httpx2.ASGITransport`, which mirrors `httpx.ASGITransport` and
    is already this project's HTTP stack.
    """
    import httpx2
    from starlette.middleware import Middleware

    from services.api.server import build_server
    from services.api.settings import Settings
    from tests.conftest import TEST_CUSTOMER

    server = build_server(Settings.for_testing(), resolver=lambda: TEST_CUSTOMER, backend=None)
    app = server.http_app(path="/mcp", middleware=[Middleware(HeaderBodyValidation, strict=False)])

    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/mcp",
            headers={
                "Mcp-Method": "tools/list",
                "Mcp-Name": "accounts.list",
                "Accept": "application/json, text/event-stream",
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "accounts.list", "arguments": {}},
            },
        )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == -32020


async def test_rejection_response_leaks_nothing_but_the_two_compared_values() -> None:
    """The `data` field in the 400 response is attacker-supplied on both
    sides -- the header and the body it was compared against -- reflected
    back to the SAME caller who sent them, so this is not a disclosure of
    anything the server holds. This test pins the stronger property: no
    other part of the request body (an unrelated `arguments` field, in
    particular) can reach the rejection response.
    """
    canary_value = "arg_super_secret_value_zzz"
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {"name": "payments.create", "arguments": {"note": canary_value}},
        }
    ).encode()
    app = HeaderBodyValidation(_downstream([]))
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, body)
    assert _status(sent) == 400
    raw = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    assert canary_value.encode() not in raw
    assert b"arguments" not in raw
    assert b"note" not in raw
    parsed = json.loads(raw)
    assert set(parsed["error"]["data"].split()) <= {
        "Mcp-Name",
        "does",
        "not",
        "match",
        "body",
        "name",
        "'payments.create'",
        "'accounts.list'",
    }


async def test_header_value_comparison_is_case_sensitive() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "Tools/Call", "Mcp-Name": "accounts.list"}, CALL)
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020
    assert seen == []


async def test_header_name_matching_is_case_insensitive() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call_raw(app, [("MCP-METHOD", "tools/call"), ("Mcp-Name", "accounts.list")], CALL)
    assert _status(sent) == 200
    assert seen == [CALL]


async def test_leading_whitespace_in_header_value_causes_a_mismatch() -> None:
    """This middleware does not strip whitespace itself. A compliant HTTP
    server (uvicorn/h11) already strips leading/trailing OWS from a header
    value per RFC 9110 5.5 before `scope["headers"]` is populated, so this
    input should never reach production code; this test only pins the
    middleware's own behaviour on a raw scope, which is the only input it
    actually controls.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call_raw(
        app, [("mcp-method", " tools/call"), ("mcp-name", "accounts.list")], CALL
    )
    assert _status(sent) == 400
    assert seen == []


async def test_header_value_with_nul_byte_does_not_crash_and_fails_closed() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call_raw(
        app, [("mcp-method", "tools/call\x00"), ("mcp-name", "accounts.list")], CALL
    )
    assert _status(sent) == 400
    assert seen == []


async def test_header_value_with_embedded_newline_does_not_crash() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call_raw(
        app, [("mcp-method", "tools/call\ninjected: x"), ("mcp-name", "accounts.list")], CALL
    )
    assert _status(sent) == 400
    assert seen == []


async def test_header_value_with_invalid_utf8_byte_does_not_crash() -> None:
    """`scope["headers"]` values are opaque bytes with no UTF-8 guarantee
    (Starlette's own `Headers` datastructure decodes as latin-1 for exactly
    this reason). The plan's original `_headers` decoded with the UTF-8
    default and would raise `UnicodeDecodeError` -- an unhandled crash inside
    a security control -- on a value like `b"\\xff"`. Fixed by decoding as
    latin-1, which accepts every byte 0-255.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    scope: Scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"mcp-method", b"tools/call"), (b"mcp-name", b"\xff\xfe")],
        "server": ("test", 80),
        "client": ("test", 1234),
    }
    pending: list[Message] = [{"type": "http.request", "body": CALL, "more_body": False}]
    sent: list[Message] = []

    async def receive() -> Message:
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)  # must not raise
    assert _status(sent) == 400
    assert seen == []


async def test_body_split_across_multiple_asgi_messages_is_reassembled_byte_identical() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    chunks = [CALL[:5], CALL[5:20], CALL[20:]]
    headers = {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}
    sent = await _call_chunks(app, headers, chunks)
    assert _status(sent) == 200
    assert seen == [CALL]


async def test_zero_length_body_is_refused_as_a_parse_error() -> None:
    """An empty body is not JSON; it is refused here like any other, and not
    left to a second parser."""
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen), strict=False)
    sent = await _call(app, {}, b"")
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32700
    assert seen == []


async def test_disconnect_mid_drain_does_not_crash_and_the_partial_body_is_refused() -> None:
    """A client can disconnect before sending the rest of the body. The drain
    loop must not raise, and whatever was collected before the disconnect is
    what is parsed: a truncated JSON document, so it is refused with a parse
    error and never replayed.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    scope: Scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(b"mcp-method", b"tools/call"), (b"mcp-name", b"accounts.list")],
        "server": ("test", 80),
        "client": ("test", 1234),
    }
    pending: list[Message] = [
        {"type": "http.request", "body": CALL[:5], "more_body": True},
        {"type": "http.disconnect"},
    ]
    sent: list[Message] = []

    async def receive() -> Message:
        return pending.pop(0) if pending else {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)  # must not raise
    assert seen == []
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32700


async def test_body_exceeding_configured_cap_is_rejected_with_413_and_stops_buffering() -> None:
    """Nothing upstream of this middleware bounds request body size (see
    dev-docs/decisions/0002-header-validation.md): the drain buffers the whole
    body into memory before any check runs. `max_body_bytes` is opt-in and
    unset by default -- this project has no basis for guessing the number a
    given deployment's edge should own -- but when a deployment does set it,
    the drain must stop as soon as the cap is crossed rather than finish
    buffering an arbitrarily large body first.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen), max_body_bytes=8)
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, CALL)
    assert _status(sent) == 413
    assert seen == []


async def test_default_max_body_bytes_is_unbounded_matching_prior_behaviour() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, CALL)
    assert _status(sent) == 200
    assert seen == [CALL]


async def test_replay_receive_keeps_returning_disconnect_after_the_body_is_exhausted() -> None:
    """ASGI spec: after a `receive()` callable has delivered the full body, a
    downstream app is allowed to call it again and must keep getting
    `http.disconnect`, not an exception or a repeat of the body.
    """
    from services.api.asgi.header_validation import _replay

    receive = _replay(b"hello")
    assert await receive() == {"type": "http.request", "body": b"hello", "more_body": False}
    assert await receive() == {"type": "http.disconnect"}
    assert await receive() == {"type": "http.disconnect"}


async def test_duplicate_header_detected_regardless_of_name_casing() -> None:
    """Header NAMES are case-insensitive (RFC 9110 5.1); 'Mcp-Method' and
    'MCP-METHOD' are the same header repeated, not two different ones.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call_raw(
        app,
        [("Mcp-Method", "tools/call"), ("MCP-METHOD", "tools/call"), ("mcp-name", "accounts.list")],
        CALL,
    )
    assert _status(sent) == 400
    assert _json(sent)["error"]["code"] == -32020
    assert seen == []


# --- The drain, and the two defects the write path fixed first ------------
#
# `0743101` closed both of these on `services/confirm/body_limit.py`. This
# section is the read path's half. The two middlewares are not the same
# control -- this one owes an HTTP 400 with JSON-RPC -32020 on a header/body
# mismatch and that one owes nothing of the sort -- so what is ported is the
# accumulator shape and the exception tuple, not the module.


class _Counted:
    """A `receive` handing `body` over `chunk` bytes at a time, counting what
    the application actually pulled.

    That count is what every claim below is about and it is the one number a
    client cannot observe: an HTTP client hands the whole body to a transport
    and the transport decides what to deliver. So these drive raw ASGI.
    """

    def __init__(self, body: bytes, chunk: int = 1 << 16) -> None:
        self.body = body
        self.chunk = chunk
        self.taken = 0
        self.calls = 0
        self._pos = 0
        self._done = False

    async def __call__(self) -> Message:
        self.calls += 1
        if self._done:
            return {"type": "http.disconnect"}
        end = min(self._pos + self.chunk, len(self.body))
        piece = self.body[self._pos : end]
        self._pos = end
        self.taken += len(piece)
        more = self._pos < len(self.body)
        if not more:
            self._done = True
        return {"type": "http.request", "body": piece, "more_body": more}


async def _drive(
    app: ASGIApp, headers: dict[str, str], receive: _Counted
) -> tuple[list[Message], _Counted]:
    scope: Scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/mcp",
        "raw_path": b"/mcp",
        "query_string": b"",
        "root_path": "",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
        "server": ("test", 80),
        "client": ("test", 1234),
        "state": {},
    }
    sent: list[Message] = []

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)
    return sent, receive


def test_the_drain_accumulates_into_a_list_and_never_with_bytes_concatenation() -> None:
    """Defect 1, pinned structurally.

    `_drain` accumulated with `body += chunk`, which reallocates and copies
    the whole accumulated body once per chunk: O(n^2) in the chunk count, and
    one `http.request` message per byte is a shape the caller picks. Measured
    head to head on 2026-09-24, both unbounded so the accumulator was the only
    difference -- 262,144 B: 0.494s vs 0.037s; 524,288 B: 1.736s vs 0.076s;
    1,048,576 B: 7.421s vs 0.152s; 2,097,152 B: 29.086s vs 0.308s. Through the
    real assembled app at the 1,048,576-byte default cap, one byte per
    message: 7.581s before, 0.237s after.

    A timing assertion would police the machine rather than the code, so what
    is checked is the shape, exactly as
    `tests/test_confirm_body_limit.py::test_the_drain_accumulates_into_a_list_and_never_with_bytes_concatenation`
    checks it for the write path: the only augmented assignment in `_drain` is
    the integer counter, and the bytes are joined exactly once.
    """
    import ast
    import inspect

    from services.api.asgi.header_validation import _drain

    tree = ast.parse(inspect.getsource(_drain))

    augmented = {
        node.target.id
        for node in ast.walk(tree)
        if isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name)
    }
    assert augmented == {"total"}, f"only the integer counter may use +=, found {augmented}"

    appends = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "append"
    ]
    joins = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
    ]
    assert len(appends) == 1, "the chunks go into a list, one append per chunk"
    assert len(joins) == 1, "and are joined exactly once, at the end"


async def test_the_drain_is_linear_in_the_number_of_chunks() -> None:
    """The behavioural half of the assertion above, and it catches shapes the
    AST guard cannot -- `chunks.append(b"".join(chunks) + chunk)` uses a list,
    one append and one join, and is still quadratic.

    The sizes and the bound are chosen so this can actually fail, which cost a
    measurement. A quadratic accumulator costs 4x per doubling and a linear
    one 2x, so 8x the bytes at one byte per message separates them by 8x in
    theory. Measured both shapes head to head on 2026-09-24 at 32,768 then
    262,144 bytes: quadratic 0.0105s then 0.5394s, a growth of 51.3x; linear
    0.0051s then 0.0416s, a growth of 8.2x. The bound asserted is 25x, which
    leaves 3x of headroom over the linear measurement and stays 2x under the
    quadratic one.

    The obvious 4x-the-bytes version of this test does NOT discriminate:
    quadratic grows 17.2x there, under the 40x bound
    `tests/test_confirm_body_limit.py::test_the_drain_is_linear_in_the_number_of_chunks`
    asserts, so that test passes against a reintroduced `body += chunk`. Only
    the AST guard catches it on the write path.
    """
    import resource

    from services.api.asgi.header_validation import _drain

    def cpu() -> float:
        usage = resource.getrusage(resource.RUSAGE_SELF)
        return usage.ru_utime + usage.ru_stime

    timings: list[float] = []
    for size in (32_768, 262_144):
        started = cpu()
        await _drain(_Counted(b"x" * size, 1), size + 1)
        timings.append(cpu() - started)

    growth = timings[1] / max(timings[0], 1e-6)
    assert growth < 25.0, f"8x the chunks cost {growth:.1f}x the time"


async def test_the_drain_stops_at_the_cap_instead_of_reading_the_whole_body() -> None:
    """The anti-amplification half of `max_body_bytes`, measured in bytes
    pulled rather than in the status code.

    `test_body_exceeding_configured_cap_is_rejected_with_413_and_stops_buffering`
    above delivers its body in one message, so the `stops_buffering` in its
    name is not actually observable there. Here the body arrives one byte at a
    time, so what the drain refused to read is countable: it costs the cap
    plus the one byte that crossed it, not the 8 KiB offered.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen), max_body_bytes=1024)
    sent, receive = await _drive(app, {}, _Counted(b"x" * 8192, 1))
    assert _status(sent) == 413
    assert seen == []
    assert receive.taken == 1025, f"pulled {receive.taken:,} bytes for a cap of 1,024"


async def test_the_cap_boundary_is_exact() -> None:
    """A body of exactly `max_body_bytes` is allowed; one byte more is not."""
    for size, expected in ((63, 200), (64, 200), (65, 413)):
        seen: list[bytes] = []
        app = HeaderBodyValidation(_downstream(seen), max_body_bytes=64)
        # A JSON string of exactly `size` bytes: valid JSON that is not an
        # object, which passes through; arbitrary bytes would be refused as
        # unparseable and would hide the cap.
        body = b'"' + b"x" * (size - 2) + b'"'
        sent, _ = await _drive(app, {}, _Counted(body, 1))
        assert _status(sent) == expected, f"{size} bytes against a cap of 64"
        assert seen == ([body] if expected == 200 else [])


DEEP = b"[" * 200_000


async def test_a_deeply_nested_body_does_not_escape_the_middleware() -> None:
    """Defect 2.

    `json.loads` raises `RecursionError` on a deeply nested body, and that is
    a `RuntimeError` subclass, so `except (ValueError, UnicodeDecodeError)`
    missed it and it left this middleware as an exception. Measured against
    the real assembled app on 2026-09-24: 200,000 bytes -- under the
    1,048,576-byte cap, and one `b"["` per level -- produced
    `500 Internal Server Error` and a logged traceback out of Starlette's
    `ServerErrorMiddleware`, which wraps `user_middleware` and is therefore
    outside this control. `services/confirm/callback.py` had the same escape
    and `0743101` closed it.

    What it produces instead is a 400 with -32700 from this middleware: a
    body it cannot parse is refused here and never handed to another parser
    (see `_parse`'s docstring). The body goes downstream only when it parsed.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, DEEP)
    assert _status(sent) == 400
    assert _json(sent)["error"] == {"code": -32700, "message": "Parse error"}
    assert seen == []


async def test_a_deeply_nested_body_behaves_identically_under_strict_headers() -> None:
    """`strict` does not reach this body, in either direction.

    `_parse` raises before either `if self.strict` branch, so an unparseable
    body is refused whether or not strict mode is on. Recorded because the
    fixes had to be checked against the flag, not because the flag should
    change: it defaults
    to `False` in `services/api/settings.py` and `docker-compose.yml` ships
    `"0"`, so a fix that only held under `strict=True` would not hold in the
    configuration that actually ships.
    """
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen), strict=True)
    sent = await _call(app, {}, DEEP)
    assert _status(sent) == 400
    assert _json(sent)["error"] == {"code": -32700, "message": "Parse error"}
    assert seen == []


async def test_a_deeply_nested_body_is_refused_by_the_middleware_with_32700() -> None:
    """The refusal is the middleware's own, at the depth where it stops parsing.

    Until 2026-10-07 `_parse` returned `None` for a body it could not read and
    this test pinned that the layer below gave up at the same depth. That was a
    fact about a parser in another package, and it did not survive contact with
    a second one (see `tests/test_strict_json_sites.py`, the integer-digit
    limit): now every body this middleware cannot parse strictly is answered
    here, and what is pinned is that the answer is the middleware's, identified
    by its fixed message "Parse error" and not FastMCP's detailed one, at the
    BOUNDARY as well as at the gross case. The depth is searched for rather
    than written down: on CPython 3.12.13 the `_json` C scanner stops at 9,997
    nested arrays, an interpreter constant this test has no business hardcoding.

    `raise_app_exceptions` is left at its default `True`, so a `RecursionError`
    escaping the middleware again propagates here and fails the test loudly
    rather than arriving as a quiet 500.
    """
    import httpx2
    from starlette.middleware import Middleware

    from services.api.asgi.header_validation import _parse, _Unparseable
    from services.api.server import build_server
    from services.api.settings import Settings
    from tests.conftest import TEST_CUSTOMER

    def body_at(depth: int) -> bytes:
        nested = "[" * depth + "]" * depth
        return (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
            '{"name":"accounts.list","arguments":{"x":' + nested + "},"
            '"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",'
            '"io.modelcontextprotocol/clientCapabilities":{}}}}'
        ).encode()

    def declined(body: bytes) -> bool:
        try:
            _parse(body)
        except _Unparseable:
            return True
        return False

    low, high = 1, 100_000
    assert not declined(body_at(low)), "the search must start from a body that parses"
    assert declined(body_at(high)), f"_parse still reads {high:,} levels; widen the search"
    while low < high - 1:
        middle = (low + high) // 2
        if declined(body_at(middle)):
            high = middle
        else:
            low = middle
    boundary = body_at(high)

    settings = Settings.for_testing()
    assert len(boundary) < settings.max_body_bytes, "this must be about defect 2, not the cap"
    assert len(DEEP) < settings.max_body_bytes, "and so must the gross case above"

    server = build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)
    app = server.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        middleware=[
            Middleware(
                HeaderBodyValidation,
                strict=settings.strict_headers,
                max_body_bytes=settings.max_body_bytes,
            )
        ],
    )

    transport = httpx2.ASGITransport(app=app)
    async with httpx2.AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            answers = []
            for content in (boundary, DEEP):
                response = await client.post(
                    "/mcp",
                    headers={
                        "Mcp-Method": "tools/call",
                        "Mcp-Name": "accounts.list",
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                        "MCP-Protocol-Version": "2026-07-28",
                    },
                    content=content,
                )
                answers.append((response.status_code, response.json()))

    for status, payload in answers:
        assert status == 400, payload
        assert payload["error"] == {"code": -32700, "message": "Parse error"}, payload


async def test_a_chunked_matching_request_is_replayed_in_a_shape_the_dispatcher_reads() -> None:
    """The replay is the read path's obligation that the write path's limiter
    shares, and the only way to know the shape is right is to make the real
    dispatcher read it.

    The body arrives one byte per `http.request` message -- 60 messages for a
    60-byte `tools/list` -- and `_replay` hands it downstream as ONE message.
    FastMCP's dispatcher parses the reassembled bytes and answers about their
    CONTENTS, echoing the id it found in them, which is what proves the
    reassembly and not merely that a 200 came back.
    """
    from starlette.middleware import Middleware

    from services.api.server import build_server
    from services.api.settings import Settings
    from tests.conftest import TEST_CUSTOMER

    settings = Settings.for_testing()
    server = build_server(settings, resolver=lambda: TEST_CUSTOMER, backend=None)
    app = server.http_app(
        path="/mcp",
        stateless_http=True,
        json_response=True,
        middleware=[
            Middleware(
                HeaderBodyValidation,
                strict=settings.strict_headers,
                max_body_bytes=settings.max_body_bytes,
            )
        ],
    )
    body = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                }
            },
        }
    ).encode()
    headers = {
        "Mcp-Method": "tools/list",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "MCP-Protocol-Version": "2026-07-28",
    }
    receive = _Counted(body, 1)
    async with app.router.lifespan_context(app):
        sent, _ = await _drive(app, headers, receive)

    assert receive.calls >= len(body), "the body must actually arrive one byte at a time"
    assert _status(sent) == 200
    answer = _json(sent)
    assert answer["id"] == 41, answer
    assert "result" in answer, answer

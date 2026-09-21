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


async def test_unparseable_body_is_left_to_the_mcp_layer() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    sent = await _call(app, {"Mcp-Method": "tools/call"}, b"not json")
    assert _status(sent) == 200


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


async def test_non_utf8_body_does_not_crash_and_is_left_to_the_mcp_layer() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen))
    body = b"\xff\xfe\x00\x01not-utf8"
    sent = await _call(app, {"Mcp-Method": "tools/call", "Mcp-Name": "accounts.list"}, body)
    assert _status(sent) == 200
    assert seen == [body]


async def test_json_array_body_is_not_a_batch_and_does_not_crash() -> None:
    """2026-07-28 sends one message per POST, so a top-level array is not a
    legitimate batch; `_parse` only accepts a dict and returns `None`
    otherwise, so this is left to the MCP layer, same as any other body this
    middleware cannot validate. It must not crash on the way there.
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


async def test_zero_length_body_passes_through_unchanged() -> None:
    seen: list[bytes] = []
    app = HeaderBodyValidation(_downstream(seen), strict=False)
    sent = await _call(app, {}, b"")
    assert _status(sent) == 200
    assert seen == [b""]


async def test_disconnect_mid_drain_does_not_crash_and_downstream_gets_the_partial_body() -> None:
    """A client can disconnect before sending the rest of the body. The drain
    loop must not raise, and whatever was collected before the disconnect is
    what gets replayed -- there is nothing else to replay.
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
    assert seen == [CALL[:5]]


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

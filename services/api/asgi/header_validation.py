"""Header/body validation (MCP 2026-07-28 Streamable HTTP, handoff §3.3).

The spec: "Servers that process the request body MUST reject requests where the
values specified in the headers do not match the corresponding values in the
request body", returning HTTP 400 with JSON-RPC -32020. A load balancer routing
on a header while the server executes on the body is a request-smuggling shape.

This runs as ASGI middleware rather than FastMCP middleware because a FastMCP
ToolError is returned as CallToolResult(is_error=True) inside an HTTP 200, and
FastMCP exposes no way to set the HTTP status from a tool or hook.
"""

import json
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

HEADER_MISMATCH = -32020

_NAME_FROM_PARAM = {"tools/call": "name", "prompts/get": "name", "resources/read": "uri"}


class HeaderBodyValidation:
    def __init__(
        self,
        app: ASGIApp,
        *,
        strict: bool = False,
        max_body_bytes: int | None = None,
    ) -> None:
        """
        `max_body_bytes` bounds how much of the request body this middleware
        will buffer before rejecting with 413. It defaults to `None`
        (unbounded), matching the behaviour before this parameter existed:
        nothing else in this stack (uvicorn, Starlette, FastMCP) imposes a
        request body size limit, so an unset cap is a real denial-of-service
        surface, not a theoretical one -- see
        dev-docs/decisions/0002-header-validation.md. This project has no basis
        for choosing that number on a deployment's behalf, so there is no
        default other than unbounded; a deployment that needs the cap must
        set it explicitly, sized to its own edge.
        """
        self.app = app
        self.strict = strict
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        try:
            body = await _drain(receive, self.max_body_bytes)
        except _BodyTooLarge:
            await _reject_too_large(send)
            return
        problem = self._check(_headers(scope), body)
        if problem is not None:
            await _reject(problem, body, scope, send)
            return
        await self.app(scope, _replay(body), send)

    def _check(self, headers: dict[str, list[str]], body: bytes) -> str | None:
        payload = _parse(body)
        if payload is None:
            return None

        method = payload.get("method")
        if not isinstance(method, str):
            return None

        header_method, duplicate = _single(headers, "mcp-method")
        if duplicate:
            return "Mcp-Method header repeated with conflicting values"
        if header_method is None:
            if self.strict:
                return "missing required Mcp-Method header"
        elif header_method != method:
            return f"Mcp-Method {header_method!r} does not match body method {method!r}"

        param = _NAME_FROM_PARAM.get(method)
        if param is None:
            return None

        params = payload.get("params")
        expected = params.get(param) if isinstance(params, dict) else None
        if not isinstance(expected, str):
            return None

        header_name, duplicate = _single(headers, "mcp-name")
        if duplicate:
            return "Mcp-Name header repeated with conflicting values"
        if header_name is None:
            if self.strict:
                return "missing required Mcp-Name header"
            return None
        if header_name != expected:
            return f"Mcp-Name {header_name!r} does not match body {param} {expected!r}"
        return None


def _headers(scope: Scope) -> dict[str, list[str]]:
    """Group header values by lower-cased name, keeping every occurrence.

    `scope["headers"]` is a list, not a mapping: a client (or a smuggled
    request) can repeat a header name. Collapsing straight to a `dict` here
    would silently pick one occurrence -- the exact desynchronisation this
    control exists to prevent, since an upstream load balancer may have
    routed on a *different* occurrence. Values are decoded as latin-1, not
    UTF-8: `scope["headers"]` values are opaque bytes with no encoding
    guarantee (Starlette's own `Headers` datastructure decodes the same way),
    and a strict UTF-8 decode would raise `UnicodeDecodeError` -- an
    unhandled crash inside a security control -- on a header value that
    merely contains a raw high-bit byte.
    """
    values: dict[str, list[str]] = {}
    for k, v in scope.get("headers", []):
        name = k.decode("latin-1").lower()
        values.setdefault(name, []).append(v.decode("latin-1"))
    return values


def _single(headers: dict[str, list[str]], name: str) -> tuple[str | None, bool]:
    """Return `(value, is_duplicate)` for a header expected at most once."""
    matches = headers.get(name)
    if not matches:
        return None, False
    if len(matches) > 1:
        return None, True
    return matches[0], False


def _parse(body: bytes) -> dict[str, Any] | None:
    """The body as a JSON object, or `None` when there is nothing to compare.

    `None` is not a verdict. It says this middleware could not derive the two
    values the spec has it cross-check, so it has no opinion and the body goes
    downstream unchanged. `test_unparseable_body_is_left_to_the_mcp_layer` and
    finding 7 of dev-docs/decisions/0002-header-validation.md already pin that
    for `b"not json"` and for a top-level array.

    `RecursionError` IS NAMED HERE BECAUSE `json.loads` RAISES IT, and it is a
    `RuntimeError` subclass that `except (ValueError, UnicodeDecodeError)` does
    not catch. Measured against the real assembled app on 2026-09-24, before
    this line named it: `b"[" * 200_000` -- 200,000 bytes, under a
    `max_body_bytes` of 1,048,576, and cheap to send -- left this middleware
    as an exception, reached Starlette's `ServerErrorMiddleware` (which wraps
    `user_middleware` and is therefore OUTSIDE this control), and produced
    `500 Internal Server Error` plus a logged traceback out of a control whose
    entire job is to refuse cleanly. `services/confirm/callback.py` had the
    same escape on the write path and `0743101` closed it; this is the read
    path's half, and `tests/test_confirm_body_limit.py`'s docstring for
    `30,000 nested arrays` names this function as the one that would still
    miss it.

    IT RETURNS `None` RATHER THAN REJECTING, which is the part that was a
    decision and not a port. The write path answers 400 for the same body
    because `services/confirm/callback.py` is the component that would
    otherwise execute on it. This middleware is not: FastMCP's dispatcher sits
    behind it and parses the same bytes itself. Measured through the real
    stack on 2026-09-24, the passed-through body gets `400` with JSON-RPC
    `-32700` "Parse error" -- the code that exists for precisely this, from
    the layer that owns JSON-RPC error semantics. Two reasons to leave it
    there:

    1. Both parses give up at the same depth, so nothing this function
       declines can go on to execute. That is measured, not assumed, and the
       mechanism is why it is stable: on CPython 3.12.13 the `_json` C scanner
       spends a C-stack budget of its own, not Python frames. Measured here,
       the ceiling is 9,997 nested arrays and it does not move --
       `sys.setrecursionlimit(100)` and `sys.setrecursionlimit(20_000)` both
       leave it at 9,997, and so do 500 and 900 extra Python frames under the
       call. So this middleware's position in the stack, which is outside the
       dispatcher, buys the dispatcher no headroom this function did not also
       have. Through the real assembled app the two thresholds coincide
       exactly: an `arguments` value nested 9,990 deep is cross-checked here
       and answered by the tool layer; 9,991 deep is passed through
       uncross-checked and answered `-32700`.
    2. Rejecting would need this control to own a code for "too deeply
       nested". It owns exactly one, `-32020` "Header mismatch", and that
       would be a false statement about a request whose headers were never
       compared to anything.

    Reason 1 is load-bearing and it is a fact about a parser in another
    package, so it is pinned rather than trusted:
    `test_a_deeply_nested_body_is_refused_by_the_mcp_layer_with_32700` finds
    the shallowest body this function declines and drives THAT through the
    real stack, so it fails if a future parser downstream ever accepts what
    this one rejects.
    """
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return payload if isinstance(payload, dict) else None


class _BodyTooLarge(Exception):
    """Raised by `_drain` once the buffered body crosses `max_body_bytes`."""


async def _drain(receive: Receive, max_body_bytes: int | None = None) -> bytes:
    """Read at most `max_body_bytes`, or raise `_BodyTooLarge`.

    STOPS AT THE CAP. The `raise` leaves the loop on the chunk that crossed
    it, so the rest of the caller's body is never pulled off the wire: against
    the 1,048,576-byte default, a 2 MiB body costs 1,048,577 bytes and one
    more `receive`, not 2 MiB.

    `list[bytes]` PLUS A RUNNING `int`, JOINED ONCE, and that is a measurement
    rather than a style preference. `body += chunk` reallocates and copies the
    whole accumulated body per chunk, which is O(n^2) in the chunk count, and
    one `http.request` message per byte is a shape a caller picks freely.
    Measured head to head on 2026-09-24, both unbounded so the accumulator was
    the only difference -- 262,144 B: 0.494s vs 0.037s; 524,288 B: 1.736s vs
    0.076s; 1,048,576 B: 7.421s vs 0.152s; 2,097,152 B: 29.086s vs 0.308s. The
    left column quadruples per doubling and the right one doubles. At the cap
    that was 7.4 CPU-seconds an unauthenticated caller could buy per request,
    spent here, before any auth, consent, store or backend work -- and
    `RequestDeadline` bounds how long that runs (101s) without making it
    cheaper. `services/confirm/body_limit.py::_drain` carries the same shape
    for the write path; `test_the_drain_accumulates_into_a_list_and_never_with_bytes_concatenation`
    pins it structurally here, as its counterpart does there.
    """
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message["type"] != "http.request":
            # `http.disconnect`, and anything else a server may send. The body
            # ends here; what has been read is what there is.
            break
        chunk: bytes = message.get("body", b"")
        if chunk:
            total += len(chunk)
            if max_body_bytes is not None and total > max_body_bytes:
                raise _BodyTooLarge(total)
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _replay(body: bytes) -> Receive:
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


async def _reject_too_large(send: Send) -> None:
    raw = json.dumps({"error": "request body exceeds the configured limit"}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": raw})


async def _reject(problem: str, body: bytes, scope: Scope, send: Send) -> None:
    payload = _parse(body) or {}
    request_id = payload.get("id")
    error = {
        "jsonrpc": "2.0",
        "id": request_id if isinstance(request_id, (str, int)) else None,
        "error": {"code": HEADER_MISMATCH, "message": "Header mismatch", "data": problem},
    }
    raw = json.dumps(error).encode()
    await send(
        {
            "type": "http.response.start",
            "status": 400,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(raw)).encode()),
            ],
        }
    )
    await send({"type": "http.response.body", "body": raw})

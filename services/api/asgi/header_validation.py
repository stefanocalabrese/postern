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

from postern_core.json_strict import loads_finite_utf8
from postern_core.unstorable import contains_unstorable_character
from starlette.types import ASGIApp, Message, Receive, Scope, Send

HEADER_MISMATCH = -32020
PARSE_ERROR = -32700

MAX_WALK_NODES = 1_000_000

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
        try:
            problem = self._check(_headers(scope), body)
        except _Unparseable:
            await _reject_parse_error(send)
            return
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


class _Unparseable(Exception):
    """The body cannot be read as JSON by the strict parser; `__call__` refuses it."""


def _parse(body: bytes) -> dict[str, Any] | None:
    """The body as a JSON object, `None` when it is JSON but not an object, and
    `_Unparseable` when the strict parser cannot read it at all.

    `None` is not a verdict. A top-level array, string or number parsed fine and
    has no `method` to compare, so the body goes downstream unchanged, as
    finding 7 of dev-docs/decisions/0002-header-validation.md records.

    EVERY BODY THE STRICT PARSER CANNOT READ IS REFUSED HERE, with HTTP 400 and
    JSON-RPC -32700, and never passed on. Until 2026-10-07 the unreadable ones
    (not JSON, not UTF-8, nested past the recursion limit) returned `None` and
    were left to FastMCP on the argument that its parser gives up at the same
    point. That argument was about a parser in another package, and it was
    false the moment the two disagreed: with `sys.set_int_max_str_digits(640)`
    (`PYTHONINTMAXSTRDIGITS=640`) the stdlib refuses a 700-digit integer, while
    FastMCP's `pydantic_core.from_json` has a limit of its own, reads it, and
    accepts `NaN`. The body then reached a tool, the backend and the audit log
    with this control's cross-check skipped. A second parser that can read what
    this one cannot makes the cross-check, and the refusal of non-finite
    numbers, decorative; so nothing this parser declines is handed to another.

    The refusals this covers, all `_Unparseable`: `json.JSONDecodeError`,
    `UnicodeDecodeError`, any other `ValueError` (an integer past the digit
    limit), `NonFiniteJsonError` (`NaN`, `Infinity`, `-Infinity`, `1e999`), and
    `RecursionError`, which is a `RuntimeError` and not a `ValueError`: 200,000
    nested arrays, under `max_body_bytes`, left this middleware as an exception
    until 2026-09-24 and produced a 500 from Starlette's `ServerErrorMiddleware`.

    THE BODY IS READ AS STRICT UTF-8 WITHOUT A BYTE-ORDER MARK
    (`loads_finite_utf8`). `json.loads(bytes)` is more lenient than its name
    suggests: it sniffs UTF-16 and UTF-32, accepts a UTF-8 BOM, and decodes raw
    CESU-8 surrogate bytes with `surrogatepass`. Until 2026-10-07 this
    docstring said non-UTF-8 bodies were refused; those were not. RFC 8259
    section 8.1 requires UTF-8 and says implementations MUST NOT add a BOM and
    MAY ignore one, so refusing a BOM is allowed and is what happens.

    A body that parses is then walked once by `_storable`: a string with U+0000
    or a surrogate, anywhere, is refused the same way (see there).

    The answer is 400 -32700 "Parse error", the code JSON-RPC defines for it,
    and not -32020, which this control owns for "Header mismatch" and would
    misstate about a request whose headers were never compared to anything.

    -32700 IS ANSWERED FOR A BODY THAT DID PARSE (the U+0000 / surrogate and
    node-cap refusals), and -32600 "Invalid Request" would describe that more
    exactly. It stays -32700 because the code is an observed contract and
    changing it would change what clients already see, not because the text
    is accurate. WHY it is a refusal at all: the audit ENTRY row is written
    before the backend is reached and cannot hold the value (PostgreSQL
    refuses U+0000, UTF-8 cannot encode a surrogate), so the call is refused
    before any side effect rather than run with no record.

    DOCUMENTED BEHAVIOUR CHANGE: a U+0000 inside an argument VALUE used to be
    stripped by `scrub_text` on its way to the audit row and the call
    succeeded. It is refused now, like the same character anywhere else in the
    body, because the walk cannot tell an argument value from a JSON-RPC `id`.

    `_reject` calls this a second time on the -32020 path, so a body that is
    refused for a header mismatch is parsed and walked twice (about 40 ms per
    MiB). Left as it is: the path is a refusal, and one parse threaded
    through `_check` would change three signatures for it.
    """
    try:
        payload = loads_finite_utf8(body)
    except (ValueError, RecursionError) as exc:
        raise _Unparseable from exc
    if not _storable(payload):
        raise _Unparseable
    return payload if isinstance(payload, dict) else None


def _storable(payload: object) -> bool:
    """False when any string in the parsed body, a key or a value at any depth,
    holds U+0000 or a surrogate code point, or the body has more than
    `MAX_WALK_NODES` nodes.

    WHY: the audit ENTRY row is written before the backend is reached and a
    failed insert fails the call closed with no row. PostgreSQL refuses U+0000
    in text and JSONB (`CharacterNotInRepertoireError`) and UTF-8 cannot encode
    a surrogate (`UnicodeEncodeError`), and both are reachable as a JSON
    escape (`"\\u0000"`, `"\\ud800"`) in a JSON-RPC `id`, which nothing scrubs.
    Refused here the call is a parse error answered before auth, like every
    other body this middleware cannot take; it never becomes a call that ends
    as a 200 with no record.

    ITERATIVE ON PURPOSE: the stdlib parser reads about 9,997 levels, and a
    recursive walk raises `RecursionError` on exactly the bodies this exists
    for. The node cap is the walk's own bound. A node costs at least two bytes
    (`0,`), so at the 1 MiB default of `max_body_bytes` a body holds about
    524,000 nodes and the cap never fires. IT DOES NOT SCALE WITH
    `max_body_bytes`: that setting is operator-chosen, and from about 1.9 MiB
    up (or with no limit set) a VALID body of more than 1,000,000 numbers is
    refused as a parse error. The constant is not derived from the setting
    because the walk's CPU bound is the point of it; raise `MAX_WALK_NODES` in
    step if a deployment sets the body limit past 1.9 MiB.
    Depth is not refused here, `scrub_tree` bounds it for the audit row.
    """
    stack: list[object] = [payload]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > MAX_WALK_NODES:
            return False
        if isinstance(node, str):
            if contains_unstorable_character(node):
                return False
        elif isinstance(node, dict):
            for key, value in node.items():
                visited += 1
                if contains_unstorable_character(key):
                    return False
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
    return True


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


async def _reject_parse_error(send: Send) -> None:
    """HTTP 400 with JSON-RPC -32700, the answer FastMCP gives a body that is not JSON.

    Same status, code and `id: null` as the dispatcher's own, without the
    parser's detail text: the detail of a refused number is not a thing a
    caller needs.
    """
    raw = json.dumps(
        {"jsonrpc": "2.0", "id": None, "error": {"code": PARSE_ERROR, "message": "Parse error"}}
    ).encode()
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

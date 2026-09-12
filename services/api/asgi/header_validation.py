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
        docs/decisions/0002-header-validation.md. This project has no basis
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
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


class _BodyTooLarge(Exception):
    """Raised by `_drain` once the buffered body crosses `max_body_bytes`."""


async def _drain(receive: Receive, max_body_bytes: int | None = None) -> bytes:
    body = b""
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        body += message.get("body", b"")
        if max_body_bytes is not None and len(body) > max_body_bytes:
            raise _BodyTooLarge(len(body))
        if not message.get("more_body", False):
            break
    return body


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

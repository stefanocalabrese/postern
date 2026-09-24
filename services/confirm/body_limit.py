"""A ceiling on what this service will read into memory from a request body.

WHY THIS EXISTS. ``579dfd7`` bounded what an approval can write to
``audit_log.arguments`` -- 7,742,315 bytes on disk became 691 -- and said in
as many words that it did not bound what reaches MEMORY:
``services/confirm/audit.py``'s ``_arguments`` docstring records "the body is
still parsed in full before any of this runs, so the MEMORY cost of a 10 MiB
approval body is unchanged. Only the bytes that reach the disk are bounded."
This module is the other half. Measured against ``create_confirm_app`` over
raw ASGI on 2026-09-24, before it existed:

- ``POST /device_authorization``, **with no credential of any kind**, read
  9,999,989 of 9,999,989 offered bytes and answered **200**. The 10 MB it
  parsed then became the ``scopes`` string on a device code the store kept.
- ``POST /challenges/{id}/approve`` with a valid assertion and an id naming
  nothing read 9,999,984 of 9,999,984 bytes to produce a 404.
- The same approval delivered ONE BYTE PER ``http.request`` message cost
  1,048,556 ``receive`` calls and 0.317 CPU-seconds for 1 MiB.
- ``POST /token``, also uncredentialled, stopped at 1,114,112 bytes with a
  400 -- and that bound is Starlette's ``_get_form`` default
  ``max_part_size`` of 1 MiB, not a number anybody in this repository chose,
  reached only on the form-encoded branch, and still a megabyte of buffering
  for a body whose legitimate form is ``grant_type=device_code&device_code=``
  plus 43 characters.

WHAT IT DOES NOT DO, said first because the gap is the part worth knowing.
A request refused here writes NO ``audit_log`` row. That is a deliberate
choice and not an oversight: this middleware runs BEFORE
``AppAssertionMiddleware``, so it has no verified subject to put in
``customer_ref`` and no business holding a ``Database`` handle. Giving it one
would mean an unauthenticated caller could drive a database INSERT per
request, which is a cheaper denial of service than the one this module
exists to close. So an oversized body is a way to make a request that leaves
no row -- it joins the classes that already leave none (an unauthenticated
401, a 404 from the router, a request with no challenge id), and like those
it changes nothing: nothing is read, no challenge moves, no write JWT is
minted. The refusal is logged and that is the whole trace.

WHY OUTERMOST, in front of ``AppAssertionMiddleware`` rather than behind it.
Behind it, the body would already have been buffered by the time the
assertion was checked, which is the cost this module exists to avoid paying.
In front of it, an oversized body is refused without a signature
verification and without a JWKS fetch, so an unauthenticated flood costs a
header read.

The property ``AppAssertionMiddleware``'s own docstring claims for its
placement -- "an unauthenticated request never reaches a handler, never opens
a database session and never touches the device code store" -- is preserved
exactly. This module reaches none of those three: it holds an ``int`` and a
``Receive``, and everything it can do is return 413 or call the app it wraps.
It is outside the authentication boundary because it does strictly less than
authenticate, not because it does something authentication should have done
first.

WHY IT COVERS EVERY ROUTE AND EVERY METHOD. ``services/api``'s
``HeaderBodyValidation`` limits itself to POST because it is a JSON-RPC
control that has nothing to say about other verbs. This one is a resource
bound and has something to say about all of them. Default-deny is the
direction this service already runs in -- ``services/confirm/auth.py``'s
``PUBLIC_PATHS`` is an explicit allowlist so that "a route added to this
service tomorrow is therefore authenticated by omission rather than
unauthenticated by omission" -- and the same argument applies here: a route
added tomorrow is bounded by omission. There is no carve-out for
``/token``'s form encoding or for the two device-grant routes, because no
route on this service has a legitimate body worth carving one out for; see
``ConfirmSettings.max_body_bytes`` for the sizes.

CHUNKING IS NORMALISED, WHICH IS THE ANTI-AMPLIFICATION PROPERTY. The drain
below reads at most ``max_body_bytes`` however many messages the caller
splits them across, joins once, and replays the result downstream as a
SINGLE ``http.request`` message. So the byte-at-a-time shape -- one
``http.request`` per byte -- is absorbed here, once, and the handler behind
it sees one message whatever the caller did.

THE ACCUMULATOR IS A ``list[bytes]``, NEVER ``body += chunk``, and that is a
finding carried over rather than a style preference.
``services/api/asgi/header_validation.py``'s ``_drain`` accumulates with
``+=``, which is O(n^2) in the number of chunks: an audit measured ~7.6
CPU-seconds to assemble 1 MiB delivered one byte at a time, roughly 7,600x
amplification per attacker byte. A running integer counter and one
``b"".join`` at the end is linear. That file is not this change's to fix.
"""

from __future__ import annotations

import json
import logging

from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger(__name__)

#: The 413 body, in this service's error shape rather than
#: ``services/api``'s single-key one. ``services/confirm/auth.py``'s
#: ``_unauthenticated``, ``services/confirm/device_auth.py::_error`` and
#: ``services/confirm/callback.py::_error`` all answer
#: ``{"error": ..., "error_description": ...}``, so a client parses one shape
#: across this whole service and this refusal does not become the exception.
_TOO_LARGE = json.dumps(
    {
        "error": "request_too_large",
        "error_description": "the request body exceeds this service's limit",
    }
).encode()


class _BodyTooLarge(Exception):
    """Raised by ``_drain`` the moment the running total crosses the limit."""


class BodySizeLimit:
    """Refuse, with 413, any request whose body exceeds ``max_body_bytes``.

    Pure ASGI rather than a ``BaseHTTPMiddleware`` subclass, for the reason
    ``AppAssertionMiddleware`` gives for the same choice: ``BaseHTTPMiddleware``
    wraps the request in an anyio task group and a streaming response, and a
    middleware that must own ``receive`` itself has no use for either.
    """

    def __init__(self, app: ASGIApp, *, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        # Not only ``websocket``: ``lifespan`` comes through the same stack
        # (``starlette/applications.py`` sends every scope type into
        # ``self.middleware_stack``), and a lifespan scope whose ``receive``
        # this drained would hang the app at startup instead of bounding
        # anything.
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # THE CHEAP PATH, and the one that makes an unauthenticated flood cost
        # nothing at all: a declared length over the limit cannot describe a
        # body under it, so the request is refused having read ZERO bytes.
        #
        # This is a fast path and never an authority. A caller who understates
        # `Content-Length`, omits it, or sends `Transfer-Encoding: chunked`
        # falls through to the drain, which counts what actually arrives and
        # refuses on that. So the header can only ever make a caller's own
        # refusal cheaper, never make an oversized body admissible.
        declared = _content_length(scope)
        if declared is not None and declared > self.max_body_bytes:
            await self._refuse(scope, send, declared, from_header=True)
            return

        try:
            body = await _drain(receive, self.max_body_bytes)
        except _BodyTooLarge as exc:
            await self._refuse(scope, send, int(exc.args[0]), from_header=False)
            return

        await self.app(scope, _replay(body), send)

    async def _refuse(self, scope: Scope, send: Send, size: int, *, from_header: bool) -> None:
        """Answer 413 and log it, because the log is the only trace there is.

        The module docstring records why this path writes no ``audit_log``
        row. That makes this line the single durable-ish signal that a caller
        is sending oversized bodies, so it carries the path, the limit and how
        big the body was -- ``declared`` when `Content-Length` refused it,
        ``read`` when the bytes did, which is also how an operator tells the
        zero-byte refusals from the ones that cost a buffer.
        """
        logger.warning(
            "confirm: %s rejected, body %s %d bytes over a limit of %d",
            scope.get("path", ""),
            "declares" if from_header else "reached",
            size,
            self.max_body_bytes,
        )
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(_TOO_LARGE)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": _TOO_LARGE})


def _content_length(scope: Scope) -> int | None:
    """The declared body length, or ``None`` if there is no usable one.

    ``None`` for absent, repeated with conflicting values, non-numeric or
    negative. Every one of those is a header this middleware declines to act
    on, and declining costs only the drain below running -- which is the
    authority anyway.
    """
    seen: int | None = None
    for name, value in scope.get("headers", []):
        if name.lower() != b"content-length":
            continue
        try:
            length = int(value)
        except ValueError:
            return None
        if length < 0:
            return None
        if seen is not None and seen != length:
            return None
        seen = length
    return seen


async def _drain(receive: Receive, limit: int) -> bytes:
    """Read at most ``limit`` bytes, or raise ``_BodyTooLarge``.

    STOPS AT THE LIMIT. The ``raise`` leaves the loop on the chunk that
    crossed it, so the rest of the caller's body is never pulled off the
    wire: a 10 MB body against a 64 KiB limit costs 64 KiB and one more
    chunk, not 10 MB.

    ``list[bytes]`` plus a running ``int``, joined once. ``body += chunk``
    reallocates and copies the whole accumulated body per chunk, which is
    O(n^2) in the chunk count and is what makes one attacker byte per message
    worth thousands of CPU cycles. See the module docstring for the
    measurement on the read path's version.
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
            if total > limit:
                raise _BodyTooLarge(total)
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _replay(body: bytes) -> Receive:
    """Hand the drained body downstream as ONE ``http.request`` message.

    One message and not the chunks as they arrived: that is what makes the
    caller's chunking stop mattering at this boundary. Whatever the handler
    behind this does per message -- and Starlette's form parser does real work
    per message -- it does it once.
    """
    sent = False

    async def receive() -> Message:
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive

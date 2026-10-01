"""``services/confirm`` bounds what it reads into memory, and a body it cannot
read is a 400 with a row rather than a 500 with none.

TWO DEFECTS, ONE SURFACE. ``579dfd7`` bounded what an approval can WRITE to
``audit_log.arguments`` and said in as many words that it did not bound what
an approval can make this service READ:
``services/confirm/audit.py::_arguments``'s docstring records "the body is
still parsed in full before any of this runs, so the MEMORY cost of a 10 MiB
approval body is unchanged". Measured against ``create_confirm_app`` over raw
ASGI on 2026-09-24, before ``services/confirm/body_limit.py`` existed:

===============================================  ==========  ===============
request                                          bytes read  answer
===============================================  ==========  ===============
``POST /device_authorization``, NO credential     9,999,989  200
``POST /token``, NO credential                    1,114,112  400 (Starlette)
``POST /challenges/{id}/approve``, valid, 404     9,999,984  404
the same, delivered one byte per message          1,048,556  404, 0.317s CPU
===============================================  ==========  ===============

The ``/token`` row is the only one that was bounded at all, and that bound is
Starlette's ``_get_form`` default ``max_part_size`` of 1 MiB -- a number
nobody in this repository chose, reached only on the form-encoded branch, and
still a megabyte for a body whose legitimate form is 78 characters.

The second defect is at ``services/confirm/callback.py``, where ``body = await
request.json()`` sat outside any ``try`` and three lines above where
``ApprovalAudit`` is built. Four shapes reached it and all four were 500s that
wrote NO row: ``{not json``, ``[1,2,3]`` (``AttributeError`` from ``.get`` on
a list), 200,000 nested arrays (``RecursionError``, a ``RuntimeError``
subclass that ``except (ValueError, UnicodeDecodeError)`` does not catch), and
an empty body. That was a silent refusal path beyond the two
``services/confirm/audit.py``'s docstring enumerates -- and one its own rule
already owed a row for, since a verified subject and a non-empty challenge id
both exist by that line.

WHAT THIS FILE DOES NOT OWN. The ``audit_log.arguments`` bound is
``tests/test_write_audit_arguments_cap.py``'s, and the row shape and two-row
protocol are ``tests/test_write_audit.py``'s. Both pass unedited across this
change except for one line in the former, which raises the body limit on its
own fixture so its 1 MiB payloads still reach the column it is about; the
comment there says why.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import resource
from collections.abc import AsyncGenerator, Generator
from typing import Any, cast

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.store.engine import Database
from postern_core.store.models import ChallengeRecord
from sqlalchemy import delete
from starlette.applications import Starlette
from starlette.types import Message, Receive, Scope, Send

from services.confirm.audit import APPROVE_ROUTE, DETAIL_MALFORMED_BODY, UNRESOLVED_TOOL_NAME
from services.confirm.auth import AppAssertionMiddleware
from services.confirm.body_limit import BodySizeLimit, _drain
from services.confirm.main import create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.fixtures.append_only_bypass import (
    delete_audit_rows_by_bypassing_the_append_only_triggers,
)
from tests.fixtures.device_keys import enrolled_store
from tests.test_write_audit import (
    AUDIENCE,
    DEVICE_PUBLIC,
    ISSUER,
    OWNER,
    Backend,
    backend,  # noqa: F401 -- a fixture, used by name in the signatures below
    bearer,
    post,
    rows,
    seed,
    signed,
)

LIMIT = 64
PROTECTED = "/challenges/chal_x/approve"


# ---------------------------------------------------------------------------
# A bare ASGI harness. Raw scopes rather than httpx, because every number this
# file reports is "how many bytes did the application PULL", which a client
# cannot observe: httpx hands the whole body to the transport and the
# transport decides what to deliver.
# ---------------------------------------------------------------------------


class Chunks:
    """A ``receive`` that hands ``body`` over ``chunk`` bytes at a time and
    counts what was actually taken."""

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


class Sink:
    def __init__(self) -> None:
        self.status: int | None = None
        self.body = b""

    async def __call__(self, message: Message) -> None:
        if message["type"] == "http.response.start":
            self.status = int(message["status"])
        elif message["type"] == "http.response.body":
            self.body += bytes(message.get("body", b""))


class Downstream:
    """The app behind the middleware, recording what it was handed."""

    def __init__(self) -> None:
        self.messages: list[Message] = []
        self.body = b""
        self.scopes: list[str] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.scopes.append(str(scope["type"]))
        while True:
            message = await receive()
            self.messages.append(message)
            if message["type"] != "http.request":
                break
            self.body += bytes(message.get("body", b""))
            if not message.get("more_body", False):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})


def http_scope(
    *,
    path: str = PROTECTED,
    content_length: int | None = None,
    extra: list[tuple[bytes, bytes]] | None = None,
) -> Scope:
    headers = [(b"host", b"t"), (b"content-type", b"application/json"), *(extra or [])]
    if content_length is not None:
        headers.append((b"content-length", str(content_length).encode()))
    return {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": headers,
        "state": {},
    }


async def through(
    body: bytes,
    *,
    limit: int = LIMIT,
    chunk: int = 1 << 16,
    content_length: int | None = None,
    path: str = PROTECTED,
) -> tuple[Sink, Chunks, Downstream]:
    inner, recv, sink = Downstream(), Chunks(body, chunk), Sink()
    await BodySizeLimit(inner, max_body_bytes=limit)(
        http_scope(path=path, content_length=content_length), recv, sink
    )
    return sink, recv, inner


def cpu() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_utime + usage.ru_stime


# ---------------------------------------------------------------------------
# 1. The middleware alone: what it lets past and what it refuses.
# ---------------------------------------------------------------------------


async def test_a_body_under_the_limit_arrives_intact() -> None:
    """The invariant a bound is most likely to break, so it goes first."""
    payload = b'{"signature":"sig_x"}'
    sink, recv, inner = await through(payload)

    assert sink.status == 200
    assert inner.body == payload
    assert recv.taken == len(payload)


async def test_a_body_of_exactly_the_limit_is_allowed() -> None:
    """The limit is a ceiling, not a fence one short of it. Off-by-one here
    would reject the largest legitimate body a deployment had sized for."""
    sink, _, inner = await through(b"E" * LIMIT)
    assert sink.status == 200
    assert len(inner.body) == LIMIT


async def test_one_byte_over_the_limit_is_refused_with_413() -> None:
    sink, _, inner = await through(b"E" * (LIMIT + 1))

    assert sink.status == 413
    assert json.loads(sink.body) == {
        "error": "request_too_large",
        "error_description": "the request body exceeds this service's limit",
    }
    # The downstream app was never called at all -- not called and handed an
    # empty body, which would be the subtler and worse failure.
    assert inner.scopes == []


async def test_the_refusal_body_is_this_services_error_shape() -> None:
    """Two keys, not ``services/api``'s one.

    ``services/confirm/auth.py::_unauthenticated``,
    ``services/confirm/device_auth.py::_error`` and
    ``services/confirm/callback.py::_error`` all answer ``error`` +
    ``error_description``. A client parses one shape across this service, and
    a 413 that broke the pattern would be the one refusal needing special
    handling.
    """
    sink, _, _ = await through(b"E" * (LIMIT + 1))
    assert set(json.loads(sink.body)) == {"error", "error_description"}


# ---------------------------------------------------------------------------
# 2. IT STOPS AT THE LIMIT. The whole point: not "reads the body then measures
#    it", which bounds nothing.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("chunk", [1, 7, 64, 4096])
async def test_the_body_is_not_fully_read(chunk: int) -> None:
    """A 1 MiB body against a 64-byte limit must cost 64 bytes and one more
    chunk, never 1 MiB. ``Content-Length`` is deliberately absent, which is
    what a chunked request looks like, so the counting drain is the only
    thing that can refuse."""
    offered = b"E" * 1_048_576
    sink, recv, _ = await through(offered, chunk=chunk)

    assert sink.status == 413
    # The exact bound is the limit plus the one chunk that crossed it. The
    # second assertion restates it as a ratio so the test still says something
    # if `LIMIT` is ever raised: whatever the chunking, what is read is a
    # rounding error against what was offered.
    assert recv.taken <= LIMIT + chunk
    assert recv.taken * 100 < len(offered)


async def test_the_byte_at_a_time_shape_stops_after_the_limit() -> None:
    """The shape that made the read path's ``_drain`` quadratic.

    One ``http.request`` per byte. What is pinned is that the loop EXITS at
    the limit: the receive-call count is the limit plus one, not the 1,048,576
    the caller offered.
    """
    offered = b"E" * 1_048_576
    started = cpu()
    sink, recv, _ = await through(offered, chunk=1)
    spent = cpu() - started

    assert sink.status == 413
    assert recv.calls == LIMIT + 1
    assert recv.taken == LIMIT + 1
    # Measured at 0.014 CPU-seconds for a 65,536-byte limit against the same
    # 1 MiB; against a 64-byte one it is unmeasurable. The assertion is loose
    # on purpose -- it exists to fail if the loop ever reads the whole body
    # again, not to police a machine's speed.
    assert spent < 1.0, spent


async def test_a_declared_length_over_the_limit_reads_nothing_at_all() -> None:
    """``Content-Length`` is a fast path, and this is what it buys: an
    oversized request costs a header read and zero bytes of body.

    That is what makes an unauthenticated flood free rather than merely
    bounded -- the middleware sits in front of ``AppAssertionMiddleware``, so
    this is the cost of a request from anybody at all.
    """
    offered = b"E" * 10_000_000
    sink, recv, _ = await through(offered, content_length=len(offered))

    assert sink.status == 413
    assert recv.taken == 0
    assert recv.calls == 0


# ---------------------------------------------------------------------------
# 3. The header is a fast path and never an authority. Every way of lying
#    about it lands on the drain, which counts what actually arrives.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "headers"),
    [
        ("absent", []),
        ("understated", [(b"content-length", b"1")]),
        ("non-numeric", [(b"content-length", b"banana")]),
        ("negative", [(b"content-length", b"-1")]),
        (
            "repeated with conflicting values",
            [(b"content-length", b"1"), (b"content-length", b"2")],
        ),
    ],
)
async def test_a_lying_content_length_cannot_admit_an_oversized_body(
    label: str, headers: list[tuple[bytes, bytes]]
) -> None:
    inner, recv, sink = Downstream(), Chunks(b"E" * 100_000), Sink()
    await BodySizeLimit(inner, max_body_bytes=LIMIT)(http_scope(extra=headers), recv, sink)

    assert sink.status == 413, label
    assert inner.scopes == [], label
    assert recv.taken <= LIMIT + recv.chunk, label


async def test_an_overstated_content_length_only_refuses_the_caller_itself() -> None:
    """The one thing a lying header CAN do: refuse a body that would have
    been admissible. That costs the caller their own request and nobody
    else's, which is why the header is worth trusting in this direction."""
    sink, recv, _ = await through(b"tiny", content_length=10_000_000)
    assert sink.status == 413
    assert recv.taken == 0


# ---------------------------------------------------------------------------
# 4. Chunking is normalised, which is the anti-amplification property.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("chunk", [1, 3, 17, 4096])
async def test_however_the_caller_chunks_it_the_handler_sees_one_message(
    chunk: int,
) -> None:
    """Whatever the handler behind this does per ``http.request`` message --
    and Starlette's form parser does real work per message -- it does it once.

    Without this, a caller who splits a 64-byte body across 64 messages makes
    every layer below iterate 64 times for it.
    """
    payload = b"E" * LIMIT
    _, _, inner = await through(payload, chunk=chunk)

    requests = [m for m in inner.messages if m["type"] == "http.request"]
    assert len(requests) == 1
    assert requests[0]["body"] == payload
    assert requests[0]["more_body"] is False


async def test_the_replay_is_exhausted_after_one_message() -> None:
    """A handler that keeps reading gets ``http.disconnect``, not the body
    again. Starlette's ``Request.stream`` loops until ``more_body`` is false,
    so a replay that repeated itself would hang a request rather than fail
    one."""
    _, _, inner = await through(b"x")
    assert [m["type"] for m in inner.messages] == ["http.request"]

    from services.confirm.body_limit import _replay

    receive = _replay(b"x")
    assert (await receive())["type"] == "http.request"
    assert (await receive())["type"] == "http.disconnect"
    assert (await receive())["type"] == "http.disconnect"


async def test_a_disconnect_mid_body_ends_the_drain_without_raising() -> None:
    """A client that goes away is not an oversized body. The drain returns
    what it has and the handler decides -- it must not become a 413, and it
    must not loop."""

    class Disconnects:
        def __init__(self) -> None:
            self.calls = 0

        async def __call__(self) -> Message:
            self.calls += 1
            if self.calls == 1:
                return {"type": "http.request", "body": b"ab", "more_body": True}
            return {"type": "http.disconnect"}

    inner, sink = Downstream(), Sink()
    await BodySizeLimit(inner, max_body_bytes=LIMIT)(http_scope(), Disconnects(), sink)

    assert sink.status == 200
    assert inner.body == b"ab"


# ---------------------------------------------------------------------------
# 5. Scope types this must not touch.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("scope_type", ["lifespan", "websocket"])
async def test_a_non_http_scope_passes_through_without_its_receive_touched(
    scope_type: str,
) -> None:
    """``lifespan`` comes through the same middleware stack. Draining its
    ``receive`` would hang the app at startup while every test that drives
    the app directly kept passing -- the same trap
    ``tests/test_confirm_auth.py`` pins for ``AppAssertionMiddleware``.
    """
    seen: list[str] = []

    async def inner(scope: Scope, receive: Receive, send: Send) -> None:
        seen.append(str(scope["type"]))

    async def receive() -> Message:  # pragma: no cover - never awaited
        raise AssertionError("receive must not be touched for a non-http scope")

    async def send(message: Message) -> None:  # pragma: no cover - never awaited
        raise AssertionError("send must not be touched for a non-http scope")

    await BodySizeLimit(inner, max_body_bytes=LIMIT)({"type": scope_type}, receive, send)
    assert seen == [scope_type]


# ---------------------------------------------------------------------------
# 6. The accumulator, pinned structurally.
# ---------------------------------------------------------------------------


def test_the_drain_accumulates_into_a_list_and_never_with_bytes_concatenation() -> None:
    """The finding this module was written not to re-introduce.

    ``services/api/asgi/header_validation.py::_drain`` accumulates with
    ``body += chunk``, which reallocates and copies the whole accumulated
    body once per chunk: O(n^2) in the chunk count. Measured head to head on
    2026-09-24, one byte per message, both unbounded so both assemble the
    same body -- 262,144 B: 0.523s vs 0.057s; 524,288 B: 1.787s vs 0.115s;
    1,048,576 B: 7.825s vs 0.231s; 2,097,152 B: 29.580s vs 0.477s. The left
    column quadruples per doubling and the right one doubles.

    A timing assertion would police the machine rather than the code, so what
    is checked is the shape: the only augmented assignment in ``_drain`` is
    the integer counter, and the bytes are joined exactly once.
    """
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
    AST guard cannot -- ``chunks.append(b"".join(chunks) + chunk)`` uses a
    list, one append and one join, and is still quadratic.

    4x the bytes does NOT discriminate: a reintroduced ``body += chunk``
    grows only ~17.2x there, under a 40x bound, so that shape of this test
    passed against the regression it exists to catch. Matched here to
    ``tests/test_header_body_mismatch.py``'s version of the same assertion on
    the read path's ``_drain``, which does discriminate: 8x the bytes at one
    byte per message. Measured both shapes head to head on 2026-09-24 at
    32,768 then 262,144 bytes, three runs on this machine: quadratic 40.1x,
    43.5x, 44.6x; linear 8.1x, 8.2x, 8.4x. The bound asserted is 25x, the same
    the read path uses, which leaves about 3x of headroom over the linear
    measurement and stays clear under every quadratic one observed.
    """
    timings: list[float] = []
    for size in (32_768, 262_144):
        payload = b"x" * size
        started = cpu()
        await _drain(Chunks(payload, 1), size + 1)
        timings.append(cpu() - started)

    # 8x the bytes. Linear predicts ~8x the time, quadratic ~64x.
    growth = timings[1] / max(timings[0], 1e-6)
    assert growth < 25.0, f"8x the chunks cost {growth:.1f}x the time"


# ---------------------------------------------------------------------------
# 7. The wiring: the limit is reachable, and the middleware is OUTERMOST.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def _app(key_pair: RSAKeyPair, **kwargs: Any) -> Starlette:
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    settings = ConfirmSettings(
        app_assertion_jwks_uri="https://app.postern-local-dev.invalid/.well-known/jwks.json",
        app_assertion_issuer="https://app.postern-local-dev.invalid",
        app_assertion_audience=AUDIENCE,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so without these two flags it gets the
        # safe defaults and refuses to start.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
        **kwargs,
    )
    return create_confirm_app(
        settings, assertion_verifier=verifier, device_key_store=no_enrolled_devices()
    )


def _installed(app: Starlette) -> list[type[object]]:
    """``Middleware.cls`` is typed as the ParamSpec-generic ``_MiddlewareFactory``
    protocol, which mypy will not compare against a concrete class without a
    cast -- the same note ``tests/test_asgi_app.py::_middleware_class`` carries
    for the read path."""
    return [cast(type[object], m.cls) for m in app.user_middleware]


def test_the_limit_is_wired_from_settings(key_pair: RSAKeyPair) -> None:
    app = _app(key_pair, max_body_bytes=4096)
    installed = next(m for m in app.user_middleware if cast(type[object], m.cls) is BodySizeLimit)
    assert installed.kwargs["max_body_bytes"] == 4096


def test_the_default_limit_is_sixty_four_kibibytes() -> None:
    assert ConfirmSettings.for_testing().max_body_bytes == 65_536


def test_the_environment_variable_is_this_services_own(monkeypatch: pytest.MonkeyPatch) -> None:
    """NOT ``services/api``'s ``POSTERN_MAX_BODY_BYTES``.

    That one is 1 MiB and its own comment invites an operator to raise it for
    "a bulk import, say". Sharing the name would make raising the READ path's
    ceiling silently raise the WRITE path's, in a repository whose
    ``docker-compose.yml`` runs both services from one file.
    """
    for var in ("POSTERN_APP_ASSERTION_JWKS_URI", "POSTERN_APP_ASSERTION_ISSUER"):
        monkeypatch.setenv(var, "https://app.postern-local-dev.invalid")
    monkeypatch.setenv("POSTERN_APP_ASSERTION_AUDIENCE", AUDIENCE)

    monkeypatch.setenv("POSTERN_MAX_BODY_BYTES", "999")
    monkeypatch.delenv("POSTERN_CONFIRM_MAX_BODY_BYTES", raising=False)
    assert ConfirmSettings.from_env().max_body_bytes == 65_536

    monkeypatch.setenv("POSTERN_CONFIRM_MAX_BODY_BYTES", "4096")
    assert ConfirmSettings.from_env().max_body_bytes == 4096


def test_the_limit_is_outermost_in_front_of_the_assertion_check(key_pair: RSAKeyPair) -> None:
    """Starlette applies ``user_middleware`` in reverse, so index 0 is the
    first thing a request reaches."""
    order = _installed(_app(key_pair))
    assert order.index(BodySizeLimit) < order.index(AppAssertionMiddleware)


async def test_an_unauthenticated_oversized_request_is_413_and_never_reaches_the_verifier() -> None:
    """The behavioural proof of that ordering, and the reason for it.

    If ``AppAssertionMiddleware`` ran first this would be a 401, reached by
    verifying a signature and possibly fetching a JWKS. It is a 413 instead,
    reached by reading one header.
    """

    class NeverCalled:
        async def verify_token(self, token: str) -> Any:  # pragma: no cover
            raise AssertionError("an oversized body must be refused before verification")

    settings = ConfirmSettings(
        app_assertion_jwks_uri="https://app.postern-local-dev.invalid/.well-known/jwks.json",
        app_assertion_issuer="https://app.postern-local-dev.invalid",
        app_assertion_audience=AUDIENCE,
        max_body_bytes=LIMIT,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so without these two flags it gets the
        # safe defaults and refuses to start.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
    app = create_confirm_app(
        settings, assertion_verifier=NeverCalled(), device_key_store=no_enrolled_devices()
    )

    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        response = await client.post(
            PROTECTED,
            content=b"E" * (LIMIT + 1),
            headers={
                "content-type": "application/json",
                "authorization": "Bearer would-have-been-verified",
            },
        )

    assert response.status_code == 413
    assert response.json()["error"] == "request_too_large"


@pytest.mark.parametrize(
    ("path", "content_type"),
    [
        ("/token", "application/x-www-form-urlencoded"),
        ("/device_authorization", "application/json"),
        ("/approve", "application/json"),
        ("/scan", "application/json"),
        (PROTECTED, "application/json"),
        ("/.well-known/jwks.json", "application/json"),
        ("/session/jwks.json", "application/json"),
        ("/verify", "text/plain"),
        ("/verify/qr.svg", "text/plain"),
        ("/verify/state", "text/plain"),
        ("/verify.js", "text/plain"),
        ("/verify.css", "text/plain"),
    ],
)
async def test_every_route_is_covered_including_the_public_and_form_encoded_ones(
    key_pair: RSAKeyPair, path: str, content_type: str
) -> None:
    """ONE LIMIT, NO CARVE-OUTS, and the two public routes are the ones that
    need it most: ``/token`` and ``/device_authorization`` hold no credential
    by the device grant's own premise, so before this middleware anybody at
    all could make this service buffer a body. ``/device_authorization`` read
    9,999,989 bytes and answered 200.

    ``/token`` is form-encoded rather than JSON and is covered by the same
    limit anyway: a bound on bytes has nothing to do with how they are
    encoded, and Starlette's accidental 1 MiB form ceiling is not a number
    this repository chose.

    The JWKS route and the five pairing-page routes are GETs that read no
    body, and are here because the limit covers every method. A route added
    to this service tomorrow is bounded by omission, the same direction
    ``PUBLIC_PATHS`` points for authentication.
    """
    app = _app(key_pair, max_body_bytes=LIMIT)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        response = await client.request(
            "GET" if path.endswith("jwks.json") or path.startswith("/verify") else "POST",
            path,
            content=b"E" * (LIMIT + 1),
            headers={"content-type": content_type},
        )

    assert response.status_code == 413, path


async def test_a_legitimate_request_on_a_public_route_still_works(key_pair: RSAKeyPair) -> None:
    """The bound must not be the thing that breaks the device grant. A real
    ``/device_authorization`` body is a client id and a scope list."""
    app = _app(key_pair)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        response = await client.post("/device_authorization", json={"client_id": "cli_1"})

    assert response.status_code == 200
    assert len(response.json()["device_code"]) >= 40


async def test_the_jwks_route_still_serves_its_key(key_pair: RSAKeyPair) -> None:
    app = _app(key_pair)
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app), base_url="http://t"
    ) as client:
        response = await client.get("/.well-known/jwks.json")

    assert response.status_code == 200
    assert response.json()["keys"][0]["kid"] == "write-1"


# ---------------------------------------------------------------------------
# 8. Defect 2, against the real column.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pg_url() -> Generator[str]:
    """Its own container, like the two write-audit files: these tests write
    and truncate ``audit_log`` around every case, and the session-scoped one
    in ``tests/conftest.py`` is shared with every read-path test that reads
    the same table."""
    import docker
    from testcontainers.community.postgres import PostgresContainer

    try:
        docker.from_env().ping()
    except docker.errors.DockerException as exc:
        pytest.skip(f"Docker is not reachable, skipping confirm body-limit tests: {exc}")

    previous = os.environ.get("POSTERN_DATABASE_URL")
    with PostgresContainer("postgres:17-alpine", driver="asyncpg") as pg:
        url = pg.get_connection_url()
        os.environ["POSTERN_DATABASE_URL"] = url
        from alembic import command
        from alembic.config import Config

        cfg = Config("alembic.ini")
        cfg.set_main_option("sqlalchemy.url", url)
        command.upgrade(cfg, "head")
        try:
            yield url
        finally:
            if previous is None:
                os.environ.pop("POSTERN_DATABASE_URL", None)
            else:
                os.environ["POSTERN_DATABASE_URL"] = previous


@pytest.fixture()
def settings(pg_url: str) -> ConfirmSettings:
    return ConfirmSettings(
        backend_base_url="https://backend.test",
        database_url=pg_url,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so without these two flags it gets the
        # safe defaults and refuses to start.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )


@pytest.fixture()
def db(settings: ConfirmSettings) -> Database:
    return Database(settings.database_url)


@pytest.fixture()
async def clean(db: Database) -> AsyncGenerator[Database, None]:
    await _wipe(db)
    yield db
    await _wipe(db)


async def _wipe(db: Database) -> None:
    async with db.sessionmaker() as s:
        await delete_audit_rows_by_bypassing_the_append_only_triggers(s)
        await s.execute(delete(ChallengeRecord))
        await s.commit()


@pytest.fixture()
def dbapp(settings: ConfirmSettings, key_pair: RSAKeyPair) -> Starlette:
    """The database-backed app, with the owner's phone enrolled.

    Unlike the middleware-only apps above, two tests here drive a REAL
    approval to completion, so this one must be able to verify a signature.
    The key is ``tests/test_write_audit.py``'s, whose ``signed`` helper this
    file also imports -- one enrolled device across both suites, so a body
    built by that helper verifies against this app.
    """
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    return create_confirm_app(
        settings,
        assertion_verifier=verifier,
        device_key_store=enrolled_store(OWNER, DEVICE_PUBLIC),
    )


async def _raw(app: Starlette, challenge_id: str, body: bytes, token: str) -> httpx2.Response:
    """POST bytes, not a dict: every case below is a body ``json=`` cannot
    express."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://t",
    ) as client:
        return await client.post(
            f"/challenges/{challenge_id}/approve",
            content=body,
            headers={"content-type": "application/json", "authorization": token},
        )


# Every shape below is UNDER the default limit, so what refuses it is the
# handler and not the middleware -- which is what makes these tests about
# defect 2 rather than defect 1. The nested case is 60,000 bytes against a
# 65,536-byte limit and still blows a recursion limit of 1,000.
MALFORMED: list[tuple[str, bytes]] = [
    ("not JSON at all", b"{not json"),
    ("a JSON array", b"[1,2,3]"),
    ("a bare JSON string", b'"hello"'),
    ("a JSON null", b"null"),
    ("invalid UTF-8", b'{"signature":"\xff\xfe"}'),
    ("30,000 nested arrays", b"[" * 30_000 + b"]" * 30_000),
    ("an empty body", b""),
]


@pytest.mark.parametrize(("label", "body"), MALFORMED, ids=[c[0] for c in MALFORMED])
async def test_a_malformed_body_is_a_400_with_a_row(
    clean: Database,
    dbapp: Starlette,
    key_pair: RSAKeyPair,
    backend: Backend,  # noqa: F811 -- the imported fixture
    label: str,
    body: bytes,
) -> None:
    """All seven were 500s writing nothing. Each is now a 400 writing one row.

    ``30,000 nested arrays`` is the one worth naming: ``json.loads`` raises
    ``RecursionError`` there, a ``RuntimeError`` subclass, so the
    ``except (ValueError, UnicodeDecodeError)`` that
    ``services/api/asgi/header_validation.py::_parse`` uses would miss it and
    this would still be a 500.
    """
    assert len(body) <= ConfirmSettings.for_testing().max_body_bytes, label

    token = bearer(key_pair, OWNER)["Authorization"]
    response = await _raw(dbapp, "chal_nothing", body, token)

    assert response.status_code == 400, label
    assert response.json() == {
        "error": "invalid_request",
        "error_description": "body must be a JSON object",
    }

    entries = await rows(clean)
    assert len(entries) == 1, label
    assert entries[0].detail == DETAIL_MALFORMED_BODY
    assert entries[0].outcome == "raised"
    # Refused before the backend, and before the challenge was ever read.
    assert backend.calls == []


async def test_the_malformed_row_names_the_caller_and_what_they_aimed_at(
    clean: Database,
    dbapp: Starlette,
    key_pair: RSAKeyPair,
    backend: Backend,  # noqa: F811 -- the imported fixture
) -> None:
    """The row an investigator actually reads.

    ``tool_name`` is the unresolved literal because no challenge was read --
    the same shape a 404 for an unknown id takes -- and ``arguments`` records
    that the caller supplied nothing this handler could use, which is the
    truth rather than an absence of data.
    """
    token = bearer(key_pair, OWNER)["Authorization"]
    await _raw(dbapp, "chal_aimed_at", b"{not json", token)

    entry = (await rows(clean))[0]
    assert entry.customer_ref == OWNER
    assert entry.tool_name == UNRESOLVED_TOOL_NAME
    assert entry.reaching_at is None
    assert entry.duration_ms is not None
    assert entry.arguments == {
        "route": APPROVE_ROUTE,
        "challenge_id": "chal_aimed_at",
        "signature_present": False,
        "confirming_device": None,
        "verification_result": None,
    }


async def test_a_malformed_body_never_touches_a_real_challenge(
    clean: Database,
    dbapp: Starlette,
    key_pair: RSAKeyPair,
    backend: Backend,  # noqa: F811 -- the imported fixture
) -> None:
    """The refusal happens before ``_approve``, so the challenge it names is
    left exactly as it was: still ``pending``, still approvable."""
    await seed(clean, "chal_live")
    token = bearer(key_pair, OWNER)["Authorization"]

    assert (await _raw(dbapp, "chal_live", b"[1,2,3]", token)).status_code == 400

    async with clean.sessionmaker() as s:
        from postern_core.store.challenges import get_challenge

        record = await get_challenge(s, "chal_live")
    assert record is not None
    assert record.status == "pending"
    assert record.signature is None
    assert backend.calls == []


async def test_an_unauthenticated_malformed_body_is_still_401_with_no_row(
    clean: Database,
    dbapp: Starlette,
    backend: Backend,  # noqa: F811 -- the imported fixture
) -> None:
    """The new 400 must not have moved in front of the authentication check.
    A caller with no assertion learns that and nothing else."""
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=dbapp), base_url="http://t"
    ) as client:
        response = await client.post(
            "/challenges/chal_x/approve",
            content=b"{not json",
            headers={"content-type": "application/json"},
        )

    assert response.status_code == 401
    assert await rows(clean) == []


async def test_an_oversized_body_writes_no_row_at_all(
    clean: Database,
    settings: ConfirmSettings,
    key_pair: RSAKeyPair,
    backend: Backend,  # noqa: F811 -- the imported fixture
) -> None:
    """THE GAP, PINNED SO IT IS A DECISION AND NOT AN ACCIDENT.

    ``services/confirm/body_limit.py`` runs in front of
    ``AppAssertionMiddleware``, so it has no verified subject to put in
    ``customer_ref`` and no database handle to write with. Giving it one
    would let an unauthenticated caller drive an INSERT per request, which is
    a cheaper denial of service than the one that middleware closes.

    So an oversized body IS a way to make a request this table does not see.
    What it costs is bounded by what such a request does, which is nothing:
    the challenge below is untouched, no write JWT is minted, and the refusal
    is logged. Contrast the two rows beside it -- a malformed body under the
    limit is recorded, because by then a subject and a challenge id exist.
    """
    verifier = JWTVerifier(public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE)
    tight = ConfirmSettings(
        backend_base_url=settings.backend_base_url,
        database_url=settings.database_url,
        max_body_bytes=LIMIT,
        # The two development flags `ConfirmSettings.for_testing` sets: this
        # settings object is built by hand, so without these two flags it gets the
        # safe defaults and refuses to start.
        allow_non_uri_audience=True,
        allow_process_local_sessions=True,
    )
    app = create_confirm_app(
        tight, assertion_verifier=verifier, device_key_store=no_enrolled_devices()
    )
    await seed(clean, "chal_untouched")
    token = bearer(key_pair, OWNER)["Authorization"]

    over = await _raw(app, "chal_untouched", b'{"signature":"' + b"E" * LIMIT + b'"}', token)
    assert over.status_code == 413
    assert await rows(clean) == []

    under = await _raw(app, "chal_untouched", b"{not json", token)
    assert under.status_code == 400
    assert [e.detail for e in await rows(clean)] == [DETAIL_MALFORMED_BODY]

    async with clean.sessionmaker() as s:
        from postern_core.store.challenges import get_challenge

        record = await get_challenge(s, "chal_untouched")
    assert record is not None and record.status == "pending"
    assert backend.calls == []


# ---------------------------------------------------------------------------
# 9. And an ordinary approval is untouched by any of it.
# ---------------------------------------------------------------------------


async def test_an_ordinary_approval_still_executes_and_records_the_same_arguments(
    clean: Database,
    dbapp: Starlette,
    key_pair: RSAKeyPair,
    backend: Backend,  # noqa: F811 -- the imported fixture
) -> None:
    """The invariant every part of this change could have broken: the body
    limit, the replay, and the restructured handler all sit on this path.

    The pair of rows, their correlation and their ``arguments`` are
    ``tests/test_write_audit.py``'s subject and it passes unedited; what is
    asserted here is that the approval still reaches the backend and still
    records byte-identical ``arguments``.
    """
    await seed(clean, "chal_ok")
    body = await signed(
        dbapp, "chal_ok", confirming_device="pixel-9", verification_result="match_0f2"
    )
    response = await post(dbapp, "chal_ok", body, bearer(key_pair, OWNER))

    assert response.status_code == 200
    assert response.json()["status"] == "executed"
    assert len(backend.calls) == 1

    entries = await rows(clean)
    assert [e.outcome for e in entries] == ["reaching", "returned"]
    for entry in entries:
        assert entry.arguments == {
            "route": APPROVE_ROUTE,
            "challenge_id": "chal_ok",
            "signature_present": True,
            "confirming_device": "pixel-9",
            "verification_result": "match_0f2",
        }


async def test_a_missing_signature_is_still_the_missing_signature_refusal(
    clean: Database,
    dbapp: Starlette,
    key_pair: RSAKeyPair,
    backend: Backend,  # noqa: F811 -- the imported fixture
) -> None:
    """An EMPTY object is a valid body and must not be swept into the new
    malformed branch: ``{}`` still reaches ``_approve`` and is refused by the
    signature check, with the detail that names it.

    This is the boundary the malformed branch is most likely to overshoot --
    ``if not body`` instead of ``if body is None`` would land ``{}`` here.
    """
    response = await _raw(dbapp, "chal_empty_obj", b"{}", bearer(key_pair, OWNER)["Authorization"])

    assert response.status_code == 400
    assert response.json()["error_description"] == "signature is required"
    entries = await rows(clean)
    assert [e.detail for e in entries] == ["missing_signature"]
    assert backend.calls == []


async def test_a_body_delivered_in_many_chunks_still_approves(
    clean: Database,
    dbapp: Starlette,
    key_pair: RSAKeyPair,
    backend: Backend,  # noqa: F811 -- the imported fixture
) -> None:
    """The replay path, end to end: an approval split across many
    ``http.request`` messages must reach the handler as the body it was."""
    await seed(clean, "chal_chunked")
    payload = json.dumps(await signed(dbapp, "chal_chunked", confirming_device="pixel-9")).encode()

    async def stream() -> AsyncGenerator[bytes, None]:
        for index in range(len(payload)):
            yield payload[index : index + 1]

    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=dbapp), base_url="http://t"
    ) as client:
        response = await client.post(
            "/challenges/chal_chunked/approve",
            content=stream(),
            headers={
                "content-type": "application/json",
                "authorization": bearer(key_pair, OWNER)["Authorization"],
            },
        )

    assert response.status_code == 200
    assert len(backend.calls) == 1
    assert (await rows(clean))[0].arguments["confirming_device"] == "pixel-9"


def test_the_limit_leaves_the_audit_column_bound_reachable() -> None:
    """The floor under ``ConfirmSettings.max_body_bytes``, asserted rather
    than only argued.

    ``postern_core.store.audit``'s ``MAX_ARGUMENTS_BYTES`` is the most of a
    body that can reach ``audit_log.arguments`` from this service. A body
    limit below it would make the bound ``579dfd7`` put on that column
    unreachable from any request this service will accept -- not a tighter
    control but a dead one, and a suite testing a shape production cannot
    receive.
    """
    from postern_core.store.audit import MAX_ARGUMENTS_BYTES

    assert ConfirmSettings.for_testing().max_body_bytes > MAX_ARGUMENTS_BYTES


def test_an_approval_body_is_three_orders_of_magnitude_under_the_limit() -> None:
    """The headroom, measured rather than asserted in prose. The whole
    approval tree is under 300 bytes; the limit is 65,536."""
    realistic = json.dumps(
        {
            "signature": "a" * 684,  # an RSA-4096 signature, base64
            "confirming_device": "Pixel 9 Pro / Android 16 / app 7.21.3",
            "verification_result": "match_0f2c91ab",
        }
    ).encode()

    limit = ConfirmSettings.for_testing().max_body_bytes
    assert len(realistic) < limit / 50, (len(realistic), limit)

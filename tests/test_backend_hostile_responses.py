"""A hostile backend, over a real socket, against the real confirm app.

The invariant: NO TEXT DERIVED FROM THE BACKEND'S RESPONSE reaches a response
body, a log record, an audit row or an exception message. ``tests/test_callback.py``
checks it with ``httpx2.MockTransport``, which hands the client a finished
``httpx2.Response`` and never runs a parser, so it cannot see the part that
failed in review: ``h11`` and ``httpcore2`` quote the bytes they refused
(``illegal status line: bytearray(b'HTTP/1.1 5x0 ...')``, a line of the body in
``illegal chunk header``), and ``AsyncClient.post()`` reads and decodes the whole
body before the status is looked at. Both need real bytes on a real socket.

What each case settles:

* the client reads the STATUS LINE and nothing else, so a garbled body behind an
  accepted status is an accepted write and a garbled body behind a refused one
  is a 207;
* a failure before any status (a bad status line, a bad header block) is a 502
  `outcome_unknown` with a fixed body; the audit detail is the original
  exception's type name and nothing the backend sent reaches any of it;
* nothing is buffered: a 50 MB body that never arrives does not hold the
  approval up;
* a cancellation is not swallowed.

Every sentinel contains ``SNTL`` or ``hunter2``.
"""

from __future__ import annotations

# The fixtures are imported from `tests/test_write_audit.py`, which is what F811
# reports on every test that names one.
# ruff: noqa: F811
import asyncio
import gzip
import json
import logging
import traceback
from dataclasses import dataclass
from types import TracebackType
from typing import Any
from unittest.mock import patch

import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.store.models import AuditEntry, ChallengeRecord
from sqlalchemy import select

from services.confirm.execute import BackendWriteClient
from services.confirm.main import create_confirm_app
from tests.test_write_audit import (  # noqa: F401  (fixtures)
    AUDIENCE,
    ISSUER,
    OWNER,
    app,
    bearer,
    clean,
    db,
    key_pair,
    pg_url,
    post,
    rows,
    seed,
    settings,
    signed,
)

SENTINELS = ("SNTL", "hunter2")


def _leaks(text: str) -> bool:
    return any(s in text for s in SENTINELS)


def _response(
    status_line: bytes, extra: bytes = b"", body: bytes = b"", *, length: int | None = None
) -> bytes:
    n = len(body) if length is None else length
    return (
        status_line + b"\r\n" + extra + b"Content-Length: " + str(n).encode() + b"\r\n\r\n" + body
    )


HOSTILE_HEADERS = (
    b"Server: SRV-SNTL\r\n"
    b"WWW-Authenticate: Bearer WWW-SNTL-eyJhbGciOiJSUzI1NiJ9\r\n"
    b"Location: http://LOC-SNTL.evil/postgresql://svc:hunter2@10.0.3.4/p\r\n"
    b"X-Debug: XDBG-SNTL postgresql://svc:hunter2@10.0.3.4/p\r\n"
)
BODY = b'{"detail":"BODY-SNTL postgresql://svc:hunter2@10.0.3.4/p"}'
CHUNKED = b"Transfer-Encoding: chunked\r\n\r\n"

#: What the approval ends as. EXECUTED: 200, row `executed`. REFUSED: 207 with
#: the numeric status, row `approved`. ESCAPES: no status ever arrived, so
#: the answer is 502 `outcome_unknown` and the row is left `approved` (the name
#: predates the 502: the exception no longer escapes the handler).
EXECUTED, REFUSED, ESCAPES = "executed", "refused", "escapes"

CASES: dict[str, tuple[bytes, str, int | None]] = {
    # --- before any status: the parser refuses, and quotes what it refused ---
    "bad_status_line": (
        b"HTTP/1.1 5x0 STATUS-SNTL\r\nContent-Length: 0\r\n\r\n",
        ESCAPES,
        None,
    ),
    "bad_header_line": (
        b"HTTP/1.1 500 X\r\nBad Header HDRLINE-SNTL\r\nContent-Length: 0\r\n\r\n",
        ESCAPES,
        None,
    ),
    # --- a refused status with a body nobody should read ---
    "refused_500_hostile_reason_and_headers": (
        _response(b"HTTP/1.1 500 RP-SNTL postgresql://svc:hunter2@x", HOSTILE_HEADERS, BODY),
        REFUSED,
        500,
    ),
    "refused_403_hostile_reason_and_headers": (
        _response(b"HTTP/1.1 403 RP-SNTL", HOSTILE_HEADERS, BODY),
        REFUSED,
        403,
    ),
    "redirect_302_hostile_location": (
        _response(b"HTTP/1.1 302 Found", HOSTILE_HEADERS, BODY),
        REFUSED,
        302,
    ),
    "refused_500_bad_chunk_header": (
        b"HTTP/1.1 500 X\r\n" + CHUNKED + b"CHUNK-SNTL-hunter2\r\n0\r\n\r\n",
        REFUSED,
        500,
    ),
    "refused_500_malformed_chunk_footer": (
        b"HTTP/1.1 500 X\r\n" + CHUNKED + b"5\r\nhelloJUNK-SNTL-hunter2\r\n0\r\n\r\n",
        REFUSED,
        500,
    ),
    "refused_500_corrupt_gzip": (
        _response(b"HTTP/1.1 500 RP-SNTL", b"Content-Encoding: gzip\r\n", b"BODY-SNTL not gzip"),
        REFUSED,
        500,
    ),
    "refused_500_truncated_gzip": (
        _response(
            b"HTTP/1.1 500 X",
            b"Content-Encoding: gzip\r\n",
            gzip.compress(b"BODY-SNTL" * 50)[:30],
        ),
        REFUSED,
        500,
    ),
    "refused_500_short_content_length": (
        _response(b"HTTP/1.1 500 RP-SNTL", b"", b"BODY-SNTL", length=1000),
        REFUSED,
        500,
    ),
    "refused_500_closed_mid_chunk": (
        b"HTTP/1.1 500 X\r\n" + CHUNKED + b"9\r\nBODY-SNTL\r\n",
        REFUSED,
        500,
    ),
    # --- an accepted status with a body nobody should read: still accepted ---
    "accepted_201_hostile_headers": (
        _response(b"HTTP/1.1 201 RP-SNTL", HOSTILE_HEADERS, BODY),
        EXECUTED,
        None,
    ),
    "accepted_201_bad_chunk_header": (
        b"HTTP/1.1 201 X\r\n" + CHUNKED + b"CHUNK-SNTL-hunter2\r\n0\r\n\r\n",
        EXECUTED,
        None,
    ),
    "accepted_201_malformed_chunk_footer": (
        b"HTTP/1.1 201 X\r\n" + CHUNKED + b"5\r\nhelloJUNK-SNTL-hunter2\r\n0\r\n\r\n",
        EXECUTED,
        None,
    ),
    "accepted_200_corrupt_gzip": (
        _response(b"HTTP/1.1 200 OK", b"Content-Encoding: gzip\r\n", b"BODY-SNTL not gzip"),
        EXECUTED,
        None,
    ),
    "accepted_201_short_content_length": (
        _response(b"HTTP/1.1 201 Created", b"", b"BODY-SNTL", length=1000),
        EXECUTED,
        None,
    ),
    "accepted_202_closed_mid_chunk": (
        b"HTTP/1.1 202 X\r\n" + CHUNKED + b"9\r\nBODY-SNTL\r\n",
        EXECUTED,
        None,
    ),
}


class HostileBackend:
    """A TCP server answering every request with fixed bytes.

    ``hold`` keeps the connection open after the bytes are written, until the
    client closes it, which is what lets a test tell "the client stopped
    reading" from "the server hung up".
    """

    def __init__(self, raw: bytes, *, hold: bool = False, dribble: float | None = None) -> None:
        self._raw = raw
        self._hold = hold
        #: Seconds between single header bytes, written forever after ``raw``.
        self._dribble = dribble
        #: With ``hold``: whether the client closed the connection within one
        #: second of the response being written. A client that reads the body
        #: it was promised does not, because it is waiting for the rest of it.
        self.client_closed_first: bool | None = None
        self.port = 0
        self.connected = asyncio.Event()
        self._writers: list[asyncio.StreamWriter] = []
        self._server: asyncio.AbstractServer | None = None

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        self._writers.append(w)
        head = await r.readuntil(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        if length:
            await r.readexactly(length)
        self.connected.set()
        if self._raw:
            w.write(self._raw)
            await w.drain()
        if self._dribble is not None:
            try:
                while True:
                    w.write(b"X")
                    await w.drain()
                    await asyncio.sleep(self._dribble)
            except (ConnectionError, OSError):
                pass
        if self._hold:
            try:
                await asyncio.wait_for(r.read(), timeout=1.0)
                self.client_closed_first = True
            except TimeoutError:
                self.client_closed_first = False
                await r.read()
        w.close()

    async def __aenter__(self) -> HostileBackend:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        assert self._server is not None
        self._server.close()
        for w in self._writers:
            w.close()
        await self._server.wait_closed()


def _point_at(backend: HostileBackend) -> Any:
    original = BackendWriteClient.__init__

    def patched(self: Any, *args: Any, **kwargs: Any) -> None:
        kwargs["base_url"] = f"http://127.0.0.1:{backend.port}"
        original(self, *args, **kwargs)

    return patch.object(BackendWriteClient, "__init__", patched)


def _chain_text(exc: BaseException) -> str:
    """Everything an exception and its whole chain can say, however it is read."""
    parts: list[str] = []
    seen: set[int] = set()
    stack: list[BaseException | None] = [exc]
    while stack:
        e = stack.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        parts.append(f"{type(e).__name__} {e!s} {e!r} {e.args!r} {vars(e)!r}")
        stack += [e.__cause__, e.__context__]
    parts.append("".join(traceback.format_exception(exc)))
    return "\n".join(parts)


@dataclass
class Outcome:
    status: int | None
    body: str
    escaped: BaseException | None
    audit: str
    entries: list[AuditEntry]
    challenge_status: str | None
    records: list[logging.LogRecord]

    def log_text(self) -> str:
        return "\n".join(
            f"{r.name} {r.levelname} {r.getMessage()} {r.args!r} {r.exc_text}" for r in self.records
        )


async def _drive(
    app: Any,
    clean: Any,
    key_pair: RSAKeyPair,
    caplog: pytest.LogCaptureFixture,
    backend: HostileBackend,
    cid: str,
) -> Outcome:
    caplog.set_level(logging.DEBUG)
    await seed(clean, cid)
    status: int | None = None
    body = ""
    escaped: BaseException | None = None
    with _point_at(backend):
        try:
            resp = await post(app, cid, await signed(app, cid), bearer(key_pair, OWNER))
            status, body = resp.status_code, resp.text
        except Exception as exc:  # what the ASGI server would log with exc_info
            escaped = exc
    entries = await rows(clean)
    audit = json.dumps(
        [{c.name: getattr(e, c.name) for c in AuditEntry.__table__.columns} for e in entries],
        default=str,
    )
    async with clean.sessionmaker() as s:
        record = (
            await s.execute(select(ChallengeRecord).where(ChallengeRecord.challenge_id == cid))
        ).scalar_one()
        challenge_status = record.status
    return Outcome(status, body, escaped, audit, entries, challenge_status, list(caplog.records))


@pytest.mark.parametrize("case", list(CASES))
async def test_hostile_response_over_a_real_socket(
    case: str,
    app: Any,
    clean: Any,
    key_pair: RSAKeyPair,
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw, expected, backend_status = CASES[case]
    async with HostileBackend(raw) as backend:
        out = await _drive(
            app, clean, key_pair, caplog, backend, f"chal_h_{list(CASES).index(case):02d}"
        )

    # 1. Nothing from the backend, anywhere.
    assert not _leaks(out.body), out.body
    assert not _leaks(out.audit), out.audit
    assert not _leaks(out.log_text()), out.log_text()
    if out.escaped is not None:
        assert not _leaks(_chain_text(out.escaped)), _chain_text(out.escaped)

    # 2. What the approval did.
    if expected == EXECUTED:
        assert out.escaped is None
        assert out.status == 200, out.body
        assert json.loads(out.body)["status"] == "executed"
        assert out.challenge_status == "executed"
    elif expected == REFUSED:
        assert out.escaped is None
        assert out.status == 207, out.body
        assert json.loads(out.body)["backend_status"] == backend_status
        assert out.challenge_status == "approved"
        assert out.entries[-1].detail == "BackendWriteError"
    else:
        # No status ever arrived: 502 `outcome_unknown` with a fixed body. The
        # exception's own shape (fixed text, no chain) is pinned by
        # `tests/test_execute.py`; it no longer leaves the handler.
        assert out.escaped is None
        assert out.status == 502, out.body
        sent = json.loads(out.body)
        assert sent.pop("challenge_id").startswith("chal_h_")
        assert sent == {
            "status": "approved",
            "execution": "outcome_unknown",
            "message": (
                "the backend call failed after the approval was recorded; the payment may or "
                "may not have been made; do not retry, it will be reconciled"
            ),
        }
        assert out.challenge_status == "approved"
        # The evidence keeps naming the ORIGINAL type, not the wrapper.
        assert [e.outcome for e in out.entries] == ["reaching", "raised"]
        assert out.entries[-1].detail == "RemoteProtocolError"
        errors = [r for r in out.records if r.levelno >= logging.ERROR]
        assert any("RemoteProtocolError" in r.getMessage() for r in errors)


#: Status-line edge cases the operator's backend must not rely on. A transport
#: failure leaves the row `approved` and answers 502 EVEN IF the backend
#: accepted the write: reconcile by `Idempotency-Key` (the challenge id).
STATUS_LINE_EDGES: dict[str, tuple[bytes, str]] = {
    "101_upgrade_is_a_transport_failure": (
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        ESCAPES,
    ),
    "http_9_9_201_is_accepted": (
        b"HTTP/9.9 201 Created\r\nContent-Length: 0\r\n\r\n",
        EXECUTED,
    ),
    "201_with_a_refused_header_block_is_a_transport_failure": (
        b"HTTP/1.1 201 Created\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
        ESCAPES,
    ),
}


@pytest.mark.parametrize("case", list(STATUS_LINE_EDGES))
async def test_status_line_edge_cases(
    case: str,
    app: Any,
    clean: Any,
    key_pair: RSAKeyPair,
    caplog: pytest.LogCaptureFixture,
) -> None:
    raw, expected = STATUS_LINE_EDGES[case]
    cid = f"chal_e_{list(STATUS_LINE_EDGES).index(case):02d}"
    async with HostileBackend(raw) as backend:
        out = await _drive(app, clean, key_pair, caplog, backend, cid)
    if expected == EXECUTED:
        assert out.escaped is None and out.status == 200, (out.status, out.escaped)
        assert out.challenge_status == "executed"
    else:
        assert out.escaped is None
        assert out.status == 502, out.body
        assert json.loads(out.body)["execution"] == "outcome_unknown"
        assert out.challenge_status == "approved"
        assert [e.outcome for e in out.entries] == ["reaching", "raised"]


async def test_a_body_that_never_arrives_is_not_waited_for(
    app: Any, clean: Any, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    """A 200 promising 50 MB and sending 1 KB, then silence: the status is enough.

    `post()` would buffer the body and sit in the read timeout (10 s here), so
    the bound below is the whole test.
    """
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 52428800\r\n\r\n" + b"A" * 1024
    async with HostileBackend(raw, hold=True) as backend:
        out = await asyncio.wait_for(
            _drive(app, clean, key_pair, caplog, backend, "chal_h_endless"), timeout=3
        )

    assert out.escaped is None
    assert out.status == 200, out.body
    assert out.challenge_status == "executed"


async def test_the_client_closes_the_connection_without_reading_the_body(
    app: Any, clean: Any, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    """Structural, not a stopwatch: the server sees the client hang up first.

    The backend promises 50 MB, sends 1 KB and waits one second for the client
    to close. A client that read the body would still be waiting for the rest
    when that second ended, so ``client_closed_first`` is the proof that nothing
    reads it. The 3-second bound in the test above is a second, independent net.
    """
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 52428800\r\n\r\n" + b"A" * 1024
    async with HostileBackend(raw, hold=True) as backend:
        out = await asyncio.wait_for(
            _drive(app, clean, key_pair, caplog, backend, "chal_h_closefirst"), timeout=60
        )
        assert out.status == 200, out.body
        await asyncio.sleep(1.2)  # the server's one-second window closes
    assert backend.client_closed_first is True


async def test_a_backend_that_dribbles_its_headers_is_cut_off_at_the_total_bound(
    app: Any,
    clean: Any,
    key_pair: RSAKeyPair,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One header byte per 0.2 s never trips the 10 s per-read timeout.

    Measured before the total bound: 1 byte per 2 s kept an approval pending at
    40 s, and the ceiling was days. The row stays `approved`, the audit detail is
    `TotalTimeout`, and the answer is the 502 every transport failure gets.
    """
    from services.confirm import execute as execute_module

    monkeypatch.setattr(execute_module, "WRITE_TOTAL_TIMEOUT_SECONDS", 1.0)
    raw = b"HTTP/1.1 200 OK\r\nX-Dribble: "
    async with HostileBackend(raw, dribble=0.2) as backend:
        started = asyncio.get_running_loop().time()
        out = await asyncio.wait_for(
            _drive(app, clean, key_pair, caplog, backend, "chal_h_dribble"), timeout=8
        )
        elapsed = asyncio.get_running_loop().time() - started

    assert elapsed < 6, elapsed
    assert out.escaped is None
    assert out.status == 502, out.body
    assert json.loads(out.body)["execution"] == "outcome_unknown"
    assert out.challenge_status == "approved"
    assert [e.outcome for e in out.entries] == ["reaching", "raised"]
    assert out.entries[-1].detail == "TotalTimeout"
    assert not _leaks(out.audit)


async def test_a_cancelled_request_is_not_swallowed(
    app: Any, clean: Any, key_pair: RSAKeyPair, caplog: pytest.LogCaptureFixture
) -> None:
    """The backend accepts the connection and never answers; the caller goes away."""
    caplog.set_level(logging.DEBUG)
    cid = "chal_h_cancel"
    await seed(clean, cid)
    body = await signed(app, cid)
    headers = bearer(key_pair, OWNER)
    async with HostileBackend(b"", hold=True) as backend:
        with _point_at(backend):
            task = asyncio.create_task(post(app, cid, body, headers))
            await asyncio.wait_for(backend.connected.wait(), timeout=5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


def test_the_http_client_loggers_are_pinned_to_warning(settings: Any, key_pair: RSAKeyPair) -> None:
    """httpx2 logs `HTTP Request: POST <url> "HTTP/1.1 500 <reason>"` at INFO and
    httpcore2 logs every response header at DEBUG. Both are backend text."""
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    from tests.fixtures.device_keys import device_key, enrolled_store

    for name in ("httpx2", "httpcore2"):
        logging.getLogger(name).setLevel(logging.NOTSET)
    _, public = device_key("pin-test-phone")
    create_confirm_app(
        settings,
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=enrolled_store(OWNER, public),
    )
    assert logging.getLogger("httpx2").level == logging.WARNING
    assert logging.getLogger("httpcore2").level == logging.WARNING

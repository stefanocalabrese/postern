"""A transport failure after the request was sent answers 502 `outcome_unknown`.

Until this change a `BackendTransportError` (``ConnectError``, ``ReadTimeout``,
``RemoteProtocolError``, ``TotalTimeout``, ...) propagated out of `_approve` to
`approve_challenge`'s outer ``except Exception``, which wrote the completion row
and re-raised: the app got Starlette's bare text 500 and could not tell "the
backend may or may not have made the payment" from an internal crash.

What is pinned here, over a real socket and a real Postgres:

* one status (502) and one fixed body for every kind, with no backend text;
* the claim stays committed: the row is `approved`, nothing retries, and a second
  approval is refused 409 without calling the backend again;
* the completion row is still written (`raised`, detail = the ORIGINAL kind) and
  its failure still fails the request (decision 0006);
* exactly one ERROR line, with the challenge id and the kind, and no exception text;
* a cancellation is not turned into a 502, and any other exception keeps today's
  behaviour.
"""

from __future__ import annotations

# The fixtures are imported from `tests/test_write_audit.py`, which is what F811
# reports on every test that names one.
# ruff: noqa: F811
import asyncio
import json
import logging
import socket
from typing import Any
from unittest.mock import patch

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from postern_core.store import audit as audit_store
from postern_core.store import challenges as store
from postern_core.store.models import AuditEntry

from services.confirm.execute import BackendWriteClient
from tests.test_backend_hostile_responses import HostileBackend, _leaks
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

MESSAGE = (
    "the backend call failed after the approval was recorded; the payment may or "
    "may not have been made; do not retry, it will be reconciled"
)


def expected_body(cid: str) -> dict[str, str]:
    return {
        "challenge_id": cid,
        "status": "approved",
        "execution": "outcome_unknown",
        "message": MESSAGE,
    }


class CountingBackend(HostileBackend):
    """The raw-socket server, counting the connections it accepted."""

    def __init__(self, raw: bytes, **kw: Any) -> None:
        super().__init__(raw, **kw)
        self.accepted = 0

    async def __aenter__(self) -> CountingBackend:
        await super().__aenter__()
        return self

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        self.accepted += 1
        await super()._handle(r, w)


def _refused_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


class Calls:
    """Counts `BackendWriteClient.execute` calls and points the client at a port."""

    def __init__(self, port: int, timeout: float | None = None) -> None:
        self.port = port
        self.timeout = timeout
        self.executes = 0

    def __enter__(self) -> Calls:
        original_init = BackendWriteClient.__init__
        original_execute = BackendWriteClient.execute
        outer = self

        def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
            kwargs["base_url"] = f"http://127.0.0.1:{outer.port}"
            if outer.timeout is not None:
                kwargs["timeout"] = outer.timeout
            original_init(self, *args, **kwargs)

        async def counting(self: Any, **kwargs: Any) -> int:
            outer.executes += 1
            return await original_execute(self, **kwargs)

        self._patches: list[Any] = [
            patch.object(BackendWriteClient, "__init__", patched_init),
            patch.object(BackendWriteClient, "execute", counting),
        ]
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc: object) -> None:
        for p in self._patches:
            p.stop()


CASES = ["ConnectError", "ReadTimeout", "RemoteProtocolError", "TotalTimeout"]


async def _run_case(
    kind: str,
    app: Any,
    clean: Any,
    key_pair: RSAKeyPair,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    cid: str,
    *,
    second_approval: bool = False,
) -> tuple[httpx2.Response, CountingBackend | None, Calls, httpx2.Response | None]:
    from services.confirm import execute as execute_module

    caplog.set_level(logging.DEBUG)
    await seed(clean, cid)
    backend: CountingBackend | None = None
    timeout: float | None = None
    if kind == "ConnectError":
        port = _refused_port()
    elif kind == "ReadTimeout":
        backend = CountingBackend(b"", hold=True)
        timeout = 0.5
    elif kind == "RemoteProtocolError":
        backend = CountingBackend(b"HTTP/1.1 5x0 STATUS-SNTL\r\nContent-Length: 0\r\n\r\n")
    else:
        monkeypatch.setattr(execute_module, "WRITE_TOTAL_TIMEOUT_SECONDS", 1.0)
        backend = CountingBackend(b"HTTP/1.1 200 OK\r\nX-Dribble: ", dribble=0.2)
    second: httpx2.Response | None = None
    if backend is not None:
        await backend.__aenter__()
        port = backend.port
    try:
        with Calls(port, timeout) as calls:
            first = await post(
                app, cid, await signed(app, cid), bearer(key_pair, OWNER), as_a_server_would=True
            )
            if second_approval:
                second = await post(
                    app,
                    cid,
                    await signed(app, cid),
                    bearer(key_pair, OWNER),
                    as_a_server_would=True,
                )
    finally:
        if backend is not None:
            await backend.__aexit__(None, None, None)
    return first, backend, calls, second


@pytest.mark.parametrize("kind", CASES)
async def test_a_transport_failure_after_the_approval_is_a_502_outcome_unknown(
    kind: str,
    app: Any,
    clean: Any,
    key_pair: RSAKeyPair,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cid = f"chal_ou_{kind.lower()}"
    resp, backend, calls, _ = await _run_case(kind, app, clean, key_pair, caplog, monkeypatch, cid)

    assert resp.status_code == 502, resp.text
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json() == expected_body(cid)

    # The claim stays committed and nothing is retried.
    async with clean.sessionmaker() as s:
        row = await store.get_challenge(s, cid)
        assert row is not None and row.status == "approved"
    assert calls.executes == 1
    if backend is not None:
        assert backend.accepted <= 1

    # The completion row is the one the old path wrote, naming the ORIGINAL kind.
    entries: list[AuditEntry] = await rows(clean)
    assert [e.outcome for e in entries] == ["reaching", "raised"]
    assert entries[-1].detail == kind

    # One ERROR line: the id, the tool and the kind, and nothing from the server.
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1, [r.getMessage() for r in errors]
    line = errors[0].getMessage()
    assert cid in line and kind in line and "outcome unknown" in line
    assert "Idempotency-Key" in line
    assert errors[0].exc_info is None and errors[0].exc_text is None
    everything = "\n".join(
        [resp.text, json.dumps([e.detail for e in entries])]
        + [f"{r.getMessage()} {r.args!r} {r.exc_text}" for r in caplog.records]
    )
    assert not _leaks(everything), everything


@pytest.mark.parametrize("kind", ["ConnectError", "RemoteProtocolError"])
async def test_a_second_approval_is_refused_409_and_the_backend_is_not_called_again(
    kind: str,
    app: Any,
    clean: Any,
    key_pair: RSAKeyPair,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cid = f"chal_ou_twice_{kind.lower()}"
    first, backend, calls, second = await _run_case(
        kind, app, clean, key_pair, caplog, monkeypatch, cid, second_approval=True
    )
    assert first.status_code == 502
    assert second is not None
    assert second.status_code == 409, second.text
    assert second.json()["error"] == "already_terminal"
    assert calls.executes == 1
    if backend is not None:
        assert backend.accepted == 1
    async with clean.sessionmaker() as s:
        row = await store.get_challenge(s, cid)
        assert row is not None and row.status == "approved"


async def test_a_cancellation_during_the_backend_call_is_not_a_502(
    app: Any, clean: Any, key_pair: RSAKeyPair
) -> None:
    cid = "chal_ou_cancel"
    await seed(clean, cid)
    body = await signed(app, cid)
    headers = bearer(key_pair, OWNER)
    async with CountingBackend(b"", hold=True) as backend:
        with Calls(backend.port):
            task = asyncio.create_task(post(app, cid, body, headers, as_a_server_would=True))
            await asyncio.wait_for(backend.connected.wait(), timeout=5)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    entries = await rows(clean)
    assert [e.outcome for e in entries] == ["reaching"]


async def test_any_other_exception_from_the_client_keeps_todays_behaviour(
    app: Any, clean: Any, key_pair: RSAKeyPair
) -> None:
    cid = "chal_ou_bug2"
    await seed(clean, cid)

    async def boom(self: Any, **kwargs: Any) -> int:
        raise RuntimeError("bug")

    with patch.object(BackendWriteClient, "execute", boom):
        resp = await post(
            app, cid, await signed(app, cid), bearer(key_pair, OWNER), as_a_server_would=True
        )
    assert resp.status_code == 500
    assert "outcome_unknown" not in resp.text
    entries = await rows(clean)
    assert [e.detail for e in entries] == ["RuntimeError"]
    with patch.object(BackendWriteClient, "execute", boom):
        with pytest.raises(RuntimeError):
            await seed(clean, "chal_ou_bug3")
            await post(
                app, "chal_ou_bug3", await signed(app, "chal_ou_bug3"), bearer(key_pair, OWNER)
            )


async def test_a_failed_completion_write_after_a_transport_failure_still_fails_the_request(
    app: Any, clean: Any, key_pair: RSAKeyPair
) -> None:
    cid = "chal_ou_auditfail"
    await seed(clean, cid)
    real_append = audit_store.append

    async def only_the_entry_row_is_written(session: Any, **kw: Any) -> None:
        if kw["outcome"] == "reaching":
            await real_append(session, **kw)
            return
        raise RuntimeError("audit store unavailable")

    async with CountingBackend(b"HTTP/1.1 5x0 STATUS-SNTL\r\nContent-Length: 0\r\n\r\n") as b:
        with Calls(b.port) as calls:
            with patch.object(audit_store, "append", only_the_entry_row_is_written):
                resp = await post(
                    app,
                    cid,
                    await signed(app, cid),
                    bearer(key_pair, OWNER),
                    as_a_server_would=True,
                )
    assert resp.status_code == 500
    assert "outcome_unknown" not in resp.text
    assert calls.executes == 1 and b.accepted == 1
    (entry,) = await rows(clean)
    assert entry.outcome == "reaching"

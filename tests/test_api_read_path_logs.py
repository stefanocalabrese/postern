"""A failing read tool leaves no backend or transport text in any log or on stderr.

FastMCP's own logger (`fastmcp.server.server`) logs a failing tool's exception
WITH ITS TEXT and its chain, through its own handler (`propagate` False) onto
stderr. Measured before the fix: ``BackendError: 500: {'error': 'db said ...'}``
(the scrubbed backend body) and, for a transport failure, the `httpx2`
exception text with the host and port.

This drives the real `create_app` over HTTP with a hostile backend and listens
on EVERY logger, `fastmcp.server.server` included, plus the process's stderr.
The assertion that a record from `fastmcp.server.server` exists is what keeps
the rest from passing vacuously.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from typing import Any

import httpx2
import pytest
from fastmcp.server.auth.providers.jwt import RSAKeyPair

from tests.test_audit_reserve import token_for
from tests.test_not_found_mapping import (  # noqa: F401  (fixtures)
    CUSTOMER,
    _call,
    _text,
    key_pair,
    serving,
)

SENTINEL = "zzsentinel_logs_6620"
HOST = "10.77.66.55"
PORT = "7391"
DSN = "postgresql://svc:hunter2pw@db.internal:5432/core"
FORBIDDEN = (SENTINEL, HOST, PORT, "hunter2pw", "db.internal", "4111111111111111")


class _Collector(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.NOTSET)
        self.rendered: list[str] = []
        self.names: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        text = record.getMessage()
        if record.exc_info:
            text += "\n" + logging.Formatter().formatException(record.exc_info)
        if record.stack_info:
            text += "\n" + record.stack_info
        self.rendered.append(text)
        self.names.append(record.name)


@pytest.fixture
def every_logger() -> Iterator[_Collector]:
    collector = _Collector()
    attached: list[tuple[logging.Logger, int]] = []
    loggers = [logging.getLogger()] + [
        item
        for item in logging.root.manager.loggerDict.values()
        if isinstance(item, logging.Logger)
    ]
    loggers.append(logging.getLogger("fastmcp.server.server"))
    for logger in loggers:
        attached.append((logger, logger.level))
        logger.addHandler(collector)
        logger.setLevel(logging.DEBUG)
    yield collector
    for logger, level in attached:
        logger.removeHandler(collector)
        logger.setLevel(level)


def _answering(status: int, body: str) -> Callable[[httpx2.Request], httpx2.Response]:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, json={"error": body, "detail": body})

    return handler


def _failing(exc: Exception) -> Callable[[httpx2.Request], httpx2.Response]:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise exc

    return handler


_HOSTILE = f"db said {SENTINEL} •••• 1111 4111111111111111 {DSN}"
_ENDPOINT = f"{HOST}:{PORT}"

_BACKENDS: dict[str, Callable[[httpx2.Request], httpx2.Response]] = {
    "500-body": _answering(500, _HOSTILE),
    "503-body": _answering(503, _HOSTILE),
    "connect-error": _failing(httpx2.ConnectError(f"[Errno 61] connect to {_ENDPOINT} {SENTINEL}")),
    "read-timeout": _failing(httpx2.ReadTimeout(f"timed out reading {_ENDPOINT} {SENTINEL}")),
    "decoding-error": _failing(httpx2.DecodingError(f"bad gzip from {_ENDPOINT} {SENTINEL}")),
    "protocol-error": _failing(httpx2.RemoteProtocolError(f"illegal line {_ENDPOINT} {SENTINEL}")),
}


@pytest.mark.parametrize("tool", ["accounts.get_balance", "transactions.list"])
@pytest.mark.parametrize("scenario", sorted(_BACKENDS))
async def test_no_backend_or_transport_text_reaches_any_log_or_stderr(
    serving: Any,  # noqa: F811
    key_pair: RSAKeyPair,  # noqa: F811
    every_logger: _Collector,
    capfd: pytest.CaptureFixture[str],
    tool: str,
    scenario: str,
) -> None:
    app = await serving(_BACKENDS[scenario])
    capfd.readouterr()

    response = await _call(app, token_for(key_pair, CUSTOMER), tool, "acc_unknown1")

    assert _text(response) == f"Error calling tool '{tool}'"
    assert "fastmcp.server.server" in every_logger.names, (
        "FastMCP's own logger wrote nothing, so this test would pass vacuously"
    )
    captured = capfd.readouterr()
    everything = "\n".join([*every_logger.rendered, response.text, captured.out, captured.err])
    for needle in FORBIDDEN:
        assert needle not in everything, f"{needle!r} leaked: {everything[:400]}"


async def test_a_404_still_reads_as_the_fixed_not_found_sentence_and_logs_no_body(
    serving: Any,  # noqa: F811
    key_pair: RSAKeyPair,  # noqa: F811
    every_logger: _Collector,
    capfd: pytest.CaptureFixture[str],
) -> None:
    from services.api.tools.not_found import NOT_FOUND

    app = await serving(_answering(404, _HOSTILE))
    capfd.readouterr()

    response = await _call(app, token_for(key_pair, CUSTOMER), "accounts.get_balance", "acc_x1")

    assert _text(response) == NOT_FOUND
    captured = capfd.readouterr()
    everything = "\n".join([*every_logger.rendered, captured.out, captured.err])
    for needle in FORBIDDEN:
        assert needle not in everything

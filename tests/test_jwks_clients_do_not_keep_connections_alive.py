"""The two long-lived JWKS clients open a connection per fetch.

Both verifiers hold one `httpx2.AsyncClient` for the life of the process and fetch
30 to 300 seconds apart. A kept-alive connection reused after that gap races the
server's idle timeout: when the server closed it just before the request was
written, the fetch fails with `RemoteProtocolError`, and the next one recovers. On
the api, a failed refresh after the TTL means every customer is refused until the
floor passes, so reuse buys nothing and costs a refusal. Both clients are built with
`limits=httpx2.Limits(max_keepalive_connections=0)`.

The raw-socket server here answers the FIRST request on a connection and then drops
the connection on the SECOND request without a response, which is what a server that
closed an idle connection looks like to a client that reused it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import socket
import threading
from collections.abc import Iterator
from typing import Any

import pytest

from services.api.server import build_server
from services.api.settings import Settings
from services.confirm.main import _assertion_verifier
from services.confirm.settings import ConfirmSettings

_BODY = b'{"keys": []}'
_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n"
    b"Content-Length: " + str(len(_BODY)).encode() + b"\r\n\r\n" + _BODY
)


class _DropsTheSecondRequest:
    def __init__(self) -> None:
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port: int = self._listener.getsockname()[1]
        self.connections = 0
        self._stop = False
        self._thread = threading.Thread(target=self._accept, daemon=True)

    def _accept(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        conn.settimeout(10)
        try:
            for answered in range(2):
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(65536)
                    if not chunk:
                        return
                    data += chunk
                if answered == 1:
                    return  # the second request on one connection is dropped unanswered
                conn.sendall(_RESPONSE)
        except OSError:
            pass
        finally:
            conn.close()

    def __enter__(self) -> _DropsTheSecondRequest:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop = True
        self._listener.close()


@pytest.fixture
def server() -> Iterator[_DropsTheSecondRequest]:
    with _DropsTheSecondRequest() as running:
        yield running


def _api_verifier(url: str) -> Any:
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri=f"{url}/session/jwks.json",
        customer_token_issuer="https://issuer.test",  # noqa: S106
        audience="https://mcp.postern.test/mcp",
    )
    return build_server(settings, None, None).auth  # type: ignore[arg-type]


def _confirm_verifier(url: str) -> Any:
    return _assertion_verifier(
        dataclasses.replace(
            ConfirmSettings.for_testing(), app_assertion_jwks_uri=f"{url}/.well-known/jwks.json"
        )
    )


@pytest.mark.parametrize("build", [_api_verifier, _confirm_verifier])
def test_the_client_keeps_no_connection_alive(build: Any) -> None:
    verifier = build("http://127.0.0.1:1")
    assert verifier._http_client._transport._pool._max_keepalive_connections == 0


@pytest.mark.parametrize("build", [_api_verifier, _confirm_verifier])
async def test_a_server_that_closed_the_connection_does_not_fail_the_second_fetch(
    build: Any, server: _DropsTheSecondRequest
) -> None:
    verifier = build(f"http://127.0.0.1:{server.port}")
    first = await asyncio.wait_for(verifier._fetch_jwks(), timeout=10)
    second = await asyncio.wait_for(verifier._fetch_jwks(), timeout=10)
    assert first == second == {"keys": []}
    assert server.connections == 2

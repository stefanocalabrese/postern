"""Every production HTTP client ignores the proxy environment.

``httpx2`` builds a client with ``trust_env=True`` unless told otherwise, and then
``HTTP_PROXY`` / ``HTTPS_PROXY`` / ``ALL_PROXY`` route its requests through the
named host (measured 7 October 2026: a proxy received ``POST http://.../cancel`` with
the signed write JWT in ``Authorization``, the ``Idempotency-Key`` and the payment
payload, and its own 201 was recorded as ``executed``), and ``SSL_CERT_FILE`` /
``SSL_CERT_DIR`` replace the CA bundle. Proxy environment variables are ignored;
egress is routed by the network (PrivateLink, security groups), not by
``HTTP_PROXY``.

Each client gets two kinds of test: a real request with every proxy variable set to
a capture server (the proxy sees zero connections and the real server sees the
request), and construction with ``SSL_CERT_FILE`` naming a file that does not
exist (a client that honours it raises ``FileNotFoundError``).

``tests/test_http_clients_trust_env_scan.py`` is the net for a client added later.
"""

from __future__ import annotations

import dataclasses
import socketserver
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from postern_core.auth.vault import VaultTransitKeySource
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerRef

from services.api.server import build_server
from services.api.session_verifier import SessionTokenVerifier
from services.api.settings import Settings
from services.confirm.execute import BackendWriteClient
from services.confirm.main import _assertion_verifier
from services.confirm.settings import ConfirmSettings

_VAULT_TOKEN = "hvs.notarealtoken"  # noqa: S105
_ANSWER = b'{"keys": []}'
_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
    b"Content-Length: " + str(len(_ANSWER)).encode() + b"\r\n\r\n" + _ANSWER
)
_PROXY_VARIABLES = (
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
)


class _Capture:
    """A threaded TCP server that counts connections and records request lines."""

    def __init__(self) -> None:
        capture = self
        self.connections = 0
        self.request_lines: list[str] = []

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                capture.connections += 1
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = self.request.recv(65536)
                    if not chunk:
                        return
                    data += chunk
                head, _, rest = data.partition(b"\r\n\r\n")
                capture.request_lines.append(head.split(b"\r\n")[0].decode("latin-1"))
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":")[1])
                while len(rest) < length:
                    chunk = self.request.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
                self.request.sendall(_RESPONSE)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self._server = Server(("127.0.0.1", 0), Handler)
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> _Capture:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture
def servers(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[_Capture, _Capture]]:
    """(proxy, real): every proxy variable names ``proxy``, no bypass list is set."""
    with _Capture() as proxy, _Capture() as real:
        for name in _PROXY_VARIABLES:
            monkeypatch.setenv(name, f"http://127.0.0.1:{proxy.port}")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        yield proxy, real


def _assert_direct(proxy: _Capture, real: _Capture) -> None:
    assert proxy.connections == 0, proxy.request_lines
    assert real.connections == 1
    assert real.request_lines


class _Minter:
    def mint(self, *, subject_value: str, audience: str, scope: str, challenge_id: str = "") -> str:
        return "stub.write.token"


async def test_the_write_client_does_not_send_a_request_to_a_proxy(
    servers: tuple[_Capture, _Capture],
) -> None:
    proxy, real = servers
    client = BackendWriteClient(
        f"http://127.0.0.1:{real.port}", _Minter(), before_backend_request=None
    )
    status = await client.execute(
        customer_ref="cust_1",
        audience="payments.svc",
        path="/payments",
        body={"amount": "1.00"},
        challenge_id="chal_proxy",
    )
    assert status == 200
    _assert_direct(proxy, real)


async def test_the_facade_client_does_not_send_a_request_to_a_proxy(
    servers: tuple[_Capture, _Capture],
) -> None:
    proxy, real = servers
    client = BackendClient(
        f"http://127.0.0.1:{real.port}",
        lambda customer, audience: "stub.read.token",
        before_backend_request=None,
    )
    assert await client.get_json("/accounts", customer=CustomerRef(value="cust_1")) == {"keys": []}
    _assert_direct(proxy, real)


def test_the_vault_client_does_not_send_a_request_to_a_proxy(
    servers: tuple[_Capture, _Capture],
) -> None:
    proxy, real = servers
    source = VaultTransitKeySource(
        address=f"http://127.0.0.1:{real.port}",
        key_name="k",
        kid="postern-read",
        token=_VAULT_TOKEN,
    )
    with pytest.raises(Exception):  # noqa: B017, PT011  (the answer is not a Vault key document)
        source.public_jwks()
    _assert_direct(proxy, real)


async def test_the_api_session_verifier_does_not_send_a_request_to_a_proxy(
    servers: tuple[_Capture, _Capture],
) -> None:
    proxy, real = servers
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri=f"http://127.0.0.1:{real.port}/session/jwks.json",
        customer_token_issuer="https://issuer.test",  # noqa: S106
        audience="https://mcp.postern.test/mcp",
    )
    verifier = build_server(settings, None, None).auth  # type: ignore[arg-type]
    assert isinstance(verifier, SessionTokenVerifier)
    assert await verifier._fetch_jwks() == {"keys": []}
    _assert_direct(proxy, real)


async def test_the_confirm_assertion_verifier_does_not_send_a_request_to_a_proxy(
    servers: tuple[_Capture, _Capture],
) -> None:
    proxy, real = servers
    settings = dataclasses.replace(
        ConfirmSettings.for_testing(),
        app_assertion_jwks_uri=f"http://127.0.0.1:{real.port}/.well-known/jwks.json",
    )
    verifier: Any = _assertion_verifier(settings)
    assert await verifier._fetch_jwks() == {"keys": []}
    _assert_direct(proxy, real)


# -- SSL_CERT_FILE: a client that honours it cannot even be built ---------


@pytest.fixture
def bogus_ca_bundle(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "no-such-bundle.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "no-such-dir"))


def test_the_write_client_ignores_ssl_cert_file(bogus_ca_bundle: None) -> None:
    client = BackendWriteClient("https://payments.test", _Minter(), before_backend_request=None)
    assert client._client.trust_env is False


def test_the_facade_client_ignores_ssl_cert_file(bogus_ca_bundle: None) -> None:
    client = BackendClient("https://backend.test", lambda c, a: "t", before_backend_request=None)
    assert client._client.trust_env is False


def test_the_vault_client_ignores_ssl_cert_file(bogus_ca_bundle: None) -> None:
    source = VaultTransitKeySource(
        address="https://vault.test:8200", key_name="k", kid="postern-read", token=_VAULT_TOKEN
    )
    assert source._client.trust_env is False


def test_both_jwks_verifier_clients_ignore_ssl_cert_file(bogus_ca_bundle: None) -> None:
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri="https://issuer.test/jwks.json",
        customer_token_issuer="https://issuer.test",  # noqa: S106
        audience="https://mcp.postern.test/mcp",
    )
    api_verifier: Any = build_server(settings, None, None).auth  # type: ignore[arg-type]
    confirm_verifier: Any = _assertion_verifier(ConfirmSettings.for_testing())
    assert api_verifier._http_client.trust_env is False
    assert confirm_verifier._http_client.trust_env is False

"""A CA bundle override in the process environment refuses startup, on both services.

WHY THIS EXISTS. ``trust_env=False`` on every production HTTP client stops
``HTTP_PROXY`` and friends. It does NOT stop ``SSL_CERT_FILE`` and ``SSL_CERT_DIR``
on Linux: ``httpx2`` builds its context with ``truststore.SSLContext``, whose Linux
backend calls ``ssl.get_default_verify_paths()`` and ``set_default_verify_paths()``,
and OpenSSL reads both variables there whatever the client's flag says. redis-py's
TLS connection calls ``ssl.create_default_context()``, which reads them too. Measured
7 October 2026 in the ``postern-confirm`` image (Debian, Python 3.12.14): with the
variable set, the write client, the Vault client and a JWKS client all accepted a
server certificate signed by a throwaway CA, and without it every one failed the
handshake. macOS ``truststore`` uses Security.framework and ignores both variables,
so a developer's machine cannot observe the defect.

So the control is a refusal to start (`enforce_no_ca_bundle_override`), pinned here
by the real startup path of both services. Those tests are platform independent:
the environment is read as a name, never as a value. The Linux-only class at the
bottom is the proof that the refusal is needed, and it is skipped elsewhere with
a reason.

``REQUESTS_CA_BUNDLE`` and ``CURL_CA_BUNDLE`` are NOT refused: nothing in this stack
reads them (``requests`` and ``curl`` do, and neither is a dependency).
"""

from __future__ import annotations

import asyncio
import dataclasses
import datetime
import ipaddress
import platform
import socket
import ssl
import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastmcp.server.auth.providers.jwt import JWTVerifier, RSAKeyPair
from postern_core.auth.device_keys import no_enrolled_devices
from postern_core.auth.vault import VaultTransitKeySource
from postern_core.env_inventory import CA_BUNDLE_OVERRIDE_ENV, enforce_no_ca_bundle_override
from postern_core.facade.client import BackendClient
from postern_core.identity import CustomerRef

from services.api.main import create_app
from services.api.server import build_server
from services.api.settings import Settings
from services.confirm.execute import BackendWriteClient
from services.confirm.main import _assertion_verifier, create_confirm_app
from services.confirm.settings import ConfirmSettings
from tests.test_device_grant import AUDIENCE, ISSUER

_SECRET_PATH = "/run/secrets/very-private-ca-bundle-7f3a.pem"  # noqa: S105


@pytest.fixture(autouse=True)
def _clean_ca_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (*CA_BUNDLE_OVERRIDE_ENV, "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(scope="module")
def key_pair() -> RSAKeyPair:
    return RSAKeyPair.generate()


def _confirm(key_pair: RSAKeyPair) -> object:
    return create_confirm_app(
        ConfirmSettings.for_testing(),
        assertion_verifier=JWTVerifier(
            public_key=key_pair.public_key, issuer=ISSUER, audience=AUDIENCE
        ),
        device_key_store=no_enrolled_devices(),
    )


def test_the_refused_names_are_exactly_the_two_openssl_reads() -> None:
    assert CA_BUNDLE_OVERRIDE_ENV == ("SSL_CERT_FILE", "SSL_CERT_DIR")


@pytest.mark.parametrize("name", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
class TestTheRealStartupPathRefuses:
    def test_the_read_path_refuses_to_build(
        self, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(name, _SECRET_PATH)
        with pytest.raises(RuntimeError, match=name) as excinfo:
            create_app(Settings.for_testing())
        message = str(excinfo.value)
        assert "install a private CA into the image's system trust store" in message
        assert _SECRET_PATH not in message

    def test_the_write_path_refuses_to_build(
        self, name: str, key_pair: RSAKeyPair, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(name, _SECRET_PATH)
        with pytest.raises(RuntimeError, match=name) as excinfo:
            _confirm(key_pair)
        message = str(excinfo.value)
        assert "install a private CA into the image's system trust store" in message
        assert _SECRET_PATH not in message

    def test_the_function_itself_refuses_for_either_service(
        self, name: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(name, _SECRET_PATH)
        for service in ("api", "confirm"):
            with pytest.raises(RuntimeError, match=name):
                enforce_no_ca_bundle_override(service=service)


def test_both_names_are_listed_when_both_are_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", _SECRET_PATH)
    monkeypatch.setenv("SSL_CERT_DIR", _SECRET_PATH)
    with pytest.raises(RuntimeError) as excinfo:
        enforce_no_ca_bundle_override(service="api")
    assert "SSL_CERT_FILE" in str(excinfo.value)
    assert "SSL_CERT_DIR" in str(excinfo.value)
    assert _SECRET_PATH not in str(excinfo.value)


def test_both_services_start_without_an_override(key_pair: RSAKeyPair) -> None:
    assert create_app(Settings.for_testing()) is not None
    assert _confirm(key_pair) is not None


@pytest.mark.parametrize("name", ["REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"])
def test_a_variable_nothing_in_this_stack_reads_is_not_refused(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(name, _SECRET_PATH)
    enforce_no_ca_bundle_override(service="api")
    enforce_no_ca_bundle_override(service="confirm")


def test_an_unknown_service_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="stub"):
        enforce_no_ca_bundle_override(service="stub")


# ---------------------------------------------------------------------------
# The proof that the refusal is needed. Linux only: macOS truststore ignores both
# variables, so this cannot fail there for the reason it exists.
# ---------------------------------------------------------------------------


class _TlsServer:
    """A local TLS server whose certificate is signed by a throwaway CA."""

    def __init__(self, directory: Path) -> None:
        now = datetime.datetime.now(datetime.UTC)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "postern throwaway CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        server_key = ec.generate_private_key(ec.SECP256R1())
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        self.ca_file = directory / "ca.pem"
        self.ca_file.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
        cert_file = directory / "server.pem"
        key_file = directory / "server.key"
        cert_file.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(
            server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(str(cert_file), str(key_file))
        self.handshakes = 0
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port: int = self._listener.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}"

    def _serve(self) -> None:
        body = b'{"keys": []}'
        while not self._stop:
            try:
                raw, _ = self._listener.accept()
            except OSError:
                return
            try:
                tls = self._context.wrap_socket(raw, server_side=True)
            except (ssl.SSLError, OSError):
                raw.close()
                continue
            try:
                self.handshakes += 1
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = tls.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                tls.sendall(
                    b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n"
                    b"Connection: close\r\nContent-Length: %d\r\n\r\n" % len(body) + body
                )
            except OSError:
                pass
            finally:
                tls.close()

    def __enter__(self) -> _TlsServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop = True
        self._listener.close()


def _subject_hash(ca_file: Path) -> str:
    """The OpenSSL hashed-directory name of a CA certificate (``<hash>.0``)."""
    return subprocess.run(  # noqa: S603
        ["openssl", "x509", "-noout", "-subject_hash", "-in", str(ca_file)],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


@pytest.fixture
def tls_server(tmp_path: Path) -> Iterator[_TlsServer]:
    with _TlsServer(tmp_path) as server:
        yield server


class _Minter:
    def mint(self, *, subject_value: str, audience: str, scope: str, challenge_id: str = "") -> str:
        return "stub.write.token"


async def _swallow(awaitable: Any) -> None:
    try:
        await asyncio.wait_for(awaitable, timeout=15)
    except Exception:  # noqa: BLE001, S110  (only the handshake is measured, not the answer)
        pass


async def _drive_all_five(url: str) -> None:
    write = BackendWriteClient(url, _Minter(), before_backend_request=None)
    await _swallow(
        write.execute(
            customer_ref="c", audience="payments.svc", path="/p", body={"a": 1}, challenge_id="ch"
        )
    )
    await write.aclose()
    facade = BackendClient(url, lambda c, a: "t", before_backend_request=None)
    await _swallow(facade.get_json("/x", customer=CustomerRef(value="cust_1")))
    vault = VaultTransitKeySource(address=url, key_name="k", kid="r", token="hvs.x")  # noqa: S106
    await _swallow(asyncio.to_thread(vault.public_jwks))
    api_verifier: Any = build_server(
        Settings(
            backend_base_url="https://backend.test",
            customer_jwks_uri=f"{url}/session/jwks.json",
            customer_token_issuer="https://issuer.test",  # noqa: S106
            audience="https://mcp.postern.test/mcp",
        ),
        None,  # type: ignore[arg-type]
        None,
    ).auth
    await _swallow(api_verifier._fetch_jwks())
    confirm_verifier: Any = _assertion_verifier(
        dataclasses.replace(
            ConfirmSettings.for_testing(), app_assertion_jwks_uri=f"{url}/.well-known/jwks.json"
        )
    )
    await _swallow(confirm_verifier._fetch_jwks())


@pytest.mark.skipif(
    platform.system() != "Linux",
    reason="truststore uses Security.framework on macOS and ignores SSL_CERT_FILE there; "
    "the defect this guard exists for can only be observed on Linux",
)
class TestOnLinuxAnOverrideReallyReplacesTheTrustAnchors:
    async def test_without_the_variable_no_client_completes_a_handshake(
        self, tls_server: _TlsServer
    ) -> None:
        await _drive_all_five(tls_server.url)
        assert tls_server.handshakes == 0

    async def test_with_the_variable_every_one_of_the_five_clients_trusts_the_attacker_ca(
        self, tls_server: _TlsServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SSL_CERT_FILE", str(tls_server.ca_file))
        await _drive_all_five(tls_server.url)
        # trust_env=False on all five, and still five completed handshakes.
        assert tls_server.handshakes == 5

    async def test_a_hashed_directory_in_ssl_cert_dir_does_the_same(
        self, tls_server: _TlsServer, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        hashed = _subject_hash(tls_server.ca_file)
        directory = tmp_path / "cadir"
        directory.mkdir()
        (directory / f"{hashed}.0").write_bytes(tls_server.ca_file.read_bytes())
        monkeypatch.setenv("SSL_CERT_DIR", str(directory))
        await _drive_all_five(tls_server.url)
        assert tls_server.handshakes == 5

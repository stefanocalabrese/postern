"""Backend façade client: GET-only, token-minted, error body scrubbed (Task 6).

Backend mocking is at the transport layer with `httpx2.MockTransport`, per
`dev-docs/decisions/0001-facade-http-client.md`. `respx` is not installed and
cannot mock `httpx2`.
"""

from collections.abc import Callable

import httpx2
import pytest
from postern_core.facade.client import BackendClient, BackendError, StubTokenMinter
from postern_core.identity import CustomerRef

CUSTOMER = CustomerRef(value="cust_7f3a")

# A well-known, mod-97-valid example IBAN (the ISO/Wikipedia worked example),
# not a real account, plus a real test PAN (the Visa test-card number).
_TEST_IBAN = "GB29NWBK60161331926819"
_TEST_PAN = "4111111111111111"


def _transport(handler: Callable[[httpx2.Request], httpx2.Response]) -> httpx2.MockTransport:
    return httpx2.MockTransport(handler)


def _ok_client() -> BackendClient:
    """A client whose transport answers every request with a bare 200."""
    return BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=_transport(lambda r: httpx2.Response(200)),
        before_backend_request=None,
    )


async def test_get_json_returns_the_decoded_body() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"accounts": []})

    client = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    assert await client.get_json("/accounts", customer=CUSTOMER) == {"accounts": []}
    await client.aclose()


async def test_get_json_attaches_a_bearer_token() -> None:
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.headers["authorization"])
        return httpx2.Response(200, json={})

    client = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    with pytest.warns(RuntimeWarning, match="StubTokenMinter"):
        await client.get_json("/accounts", customer=CUSTOMER)
    assert seen == ["Bearer stub.read.cust_7f3a"]
    await client.aclose()


async def test_query_parameters_are_forwarded() -> None:
    seen: list[str] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(str(request.url))
        return httpx2.Response(200, json={})

    client = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    await client.get_json("/transactions", customer=CUSTOMER, params={"days": 30})
    assert seen == ["https://backend.test/transactions?days=30"]
    await client.aclose()


async def test_a_404_becomes_an_actionable_backend_error() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(404, json={"detail": "no such account"})

    client = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    with pytest.raises(BackendError) as excinfo:
        await client.get_json("/accounts/acc_missing", customer=CUSTOMER)
    assert excinfo.value.status == 404
    await client.aclose()


async def test_the_client_never_sends_a_write_method() -> None:
    client = _ok_client()
    assert not hasattr(client, "post_json")
    assert not hasattr(client, "put_json")
    await client.aclose()


def test_the_client_class_exposes_no_write_method_of_any_kind() -> None:
    """Belt-and-suspenders on top of the instance-level check above: this
    enumerates the *entire* public surface of the class, so adding any new
    public method -- a write method or otherwise -- fails this test and is
    visible in the diff and in CI, not just to a reviewer who remembers to
    check.
    """
    public_callables = {
        name
        for name in dir(BackendClient)
        if not name.startswith("_") and callable(getattr(BackendClient, name))
    }
    assert public_callables == {"get_json", "aclose"}


# --- Leak path 1 (a backend body reaching a `BackendError`) is closed by ----
# --- carrying no body at all: `tests/test_read_path_exception_text.py`. ----


# --- Leak path 2: `path` must be validated as relative and rooted, or an --
# --- absolute URL / traversal can redirect the request off the intended --
# --- host, carrying the `Authorization` header with it (empirically -------
# --- confirmed: `client.get("https://evil.example/x")` against a client ---
# --- constructed with `base_url="https://backend.test"` reaches ----------
# --- evil.example, not backend.test). --------------------------------------


async def test_get_json_rejects_an_absolute_url_path() -> None:
    client = _ok_client()
    with pytest.raises(ValueError, match="relative"):
        await client.get_json("https://evil.example/steal", customer=CUSTOMER)
    await client.aclose()


async def test_get_json_rejects_a_protocol_relative_path() -> None:
    client = _ok_client()
    with pytest.raises(ValueError, match="relative"):
        await client.get_json("//evil.example/steal", customer=CUSTOMER)
    await client.aclose()


async def test_get_json_rejects_a_path_with_dot_dot_segments() -> None:
    client = _ok_client()
    with pytest.raises(ValueError, match=r"\.\."):
        await client.get_json("/accounts/../../etc/passwd", customer=CUSTOMER)
    await client.aclose()


async def test_get_json_rejects_a_non_rooted_path() -> None:
    client = _ok_client()
    with pytest.raises(ValueError, match="rooted"):
        await client.get_json("accounts", customer=CUSTOMER)
    await client.aclose()


async def test_a_rejected_path_never_reaches_the_transport_or_mints_a_token() -> None:
    called: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        called.append(request)
        return httpx2.Response(200, json={})

    client = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    with pytest.raises(ValueError):
        await client.get_json("https://evil.example/steal", customer=CUSTOMER)
    assert called == []
    await client.aclose()


# --- Redirects: httpx2 does not follow them by default, but the client ----
# --- sets `follow_redirects=False` explicitly rather than relying on that -
# --- default (empirically confirmed separately: `AsyncClient.__init__`'s ---
# --- own default is already `False`). --------------------------------------


async def test_the_client_does_not_follow_a_redirect_to_another_host() -> None:
    hosts_seen: list[str | None] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        hosts_seen.append(request.url.host)
        if request.url.host == "backend.test":
            return httpx2.Response(302, headers={"Location": "https://evil.example/steal"}, json={})
        return httpx2.Response(200, json={"stolen": True})

    client = BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=_transport(handler),
        before_backend_request=None,
    )
    result = await client.get_json("/accounts", customer=CUSTOMER)
    assert hosts_seen == ["backend.test"]
    assert result == {}
    await client.aclose()


# --- StubTokenMinter is a placeholder; it must be loud, not silent. -------


def test_stub_token_minter_warns_on_every_call() -> None:
    with pytest.warns(RuntimeWarning, match="StubTokenMinter"):
        minted = StubTokenMinter()(CUSTOMER, "accounts.svc")
    assert minted == "stub.read.cust_7f3a"

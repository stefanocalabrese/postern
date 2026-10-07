"""Backend, transport, Vault and Redis text stays out of the read path's exceptions.

FastMCP's own logger (`fastmcp.server.server`, its own handler, `propagate`
False, stderr) logs a failing tool's exception WITH ITS TEXT and its chain. So
the only place to stop backend text reaching a log is the exception itself:

* `BackendError` carries the status and a fixed sentence, never the body or URL.
* `BackendUnavailableError` replaces an `httpx2` transport failure: fixed text,
  the original's TYPE NAME as `kind`, `from None`, raised outside the `except`.
* `VaultTransitError` text is fixed plus status or kind: no path, no body.
* The Redis store wrappers re-raise with `from None`, so the chain a traceback
  prints stops at the wrapper and the driver's text (host, port, userinfo)
  never prints.

The write side already did this in `services/confirm/execute.py`
(`BackendWriteError`, `BackendTransportError`); these tests are its read-side
counterpart, and `tests/test_execute.py` is the template.
"""

from __future__ import annotations

import ast
import asyncio
import traceback
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

import httpx2
import pytest
from postern_core.auth import redis_preflight
from postern_core.auth.revocation import RedisRevocationStore, RevocationStoreUnavailable
from postern_core.auth.vault import VaultTransitError, VaultTransitKeySource
from postern_core.facade.client import (
    BackendClient,
    BackendError,
    BackendUnavailableError,
    StubTokenMinter,
)
from postern_core.identity import CustomerRef
from postern_core.risk.context import RiskContext
from postern_core.risk.session import RedisSessionStore, SessionKey, SessionStoreUnavailable
from redis.exceptions import ConnectionError as RedisConnectionError

from services.confirm.customer_rate_limit import (
    CustomerRateLimitStoreUnavailable,
    RedisCustomerRateLimitStore,
)
from services.confirm.rate_limit import Limit
from tests.test_vault_transit_key_source import ADDRESS, TOKEN, FakeVault

ROOT = Path(__file__).resolve().parent.parent
CUSTOMER = CustomerRef(value="cust_exctext01")
SENTINEL = "zzsentinel_text_5531"
PAN = "4111 1111 1111 1111"
IBAN = "ES9121000418450200051332"
DSN = "postgresql://svc:hunter2pw@db.internal:5432/core"
JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"
HOST_PORT = "10.9.8.7:6379"
HOSTILE = f"db said {SENTINEL} {PAN} {IBAN} {DSN} {JWT} {HOST_PORT}"
FORBIDDEN = (SENTINEL, "4111", IBAN, "hunter2pw", "db.internal", JWT, "10.9.8.7", "6379")


def _everything(exc: BaseException) -> str:
    """Every rendering of ``exc`` a logger or a handler could produce."""
    parts = [
        str(exc),
        repr(exc),
        repr(exc.args),
        repr(vars(exc)),
        "".join(traceback.format_exception(exc)),
    ]
    return "\n".join(parts)


def _assert_clean(text: str) -> None:
    for needle in FORBIDDEN:
        assert needle not in text, f"{needle!r} leaked in: {text[:300]}"


def _client(handler: Callable[[httpx2.Request], httpx2.Response]) -> BackendClient:
    return BackendClient(
        "https://backend.test",
        StubTokenMinter(),
        transport=httpx2.MockTransport(handler),
        before_backend_request=None,
    )


# --- the facade: a status answer ---------------------------------------------


@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 502, 503])
@pytest.mark.parametrize("as_json", [True, False], ids=["json", "text"])
async def test_backend_error_carries_the_status_and_a_fixed_sentence(
    status: int, as_json: bool
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        if as_json:
            return httpx2.Response(status, json={"detail": HOSTILE, "dsn": DSN})
        return httpx2.Response(status, text=HOSTILE, headers={"content-type": "text/plain"})

    client = _client(handler)
    with pytest.raises(BackendError) as failed:
        await client.get_json("/accounts", customer=CUSTOMER)
    await client.aclose()

    assert failed.value.status == status
    assert str(failed.value) == f"backend answered {status}"
    assert failed.value.args == (f"backend answered {status}",)
    _assert_clean(_everything(failed.value))
    assert failed.value.guidance


async def test_backend_error_has_no_detail_field() -> None:
    client = _client(lambda request: httpx2.Response(500, json={"detail": HOSTILE}))
    with pytest.raises(BackendError) as failed:
        await client.get_json("/accounts", customer=CUSTOMER)
    await client.aclose()
    assert not hasattr(failed.value, "detail")
    assert set(vars(failed.value)) <= {"status", "guidance"}


# --- the facade: no status arrived -------------------------------------------


def _raising(exc: BaseException) -> Callable[[httpx2.Request], httpx2.Response]:
    def handler(request: httpx2.Request) -> httpx2.Response:
        raise exc

    return handler


_TRANSPORT_FAILURES = [
    httpx2.ConnectError(f"connect {HOSTILE}"),
    httpx2.ReadTimeout(f"timed out {HOSTILE}"),
    httpx2.DecodingError(f"bad gzip {HOSTILE}"),
    httpx2.RemoteProtocolError(f"illegal status line: {HOSTILE}"),
]


@pytest.mark.parametrize("failure", _TRANSPORT_FAILURES, ids=lambda f: type(f).__name__)
async def test_a_transport_failure_becomes_a_fixed_wrapper_with_no_chain(
    failure: httpx2.HTTPError,
) -> None:
    client = _client(_raising(failure))
    with pytest.raises(BackendUnavailableError) as failed:
        await client.get_json("/accounts", customer=CUSTOMER)
    await client.aclose()

    exc = failed.value
    assert exc.kind == type(failure).__name__
    assert exc.__cause__ is None
    assert exc.__context__ is None
    assert exc.__suppress_context__ is True
    assert not isinstance(exc, BackendError), "no status exists, so no `.status` to misread"
    assert str(exc) == "the backend could not be reached or answered improperly"
    _assert_clean(_everything(exc))


async def test_a_bug_that_is_not_an_http_error_propagates_unwrapped() -> None:
    client = _client(_raising(RuntimeError(f"bug {SENTINEL}")))
    with pytest.raises(RuntimeError, match=SENTINEL) as failed:
        await client.get_json("/accounts", customer=CUSTOMER)
    await client.aclose()
    assert type(failed.value) is RuntimeError


async def test_cancellation_propagates_and_is_never_wrapped() -> None:
    client = _client(_raising(asyncio.CancelledError()))
    with pytest.raises(asyncio.CancelledError):
        await client.get_json("/accounts", customer=CUSTOMER)
    await client.aclose()


def test_the_client_still_ignores_proxy_environment_variables() -> None:
    client = _client(lambda request: httpx2.Response(200, json={}))
    assert client._client._trust_env is False


# --- Vault -------------------------------------------------------------------


def _vault_with(
    handler: Callable[[httpx2.Request], httpx2.Response],
) -> VaultTransitKeySource:
    return VaultTransitKeySource(
        address=ADDRESS,
        key_name="postern-read",
        kid="read-1",
        token=TOKEN,
        transport=httpx2.MockTransport(handler),
    )


@pytest.mark.parametrize("status", [403, 404, 500, 503])
@pytest.mark.parametrize("operation", ["sign", "keys"])
def test_a_vault_refusal_carries_status_and_no_path_or_body(status: int, operation: str) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(status, json={"errors": [HOSTILE, f"path {request.url.path}"]})

    source = _vault_with(handler)
    with pytest.raises(VaultTransitError) as failed:
        if operation == "sign":
            source.sign({"sub": CUSTOMER.value})
        else:
            source.public_jwks()
    source.close()

    exc = failed.value
    assert exc.status == status
    assert exc.kind is None
    assert f"HTTP {status}" in str(exc)
    for text in (_everything(exc), "transit/sign", "transit/keys", "postern-read", "errors"):
        _assert_clean(text)
    assert "/v1/" not in _everything(exc)
    assert "postern-read" not in _everything(exc)


def test_a_vault_transport_failure_is_wrapped_with_the_type_name_only() -> None:
    source = _vault_with(_raising(httpx2.ConnectError(f"refused {HOSTILE} {ADDRESS}")))
    with pytest.raises(VaultTransitError) as failed:
        source.sign({"sub": CUSTOMER.value})
    source.close()

    exc = failed.value
    assert exc.kind == "ConnectError"
    assert exc.status is None
    assert "unreachable" in str(exc)
    assert exc.__cause__ is None and exc.__context__ is None
    assert exc.__suppress_context__ is True
    _assert_clean(_everything(exc))
    assert ADDRESS not in _everything(exc)


def test_a_vault_key_description_it_cannot_parse_carries_none_of_it() -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            200, json={"data": {"type": "rsa-2048", "latest_version": HOSTILE, "keys": {}}}
        )

    source = _vault_with(handler)
    with pytest.raises(VaultTransitError) as failed:
        source.public_jwks()
    source.close()
    _assert_clean(_everything(failed.value))
    assert failed.value.__cause__ is None and failed.value.__context__ is None


def test_a_non_rsa_key_type_from_vault_is_not_echoed() -> None:
    vault = FakeVault()
    vault.key_type = HOSTILE
    source = _vault_with(vault)
    with pytest.raises(VaultTransitError) as failed:
        source.public_jwks()
    source.close()
    _assert_clean(_everything(failed.value))
    assert "RSA" in str(failed.value)


def test_a_missing_token_file_names_the_variable_and_not_the_path(tmp_path: Path) -> None:
    missing = tmp_path / "zzsentinel_tokenfile_7788"
    source = VaultTransitKeySource(
        address=ADDRESS,
        key_name="postern-read",
        kid="read-1",
        token_path=missing,
        transport=httpx2.MockTransport(lambda request: httpx2.Response(200)),
    )
    with pytest.raises(VaultTransitError) as failed:
        source.sign({"sub": CUSTOMER.value})
    source.close()
    assert "POSTERN_VAULT_TOKEN_PATH" in str(failed.value)
    assert failed.value.kind == "FileNotFoundError"
    assert "zzsentinel_tokenfile_7788" not in _everything(failed.value)
    assert failed.value.__cause__ is None and failed.value.__context__ is None


def test_a_wrong_signing_version_is_a_fixed_sentence() -> None:
    vault = FakeVault()

    def lie(request: httpx2.Request) -> httpx2.Response:
        response = vault(request)
        if request.method == "POST":
            body = response.json()
            body["data"]["key_version"] = f"v-{SENTINEL}"
            return httpx2.Response(200, json=body)
        return response

    source = _vault_with(lie)
    with pytest.raises(VaultTransitError, match="version") as failed:
        source.sign({"sub": CUSTOMER.value})
    source.close()
    _assert_clean(_everything(failed.value))
    assert "read-1" not in _everything(failed.value)


# --- Redis -------------------------------------------------------------------

REDIS_URL = f"redis://aclUser{SENTINEL}:pw{SENTINEL}@redis-host.internal:6379/0"
REDIS_TEXT = f"Error 111 connecting to redis-host.internal:6379. {REDIS_URL} {SENTINEL}"
REDIS_FORBIDDEN = (SENTINEL, "redis-host.internal", "6379", "aclUser")


class _Pipe:
    """Queues are fine; `execute` is where a real pipeline fails."""

    def __getattr__(self, name: str) -> Callable[..., _Pipe]:
        return lambda *args, **kwargs: self

    async def execute(self) -> Any:
        raise RedisConnectionError(REDIS_TEXT)


class _DownRedis:
    def __getattr__(self, name: str) -> Callable[..., Coroutine[Any, Any, Any]]:
        if name == "pipeline":
            return lambda *args, **kwargs: _Pipe()  # type: ignore[return-value]

        async def fail(*args: Any, **kwargs: Any) -> Any:
            raise RedisConnectionError(REDIS_TEXT)

        return fail


def _walk(exc: BaseException) -> list[BaseException]:
    """What a traceback printer reaches: `__cause__`, and `__context__` unless suppressed."""
    seen: list[BaseException] = []
    pending: list[BaseException | None] = [exc]
    while pending:
        current = pending.pop()
        if current is None or current in seen:
            continue
        seen.append(current)
        pending.append(current.__cause__)
        if not current.__suppress_context__:
            pending.append(current.__context__)
    return seen


def _assert_chain_is_clean(exc: BaseException) -> None:
    assert exc.__cause__ is None
    assert exc.__suppress_context__ is True
    assert len(_walk(exc)) == 1, "the printed chain stops at the wrapper"
    rendered = "".join(traceback.format_exception(exc)) + repr(exc) + str(exc)
    for needle in REDIS_FORBIDDEN:
        assert needle not in rendered, f"{needle!r} leaked: {rendered[:300]}"
    assert "ConnectionError" in str(exc)


def _revocation() -> RedisRevocationStore:
    store = RedisRevocationStore(url=REDIS_URL)
    store._redis = _DownRedis()
    return store


_CLAIMS = {"jti": "j1", "sub": "cust_a", "client_id": "c1", "iat": 1}

_REVOCATION_CALLS: dict[str, Callable[[RedisRevocationStore], Coroutine[Any, Any, Any]]] = {
    "is_revoked": lambda s: s.is_revoked(_CLAIMS),
    "revoke_session": lambda s: s.revoke_session(jti="j1"),
    "restore_session": lambda s: s.restore_session(jti="j1"),
    "prune_sessions": lambda s: s.prune_sessions(),
    "unindexed_session_count": lambda s: s.unindexed_session_count(),
    "revoke_customer_client": lambda s: s.revoke_customer_client(customer_ref="a", client_id="c"),
    "restore_customer_client": lambda s: s.restore_customer_client(customer_ref="a", client_id="c"),
    "customer_revoked_at": lambda s: s.customer_revoked_at("cust_a"),
    "client_revoked_at": lambda s: s.client_revoked_at("c1"),
    "kill_switch": lambda s: s.kill_switch(client_id="c1"),
    "restore_client": lambda s: s.restore_client(client_id="c1"),
    "entries": lambda s: s.entries(),
    "is_customer_revoked": lambda s: s.is_customer_revoked("cust_a"),
}


@pytest.mark.parametrize("name", sorted(_REVOCATION_CALLS))
async def test_every_revocation_wrapper_stops_the_chain_at_itself(name: str) -> None:
    store = _revocation()
    with pytest.raises(RevocationStoreUnavailable) as failed:
        await _REVOCATION_CALLS[name](store)
    _assert_chain_is_clean(failed.value)


async def test_a_corrupt_stored_stamp_does_not_echo_the_stored_value() -> None:
    store = RedisRevocationStore(url=REDIS_URL)

    class _Corrupt:
        async def get(self, key: str) -> str:
            return f"not-a-number-{SENTINEL}"

    store._redis = _Corrupt()
    with pytest.raises(RevocationStoreUnavailable) as failed:
        await store.customer_revoked_at("cust_a")
    assert failed.value.__cause__ is None
    assert failed.value.__suppress_context__ is True
    assert SENTINEL not in "".join(traceback.format_exception(failed.value))


_SESSION_KEY = SessionKey(customer_ref="cust_a", client_id="c1")


@pytest.mark.parametrize("call", ["load", "save", "remove"])
async def test_every_session_store_wrapper_stops_the_chain_at_itself(call: str) -> None:
    store = RedisSessionStore(url=REDIS_URL)
    store._redis = _DownRedis()
    with pytest.raises(SessionStoreUnavailable) as failed:
        if call == "load":
            await store.load(_SESSION_KEY)
        elif call == "save":
            await store.save(_SESSION_KEY, RiskContext(session_id=_SESSION_KEY.value))
        else:
            await store.remove(_SESSION_KEY)
    _assert_chain_is_clean(failed.value)


async def test_the_customer_rate_limit_wrapper_stops_the_chain_at_itself() -> None:
    store = RedisCustomerRateLimitStore(url=REDIS_URL)
    store._redis = _DownRedis()
    with pytest.raises(CustomerRateLimitStoreUnavailable) as failed:
        await store.charge("cust_a", "/approve", Limit(requests=1, window_seconds=60))
    _assert_chain_is_clean(failed.value)


def test_the_preflight_refusals_carry_no_url_or_userinfo() -> None:
    class _Skewed:
        def time(self) -> tuple[int, int]:
            return (10**10, 0)

        def config_get(self, name: str) -> dict[str, str]:
            return {"maxmemory-policy": "allkeys-lru"}

    for check in (redis_preflight.check_clock_skew, redis_preflight.check_eviction_policy):
        with pytest.raises(redis_preflight.RedisPreflightError) as failed:
            check(_Skewed())
        text = _everything(failed.value)
        for needle in ("redis://", "@", "aclUser", SENTINEL):
            assert needle not in text


def test_the_preflight_never_reaches_a_url_through_run_redis_preflight(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The checks take a client and never see the URL, so no refusal can print it."""
    monkeypatch.setenv("POSTERN_REDIS_URL", REDIS_URL)

    class _Skewed:
        def time(self) -> tuple[int, int]:
            return (10**10, 0)

        def close(self) -> None:
            pass

    monkeypatch.setattr(redis_preflight, "_client_from_url", lambda url: _Skewed())
    with pytest.raises(redis_preflight.RedisPreflightError) as failed:
        redis_preflight.run_redis_preflight()
    text = _everything(failed.value)
    for needle in REDIS_FORBIDDEN:
        assert needle not in text


# --- the scan ----------------------------------------------------------------

#: Files where an `except` wraps a Redis, `httpx2` or Vault call and re-raises.
SCANNED = (
    "packages/postern-core/src/postern_core/auth/revocation.py",
    "packages/postern-core/src/postern_core/risk/session.py",
    "packages/postern-core/src/postern_core/facade/client.py",
    "packages/postern-core/src/postern_core/auth/vault.py",
    "services/confirm/customer_rate_limit.py",
    "services/confirm/execute.py",
)


def _chaining_raises(source: str) -> list[tuple[int, str]]:
    """``raise X from <the handler's own name>`` and a bare ``raise``, inside an `except`.

    A heuristic and a narrow one: it sees these two shapes in a handler body,
    in the files listed in `SCANNED`. It does not follow a call into another
    function, and it does not see `raise exc`, `raise X(...)` with no `from`
    (which chains implicitly as `__context__` and is printed), or a wrapper
    defined elsewhere. The `raise X(...)` with no `from` shape is checked
    separately below.
    """
    found: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ExceptHandler):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Raise):
                continue
            if inner.exc is None:
                # `except TimeoutError: ... raise` re-raises a bare asyncio timeout
                # that was not this module's own deadline: it carries no text.
                if isinstance(node.type, ast.Name) and node.type.id == "TimeoutError":
                    continue
                found.append((inner.lineno, "bare raise"))
            elif node.name and isinstance(inner.cause, ast.Name) and inner.cause.id == node.name:
                found.append((inner.lineno, f"from {node.name}"))
    return found


def _implicit_chains(source: str) -> list[int]:
    """``raise X(...)`` inside an `except` with no ``from`` clause at all."""
    found: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ExceptHandler):
            continue
        for inner in ast.walk(node):
            if isinstance(inner, ast.Raise) and inner.exc is not None and inner.cause is None:
                found.append(inner.lineno)
    return found


@pytest.mark.parametrize("relative", SCANNED)
def test_no_handler_in_the_read_path_clients_chains_the_original(relative: str) -> None:
    source = (ROOT / relative).read_text(encoding="utf-8")
    assert _chaining_raises(source) == []


@pytest.mark.parametrize("relative", SCANNED)
def test_no_handler_in_the_read_path_clients_raises_with_an_implicit_chain(relative: str) -> None:
    source = (ROOT / relative).read_text(encoding="utf-8")
    assert _implicit_chains(source) == []


def test_the_scan_sees_what_it_claims_to() -> None:
    chained = "try:\n    f()\nexcept Exception as exc:\n    raise X('a') from exc\n"
    bare = "try:\n    f()\nexcept Exception:\n    raise\n"
    implicit = "try:\n    f()\nexcept Exception:\n    raise X('a')\n"
    timeout = "try:\n    f()\nexcept TimeoutError:\n    raise\n"
    clean = "try:\n    f()\nexcept Exception:\n    raise X('a') from None\n"
    assert _chaining_raises(chained) == [(4, "from exc")]
    assert _chaining_raises(bare) == [(4, "bare raise")]
    assert _implicit_chains(implicit) == [4]
    assert _chaining_raises(timeout) == []
    assert _chaining_raises(clean) == [] and _implicit_chains(clean) == []

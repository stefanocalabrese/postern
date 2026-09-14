"""Server assembly with an injected customer resolver (Task 4)."""

import dataclasses

import pytest
from fastmcp import FastMCP
from fastmcp.client import Client
from fastmcp.server import dependencies as deps
from fastmcp.server.auth import AccessToken
from pydantic import ValidationError

from services.api.server import build_server, token_customer_resolver
from services.api.settings import Settings
from tests.conftest import TEST_CUSTOMER as _REF


def test_build_server_returns_a_fastmcp_instance() -> None:
    server = build_server(Settings.for_testing(), resolver=lambda: _REF, backend=None)
    assert isinstance(server, FastMCP)


def test_server_starts_with_no_tools_registered() -> None:
    server = build_server(Settings.for_testing(), resolver=lambda: _REF, backend=None)
    assert server.name == "postern"


async def test_client_can_list_tools_in_process() -> None:
    server = build_server(Settings.for_testing(), resolver=lambda: _REF, backend=None)
    async with Client(transport=server) as client:
        assert await client.list_tools() == []


def test_settings_from_env_raises_a_keyerror_naming_the_missing_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`from_env` reads three mandatory keys via `os.environ[...]`; a missing
    one must fail loudly at startup, and the exception must name it.
    """
    monkeypatch.delenv("POSTERN_BACKEND_BASE_URL", raising=False)
    monkeypatch.delenv("POSTERN_JWKS_URI", raising=False)
    monkeypatch.delenv("POSTERN_TOKEN_ISSUER", raising=False)
    with pytest.raises(KeyError) as excinfo:
        Settings.from_env()
    assert excinfo.value.args[0] == "POSTERN_BACKEND_BASE_URL"


async def test_cache_ttl_seconds_and_scope_reach_the_wire() -> None:
    """Empirical: FastMCP's `cache_ttl` constructor argument is in seconds and
    is multiplied by 1000 onto the wire's `ttlMs`
    (fastmcp/server/caching.py: `CacheHint(ttl_ms=cache_ttl * 1000, ...)`).
    """
    settings = Settings(backend_base_url="https://backend.test", cache_ttl_seconds=5)
    server = build_server(settings, resolver=lambda: _REF, backend=None)
    async with Client(transport=server) as client:
        raw = await client.list_tools_mcp()
        dumped = raw.model_dump(by_alias=True)
        assert dumped["ttlMs"] == 5_000
        assert dumped["cacheScope"] == "private"


def test_build_server_rejects_jwks_uri_set_without_issuer() -> None:
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_jwks_uri="https://issuer.test/.well-known/jwks.json",
    )
    with pytest.raises(ValueError, match="customer_jwks_uri.*customer_token_issuer"):
        build_server(settings, resolver=lambda: _REF, backend=None)


def test_build_server_rejects_issuer_set_without_jwks_uri() -> None:
    settings = Settings(
        backend_base_url="https://backend.test",
        customer_token_issuer="https://issuer.test",  # noqa: S106
    )
    with pytest.raises(ValueError, match="customer_jwks_uri.*customer_token_issuer"):
        build_server(settings, resolver=lambda: _REF, backend=None)


def test_build_server_stays_unauthenticated_when_neither_is_set() -> None:
    """`Settings.for_testing()` and the local docker-compose stack rely on
    this: deliberately no auth, not a half-configured one.
    """
    server = build_server(Settings.for_testing(), resolver=lambda: _REF, backend=None)
    assert server.auth is None


def test_settings_from_env_treats_missing_jwks_and_issuer_as_no_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`os.environ[...]` can never produce `None`, only a `KeyError` or a
    `str` -- reading these two that way made `build_server`'s documented
    no-auth path (the one the previous test exercises) unreachable through
    `from_env()`, which is what the local docker-compose stack actually
    calls (Task 13 finding).
    """
    monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
    monkeypatch.delenv("POSTERN_JWKS_URI", raising=False)
    monkeypatch.delenv("POSTERN_TOKEN_ISSUER", raising=False)
    settings = Settings.from_env()
    assert settings.customer_jwks_uri is None
    assert settings.customer_token_issuer is None
    server = build_server(settings, resolver=lambda: _REF, backend=None)
    assert server.auth is None


def test_settings_from_env_treats_empty_string_jwks_and_issuer_as_no_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compose convention this repo's plan used (`POSTERN_JWKS_URI: ""`)
    must reach the same `None` normalization as leaving the variable unset,
    since docker-compose setting a key to `""` still makes the environment
    variable present (not absent) in the container.
    """
    monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
    monkeypatch.setenv("POSTERN_JWKS_URI", "")
    monkeypatch.setenv("POSTERN_TOKEN_ISSUER", "")
    settings = Settings.from_env()
    assert settings.customer_jwks_uri is None
    assert settings.customer_token_issuer is None


def test_token_customer_resolver_with_no_access_token_raises_permission_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(deps, "get_access_token", lambda: None)
    with pytest.raises(PermissionError, match="no validated access token"):
        token_customer_resolver()


def test_token_customer_resolver_with_no_subject_claim_raises_permission_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = AccessToken(token="t", client_id="c", scopes=[], claims={})  # noqa: S106
    monkeypatch.setattr(deps, "get_access_token", lambda: token)
    with pytest.raises(PermissionError, match="no subject claim"):
        token_customer_resolver()


def test_token_customer_resolver_rejects_a_malformed_subject_without_leaking_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A compromised issuer's `sub` is attacker-influenced (identity.py'
    provenance-only comment). A `CustomerRef` validation failure here must not
    leak the raw subject through the resolver's own exception:
    `CustomerRef.hide_input_in_errors` scrubs only `str()`/`repr()`, not the
    structured `.errors()` that FastMCP's own dispatcher logs when a raw
    `pydantic.ValidationError` escapes a tool (fastmcp/server/server.py, the
    `except PydanticValidationError` branch calls `e.errors(include_url=False)`
    with no `include_input=False`).
    """
    raw_pan = "4111111111111111"
    token = AccessToken(token="t", client_id="c", scopes=[], claims={"sub": raw_pan})  # noqa: S106
    monkeypatch.setattr(deps, "get_access_token", lambda: token)
    with pytest.raises(PermissionError) as excinfo:
        token_customer_resolver()
    assert raw_pan not in str(excinfo.value)
    assert not isinstance(excinfo.value.__cause__, ValidationError)


def test_settings_reads_the_database_url_from_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("POSTERN_BACKEND_BASE_URL", "https://backend.test")
    monkeypatch.setenv("POSTERN_DATABASE_URL", "postgresql+asyncpg://u:p@db:5432/postern")
    monkeypatch.delenv("POSTERN_JWKS_URI", raising=False)
    monkeypatch.delenv("POSTERN_TOKEN_ISSUER", raising=False)
    assert Settings.from_env().database_url == "postgresql+asyncpg://u:p@db:5432/postern"


def test_settings_database_url_is_required() -> None:
    assert "database_url" in {f.name for f in dataclasses.fields(Settings)}
